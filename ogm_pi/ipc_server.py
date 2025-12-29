"""IPC server exposing register access over a Unix domain socket (NDJSON)."""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from typing import Any, Dict, Optional

from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)


class IPCServer:
    """Line-delimited JSON IPC server for local clients."""

    def __init__(self, store: RegisterStore, pinmap: PinMap, socket_path: str) -> None:
        self._store = store
        self._pinmap = pinmap
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()

    def serve_forever(self) -> None:
        """Start accepting connections and processing JSON requests."""
        self._sock = self._get_listening_socket()
        LOGGER.info("IPC listening on %s", self._socket_path)

        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            thread = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            thread.start()

    def stop(self) -> None:
        """Stop accepting new connections and close the listening socket."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _handle_client(self, conn: socket.socket) -> None:
        """Handle a single client connection (one request per line)."""
        with conn:
            fileobj = conn.makefile("rb")
            for raw in fileobj:
                line = raw.strip()
                if not line:
                    continue
                response = self._process_line(line)
                conn.sendall(json.dumps(response).encode("utf-8") + b"\n")

    def _process_line(self, line: bytes) -> Dict[str, Any]:
        """Parse a request line and return a response payload."""
        try:
            request = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"Invalid JSON: {exc}"}

        request_id = request.get("id")
        cmd = request.get("cmd")
        if not cmd:
            return self._error("Missing cmd", request_id)

        try:
            if cmd == "list":
                return self._ok(self._list_pins(), request_id)
            if cmd == "schema":
                return self._ok(self._pinmap.raw, request_id)
            if cmd == "get":
                name = request.get("name")
                return self._ok(self._get_pin(name), request_id)
            if cmd == "set":
                name = request.get("name")
                values = request.get("values")
                return self._ok(self._set_pin(name, values), request_id)
        except Exception as exc:
            LOGGER.exception("IPC request failed")
            return self._error(str(exc), request_id)

        return self._error(f"Unknown cmd '{cmd}'", request_id)

    def _list_pins(self) -> Dict[str, Any]:
        """Return a listing of all pins with metadata."""
        pins = []
        for pin in self._pinmap.pins:
            pins.append(
                {
                    "name": pin.name,
                    "type": pin.type,
                    "pin": pin.pin,
                    "args": pin.args,
                    "coils": [pin.coils.start, pin.coils.count],
                    "discretes": [pin.discretes.start, pin.discretes.count],
                    "input_regs": [pin.input_regs.start, pin.input_regs.count],
                    "holding_regs": [pin.holding_regs.start, pin.holding_regs.count],
                }
            )
        return {"pins": pins}

    def _get_pin(self, name: Any) -> Dict[str, Any]:
        """Return register values for a named pin."""
        if not name:
            raise ValueError("Missing pin name")
        pin = self._pinmap.find_pin(str(name))
        return {"name": pin.name, "values": self._store.get_pin(pin)}

    def _set_pin(self, name: Any, values: Any) -> Dict[str, Any]:
        """Set register values for a named pin."""
        if not name:
            raise ValueError("Missing pin name")
        if not isinstance(values, dict):
            raise ValueError("values must be an object of register arrays")
        pin = self._pinmap.find_pin(str(name))
        updated = self._store.set_pin(pin, values)
        return {"name": pin.name, "values": updated}

    @staticmethod
    def _ok(payload: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        """Wrap a success payload with ok/id metadata."""
        resp = {"ok": True}
        if request_id is not None:
            resp["id"] = request_id
        resp.update(payload)
        return resp

    @staticmethod
    def _error(message: str, request_id: Any) -> Dict[str, Any]:
        """Wrap an error payload with ok/id metadata."""
        resp = {"ok": False, "error": message}
        if request_id is not None:
            resp["id"] = request_id
        return resp

    def _get_listening_socket(self) -> socket.socket:
        """Create or reuse a listening socket (systemd socket activation supported)."""
        sock = systemd_listen_socket()
        if sock is not None:
            return sock

        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self._socket_path)
        sock.listen(5)
        return sock


def systemd_listen_socket() -> Optional[socket.socket]:
    """Return a socket from systemd activation if present, else None."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    if not listen_pid or int(listen_pid) != os.getpid() or listen_fds < 1:
        return None
    return socket.socket(fileno=3)
