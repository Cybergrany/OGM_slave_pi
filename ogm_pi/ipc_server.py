"""IPC server exposing register access over a Unix domain socket (NDJSON)."""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Set

from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)

DEFAULT_SUBSCRIBE_TYPES = {"coils", "holding_regs"}
SUPPORTED_TYPES = {"coils", "holding_regs"}


@dataclass
class Subscriber:
    """Subscription state for a single client connection."""

    conn: socket.socket
    types: Set[str]
    names: Optional[Set[str]]
    queue: "queue.Queue[Dict[str, Any]]"
    dropped: int = 0

    def matches(self, event: Dict[str, Any]) -> bool:
        """Return True if this subscriber should receive the event."""
        if event.get("event") != "change":
            return False
        event_types = set(event.get("types") or [])
        if not event_types.intersection(self.types):
            return False
        name = event.get("name")
        if self.names is not None and name not in self.names:
            return False
        return True

    def enqueue(self, event: Dict[str, Any]) -> None:
        """Queue an event for delivery, dropping the oldest if needed."""
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(event)
                self.dropped += 1
            except queue.Empty:
                pass


class IPCServer:
    """Line-delimited JSON IPC server for local clients."""

    def __init__(self, store: RegisterStore, pinmap: PinMap, socket_path: str) -> None:
        self._store = store
        self._pinmap = pinmap
        self._socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._subscribers: list[Subscriber] = []
        self._sub_lock = threading.Lock()
        self._last_seq_by_pin: Dict[str, int] = {}

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

    def publish_events(self, events: Iterable[Dict[str, Any]]) -> None:
        """Publish change events to any matching subscribers."""
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for event in events:
            name = event.get("name")
            seq = event.get("seq")
            if name and isinstance(seq, int):
                self._last_seq_by_pin[name] = seq
            for sub in subscribers:
                if sub.matches(event):
                    sub.enqueue(event)

    def _handle_client(self, conn: socket.socket) -> None:
        """Handle a single client connection (one request per line)."""
        with conn:
            fileobj = conn.makefile("rb")
            for raw in fileobj:
                line = raw.strip()
                if not line:
                    continue
                request = self._decode_request(line)
                if request is None:
                    conn.sendall(json.dumps({"ok": False, "error": "Invalid JSON"}).encode("utf-8") + b"\n")
                    continue
                if request.get("cmd") == "subscribe":
                    self._handle_subscribe(conn, request)
                    return
                response = self._handle_request(request)
                conn.sendall(json.dumps(response).encode("utf-8") + b"\n")

    def _handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch request/response commands."""
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
                since = request.get("since")
                return self._ok(self._get_pin(name, since), request_id)
            if cmd == "set":
                name = request.get("name")
                values = request.get("values")
                return self._ok(self._set_pin(name, values), request_id)
        except Exception as exc:
            LOGGER.exception("IPC request failed")
            return self._error(str(exc), request_id)

        return self._error(f"Unknown cmd '{cmd}'", request_id)

    def _handle_subscribe(self, conn: socket.socket, request: Dict[str, Any]) -> None:
        """Register a subscription and stream events until disconnect."""
        request_id = request.get("id")
        types = self._parse_types(request.get("types"))
        names = self._parse_names(request.get("names"))
        subscriber = Subscriber(conn=conn, types=types, names=names, queue=queue.Queue(maxsize=256))

        with self._sub_lock:
            self._subscribers.append(subscriber)

        ack = {"ok": True, "subscribed": True}
        if request_id is not None:
            ack["id"] = request_id
        conn.sendall(json.dumps(ack).encode("utf-8") + b"\n")

        try:
            while not self._stop_event.is_set():
                try:
                    event = subscriber.queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                conn.sendall(json.dumps(event).encode("utf-8") + b"\n")
        except OSError:
            pass
        finally:
            with self._sub_lock:
                if subscriber in self._subscribers:
                    self._subscribers.remove(subscriber)

    def _parse_types(self, raw: Any) -> Set[str]:
        """Parse subscription types, defaulting to master-writable registers."""
        if raw is None:
            return set(DEFAULT_SUBSCRIBE_TYPES)
        if not isinstance(raw, list):
            raise ValueError("types must be a list")
        types = {str(t) for t in raw}
        invalid = types.difference(SUPPORTED_TYPES)
        if invalid:
            raise ValueError(f"Unsupported types: {sorted(invalid)}")
        return types

    @staticmethod
    def _parse_names(raw: Any) -> Optional[Set[str]]:
        """Parse an optional list of pin names to filter on."""
        if raw is None:
            return None
        if not isinstance(raw, list):
            raise ValueError("names must be a list")
        return {str(n) for n in raw}

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

    def _get_pin(self, name: Any, since: Any = None) -> Dict[str, Any]:
        """Return register values for a named pin."""
        if not name:
            raise ValueError("Missing pin name")
        pin = self._pinmap.find_pin(str(name))
        payload = {"name": pin.name, "values": self._store.get_pin(pin)}
        if since is not None:
            try:
                since_val = int(since)
            except (TypeError, ValueError):
                raise ValueError("since must be an integer")
            last_seq = self._last_seq_by_pin.get(pin.name, 0)
            payload["changed"] = last_seq > since_val
            payload["last_seq"] = last_seq
        return payload

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

    @staticmethod
    def _decode_request(line: bytes) -> Optional[Dict[str, Any]]:
        """Decode a request line into JSON (returns None on failure)."""
        try:
            return json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            return None

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
