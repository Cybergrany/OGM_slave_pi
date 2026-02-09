"""IPC server exposing register/GPIO access over a Unix domain socket (NDJSON)."""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Set

from .gpio import GpioAdapter
from .gpio_claims import GpioClaimRegistry
from .pin_resolver import HandleInfo, PinResolver
from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)

DEFAULT_SUBSCRIBE_TYPES = {"coils", "holding_regs"}
SUPPORTED_TYPES = {"coils", "holding_regs"}

DEFAULT_SUBSCRIBE_EVENTS = {"change"}
SUPPORTED_EVENTS = {"change", "board_reset"}


@dataclass
class Subscriber:
    """Subscription state for a single client connection."""

    conn: socket.socket
    events: Set[str]
    types: Set[str]
    names: Optional[Set[str]]
    queue: "queue.Queue[Dict[str, Any]]"
    dropped: int = 0

    def matches(self, event: Dict[str, Any]) -> bool:
        """Return True if this subscriber should receive the event."""
        event_name = str(event.get("event") or "")
        if event_name not in self.events:
            return False

        if event_name == "board_reset":
            return True

        if event_name != "change":
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

    def __init__(
        self,
        store: RegisterStore,
        pinmap: PinMap,
        socket_path: str,
        *,
        resolver: Optional[PinResolver] = None,
        gpio: Optional[GpioAdapter] = None,
        gpio_claims: Optional[GpioClaimRegistry] = None,
        app_reload_cb: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        self._store = store
        self._pinmap = pinmap
        self._socket_path = socket_path
        self._resolver = resolver or PinResolver(pinmap)
        self._gpio = gpio
        self._gpio_claims = gpio_claims
        self._app_reload_cb = app_reload_cb

        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._subscribers: list[Subscriber] = []
        self._sub_lock = threading.Lock()
        self._last_seq_by_pin: Dict[str, int] = {}
        self._startup_error: Optional[str] = None
        self._startup_error_lock = threading.Lock()

    def set_app_reload_handler(self, callback: Optional[Callable[[], Dict[str, Any]]]) -> None:
        self._app_reload_cb = callback

    def consume_startup_error(self) -> Optional[str]:
        """Return and clear the last fatal startup error, if present."""
        with self._startup_error_lock:
            error = self._startup_error
            self._startup_error = None
            return error

    def serve_forever(self) -> None:
        """Start accepting connections and processing JSON requests."""
        self._stop_event.clear()
        try:
            self._sock = self._get_listening_socket()
        except Exception as exc:
            with self._startup_error_lock:
                self._startup_error = str(exc)
            LOGGER.exception("IPC startup failed")
            return
        with self._startup_error_lock:
            self._startup_error = None
        self._sock.settimeout(1.0)
        LOGGER.info("IPC listening on %s", self._socket_path)

        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except BlockingIOError:
                time.sleep(0.05)
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                LOGGER.exception("IPC accept failed; retrying")
                time.sleep(0.1)
                continue
            thread = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            thread.start()

    def stop(self) -> None:
        """Stop accepting new connections and close the listening socket."""
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass

    def publish_events(self, events: Iterable[Dict[str, Any]]) -> None:
        """Publish events to any matching subscribers."""
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for event in events:
            name = event.get("name")
            seq = event.get("seq")
            if name and isinstance(seq, int):
                self._last_seq_by_pin[str(name)] = seq
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
                return self._ok(self._get_pin(request.get("name"), request.get("since")), request_id)
            if cmd == "set":
                return self._ok(self._set_pin(request.get("name"), request.get("values")), request_id)
            if cmd == "resolve":
                return self._ok(self._resolve_handles(request.get("names")), request_id)
            if cmd == "get_many":
                return self._ok(self._get_many(request.get("handles")), request_id)
            if cmd == "set_many":
                return self._ok(self._set_many(request.get("writes")), request_id)
            if cmd == "gpio_read":
                return self._ok(self._gpio_read(request.get("handles")), request_id)
            if cmd == "gpio_write":
                return self._ok(self._gpio_write(request.get("writes")), request_id)
            if cmd == "app_reload":
                return self._ok(self._app_reload(), request_id)
        except Exception as exc:
            LOGGER.exception("IPC request failed")
            return self._error(str(exc), request_id)

        return self._error(f"Unknown cmd {cmd}", request_id)

    def _handle_subscribe(self, conn: socket.socket, request: Dict[str, Any]) -> None:
        """Register a subscription and stream events until disconnect."""
        request_id = request.get("id")
        events = self._parse_events(request.get("events"))
        types = self._parse_types(request.get("types"))
        names = self._parse_names(request.get("names"))
        subscriber = Subscriber(conn=conn, events=events, types=types, names=names, queue=queue.Queue(maxsize=256))

        with self._sub_lock:
            self._subscribers.append(subscriber)

        ack = {
            "ok": True,
            "subscribed": True,
            "events": sorted(events),
            "types": sorted(types),
            "names": sorted(names) if names else None,
        }
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

    def _parse_events(self, raw: Any) -> Set[str]:
        """Parse subscribe event names."""
        if raw is None:
            return set(DEFAULT_SUBSCRIBE_EVENTS)
        if not isinstance(raw, list):
            raise ValueError("events must be a list")
        events = {str(e) for e in raw}
        invalid = events.difference(SUPPORTED_EVENTS)
        if invalid:
            raise ValueError(f"Unsupported events: {sorted(invalid)}")
        if not events:
            raise ValueError("events list cannot be empty")
        return events

    def _parse_types(self, raw: Any) -> Set[str]:
        """Parse subscription register types, defaulting to master-writable regs."""
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
            handle = self._resolver.handle_for_name(pin.name)
            pins.append(
                {
                    "handle": handle,
                    "name": pin.name,
                    "type": pin.type,
                    "pin": pin.pin,
                    "gpio_line": self._resolver.gpio_line_for_handle(handle),
                    "args": pin.args,
                    "coils": [pin.coils.start, pin.coils.count],
                    "discretes": [pin.discretes.start, pin.discretes.count],
                    "input_regs": [pin.input_regs.start, pin.input_regs.count],
                    "holding_regs": [pin.holding_regs.start, pin.holding_regs.count],
                }
            )
        return {"pins": pins}

    def _resolve_handles(self, raw_names: Any) -> Dict[str, Any]:
        if not isinstance(raw_names, list):
            raise ValueError("names must be a list")
        infos = self._resolver.resolve_names(raw_names)
        return {"handles": [self._handle_info_to_dict(info) for info in infos]}

    def _get_many(self, raw_handles: Any) -> Dict[str, Any]:
        if not isinstance(raw_handles, list):
            raise ValueError("handles must be a list")
        items = []
        for raw in raw_handles:
            handle = self._coerce_handle(raw)
            pin = self._resolver.pin_for_handle(handle)
            items.append({"handle": handle, "name": pin.name, "values": self._store.get_pin(pin)})
        return {"items": items}

    def _set_many(self, raw_writes: Any) -> Dict[str, Any]:
        if not isinstance(raw_writes, list):
            raise ValueError("writes must be a list")
        items = []
        for entry in raw_writes:
            if not isinstance(entry, dict):
                raise ValueError("each write entry must be an object")
            handle = self._coerce_handle(entry.get("handle"))
            values = entry.get("values")
            if not isinstance(values, dict):
                raise ValueError("write values must be an object of register arrays")
            pin = self._resolver.pin_for_handle(handle)
            updated = self._store.set_pin(pin, values)
            items.append({"handle": handle, "name": pin.name, "values": updated})
        return {"items": items}

    def _gpio_read(self, raw_handles: Any) -> Dict[str, Any]:
        if self._gpio is None:
            raise ValueError("GPIO is not available")
        if not isinstance(raw_handles, list):
            raise ValueError("handles must be a list")
        items = []
        for raw in raw_handles:
            handle = self._coerce_handle(raw)
            pin = self._resolver.pin_for_handle(handle)
            line = self._resolver.gpio_line_for_handle(handle)
            if line is None:
                raise ValueError(f"Pin {pin.name} does not map to a GPIO line")
            self._ensure_app_claimed(line)
            items.append({"handle": handle, "name": pin.name, "line": line, "value": int(self._gpio.read(line))})
        return {"items": items}

    def _gpio_write(self, raw_writes: Any) -> Dict[str, Any]:
        if self._gpio is None:
            raise ValueError("GPIO is not available")
        if not isinstance(raw_writes, list):
            raise ValueError("writes must be a list")

        items = []
        for entry in raw_writes:
            if not isinstance(entry, dict):
                raise ValueError("each write entry must be an object")
            handle = self._coerce_handle(entry.get("handle"))
            value = self._coerce_gpio_value(entry.get("value"))
            pin = self._resolver.pin_for_handle(handle)
            line = self._resolver.gpio_line_for_handle(handle)
            if line is None:
                raise ValueError(f"Pin {pin.name} does not map to a GPIO line")
            self._ensure_app_claimed(line)
            self._gpio.write(line, value)
            items.append({"handle": handle, "name": pin.name, "line": line, "value": 1 if value else 0})
        return {"items": items}

    def _app_reload(self) -> Dict[str, Any]:
        if self._app_reload_cb is None:
            raise ValueError("App reload is not configured")
        result = self._app_reload_cb()
        if isinstance(result, dict):
            return {"app": result}
        return {"app": {"result": result}}

    def _ensure_app_claimed(self, line: int) -> None:
        if self._gpio_claims is None:
            return
        owner = self._gpio_claims.owner_for_line(line)
        if owner is None or not owner.startswith("app:"):
            raise ValueError(f"GPIO line {line} is not app-claimed")

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
    def _handle_info_to_dict(info: HandleInfo) -> Dict[str, Any]:
        return {
            "handle": info.handle,
            "name": info.name,
            "type": info.type,
            "pin": info.pin,
            "gpio_line": info.gpio_line,
            "args": info.args,
            "coils": info.coils,
            "discretes": info.discretes,
            "input_regs": info.input_regs,
            "holding_regs": info.holding_regs,
        }

    @staticmethod
    def _coerce_handle(raw: Any) -> int:
        try:
            handle = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid handle {raw}")
        if handle <= 0:
            raise ValueError("handle must be > 0")
        return handle

    @staticmethod
    def _coerce_gpio_value(raw: Any) -> bool:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, (int, float)):
            return bool(int(raw))
        if isinstance(raw, str):
            normalized = raw.strip().lower()
            if normalized in {"1", "true", "on", "yes", "y"}:
                return True
            if normalized in {"0", "false", "off", "no", "n"}:
                return False
        raise ValueError(f"Invalid GPIO value {raw}")

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
