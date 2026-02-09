#!/usr/bin/env python3
"""Minimal NDJSON IPC helpers for gui_hook_test app scripts."""

from __future__ import annotations

import json
import socket
from typing import Any, Dict, Iterable, Optional


class IpcError(RuntimeError):
    """Raised when IPC request/response fails."""


class IpcClient:
    """Simple one-request-per-connection NDJSON client."""

    def __init__(self, socket_path: str, timeout_s: float = 3.0) -> None:
        self.socket_path = socket_path
        self.timeout_s = max(float(timeout_s), 0.1)

    def request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_s)
            sock.connect(self.socket_path)
            sock.sendall(data)
            raw = sock.makefile("rb").readline()
        if not raw:
            raise IpcError("empty IPC response")
        try:
            obj = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise IpcError(f"invalid JSON response: {exc}") from exc
        if not isinstance(obj, dict):
            raise IpcError("IPC response is not an object")
        return obj


def subscribe_events(
    socket_path: str,
    *,
    events: Iterable[str],
    types: Iterable[str] = ("coils", "holding_regs"),
    timeout_s: float = 5.0,
) -> tuple[socket.socket, Dict[str, Any], Any]:
    """Create a subscription stream and return (socket, ack, fileobj)."""
    payload: Dict[str, Any] = {
        "id": 1,
        "cmd": "subscribe",
        "events": list(events),
        "types": list(types),
    }
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(max(float(timeout_s), 0.1))
    sock.connect(socket_path)
    sock.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream = sock.makefile("rb")
    raw_ack = stream.readline()
    if not raw_ack:
        sock.close()
        raise IpcError("empty subscribe ack")
    try:
        ack = json.loads(raw_ack.decode("utf-8"))
    except json.JSONDecodeError as exc:
        sock.close()
        raise IpcError(f"invalid subscribe ack: {exc}") from exc
    if not isinstance(ack, dict):
        sock.close()
        raise IpcError("subscribe ack is not an object")
    if not ack.get("ok", False):
        sock.close()
        raise IpcError(f"subscribe failed: {ack}")
    return sock, ack, stream


def wait_for_event(
    stream: Any,
    event_name: str,
    *,
    timeout_s: float = 5.0,
) -> Optional[Dict[str, Any]]:
    """Wait for a named event on an open subscription stream."""
    timeout = max(float(timeout_s), 0.1)
    sock_obj = getattr(stream, "_sock", None)
    if sock_obj is not None:
        sock_obj.settimeout(timeout)
    while True:
        try:
            raw = stream.readline()
        except socket.timeout:
            return None
        if not raw:
            return None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("event") == event_name:
            return obj
