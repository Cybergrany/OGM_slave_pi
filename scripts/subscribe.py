#!/usr/bin/env python3
"""Subscribe to OGM_slave_pi change events over the IPC socket.

Usage example:
  ./scripts/subscribe.py --socket /run/ogm_pi.sock --types coils,holding_regs --events change,board_reset
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the subscription helper."""
    parser = argparse.ArgumentParser(description="Subscribe to OGM_slave_pi change events")
    parser.add_argument("--socket", default="/run/ogm_pi.sock", help="Path to IPC socket")
    parser.add_argument(
        "--events",
        default="change",
        help="Comma-separated event kinds to watch (change,board_reset)",
    )
    parser.add_argument(
        "--types",
        default="coils,holding_regs",
        help="Comma-separated register types to watch (coils,holding_regs)",
    )
    parser.add_argument(
        "--names",
        default=None,
        help="Optional comma-separated list of pin names to filter",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON events")
    return parser.parse_args()


def build_request(args: argparse.Namespace) -> Dict[str, Any]:
    """Build a subscribe request payload."""
    events = [e.strip() for e in args.events.split(",") if e.strip()]
    types = [t.strip() for t in args.types.split(",") if t.strip()]
    payload: Dict[str, Any] = {"id": 1, "cmd": "subscribe", "events": events, "types": types}
    if args.names:
        names = [n.strip() for n in args.names.split(",") if n.strip()]
        if names:
            payload["names"] = names
    return payload


def main() -> int:
    """Connect to the IPC socket and stream events until interrupted."""
    args = parse_args()
    payload = build_request(args)

    message = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(args.socket)
        sock.sendall(message)
        stream = sock.makefile("rb")

        # First line is the subscribe ack or an error.
        ack = stream.readline()
        if not ack:
            print("No response from server", file=sys.stderr)
            return 1
        try:
            ack_obj = json.loads(ack.decode("utf-8"))
        except json.JSONDecodeError:
            print("Invalid response from server", file=sys.stderr)
            return 1
        if not ack_obj.get("ok", False):
            print(json.dumps(ack_obj, indent=2))
            return 1

        for line in stream:
            if not line:
                break
            try:
                obj = json.loads(line.decode("utf-8"))
                if args.pretty:
                    print(json.dumps(obj, indent=2))
                else:
                    print(json.dumps(obj))
            except json.JSONDecodeError:
                print(line.decode("utf-8").rstrip())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
