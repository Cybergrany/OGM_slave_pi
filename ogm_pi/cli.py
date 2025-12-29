"""CLI client for the OGM_slave_pi IPC server."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from typing import Any, Dict, List

DEFAULT_SOCKET_PATH = "/run/ogm_pi.sock"


def send_request(payload: Dict[str, Any], socket_path: str) -> Dict[str, Any]:
    """Send a single NDJSON request and return the decoded response."""
    message = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(socket_path)
        sock.sendall(message)
        response = sock.makefile("rb").readline()
    if not response:
        raise RuntimeError("Empty response from IPC server")
    return json.loads(response.decode("utf-8"))


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for IPC requests."""
    parser = argparse.ArgumentParser(description="OGM_slave_pi IPC client")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH, help="Path to IPC socket")

    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List available pins")
    sub.add_parser("schema", help="Return the full pinmap JSON")

    get_cmd = sub.add_parser("get", help="Get register values for a pin")
    get_cmd.add_argument("name", help="Pin name")

    set_cmd = sub.add_parser("set", help="Set register values for a pin")
    set_cmd.add_argument("name", help="Pin name")
    set_cmd.add_argument("--type", required=True, choices=["coils", "discretes", "input_regs", "holding_regs"], help="Register table")
    set_cmd.add_argument("--value", help="Single value (for count=1)")
    set_cmd.add_argument("--values", help="Comma-separated list for multi-register pins")

    return parser.parse_args()


def parse_values(value: str | None, values: str | None) -> List[Any]:
    """Parse CLI value arguments into a list."""
    if value is None and values is None:
        raise ValueError("Provide --value or --values")
    if values is not None:
        return [parse_scalar(v) for v in values.split(",") if v != ""]
    return [parse_scalar(value)]


def parse_scalar(token: str) -> Any:
    """Parse a scalar CLI token into bool/int/string."""
    if token is None:
        return 0
    lowered = token.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(token, 0)
    except ValueError:
        return token


def main() -> None:
    """Run the CLI and print JSON responses."""
    args = parse_args()
    request: Dict[str, Any] = {"id": 1, "cmd": args.cmd}

    if args.cmd == "get":
        request["name"] = args.name
    elif args.cmd == "set":
        request["name"] = args.name
        request["values"] = {args.type: parse_values(args.value, args.values)}

    response = send_request(request, args.socket)
    print(json.dumps(response, indent=2))
    if not response.get("ok", False):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
