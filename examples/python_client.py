#!/usr/bin/env python3
"""Example Python client for the OGM_slave_pi IPC server.

Run this on the Pi to read/write pin values via the Unix socket.
"""

import json
import socket

SOCK_PATH = "/run/ogm_pi.sock"


def request(payload):
    """Send a single request and return the decoded JSON response."""
    msg = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCK_PATH)
        sock.sendall(msg)
        data = sock.makefile("rb").readline()
    return json.loads(data.decode("utf-8"))


if __name__ == "__main__":
    print(request({"id": 1, "cmd": "list"}))
    print(request({"id": 2, "cmd": "get", "name": "DoorSensor"}))
    print(
        request(
            {
                "id": 3,
                "cmd": "set",
                "name": "LightRelay",
                "values": {"coils": [1]},
            }
        )
    )
