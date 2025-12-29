"""Daemon entry point for OGM_slave_pi.

Starts the Modbus backend (if enabled) and the IPC server for local clients.
"""

from __future__ import annotations

import argparse
import logging
import signal

from .ipc_server import IPCServer
from .modbus_server import create_backend
from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the daemon."""
    parser = argparse.ArgumentParser(description="OGM_slave_pi Modbus RTU + IPC daemon")
    parser.add_argument("--pinmap", required=True, help="Path to exported pinmap JSON")
    parser.add_argument("--serial", default="/dev/ttyUSB0", help="Serial device for Modbus RTU")
    parser.add_argument("--baud", type=int, default=250000, help="Modbus RTU baud rate")
    parser.add_argument("--parity", default="N", help="Serial parity (N/E/O)")
    parser.add_argument("--data-bits", type=int, default=8, help="Serial data bits")
    parser.add_argument("--stop-bits", type=int, default=1, help="Serial stop bits")
    parser.add_argument("--slave-address", type=int, default=None, help="Override Modbus slave address")
    parser.add_argument("--socket-path", default="/run/ogm_pi.sock", help="IPC Unix socket path")
    parser.add_argument("--no-modbus", action="store_true", help="Disable Modbus backend (IPC only)")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING)")
    return parser.parse_args()


def configure_logging(level: str) -> None:
    """Set up basic logging for the daemon."""
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")


def main() -> int:
    """CLI entry point for running the daemon."""
    args = parse_args()
    configure_logging(args.log_level)

    pinmap = PinMap.load(args.pinmap)
    store = RegisterStore(pinmap.totals)
    store.seed_pin_hash(pinmap)

    slave_address = args.slave_address if args.slave_address is not None else pinmap.address
    backend = create_backend(
        store,
        pinmap,
        args.serial,
        args.baud,
        slave_address,
        parity=args.parity,
        data_bits=args.data_bits,
        stop_bits=args.stop_bits,
        disabled=args.no_modbus,
    )
    backend.start()

    server = IPCServer(store, pinmap, args.socket_path)

    def shutdown(_signum=None, _frame=None):
        LOGGER.info("Shutting down")
        server.stop()
        backend.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        server.serve_forever()
    finally:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
