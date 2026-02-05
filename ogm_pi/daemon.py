"""Daemon entry point for OGM_slave_pi.

Starts the Modbus backend (if enabled) and the IPC server for local clients.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

import yaml

from .ipc_server import IPCServer
from .gpio import LibgpiodAdapter, NullGpioAdapter
from .modbus_server import create_backend
from .pinmap import PinMap
from .pin_runtime import PinRuntime
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)


DEFAULT_CONFIG_PATH = "/etc/ogm_pi/ogm_pi.yaml"
DEFAULT_SETTINGS = {
    "pinmap": None,
    "custom_types_dir": None,
    "serial": "/dev/ttyUSB0",
    "baud": 250000,
    "parity": "N",
    "data_bits": 8,
    "stop_bits": 1,
    "slave_address": None,
    "socket_path": "/run/ogm_pi.sock",
    "no_modbus": False,
    "no_gpio": False,
    "gpio_chip": "/dev/gpiochip0",
    "pin_poll_ms": 20,
    "stats_interval": 5.0,
    "log_level": "INFO",
}


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the daemon."""
    parser = argparse.ArgumentParser(description="OGM_slave_pi Modbus RTU + IPC daemon", argument_default=argparse.SUPPRESS)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to daemon config YAML")
    parser.add_argument("--pinmap", help="Path to exported pinmap JSON")
    parser.add_argument("--custom-types-dir", help="Path to custom pin handler modules")
    parser.add_argument("--serial", help="Serial device for Modbus RTU")
    parser.add_argument("--baud", type=int, help="Modbus RTU baud rate")
    parser.add_argument("--parity", help="Serial parity (N/E/O)")
    parser.add_argument("--data-bits", type=int, help="Serial data bits")
    parser.add_argument("--stop-bits", type=int, help="Serial stop bits")
    parser.add_argument("--slave-address", type=int, help="Override Modbus slave address")
    parser.add_argument("--socket-path", help="IPC Unix socket path")
    parser.add_argument("--no-modbus", action="store_true", help="Disable Modbus backend (IPC only)")
    parser.add_argument("--no-gpio", action="store_true", help="Disable GPIO access")
    parser.add_argument("--gpio-chip", help="libgpiod chip path")
    parser.add_argument("--pin-poll-ms", type=int, help="Pin update poll interval (ms)")
    parser.add_argument("--stats-interval", type=float, help="Board stats update interval (s)")
    parser.add_argument("--log-level", help="Logging level (DEBUG, INFO, WARNING)")
    return parser.parse_args()


def load_config(path: str) -> dict:
    """Load daemon config from YAML, returning an empty dict on missing file."""
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        print(f"ogm_pi: failed to read config {path}: {exc}", file=sys.stderr)
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"Config {path} must be a mapping")
    return data


def build_settings(config: dict, cli: argparse.Namespace) -> dict:
    """Merge defaults + config + CLI overrides."""
    settings = dict(DEFAULT_SETTINGS)
    for key in DEFAULT_SETTINGS:
        if key in config:
            settings[key] = config[key]
    for key, value in vars(cli).items():
        if key == "config":
            continue
        settings[key] = value
    return settings


def configure_logging(level: str) -> None:
    """Set up basic logging for the daemon."""
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")


def main() -> int:
    """CLI entry point for running the daemon."""
    args = parse_args()
    config = load_config(getattr(args, "config", DEFAULT_CONFIG_PATH))
    settings = build_settings(config, args)
    configure_logging(str(settings.get("log_level", "INFO")))

    if not settings.get("pinmap"):
        raise SystemExit("ogm_pi: pinmap path missing (set in config or pass --pinmap)")
    pinmap = PinMap.load(str(settings["pinmap"]))
    store = RegisterStore(pinmap.totals)
    store.seed_pin_hash(pinmap)

    custom_types_dir = settings.get("custom_types_dir")
    if custom_types_dir in (None, ""):
        default_custom_dir = Path(__file__).resolve().parents[1] / "custom_types"
        custom_types_dir = str(default_custom_dir) if default_custom_dir.exists() else None

    server = IPCServer(store, pinmap, str(settings["socket_path"]))

    if settings.get("no_gpio"):
        gpio = NullGpioAdapter()
    else:
        try:
            gpio = LibgpiodAdapter(str(settings["gpio_chip"]))
        except Exception as exc:
            LOGGER.warning("GPIO init failed (%s); running with NullGpioAdapter", exc)
            gpio = NullGpioAdapter()

    runtime = PinRuntime(
        pinmap,
        store,
        gpio,
        poll_interval=max(int(settings.get("pin_poll_ms", 20)), 1) / 1000.0,
        stats_interval=max(float(settings.get("stats_interval", 5.0)), 0.5),
        custom_types_dir=custom_types_dir,
    )
    runtime.start()

    slave_address = settings.get("slave_address")
    if slave_address is None:
        slave_address = pinmap.address

    fatal_event = threading.Event()

    def on_modbus_error(_exc: Exception) -> None:
        if fatal_event.is_set():
            return
        fatal_event.set()
        runtime.force_safe_outputs("modbus_error")
        os.kill(os.getpid(), signal.SIGTERM)

    backend = create_backend(
        store,
        pinmap,
        str(settings["serial"]),
        int(settings.get("baud", 250000)),
        int(slave_address),
        parity=str(settings.get("parity", "N")),
        data_bits=int(settings.get("data_bits", 8)),
        stop_bits=int(settings.get("stop_bits", 1)),
        disabled=bool(settings.get("no_modbus", False)),
        event_sink=server.publish_events,
        error_handler=on_modbus_error,
    )
    backend.start()

    def shutdown(_signum=None, _frame=None):
        LOGGER.info("Shutting down")
        runtime.force_safe_outputs("shutdown")
        server.stop()
        runtime.stop()
        backend.stop()
        gpio.close()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        server.serve_forever()
    finally:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
