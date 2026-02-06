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
import time
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
    "failure_log": None,
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
    parser.add_argument("--failure-log", help="Path to append daemon failure/runtime logs")
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


def resolve_failure_log_path(settings: dict) -> str | None:
    """Pick a writable runtime failure log path."""
    candidates: list[str] = []
    cfg = settings.get("failure_log")
    if cfg:
        candidates.append(str(cfg))

    env = os.environ.get("OGM_PI_FAILURE_LOG")
    if env:
        candidates.append(env)

    # In deploy layout WorkingDirectory=<root>/runtime, so this lands in
    # <root>/runtime_failures.log for easy retrieval.
    candidates.append(str((Path.cwd().parent / "runtime_failures.log").resolve()))
    candidates.append("/tmp/ogm_pi_runtime_failures.log")

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        path = Path(candidate)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8"):
                pass
            return str(path)
        except OSError:
            continue
    return None


def configure_logging(level: str, *, failure_log: str | None = None) -> None:
    """Set up daemon logging (stderr + optional persistent failure file)."""
    level_value = getattr(logging, level.upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    root = logging.getLogger()
    root.setLevel(level_value)
    root.handlers.clear()

    stream = logging.StreamHandler()
    stream.setLevel(level_value)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    if failure_log:
        try:
            file_handler = logging.FileHandler(failure_log, encoding="utf-8")
            file_handler.setLevel(level_value)
            file_handler.setFormatter(fmt)
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning("Could not open failure log at %s: %s", failure_log, exc)


def main() -> int:
    """CLI entry point for running the daemon."""
    args = parse_args()
    config = load_config(getattr(args, "config", DEFAULT_CONFIG_PATH))
    settings = build_settings(config, args)
    failure_log = resolve_failure_log_path(settings)
    configure_logging(str(settings.get("log_level", "INFO")), failure_log=failure_log)
    if failure_log:
        LOGGER.info("Persistent runtime/failure log: %s", failure_log)
    else:
        LOGGER.warning("No writable persistent runtime/failure log path found.")

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

    # Start IPC serving early so local health checks remain responsive even if
    # Modbus startup blocks on serial/device state.
    ipc_thread = threading.Thread(target=server.serve_forever, name="ogm_ipc", daemon=True)
    ipc_thread.start()

    shutdown_once = threading.Event()

    def shutdown(_signum=None, _frame=None):
        if shutdown_once.is_set():
            return
        shutdown_once.set()
        LOGGER.info("Shutting down")
        runtime.force_safe_outputs("shutdown")
        server.stop()
        runtime.stop()
        backend.stop()
        gpio.close()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    backend_start_error: list[Exception] = []
    backend_start_done = threading.Event()

    def start_backend_async() -> None:
        try:
            backend.start()
        except Exception as exc:
            LOGGER.exception("Modbus backend failed to start")
            backend_start_error.append(exc)
            fatal_event.set()
        finally:
            backend_start_done.set()

    backend_start_thread = threading.Thread(target=start_backend_async, name="ogm_modbus_start", daemon=True)
    backend_start_thread.start()
    if not backend_start_done.wait(timeout=5.0):
        LOGGER.warning("Modbus backend startup is taking longer than expected; IPC remains available.")
    elif backend_start_error:
        raise backend_start_error[0]

    try:
        while not fatal_event.is_set():
            if not ipc_thread.is_alive():
                break
            time.sleep(0.25)
    finally:
        shutdown()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        LOGGER.exception("Fatal daemon error")
        raise
