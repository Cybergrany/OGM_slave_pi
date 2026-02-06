"""Daemon entry point for OGM_slave_pi.

Starts the Modbus backend (if enabled) and the IPC server for local clients.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import logging
import os
import signal
import sys
import threading
import time
import traceback
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
    "crash_dump_dir": None,
    "modbus_fail_open": False,
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
    parser.add_argument("--crash-dump-dir", help="Directory for crash dump files")
    parser.add_argument(
        "--modbus-fail-open",
        dest="modbus_fail_open",
        action="store_true",
        help="Keep daemon running (IPC + safe outputs) if Modbus backend fails",
    )
    parser.add_argument(
        "--no-modbus-fail-open",
        dest="modbus_fail_open",
        action="store_false",
        help="Exit daemon if Modbus backend fails",
    )
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


def as_bool(value: object, *, default: bool) -> bool:
    """Parse bool-like values from config/CLI overlays."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return bool(value)


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
    # Fallback that remains inside service-owned runtime dir.
    candidates.append(str((Path.cwd() / "runtime_failures.log").resolve()))
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


def resolve_crash_dump_dir(settings: dict) -> str | None:
    """Pick a writable crash-dump directory."""
    candidates: list[str] = []
    cfg = settings.get("crash_dump_dir")
    if cfg:
        candidates.append(str(cfg))

    env = os.environ.get("OGM_PI_CRASH_DUMP_DIR")
    if env:
        candidates.append(env)

    # In deploy layout WorkingDirectory=<root>/runtime, so this lands in
    # <root>/crash_dumps for easy retrieval.
    candidates.append(str((Path.cwd().parent / "crash_dumps").resolve()))
    # Fallback that remains inside service-owned runtime dir.
    candidates.append(str((Path.cwd() / "crash_dumps").resolve()))
    candidates.append("/tmp/ogm_pi_crash_dumps")

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        directory = Path(candidate)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            probe = directory / ".write_test"
            with probe.open("a", encoding="utf-8"):
                pass
            probe.unlink(missing_ok=True)
            return str(directory)
        except OSError:
            continue
    return None


def write_crash_dump(
    crash_dump_dir: str | None,
    *,
    reason: str,
    exc: BaseException | None = None,
    details: dict[str, object] | None = None,
) -> None:
    """Write a structured crash dump and append to latest.log."""
    if not crash_dump_dir:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    safe_reason = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in reason).strip("_") or "error"
    ts_file = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dump_dir = Path(crash_dump_dir)
    dump_path = dump_dir / f"{ts_file}_{safe_reason}.log"
    latest_path = dump_dir / "latest.log"

    lines = [
        f"timestamp: {timestamp}",
        f"reason: {reason}",
        f"pid: {os.getpid()}",
        f"cwd: {Path.cwd()}",
        f"python: {sys.executable}",
    ]
    if details:
        for key in sorted(details):
            lines.append(f"{key}: {details[key]}")
    if exc is not None:
        lines.extend(
            [
                "",
                f"exception_type: {type(exc).__name__}",
                f"exception: {exc}",
                "",
                "traceback:",
                "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip(),
            ]
        )

    payload = "\n".join(lines).rstrip() + "\n"
    try:
        dump_dir.mkdir(parents=True, exist_ok=True)
        try:
            dump_dir.chmod(0o755)
        except OSError:
            pass
        with dump_path.open("w", encoding="utf-8") as handle:
            handle.write(payload)
        try:
            dump_path.chmod(0o644)
        except OSError:
            pass
        with latest_path.open("a", encoding="utf-8") as handle:
            handle.write("\n===\n")
            handle.write(payload)
        try:
            latest_path.chmod(0o644)
        except OSError:
            pass
        LOGGER.error("Crash dump written: %s", dump_path)
    except OSError as dump_exc:
        LOGGER.error("Failed to write crash dump to %s: %s", dump_dir, dump_exc)


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
            try:
                Path(failure_log).chmod(0o644)
            except OSError:
                pass
        except OSError as exc:
            root.warning("Could not open failure log at %s: %s", failure_log, exc)


def main() -> int:
    """CLI entry point for running the daemon."""
    args = parse_args()
    config = load_config(getattr(args, "config", DEFAULT_CONFIG_PATH))
    settings = build_settings(config, args)
    failure_log = resolve_failure_log_path(settings)
    crash_dump_dir = resolve_crash_dump_dir(settings)
    configure_logging(str(settings.get("log_level", "INFO")), failure_log=failure_log)
    if failure_log:
        LOGGER.info("Persistent runtime/failure log: %s", failure_log)
    else:
        LOGGER.warning("No writable persistent runtime/failure log path found.")
    if crash_dump_dir:
        LOGGER.info("Crash dump directory: %s", crash_dump_dir)
    else:
        LOGGER.warning("No writable crash dump directory found.")

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
    modbus_fail_open = as_bool(settings.get("modbus_fail_open", False), default=False)
    if modbus_fail_open:
        LOGGER.warning(
            "modbus_fail_open is deprecated for fatal backend failures; "
            "startup/severe runtime errors now fail fast."
        )

    fatal_event = threading.Event()
    backend_failed = threading.Event()

    def on_modbus_error(exc: Exception) -> None:
        if backend_failed.is_set():
            return
        backend_failed.set()
        runtime.force_safe_outputs("modbus_error")
        write_crash_dump(
            crash_dump_dir,
            reason="modbus_runtime_error",
            exc=exc,
            details={
                "serial": str(settings["serial"]),
                "slave_address": int(slave_address),
                "policy": "strict-fail-on-severe",
            },
        )
        if fatal_event.is_set():
            return
        fatal_event.set()
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
        fatal_event.set()
        LOGGER.info("Shutting down")
        runtime.force_safe_outputs("shutdown")
        server.stop()
        if ipc_thread.is_alive():
            ipc_thread.join(timeout=1.0)
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
            backend_failed.set()
            runtime.force_safe_outputs("modbus_start_failed")
            write_crash_dump(
                crash_dump_dir,
                reason="modbus_startup_error",
                exc=exc,
                details={
                    "serial": str(settings["serial"]),
                    "slave_address": int(slave_address),
                    "policy": "strict-fail-on-severe",
                },
            )
            fatal_event.set()
        finally:
            backend_start_done.set()

    backend_start_thread = threading.Thread(target=start_backend_async, name="ogm_modbus_start", daemon=True)
    backend_start_thread.start()
    if not backend_start_done.wait(timeout=5.0):
        LOGGER.warning("Modbus backend startup is taking longer than expected; IPC remains available.")
    elif backend_start_error:
        write_crash_dump(
            crash_dump_dir,
            reason="modbus_startup_fatal",
            exc=backend_start_error[0],
            details={
                "serial": str(settings["serial"]),
                "slave_address": int(slave_address),
                "policy": "strict-fail-on-severe",
            },
        )
        raise backend_start_error[0]

    try:
        while not fatal_event.is_set():
            if not ipc_thread.is_alive():
                LOGGER.error("IPC server thread exited unexpectedly; restarting it.")
                ipc_thread = threading.Thread(target=server.serve_forever, name="ogm_ipc", daemon=True)
                ipc_thread.start()
                time.sleep(0.25)
                continue
            time.sleep(0.25)
    except Exception as exc:
        write_crash_dump(
            crash_dump_dir,
            reason="daemon_main_error",
            exc=exc,
            details={
                "serial": str(settings["serial"]),
                "slave_address": int(slave_address),
                "policy": "strict-fail-on-severe",
            },
        )
        raise
    finally:
        shutdown()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Best-effort fallback for very-early failures (before config/log paths are loaded).
        fallback_dir = (
            os.environ.get("OGM_PI_CRASH_DUMP_DIR")
            or str((Path.cwd() / "crash_dumps").resolve())
            or "/tmp/ogm_pi_crash_dumps"
        )
        write_crash_dump(fallback_dir, reason="daemon_fatal_uncaught", exc=exc)
        LOGGER.exception("Fatal daemon error")
        raise
