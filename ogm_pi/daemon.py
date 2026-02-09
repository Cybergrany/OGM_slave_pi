"""Daemon entry point for OGM_slave_pi.

Starts the Modbus backend (if enabled) and the IPC server for local clients.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
import os
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

import yaml

from .app_supervisor import AppConfig, AppSupervisor
from .gpio_claims import GpioClaimError, GpioClaimRegistry
from .ipc_server import IPCServer
from .gpio import LibgpiodAdapter, NullGpioAdapter
from .modbus_server import create_backend
from .pinmap import PinMap
from .pin_runtime import PinRuntime
from .pin_resolver import PinResolver
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)


DEFAULT_CONFIG_PATH = "/etc/ogm_pi/ogm_pi.yaml"
DEFAULT_SETTINGS = {
    "pinmap": None,
    "custom_types_dir": None,
    "apps_dir": "/opt/OGM_slave_pi/apps",
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
    "modbus_log_every_failure": False,
    "modbus_show_all_frames": False,
    "app": None,
}


class ConfigLoadError(ValueError):
    """Raised when daemon config exists but cannot be read/parsed/validated."""


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the daemon."""
    parser = argparse.ArgumentParser(description="OGM_slave_pi Modbus RTU + IPC daemon", argument_default=argparse.SUPPRESS)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to daemon config YAML")
    parser.add_argument("--pinmap", help="Path to exported pinmap JSON")
    parser.add_argument("--custom-types-dir", help="Path to custom pin handler modules")
    parser.add_argument("--apps-dir", help="Default child app payload root directory")
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
    parser.add_argument(
        "--modbus-show-all-frames",
        dest="modbus_show_all_frames",
        action="store_true",
        help="Log every received Modbus request frame (very verbose)",
    )
    parser.add_argument(
        "--no-modbus-show-all-frames",
        dest="modbus_show_all_frames",
        action="store_false",
        help="Disable per-frame Modbus request logging",
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
        raise ConfigLoadError(f"failed to read config {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"failed to parse config {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigLoadError(f"config {path} must be a mapping")
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


def build_app_supervisor(
    settings: dict,
    *,
    pinmap: PinMap,
    resolver: PinResolver,
    gpio_claims: GpioClaimRegistry,
    socket_path: str,
    apps_dir: str,
) -> tuple[Optional[AppSupervisor], Optional[dict[str, object]]]:
    """Build and validate optional child-app supervision config."""
    raw = settings.get("app")
    if raw in (None, "", False):
        return None, None
    if not isinstance(raw, dict):
        raise ValueError("app config must be a mapping")

    enabled = as_bool(raw.get("enabled", False), default=False)
    if not enabled:
        return None, None

    name = str(raw.get("name") or "default").strip() or "default"
    owner = f"app:{name}"
    command = raw.get("command")
    if not command:
        raise ValueError("app.enabled=true requires app.command")

    raw_env = raw.get("env") or {}
    if not isinstance(raw_env, dict):
        raise ValueError("app.env must be a mapping")
    app_env = {str(key): str(value) for key, value in raw_env.items()}

    raw_pin_bindings = raw.get("pin_bindings") or []
    if not isinstance(raw_pin_bindings, list):
        raise ValueError("app.pin_bindings must be a list")
    pin_infos = resolver.resolve_names(raw_pin_bindings)

    raw_gpio_bindings = raw.get("gpio_bindings") or []
    if not isinstance(raw_gpio_bindings, list):
        raise ValueError("app.gpio_bindings must be a list")
    gpio_handles: list[dict[str, object]] = []
    for raw_name in raw_gpio_bindings:
        pin_name = str(raw_name)
        handle = resolver.handle_for_name(pin_name)
        line = resolver.gpio_line_for_handle(handle)
        if line is None:
            raise ValueError(f"GPIO binding pin '{pin_name}' does not map to a concrete GPIO line")
        gpio_claims.claim_line(owner, line)
        gpio_handles.append({"name": pin_name, "handle": handle, "line": line})

    extra_env = {
        "OGM_PI_SOCKET_PATH": socket_path,
        "OGM_PI_APPS_DIR": str(apps_dir),
        "OGM_PI_PINMAP_HASH": str(pinmap.hash),
        "OGM_PI_BOARD_ID": str(pinmap.raw.get("id", "")),
        "OGM_PI_BOARD_NAME": str(pinmap.raw.get("label", "")),
        "OGM_PI_PIN_BINDINGS": json.dumps(
            [{"name": info.name, "handle": info.handle} for info in pin_infos],
            separators=(",", ":"),
        ),
        "OGM_PI_GPIO_BINDINGS": json.dumps(gpio_handles, separators=(",", ":")),
    }

    raw_cwd = str(raw.get("cwd") or "").strip()
    resolved_cwd = raw_cwd
    if not resolved_cwd and apps_dir:
        resolved_cwd = str(Path(apps_dir) / name)

    cfg = AppConfig(
        enabled=True,
        name=name,
        command=str(command),
        cwd=resolved_cwd,
        restart_policy=str(raw.get("restart_policy", "always") or "always"),
        restart_backoff_ms=max(int(raw.get("restart_backoff_ms", 2000)), 0),
        startup_timeout_ms=max(int(raw.get("startup_timeout_ms", 10000)), 0),
        shutdown_timeout_ms=max(int(raw.get("shutdown_timeout_ms", 5000)), 0),
        env=app_env,
    )
    supervisor = AppSupervisor(cfg, extra_env=extra_env)
    meta = {
        "name": name,
        "owner": owner,
        "apps_dir": str(apps_dir),
        "cwd": resolved_cwd,
        "pin_bindings": [{"name": info.name, "handle": info.handle} for info in pin_infos],
        "gpio_bindings": gpio_handles,
    }
    return supervisor, meta


def main() -> int:
    """CLI entry point for running the daemon."""
    args = parse_args()
    config_path = getattr(args, "config", DEFAULT_CONFIG_PATH)
    try:
        config = load_config(config_path)
    except ConfigLoadError as exc:
        fallback_dump_dir = (
            os.environ.get("OGM_PI_CRASH_DUMP_DIR")
            or str((Path.cwd().parent / "crash_dumps").resolve())
            or str((Path.cwd() / "crash_dumps").resolve())
            or "/tmp/ogm_pi_crash_dumps"
        )
        write_crash_dump(
            fallback_dump_dir,
            reason="config_load_error",
            exc=exc,
            details={"config_path": config_path},
        )
        raise SystemExit(f"ogm_pi: {exc}")
    settings = build_settings(config, args)
    modbus_log_every_failure = as_bool(settings.get("modbus_log_every_failure", False), default=False)
    settings["modbus_log_every_failure"] = modbus_log_every_failure
    modbus_show_all_frames = as_bool(settings.get("modbus_show_all_frames", False), default=False)
    settings["modbus_show_all_frames"] = modbus_show_all_frames
    failure_log = resolve_failure_log_path(settings)
    crash_dump_dir = resolve_crash_dump_dir(settings)
    configure_logging(str(settings.get("log_level", "INFO")), failure_log=failure_log)
    LOGGER.info("Reading daemon config from: %s", config_path)
    if failure_log:
        LOGGER.info("Persistent runtime/failure log: %s", failure_log)
    else:
        LOGGER.warning("No writable persistent runtime/failure log path found.")
    if crash_dump_dir:
        LOGGER.info("Crash dump directory: %s", crash_dump_dir)
    else:
        LOGGER.warning("No writable crash dump directory found.")
    if modbus_log_every_failure:
        LOGGER.warning("Modbus per-failure logging enabled via ogm_pi.yaml (modbus_log_every_failure=true).")
    if modbus_show_all_frames:
        LOGGER.warning("Modbus per-frame logging enabled via ogm_pi.yaml (modbus_show_all_frames=true).")

    if not settings.get("pinmap"):
        raise SystemExit("ogm_pi: pinmap path missing (set in config or pass --pinmap)")
    pinmap = PinMap.load(str(settings["pinmap"]))
    store = RegisterStore(pinmap.totals)
    store.seed_pin_hash(pinmap)
    resolver = PinResolver(pinmap)
    gpio_claims = GpioClaimRegistry()

    custom_types_dir = settings.get("custom_types_dir")
    if custom_types_dir in (None, ""):
        default_custom_dir = Path(__file__).resolve().parents[1] / "custom_types"
        custom_types_dir = str(default_custom_dir) if default_custom_dir.exists() else None

    if settings.get("no_gpio"):
        gpio = NullGpioAdapter()
    else:
        try:
            gpio = LibgpiodAdapter(str(settings["gpio_chip"]))
        except Exception as exc:
            LOGGER.warning("GPIO init failed (%s); running with NullGpioAdapter", exc)
            gpio = NullGpioAdapter()

    server = IPCServer(
        store,
        pinmap,
        str(settings["socket_path"]),
        resolver=resolver,
        gpio=gpio,
        gpio_claims=gpio_claims,
    )

    runtime = PinRuntime(
        pinmap,
        store,
        gpio,
        poll_interval=max(int(settings.get("pin_poll_ms", 20)), 1) / 1000.0,
        stats_interval=max(float(settings.get("stats_interval", 5.0)), 0.5),
        custom_types_dir=custom_types_dir,
        gpio_claims=gpio_claims,
        event_sink=server.publish_events,
    )

    app_supervisor: Optional[AppSupervisor] = None
    app_meta: Optional[dict[str, object]] = None
    try:
        app_supervisor, app_meta = build_app_supervisor(
            settings,
            pinmap=pinmap,
            resolver=resolver,
            gpio_claims=gpio_claims,
            socket_path=str(settings["socket_path"]),
            apps_dir=str(settings.get("apps_dir") or ""),
        )
    except GpioClaimError as exc:
        raise SystemExit(f"ogm_pi: app GPIO claim failed: {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"ogm_pi: invalid app config: {exc}") from exc

    if app_supervisor is not None:
        server.set_app_reload_handler(app_supervisor.reload)
        LOGGER.info(
            "App supervision enabled (%s): cwd=%s, %s pin bindings, %s gpio bindings",
            app_meta.get("name", "default") if isinstance(app_meta, dict) else "default",
            app_meta.get("cwd", "") if isinstance(app_meta, dict) else "",
            len(app_meta.get("pin_bindings", [])) if isinstance(app_meta, dict) else 0,
            len(app_meta.get("gpio_bindings", [])) if isinstance(app_meta, dict) else 0,
        )

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
                "baud": int(settings.get("baud", 250000)),
                "parity": str(settings.get("parity", "N")),
                "data_bits": int(settings.get("data_bits", 8)),
                "stop_bits": int(settings.get("stop_bits", 1)),
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
        log_every_recoverable_error=modbus_log_every_failure,
        show_all_frames=modbus_show_all_frames,
    )

    # Start IPC serving early so local health checks remain responsive even if
    # Modbus startup blocks on serial/device state.
    ipc_thread = threading.Thread(target=server.serve_forever, name="ogm_ipc", daemon=True)
    ipc_thread.start()
    time.sleep(0.1)
    ipc_startup_error = server.consume_startup_error()
    if ipc_startup_error is not None or not ipc_thread.is_alive():
        exc = RuntimeError(f"IPC server failed to start: {ipc_startup_error or 'thread exited during startup'}")
        write_crash_dump(
            crash_dump_dir,
            reason="ipc_startup_error",
            exc=exc,
            details={"socket_path": str(settings["socket_path"])},
        )
        raise exc

    runtime.start()
    if app_supervisor is not None:
        app_supervisor.start()

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
        if app_supervisor is not None:
            app_supervisor.stop()
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
                    "baud": int(settings.get("baud", 250000)),
                    "parity": str(settings.get("parity", "N")),
                    "data_bits": int(settings.get("data_bits", 8)),
                    "stop_bits": int(settings.get("stop_bits", 1)),
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
                "baud": int(settings.get("baud", 250000)),
                "parity": str(settings.get("parity", "N")),
                "data_bits": int(settings.get("data_bits", 8)),
                "stop_bits": int(settings.get("stop_bits", 1)),
                "slave_address": int(slave_address),
                "policy": "strict-fail-on-severe",
            },
        )
        raise backend_start_error[0]

    try:
        ipc_restart_attempts = 0
        while not fatal_event.is_set():
            if not ipc_thread.is_alive():
                ipc_error = server.consume_startup_error()
                if ipc_error is not None:
                    raise RuntimeError(f"IPC server exited with startup error: {ipc_error}")
                ipc_restart_attempts += 1
                if ipc_restart_attempts > 5:
                    raise RuntimeError("IPC server thread exited repeatedly")
                LOGGER.error("IPC server thread exited unexpectedly; restarting it (%s/5).", ipc_restart_attempts)
                ipc_thread = threading.Thread(target=server.serve_forever, name="ogm_ipc", daemon=True)
                ipc_thread.start()
                time.sleep(0.2)
                ipc_error = server.consume_startup_error()
                if ipc_error is not None or not ipc_thread.is_alive():
                    raise RuntimeError(
                        f"IPC server restart failed: {ipc_error or 'thread exited during restart'}"
                    )
                continue
            ipc_restart_attempts = 0
            time.sleep(0.25)
    except Exception as exc:
        write_crash_dump(
            crash_dump_dir,
            reason="daemon_main_error",
            exc=exc,
            details={
                "serial": str(settings["serial"]),
                "baud": int(settings.get("baud", 250000)),
                "parity": str(settings.get("parity", "N")),
                "data_bits": int(settings.get("data_bits", 8)),
                "stop_bits": int(settings.get("stop_bits", 1)),
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
