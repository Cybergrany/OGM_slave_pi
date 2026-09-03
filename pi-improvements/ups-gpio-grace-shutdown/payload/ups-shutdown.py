#!/usr/bin/env python3
"""UPS mains-loss monitor for Raspberry Pi.

The monitor owns only the UPS input GPIO. GPIO26 remains owned by the kernel
through the gpio-poweroff device-tree overlay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

EX_CONFIG = 78
SCHEMA = 1
DEFAULT_STATE_DIR = Path("/var/lib/ups-shutdown")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
DT_BASE = Path("/sys/firmware/devicetree/base")
SYSTEMCTL = "/usr/bin/systemctl"
MIN_PRODUCTION_SHUTDOWN_AFTER = 60.0
SHORT_TEST_ARM_PATH = Path("/run/ups-shutdown/allow-short-test")

running = True
state: dict[str, Any] | None = None
state_dir = DEFAULT_STATE_DIR


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def monotonic() -> float:
    return time.monotonic()


def get_boot_id() -> str:
    return BOOT_ID_PATH.read_text(encoding="ascii").strip()


def script_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def config_sha256() -> str:
    try:
        return hashlib.sha256(Path("/etc/default/ups-shutdown").read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        fsync_dir(path.parent)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def append_history(level: str, event: str, message: str, **fields: Any) -> None:
    global state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    line = {
        "time": now_iso(),
        "monotonic": round(monotonic(), 3),
        "boot_id": get_boot_id() if BOOT_ID_PATH.exists() else "unknown",
        "level": level,
        "event": event,
        "message": message,
        **fields,
    }
    human = f"{line['time']} [{level}] {event}: {message}"
    if fields:
        human += " | " + " ".join(f"{k}={v}" for k, v in fields.items())
    print(human, flush=True)

    path = state_dir / "history.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, (human + "\n").encode("utf-8", errors="replace"))
        os.fsync(fd)
    finally:
        os.close(fd)

    jpath = state_dir / "history.jsonl"
    fd = os.open(jpath, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, (json.dumps(line, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def save_state(event: str | None = None, **updates: Any) -> None:
    global state, state_dir
    if state is None:
        return
    state.update(updates)
    if event is not None:
        state["last_event"] = event
    state["last_update_wall"] = now_iso()
    state["last_update_monotonic"] = round(monotonic(), 3)
    atomic_write_json(state_dir / "current.json", state)


def level_to_int(value: str) -> int:
    v = value.strip().upper()
    if v in {"HIGH", "HI", "1", "TRUE"}:
        return 1
    if v in {"LOW", "LO", "0", "FALSE"}:
        return 0
    raise ValueError(f"invalid GPIO level {value!r}; expected HIGH or LOW")


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not numeric") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name}={value} outside allowed range {minimum}..{maximum}")
    return value


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name}={value} outside allowed range {minimum}..{maximum}")
    return value


def load_config(shutdown_after_override: float | None = None) -> dict[str, Any]:
    pull = os.getenv("GPIO_PULL", "UP").strip().upper()
    if pull not in {"UP", "DOWN", "NONE"}:
        raise ValueError("GPIO_PULL must be UP, DOWN, or NONE")

    cfg: dict[str, Any] = {
        "gpio_input": env_int("GPIO_INPUT", 12, 0, 53),
        "gpio_pull": pull,
        "power_fail_level": level_to_int(os.getenv("POWER_FAIL_LEVEL", "HIGH")),
        "shutdown_after": env_float("SHUTDOWN_AFTER", 300.0, 1.0, 86400.0),
        "restore_debounce": env_float("RESTORE_DEBOUNCE", 3.0, 0.0, 60.0),
        "poll_interval": env_float("POLL_INTERVAL", 1.0, 0.05, 10.0),
        "shutdown_retry_seconds": env_float("SHUTDOWN_RETRY_SECONDS", 5.0, 1.0, 300.0),
        "shutdown_accepted_watchdog": env_float("SHUTDOWN_ACCEPTED_WATCHDOG", 30.0, 5.0, 600.0),
        "poweroff_pin": env_int("GPIO_POWEROFF_PIN", 26, 0, 53),
        "poweroff_active_delay_ms": env_int("GPIO_POWEROFF_ACTIVE_DELAY_MS", 1000, 0, 60000),
        "poweroff_inactive_delay_ms": env_int("GPIO_POWEROFF_INACTIVE_DELAY_MS", 1000, 0, 60000),
        "state_dir": DEFAULT_STATE_DIR,
    }
    if shutdown_after_override is not None:
        if not 1 <= shutdown_after_override <= 86400:
            raise ValueError("shutdown-after override must be 1..86400 seconds")
        cfg["shutdown_after"] = float(shutdown_after_override)

    short_test_armed = False
    if cfg["shutdown_after"] < MIN_PRODUCTION_SHUTDOWN_AFTER:
        try:
            short_test_armed = SHORT_TEST_ARM_PATH.read_text(encoding="utf-8").strip() == get_boot_id()
        except OSError:
            short_test_armed = False
        if not short_test_armed:
            raise ValueError(
                f"SHUTDOWN_AFTER={cfg['shutdown_after']} is below the production minimum "
                f"of {MIN_PRODUCTION_SHUTDOWN_AFTER:g}s. Short thresholds may only be armed "
                "by ups-shutdown-smoke-test on the current boot."
            )
    cfg["short_test_armed"] = short_test_armed
    return cfg


def find_gpio_poweroff_node() -> Path | None:
    direct = DT_BASE / "power_ctrl"
    if (direct / "compatible").exists():
        try:
            if b"gpio-poweroff" in (direct / "compatible").read_bytes():
                return direct
        except OSError:
            pass

    if not DT_BASE.exists():
        return None
    for root, dirs, files in os.walk(DT_BASE):
        # The gpio-poweroff node is normally near the root. Avoid walking huge trees.
        rel_depth = len(Path(root).relative_to(DT_BASE).parts)
        if rel_depth > 4:
            dirs[:] = []
            continue
        if "compatible" not in files:
            continue
        p = Path(root)
        try:
            if b"gpio-poweroff" in (p / "compatible").read_bytes():
                return p
        except OSError:
            continue
    return None


def read_be_u32(path: Path) -> int | None:
    try:
        data = path.read_bytes()
        if len(data) < 4:
            return None
        return struct.unpack(">I", data[:4])[0]
    except OSError:
        return None


def check_gpio_poweroff(cfg: dict[str, Any]) -> tuple[bool, list[str]]:
    problems: list[str] = []
    node = find_gpio_poweroff_node()
    if node is None:
        problems.append("live device tree has no gpio-poweroff node")
        return False, problems

    gpios_path = node / "gpios"
    try:
        data = gpios_path.read_bytes()
        cells = struct.unpack(">" + "I" * (len(data) // 4), data[: (len(data) // 4) * 4])
        if len(cells) < 3:
            problems.append(f"unexpected {gpios_path} format")
        else:
            pin = cells[-2]
            flags = cells[-1]
            if pin != cfg["poweroff_pin"]:
                problems.append(f"gpio-poweroff pin is GPIO{pin}, expected GPIO{cfg['poweroff_pin']}")
            if not (flags & 0x1):
                problems.append("gpio-poweroff is not active-low")
    except (OSError, struct.error):
        problems.append("unable to read gpio-poweroff gpios property")

    active = read_be_u32(node / "active-delay-ms")
    inactive = read_be_u32(node / "inactive-delay-ms")
    if active != cfg["poweroff_active_delay_ms"]:
        problems.append(
            f"active-delay-ms={active!r}, expected {cfg['poweroff_active_delay_ms']}"
        )
    if inactive != cfg["poweroff_inactive_delay_ms"]:
        problems.append(
            f"inactive-delay-ms={inactive!r}, expected {cfg['poweroff_inactive_delay_ms']}"
        )

    try:
        cp = subprocess.run(["gpioinfo"], capture_output=True, text=True, timeout=5, check=False)
        expected_name = f'"GPIO{cfg["poweroff_pin"]}"'
        matching = [ln for ln in cp.stdout.splitlines() if expected_name in ln]
        if not any('"power_ctrl"' in ln and "output" in ln and "active-low" in ln and "[used]" in ln for ln in matching):
            problems.append(
                f"GPIO{cfg['poweroff_pin']} is not visibly owned by kernel consumer power_ctrl as active-low output"
            )
    except (FileNotFoundError, subprocess.SubprocessError):
        problems.append("gpioinfo unavailable; install the gpiod package")

    # pinctrl is an additional live-state check, but absence is not fatal if DT+gpioinfo agree.
    pinctrl = None
    for candidate in ("/usr/bin/pinctrl", "/usr/bin/raspi-gpio", "/usr/local/bin/pinctrl"):
        if Path(candidate).exists():
            pinctrl = candidate
            break
    if pinctrl:
        args = [pinctrl, "get", str(cfg["poweroff_pin"])]
        try:
            cp = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
            out = (cp.stdout + " " + cp.stderr).lower()
            if cp.returncode == 0:
                if " op " not in f" {out} ":
                    problems.append(f"GPIO{cfg['poweroff_pin']} is not currently configured as output")
                if " hi " not in f" {out} ":
                    problems.append(
                        f"GPIO{cfg['poweroff_pin']} is not currently HIGH in the running state"
                    )
        except subprocess.SubprocessError:
            pass

    return not problems, problems


def preflight(cfg: dict[str, Any], quiet: bool = False) -> int:
    ok, problems = check_gpio_poweroff(cfg)
    if not ok:
        if not quiet:
            print("UPS shutdown host preflight: NOT ARMED", file=sys.stderr)
            for problem in problems:
                print(f"  ERROR: {problem}", file=sys.stderr)
            print(
                "Run: sudo ups-shutdown-host-setup --apply\n"
                "Then reboot if the host setup tool reports that a reboot is required.",
                file=sys.stderr,
            )
        return EX_CONFIG
    if not quiet:
        print(
            f"UPS shutdown host preflight: OK (GPIO{cfg['poweroff_pin']} kernel-owned by gpio-poweroff)"
        )
    return 0


def classify_previous(previous: dict[str, Any] | None, clean: dict[str, Any] | None, current_boot: str) -> tuple[str, str]:
    if not previous:
        return "INFO", "No previous monitor state exists (first run or state was cleared)."

    prev_boot = previous.get("boot_id")
    if not prev_boot:
        return "WARNING", "Previous monitor state has no boot ID; unable to classify it reliably."
    if prev_boot == current_boot:
        if previous.get("shutdown_requested"):
            return "WARNING", "Monitor restarted during the same boot after a UPS shutdown request; shutdown will be retried."
        if previous.get("power_fail_active"):
            return "WARNING", "Monitor restarted during the same boot while a power-fail timer was active; countdown will be recovered."
        if previous.get("stopped_cleanly"):
            return "INFO", "Monitor was deliberately stopped/restarted during the current host boot."
        return "WARNING", "Monitor restarted unexpectedly during the same host boot."

    clean_for_prev = bool(clean and clean.get("boot_id") == prev_boot)
    requested = bool(previous.get("shutdown_requested"))
    accepted = bool(previous.get("shutdown_command_accepted"))
    power_fail = bool(previous.get("power_fail_active"))

    if clean_for_prev and requested:
        if accepted:
            return "INFO", "Previous boot: UPS-triggered graceful shutdown completed through systemd."
        return "WARNING", "Previous boot: UPS shutdown was requested and an orderly shutdown began, but the monitor did not record systemctl accepting the request."
    if clean_for_prev and not requested:
        return "INFO", "Previous boot: orderly shutdown/reboot occurred through a non-UPS path (manual or another service)."
    if not clean_for_prev and power_fail and not requested:
        return "ERROR", "Previous boot ended abruptly during an active mains-loss hold-up period; this monitor had NOT requested host shutdown."
    if not clean_for_prev and requested:
        if accepted:
            return "ERROR", "Previous boot ended without the independent clean-shutdown marker after systemctl accepted the UPS poweroff request."
        return "ERROR", "Previous boot ended after the UPS monitor requested shutdown, but without evidence that systemd accepted/completed an orderly shutdown."
    return "ERROR", "Previous boot ended abruptly with no UPS shutdown request and no independent clean-shutdown marker."


def write_report(level: str, message: str, previous: dict[str, Any] | None = None) -> None:
    global state_dir
    lines = [
        f"Generated: {now_iso()}",
        f"Result: {level}",
        message,
    ]
    if previous:
        lines.extend(
            [
                "",
                f"Previous boot ID: {previous.get('boot_id', 'unknown')}",
                f"Last event: {previous.get('last_event', 'unknown')}",
                f"Last update: {previous.get('last_update_wall', 'unknown')}",
                f"Power fail active: {previous.get('power_fail_active', False)}",
                f"Power fail detected: {previous.get('power_fail_started_wall', 'n/a')}",
                f"UPS shutdown requested: {previous.get('shutdown_requested', False)}",
                f"Shutdown command accepted: {previous.get('shutdown_command_accepted', False)}",
            ]
        )
    atomic_write_text(state_dir / "last-report.txt", "\n".join(lines) + "\n")


def mark_clean_shutdown(cfg: dict[str, Any]) -> int:
    global state_dir
    state_dir = cfg["state_dir"]
    state_dir.mkdir(parents=True, exist_ok=True)
    current = read_json(state_dir / "current.json")
    marker = {
        "schema": SCHEMA,
        "boot_id": get_boot_id(),
        "time": now_iso(),
        "monotonic": round(monotonic(), 3),
        "monitor_shutdown_requested": bool(current and current.get("shutdown_requested")),
        "monitor_last_event": current.get("last_event") if current else None,
    }
    atomic_write_json(state_dir / "clean-shutdown.json", marker)
    append_history(
        "INFO",
        "CLEAN_SHUTDOWN_STARTED",
        "systemd entered the orderly shutdown transaction",
        monitor_shutdown_requested=marker["monitor_shutdown_requested"],
    )
    return 0


def signal_handler(signum: int, _frame: Any) -> None:
    global running
    running = False
    try:
        save_state("MONITOR_STOP_SIGNAL", stopped_cleanly=True, stop_signal=signum)
        append_history("INFO", "MONITOR_STOP_SIGNAL", "monitor received termination signal", signal=signum)
    except Exception:
        # Never turn signal handling into a hang during host shutdown.
        pass


def raw_input(device: Any) -> int:
    # gpiozero's low-level Pin.state is explicitly raw: no pull-up polarity inversion.
    return 1 if bool(device.pin.state) else 0


def request_poweroff(cfg: dict[str, Any]) -> bool:
    """Return True if systemctl accepted the poweroff transaction."""
    first_request = not bool(state and state.get("shutdown_requested"))
    if first_request:
        request_wall = now_iso()
        request_mono = round(monotonic(), 3)
        save_state(
            "UPS_SHUTDOWN_REQUESTED",
            shutdown_requested=True,
            shutdown_requested_wall=request_wall,
            shutdown_requested_monotonic=request_mono,
        )
        append_history(
            "WARNING",
            "UPS_SHUTDOWN_REQUESTED",
            "UPS hold-up threshold reached; requesting orderly host poweroff",
            threshold_seconds=cfg["shutdown_after"],
        )
    else:
        save_state("SHUTDOWN_COMMAND_RETRY", shutdown_retry_wall=now_iso())
        append_history(
            "ERROR",
            "SHUTDOWN_COMMAND_RETRY",
            "retrying orderly host poweroff request",
        )

    command = [SYSTEMCTL, "--no-block", "--ignore-inhibitors", "poweroff"]
    try:
        cp = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except Exception as exc:
        save_state(
            "SHUTDOWN_COMMAND_ERROR",
            shutdown_command_accepted=False,
            shutdown_command_error=repr(exc),
        )
        append_history("ERROR", "SHUTDOWN_COMMAND_ERROR", "failed to execute systemctl poweroff", error=repr(exc))
        return False

    stdout = cp.stdout.strip()
    stderr = cp.stderr.strip()
    accepted = cp.returncode == 0
    save_state(
        "SHUTDOWN_COMMAND_RESULT",
        shutdown_command_accepted=accepted,
        shutdown_command_returncode=cp.returncode,
        shutdown_command_stdout=stdout[-1000:],
        shutdown_command_stderr=stderr[-1000:],
    )
    append_history(
        "INFO" if accepted else "ERROR",
        "SHUTDOWN_COMMAND_RESULT",
        "systemctl poweroff accepted" if accepted else "systemctl poweroff FAILED",
        returncode=cp.returncode,
        stderr=stderr[-500:],
    )
    return accepted


def main_monitor(cfg: dict[str, Any]) -> int:
    global state, state_dir, running
    state_dir = cfg["state_dir"]
    state_dir.mkdir(parents=True, exist_ok=True)

    if preflight(cfg, quiet=False) != 0:
        append_history("ERROR", "HOST_PREFLIGHT_FAILED", "gpio-poweroff host prerequisite is not correctly active")
        return EX_CONFIG

    previous = read_json(state_dir / "current.json")
    clean = read_json(state_dir / "clean-shutdown.json")
    boot_id = get_boot_id()
    if previous and previous.get("boot_id") != boot_id:
        # Preserve the exact previous-boot terminal state before current.json is replaced.
        atomic_write_json(state_dir / "previous-boot.json", previous)
    level, report = classify_previous(previous, clean, boot_id)
    print(f"Previous-state assessment [{level}]: {report}", flush=True)
    write_report(level, report, previous)
    append_history(level, "PREVIOUS_BOOT_ASSESSMENT", report)

    same_boot = bool(previous and previous.get("boot_id") == boot_id)
    recovered_fail = bool(same_boot and previous.get("power_fail_active"))
    recovered_shutdown = bool(same_boot and previous.get("shutdown_requested"))

    instance_id = str(uuid.uuid4())
    state = {
        "schema": SCHEMA,
        "boot_id": boot_id,
        "monitor_instance": instance_id,
        "monitor_pid": os.getpid(),
        "script_sha256": script_sha256(),
        "config_sha256": config_sha256(),
        "kernel_release": platform.release(),
        "monitor_started_wall": now_iso(),
        "monitor_started_monotonic": round(monotonic(), 3),
        "gpio_input": cfg["gpio_input"],
        "gpio_pull": cfg["gpio_pull"],
        "power_fail_level": cfg["power_fail_level"],
        "shutdown_after": cfg["shutdown_after"],
        "restore_debounce": cfg["restore_debounce"],
        "short_test_armed": cfg["short_test_armed"],
        "poweroff_pin": cfg["poweroff_pin"],
        "power_fail_active": recovered_fail,
        "power_fail_started_wall": previous.get("power_fail_started_wall") if recovered_fail and previous else None,
        "power_fail_started_monotonic": previous.get("power_fail_started_monotonic") if recovered_fail and previous else None,
        "shutdown_requested": recovered_shutdown,
        "shutdown_command_accepted": bool(previous.get("shutdown_command_accepted")) if recovered_shutdown and previous else False,
        "stopped_cleanly": False,
        "last_event": "MONITOR_START",
    }
    save_state()

    try:
        from gpiozero import DigitalInputDevice
    except Exception as exc:
        append_history("ERROR", "GPIOZERO_IMPORT_FAILED", "unable to import gpiozero", error=repr(exc))
        save_state("GPIOZERO_IMPORT_FAILED", fatal_error=repr(exc))
        return EX_CONFIG

    pull = cfg["gpio_pull"]
    kwargs: dict[str, Any]
    if pull == "UP":
        kwargs = {"pull_up": True}
    elif pull == "DOWN":
        kwargs = {"pull_up": False}
    else:
        kwargs = {"pull_up": None, "active_state": True}

    try:
        pin = DigitalInputDevice(cfg["gpio_input"], **kwargs)
    except Exception as exc:
        append_history(
            "ERROR",
            "GPIO_INPUT_CLAIM_FAILED",
            f"unable to claim GPIO{cfg['gpio_input']}; another process may own it",
            error=repr(exc),
        )
        save_state("GPIO_INPUT_CLAIM_FAILED", fatal_error=repr(exc))
        return EX_CONFIG

    factory = type(pin.pin_factory).__name__
    initial_raw = raw_input(pin)
    save_state("GPIO_INPUT_ACQUIRED", gpio_raw=initial_raw, gpio_factory=factory)
    append_history(
        "INFO",
        "MONITOR_ARMED",
        "UPS shutdown monitor armed",
        gpio=cfg["gpio_input"],
        raw_level="HIGH" if initial_raw else "LOW",
        fail_level="HIGH" if cfg["power_fail_level"] else "LOW",
        shutdown_after=cfg["shutdown_after"],
        pin_factory=factory,
        short_test_armed=cfg["short_test_armed"],
    )

    # Recover a same-boot countdown. If its monotonic timestamp is invalid, fail safe
    # by refusing to invent elapsed time rather than initiating an early shutdown.
    low_start = state.get("power_fail_started_monotonic") if recovered_fail else None
    if low_start is not None:
        try:
            low_start = float(low_start)
            if low_start > monotonic() + 1:
                raise ValueError("stored monotonic start is in the future")
        except (TypeError, ValueError) as exc:
            append_history("ERROR", "RECOVERY_TIMER_INVALID", "stored outage timer is invalid; resetting timer", error=repr(exc))
            low_start = None
            save_state(
                "RECOVERY_TIMER_INVALID",
                power_fail_active=False,
                power_fail_started_monotonic=None,
                power_fail_started_wall=None,
                shutdown_requested=False,
                shutdown_command_accepted=False,
            )

    restore_candidate_since: float | None = None
    last_raw = initial_raw
    shutdown_accepted_at: float | None = None
    last_shutdown_attempt = 0.0

    try:
        while running:
            raw = raw_input(pin)
            fail = raw == cfg["power_fail_level"]

            if raw != last_raw:
                save_state("GPIO_INPUT_CHANGED", gpio_raw=raw)
                append_history(
                    "INFO",
                    "GPIO_INPUT_CHANGED",
                    f"GPIO{cfg['gpio_input']} changed to {'HIGH' if raw else 'LOW'}",
                    raw_level=raw,
                )
                last_raw = raw

            if state.get("shutdown_requested"):
                # Once a shutdown has been requested we do not cancel it if mains returns.
                now_mono = monotonic()
                if state.get("shutdown_command_accepted"):
                    if shutdown_accepted_at is None:
                        shutdown_accepted_at = float(state.get("shutdown_requested_monotonic") or now_mono)
                    if now_mono - shutdown_accepted_at >= cfg["shutdown_accepted_watchdog"]:
                        append_history(
                            "ERROR",
                            "SHUTDOWN_STALLED",
                            "host is still running after systemctl accepted poweroff; retrying",
                            seconds=round(now_mono - shutdown_accepted_at, 1),
                        )
                        accepted = request_poweroff(cfg)
                        shutdown_accepted_at = monotonic() if accepted else None
                        last_shutdown_attempt = monotonic()
                elif now_mono - last_shutdown_attempt >= cfg["shutdown_retry_seconds"]:
                    accepted = request_poweroff(cfg)
                    shutdown_accepted_at = monotonic() if accepted else None
                    last_shutdown_attempt = monotonic()
                time.sleep(cfg["poll_interval"])
                continue

            if fail:
                restore_candidate_since = None
                if low_start is None:
                    low_start = monotonic()
                    save_state(
                        "POWER_FAIL_DETECTED",
                        power_fail_active=True,
                        power_fail_started_wall=now_iso(),
                        power_fail_started_monotonic=round(low_start, 3),
                        gpio_raw=raw,
                    )
                    append_history(
                        "WARNING",
                        "POWER_FAIL_DETECTED",
                        "mains-loss input asserted; UPS hold-up timer started",
                        gpio=cfg["gpio_input"],
                        shutdown_after=cfg["shutdown_after"],
                    )

                elapsed = monotonic() - low_start
                if elapsed < -0.001:
                    append_history("ERROR", "MONOTONIC_INVARIANT", "monotonic elapsed time became negative; refusing shutdown")
                    save_state("MONOTONIC_INVARIANT", fatal_error="negative monotonic elapsed")
                    return EX_CONFIG

                if elapsed >= cfg["shutdown_after"]:
                    # Enforce the timing condition here, immediately adjacent to the only
                    # poweroff call. This guards future refactors against an early call.
                    save_state("SHUTDOWN_THRESHOLD_REACHED", outage_elapsed=round(elapsed, 3))
                    append_history(
                        "WARNING",
                        "SHUTDOWN_THRESHOLD_REACHED",
                        "configured continuous mains-loss interval reached",
                        elapsed=round(elapsed, 3),
                    )
                    accepted = request_poweroff(cfg)
                    shutdown_accepted_at = monotonic() if accepted else None
                    last_shutdown_attempt = monotonic()
            else:
                if low_start is not None:
                    if restore_candidate_since is None:
                        restore_candidate_since = monotonic()
                        append_history(
                            "INFO",
                            "POWER_RESTORE_CANDIDATE",
                            "mains-good level observed; waiting for restore debounce",
                            debounce_seconds=cfg["restore_debounce"],
                        )
                    if monotonic() - restore_candidate_since >= cfg["restore_debounce"]:
                        outage_duration = monotonic() - low_start
                        save_state(
                            "POWER_RESTORED",
                            power_fail_active=False,
                            power_fail_started_wall=None,
                            power_fail_started_monotonic=None,
                            last_outage_seconds=round(outage_duration, 3),
                        )
                        append_history(
                            "INFO",
                            "POWER_RESTORED",
                            "mains restored before shutdown threshold; outage timer cancelled",
                            outage_seconds=round(outage_duration, 3),
                        )
                        low_start = None
                        restore_candidate_since = None

            time.sleep(cfg["poll_interval"])
    finally:
        try:
            pin.close()
        except Exception:
            pass

    save_state("MONITOR_EXIT", stopped_cleanly=True)
    append_history("INFO", "MONITOR_EXIT", "UPS shutdown monitor exiting cleanly")
    return 0


def self_test() -> int:
    current = "boot-new"
    cases = [
        (None, None, "INFO", "No previous"),
        ({"boot_id": "boot-old", "shutdown_requested": True, "shutdown_command_accepted": True}, {"boot_id": "boot-old"}, "INFO", "UPS-triggered"),
        ({"boot_id": "boot-old", "shutdown_requested": False}, {"boot_id": "boot-old"}, "INFO", "non-UPS"),
        ({"boot_id": "boot-old", "power_fail_active": True, "shutdown_requested": False}, None, "ERROR", "NOT requested"),
        ({"boot_id": "boot-old", "shutdown_requested": True, "shutdown_command_accepted": False}, None, "ERROR", "requested shutdown"),
        ({"boot_id": current, "power_fail_active": True, "shutdown_requested": False}, None, "WARNING", "countdown"),
    ]
    for idx, (prev, clean, want_level, phrase) in enumerate(cases, 1):
        got_level, got_message = classify_previous(prev, clean, current)
        if got_level != want_level or phrase not in got_message:
            print(f"SELF-TEST {idx} FAILED: {got_level=} {got_message=}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "state.json"
        atomic_write_json(p, {"test": True, "n": 1})
        if read_json(p) != {"test": True, "n": 1}:
            print("SELF-TEST atomic state I/O FAILED", file=sys.stderr)
            return 1
    print("ups-shutdown self-test: PASS")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Raspberry Pi UPS graceful-shutdown monitor")
    parser.add_argument("--preflight", action="store_true", help="validate host gpio-poweroff configuration only")
    parser.add_argument("--mark-clean-shutdown", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true", help="run internal tests without touching GPIO")
    parser.add_argument("--shutdown-after", type=float, default=None, help="override SHUTDOWN_AFTER for this process only")
    return parser.parse_args()


def entrypoint() -> int:
    global state_dir
    args = parse_args()
    if args.self_test:
        return self_test()
    try:
        cfg = load_config(args.shutdown_after)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EX_CONFIG
    state_dir = cfg["state_dir"]

    if args.preflight:
        return preflight(cfg)
    if args.mark_clean_shutdown:
        return mark_clean_shutdown(cfg)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        return main_monitor(cfg)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        try:
            append_history("ERROR", "UNHANDLED_EXCEPTION", "monitor crashed", error=repr(exc))
            save_state("UNHANDLED_EXCEPTION", fatal_error=repr(exc), traceback=traceback.format_exc()[-8000:])
        except Exception:
            pass
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(entrypoint())
