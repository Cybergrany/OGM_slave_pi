#!/usr/bin/env python3
"""Pi-side test runner for gui_hook_test app lifecycle + hook coverage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Any, Dict, List

from ipc_ndjson import IpcClient


REQUIRED_CHECKS = [
    "env_bindings_present",
    "ipc_list",
    "ipc_schema",
    "ipc_resolve",
    "ipc_get_many",
    "ipc_set_many",
    "event_board_reset",
]

GPIO_CHECKS = ["ipc_gpio_read", "ipc_gpio_write"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run gui_hook_test verification on Pi")
    parser.add_argument("--socket-path", default="/run/ogm_pi.sock")
    parser.add_argument(
        "--app-dir",
        default=str(Path(__file__).resolve().parent),
        help="Path to deployed gui_hook_test app directory",
    )
    parser.add_argument("--startup-timeout-s", type=float, default=30.0)
    parser.add_argument("--reload-timeout-s", type=float, default=30.0)
    parser.add_argument(
        "--require-gpio",
        action="store_true",
        help="Fail if gpio checks are skipped (requires gpio_bindings in app config)",
    )
    return parser.parse_args()


def load_report(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError(f"report is not an object: {path}")
    return obj


def wait_for_report(path: Path, timeout_s: float, *, min_start_count: int = 1) -> Dict[str, Any]:
    deadline = time.monotonic() + max(timeout_s, 1.0)
    last_err = ""
    while time.monotonic() < deadline:
        if path.exists():
            try:
                report = load_report(path)
            except Exception as exc:
                last_err = str(exc)
                time.sleep(0.25)
                continue
            start_count = int(report.get("start_count", 0))
            if start_count >= min_start_count:
                return report
        time.sleep(0.25)
    if last_err:
        raise RuntimeError(f"timed out waiting for valid report ({last_err})")
    raise RuntimeError("timed out waiting for gui_hook_test report")


def map_checks(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        raise RuntimeError("report.checks is not a list")
    out: Dict[str, Dict[str, Any]] = {}
    for item in checks:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                out[name] = item
    return out


def validate_report(report: Dict[str, Any], *, require_gpio: bool) -> List[str]:
    errors: List[str] = []
    checks = map_checks(report)

    for name, item in checks.items():
        if bool(item.get("skipped", False)):
            continue
        if not bool(item.get("ok", False)):
            errors.append(f"check failed: {name} ({item.get('detail', '')})")

    for name in REQUIRED_CHECKS:
        item = checks.get(name)
        if item is None:
            errors.append(f"missing required check: {name}")
            continue
        if bool(item.get("skipped", False)):
            errors.append(f"required check was skipped: {name}")

    if require_gpio:
        for name in GPIO_CHECKS:
            item = checks.get(name)
            if item is None:
                errors.append(f"missing gpio check: {name}")
                continue
            if bool(item.get("skipped", False)):
                errors.append(f"gpio check was skipped: {name}")

    if not bool(report.get("ok", False)):
        errors.append("report.ok is false")
    return errors


def request_or_raise(client: IpcClient, payload: Dict[str, Any]) -> Dict[str, Any]:
    resp = client.request(payload)
    if not resp.get("ok", False):
        raise RuntimeError(f"IPC call failed for {payload.get('cmd')}: {resp}")
    return resp


def main() -> int:
    args = parse_args()
    app_dir = Path(args.app_dir).resolve()
    out_dir = app_dir / "test_output"
    report_path = out_dir / "latest_startup_report.json"

    print(f"[gui_hook_test] waiting for initial report: {report_path}")
    first = wait_for_report(report_path, args.startup_timeout_s, min_start_count=1)
    first_count = int(first.get("start_count", 0))
    first_pid = int(first.get("pid", -1))
    first_errors = validate_report(first, require_gpio=args.require_gpio)
    if first_errors:
        print("[gui_hook_test] initial report validation failed:")
        for err in first_errors:
            print(f"  - {err}")
        return 1
    print(f"[gui_hook_test] initial report OK (start_count={first_count}, pid={first_pid})")

    client = IpcClient(args.socket_path)
    print("[gui_hook_test] triggering app_reload")
    reload_resp = request_or_raise(client, {"id": 901, "cmd": "app_reload"})
    app_meta = reload_resp.get("app", {}) if isinstance(reload_resp, dict) else {}
    print(f"[gui_hook_test] app_reload response: {app_meta}")

    print("[gui_hook_test] waiting for restarted report")
    second = wait_for_report(report_path, args.reload_timeout_s, min_start_count=first_count + 1)
    second_count = int(second.get("start_count", 0))
    second_pid = int(second.get("pid", -1))
    second_errors = validate_report(second, require_gpio=args.require_gpio)
    if second_errors:
        print("[gui_hook_test] restarted report validation failed:")
        for err in second_errors:
            print(f"  - {err}")
        return 1

    if second_count <= first_count:
        print("[gui_hook_test] start_count did not increment after reload")
        return 1
    if second_pid == first_pid:
        print("[gui_hook_test] warning: pid did not change after reload (supervisor may have recycled quickly)")

    print(
        "[gui_hook_test] PASS "
        f"(start_count {first_count} -> {second_count}, pid {first_pid} -> {second_pid})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
