#!/usr/bin/env python3
"""Deploy-loadable GUI emulator for validating OGM_slave_pi app hooks."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ipc_ndjson import IpcClient, IpcError, subscribe_events, wait_for_event


STOP = False


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def append_line(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")


def bump_counter(path: Path) -> int:
    count = 0
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            count = int(raw)
    count += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{count}\n", encoding="utf-8")
    return count


def as_check(
    name: str,
    *,
    ok: bool,
    detail: str = "",
    skipped: bool = False,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "ok": bool(ok),
        "skipped": bool(skipped),
        "detail": detail,
        "data": data or {},
    }


def parse_bindings(env_key: str) -> List[Dict[str, Any]]:
    raw = os.environ.get(env_key, "[]")
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise ValueError(f"{env_key} must be a JSON list")
    out: List[Dict[str, Any]] = []
    for idx, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            raise ValueError(f"{env_key}[{idx}] must be an object")
        name = str(entry.get("name", "")).strip()
        handle = int(entry.get("handle", 0))
        line = entry.get("line")
        if not name or handle <= 0:
            raise ValueError(f"{env_key}[{idx}] requires name + handle")
        item: Dict[str, Any] = {"name": name, "handle": handle}
        if line is not None:
            item["line"] = int(line)
        out.append(item)
    return out


def pin_lookup(pin_list: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for pin in pin_list:
        name = str(pin.get("name", ""))
        if name:
            out[name] = pin
    return out


def unique_names(bindings: Iterable[Dict[str, Any]]) -> List[str]:
    seen: set[str] = set()
    names: List[str] = []
    for item in bindings:
        name = str(item["name"])
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def choose_safe_write_candidate(
    pin_bindings: List[Dict[str, Any]],
    pin_by_name: Dict[str, Dict[str, Any]],
) -> Optional[Tuple[int, str, List[Any]]]:
    unsafe_types = {"BOARD_RESET", "BOARD_SHUTDOWN"}
    for binding in pin_bindings:
        name = str(binding["name"])
        handle = int(binding["handle"])
        pin = pin_by_name.get(name)
        if not pin:
            continue
        pin_type = str(pin.get("type", ""))
        if pin_type in unsafe_types:
            continue
        coils = pin.get("coils") or [0, 0]
        holding = pin.get("holding_regs") or [0, 0]
        if int(coils[1]) > 0:
            return handle, "coils", []
        if int(holding[1]) > 0:
            return handle, "holding_regs", []
    return None


def run_startup_suite(
    socket_path: str,
    *,
    pin_bindings: List[Dict[str, Any]],
    gpio_bindings: List[Dict[str, Any]],
    board_reset_timeout_s: float,
) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    client = IpcClient(socket_path)

    checks.append(
        as_check(
            "env_bindings_present",
            ok=True,
            detail="parsed app binding environment",
            data={"pin_bindings": len(pin_bindings), "gpio_bindings": len(gpio_bindings)},
        )
    )

    list_resp = client.request({"id": 1, "cmd": "list"})
    if not list_resp.get("ok", False):
        raise IpcError(f"list failed: {list_resp}")
    pins = list_resp.get("pins", [])
    if not isinstance(pins, list):
        raise IpcError("list response missing pins[]")
    pin_by_name = pin_lookup(pins)
    checks.append(
        as_check(
            "ipc_list",
            ok=True,
            detail="list command returned pin metadata",
            data={"pins": len(pins)},
        )
    )

    schema_resp = client.request({"id": 2, "cmd": "schema"})
    schema_ok = bool(schema_resp.get("ok", False) and isinstance(schema_resp.get("pins"), list))
    checks.append(
        as_check(
            "ipc_schema",
            ok=schema_ok,
            detail="schema command returned pinmap payload" if schema_ok else f"schema failed: {schema_resp}",
            data={"address": schema_resp.get("address")},
        )
    )
    if not schema_ok:
        return {"ok": False, "checks": checks}

    names_for_resolve = unique_names(pin_bindings + gpio_bindings)
    resolve_ok = True
    resolved_by_name: Dict[str, Dict[str, Any]] = {}
    if names_for_resolve:
        resolve_resp = client.request({"id": 3, "cmd": "resolve", "names": names_for_resolve})
        resolve_ok = bool(resolve_resp.get("ok", False))
        if resolve_ok:
            handles = resolve_resp.get("handles", [])
            if not isinstance(handles, list):
                resolve_ok = False
            else:
                for item in handles:
                    if isinstance(item, dict):
                        resolved_by_name[str(item.get("name", ""))] = item
                for item in pin_bindings + gpio_bindings:
                    name = str(item["name"])
                    expected = int(item["handle"])
                    actual = int(resolved_by_name.get(name, {}).get("handle", -1))
                    if actual != expected:
                        resolve_ok = False
                        break
        checks.append(
            as_check(
                "ipc_resolve",
                ok=resolve_ok,
                detail="resolve handle mapping verified" if resolve_ok else f"resolve failed: {resolve_resp}",
                data={"names": names_for_resolve},
            )
        )
    else:
        checks.append(
            as_check(
                "ipc_resolve",
                ok=True,
                skipped=True,
                detail="no pin/gpio bindings provided; skipping resolve check",
            )
        )

    handles_to_get = [int(item["handle"]) for item in (pin_bindings + gpio_bindings)]
    seen_handles: List[int] = []
    if handles_to_get:
        unique_handles: List[int] = []
        seen = set()
        for handle in handles_to_get:
            if handle in seen:
                continue
            seen.add(handle)
            unique_handles.append(handle)
        gm_resp = client.request({"id": 4, "cmd": "get_many", "handles": unique_handles})
        gm_ok = bool(gm_resp.get("ok", False))
        if gm_ok:
            items = gm_resp.get("items", [])
            if not isinstance(items, list):
                gm_ok = False
            else:
                seen_handles = [int(item.get("handle", -1)) for item in items if isinstance(item, dict)]
                gm_ok = len(seen_handles) == len(unique_handles)
        checks.append(
            as_check(
                "ipc_get_many",
                ok=gm_ok,
                detail="get_many returned all requested handles" if gm_ok else f"get_many failed: {gm_resp}",
                data={"requested_handles": unique_handles, "returned_handles": seen_handles},
            )
        )

        candidate = choose_safe_write_candidate(pin_bindings, pin_by_name)
        if candidate is None:
            checks.append(
                as_check(
                    "ipc_set_many",
                    ok=True,
                    skipped=True,
                    detail="no safe writable test binding found; skipping set_many smoke test",
                )
            )
        else:
            handle, table, _ = candidate
            base = client.request({"id": 5, "cmd": "get_many", "handles": [handle]})
            write_ok = bool(base.get("ok", False))
            if write_ok:
                items = base.get("items", [])
                write_ok = isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict)
            values: List[Any] = []
            if write_ok:
                values = list((base["items"][0].get("values") or {}).get(table) or [])
                set_resp = client.request(
                    {
                        "id": 6,
                        "cmd": "set_many",
                        "writes": [{"handle": handle, "values": {table: values}}],
                    }
                )
                write_ok = bool(set_resp.get("ok", False))
            checks.append(
                as_check(
                    "ipc_set_many",
                    ok=write_ok,
                    detail=f"set_many idempotent write on {table}" if write_ok else "set_many failed",
                    data={"handle": handle, "table": table, "value_count": len(values)},
                )
            )
    else:
        checks.append(
            as_check(
                "ipc_get_many",
                ok=True,
                skipped=True,
                detail="no bindings provided; skipping get_many",
            )
        )
        checks.append(
            as_check(
                "ipc_set_many",
                ok=True,
                skipped=True,
                detail="no bindings provided; skipping set_many",
            )
        )

    if gpio_bindings:
        gpio_handles = [int(item["handle"]) for item in gpio_bindings]
        gr_resp = client.request({"id": 7, "cmd": "gpio_read", "handles": gpio_handles})
        gr_ok = bool(gr_resp.get("ok", False))
        first_read_val = 0
        if gr_ok:
            items = gr_resp.get("items", [])
            gr_ok = isinstance(items, list) and len(items) == len(gpio_handles)
            if gr_ok and items:
                first_read_val = int(items[0].get("value", 0))
        checks.append(
            as_check(
                "ipc_gpio_read",
                ok=gr_ok,
                detail="gpio_read returned app-claimed lines" if gr_ok else f"gpio_read failed: {gr_resp}",
                data={"handles": gpio_handles},
            )
        )
        gw_resp = client.request(
            {
                "id": 8,
                "cmd": "gpio_write",
                "writes": [{"handle": gpio_handles[0], "value": first_read_val}],
            }
        )
        gw_ok = bool(gw_resp.get("ok", False))
        checks.append(
            as_check(
                "ipc_gpio_write",
                ok=gw_ok,
                detail="gpio_write succeeded on app-claimed line" if gw_ok else f"gpio_write failed: {gw_resp}",
                data={"handle": gpio_handles[0], "value": first_read_val},
            )
        )
    else:
        checks.append(
            as_check(
                "ipc_gpio_read",
                ok=True,
                skipped=True,
                detail="no gpio bindings configured; skipping gpio_read",
            )
        )
        checks.append(
            as_check(
                "ipc_gpio_write",
                ok=True,
                skipped=True,
                detail="no gpio bindings configured; skipping gpio_write",
            )
        )

    board_reset_candidates = [pin for pin in pins if str(pin.get("type", "")) == "BOARD_RESET"]
    if board_reset_candidates:
        reset_name = str(board_reset_candidates[0].get("name", ""))
        sub_sock = None
        sub_stream = None
        try:
            sub_sock, _, sub_stream = subscribe_events(
                socket_path,
                events=("board_reset",),
                timeout_s=max(board_reset_timeout_s, 1.0),
            )
            set_resp = client.request({"id": 9, "cmd": "set", "name": reset_name, "values": {"coils": [1]}})
            event = wait_for_event(sub_stream, "board_reset", timeout_s=max(board_reset_timeout_s, 1.0))
            br_ok = bool(set_resp.get("ok", False) and event is not None)
            detail = "board_reset event observed after trigger" if br_ok else "board_reset trigger or event failed"
            checks.append(
                as_check(
                    "event_board_reset",
                    ok=br_ok,
                    detail=detail,
                    data={"reset_pin": reset_name, "event": event or {}},
                )
            )
        finally:
            if sub_stream is not None:
                sub_stream.close()
            if sub_sock is not None:
                sub_sock.close()
    else:
        checks.append(
            as_check(
                "event_board_reset",
                ok=True,
                skipped=True,
                detail="no BOARD_RESET pin present; skipping board_reset event check",
            )
        )

    overall_ok = all(item.get("ok", False) for item in checks if not item.get("skipped", False))
    return {"ok": overall_ok, "checks": checks}


def handle_signal(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GUI hook test child app for OGM_slave_pi")
    parser.add_argument("--socket-path", default=os.environ.get("OGM_PI_SOCKET_PATH", "/run/ogm_pi.sock"))
    parser.add_argument("--heartbeat-ms", type=int, default=1000, help="Heartbeat write interval")
    parser.add_argument("--board-reset-timeout-s", type=float, default=5.0, help="Timeout waiting for board_reset event")
    parser.add_argument("--once", action="store_true", help="Run startup checks once and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    app_dir = Path(__file__).resolve().parent
    out_dir = app_dir / "test_output"
    counter_file = out_dir / "start_count.txt"
    report_file = out_dir / "latest_startup_report.json"
    history_file = out_dir / "startup_history.ndjson"
    heartbeat_file = out_dir / "heartbeat.json"

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        pin_bindings = parse_bindings("OGM_PI_PIN_BINDINGS")
    except Exception as exc:
        pin_bindings = []
        binding_error = f"OGM_PI_PIN_BINDINGS parse failed: {exc}"
    else:
        binding_error = ""

    try:
        gpio_bindings = parse_bindings("OGM_PI_GPIO_BINDINGS")
    except Exception as exc:
        gpio_bindings = []
        gpio_binding_error = f"OGM_PI_GPIO_BINDINGS parse failed: {exc}"
    else:
        gpio_binding_error = ""

    start_count = bump_counter(counter_file)
    start_ts = now_iso()
    base_report: Dict[str, Any] = {
        "app": "gui_hook_test",
        "pid": os.getpid(),
        "start_count": start_count,
        "started_at": start_ts,
        "socket_path": args.socket_path,
        "apps_dir_env": os.environ.get("OGM_PI_APPS_DIR", ""),
        "board_id_env": os.environ.get("OGM_PI_BOARD_ID", ""),
        "board_name_env": os.environ.get("OGM_PI_BOARD_NAME", ""),
        "pinmap_hash_env": os.environ.get("OGM_PI_PINMAP_HASH", ""),
        "checks": [],
        "ok": False,
    }

    if binding_error or gpio_binding_error:
        if binding_error:
            base_report["checks"].append(as_check("env_pin_bindings_parse", ok=False, detail=binding_error))
        if gpio_binding_error:
            base_report["checks"].append(as_check("env_gpio_bindings_parse", ok=False, detail=gpio_binding_error))
        base_report["ok"] = False
    else:
        try:
            result = run_startup_suite(
                args.socket_path,
                pin_bindings=pin_bindings,
                gpio_bindings=gpio_bindings,
                board_reset_timeout_s=args.board_reset_timeout_s,
            )
            base_report["checks"] = result.get("checks", [])
            base_report["ok"] = bool(result.get("ok", False))
        except Exception as exc:
            base_report["checks"] = [as_check("startup_suite_exception", ok=False, detail=str(exc))]
            base_report["ok"] = False

    base_report["completed_at"] = now_iso()
    atomic_write_json(report_file, base_report)
    atomic_write_json(out_dir / f"startup_report_{start_count:04d}.json", base_report)
    append_line(history_file, base_report)

    if args.once:
        return 0 if base_report.get("ok", False) else 2

    heartbeat_s = max(args.heartbeat_ms, 100) / 1000.0
    while not STOP:
        atomic_write_json(
            heartbeat_file,
            {
                "app": "gui_hook_test",
                "pid": os.getpid(),
                "start_count": start_count,
                "ok": bool(base_report.get("ok", False)),
                "ts": now_iso(),
            },
        )
        time.sleep(heartbeat_s)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
