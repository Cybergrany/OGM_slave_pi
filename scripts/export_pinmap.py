#!/usr/bin/env python3
"""Export a per-board pinmap JSON from ExternalIODefines.yaml.

This mirrors the master layout rules (PIN_HASH injection, optional BOARD_STATS)
and computes the same 32-bit FNV-1a hash used by OGM_Portable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193

PIN_REQUIRED_TYPES = {
    "OUTPUT_DIGITAL",
    "INPUT_DIGITAL",
    "INPUT_ANALOG",
    "OUTPUT_PWM",
    "TIMED_DIGITAL",
    "BAM_DIMMER",
}


class ExportError(RuntimeError):
    """Raised when YAML inputs are invalid or incomplete."""


def load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file and return a dict (empty if file is missing)."""
    if not path.exists():
        raise ExportError(f"Missing required file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ExportError(f"Expected mapping in {path}")
    return data


def ensure_version(data: Dict[str, Any], path: Path) -> None:
    """Validate version field for traits/config compatibility."""
    if int(data.get("version", 0)) != 1:
        raise ExportError(f"{path} must set version: 1")


def load_traits(paths: Iterable[Path], namespace: str = "master") -> Tuple[Dict[str, Dict[str, int]], Dict[str, str]]:
    """Load pin footprint traits for the requested namespace."""
    traits: Dict[str, Dict[str, int]] = {}
    aliases: Dict[str, str] = {}

    for path in paths:
        data = load_yaml(path)
        ensure_version(data, path)

        for entry in data.get("traits", []):
            name = entry.get("name")
            namespaces = entry.get("namespaces", [])
            if not name or namespace not in namespaces:
                continue
            if name in traits:
                raise ExportError(f"Duplicate trait '{name}' from {path}")
            traits[name] = {
                "coils": int(entry.get("coils", 0)),
                "discretes": int(entry.get("discretes", 0)),
                "input_regs": int(entry.get("input_regs", 0)),
                "holding_regs": int(entry.get("holding_regs", 0)),
            }

        for entry in data.get("aliases", []):
            name = entry.get("name")
            namespaces = entry.get("namespaces", [])
            target = entry.get("target")
            if not name or namespace not in namespaces:
                continue
            if not target:
                raise ExportError(f"Alias '{name}' in {path} missing target")
            if name in aliases:
                raise ExportError(f"Duplicate alias '{name}' from {path}")
            aliases[name] = str(target)

    return traits, aliases


def resolve_trait(pin_type: str, traits: Dict[str, Dict[str, int]], aliases: Dict[str, str]) -> Dict[str, int]:
    """Resolve a pin type to its register footprint, following aliases."""
    if pin_type in traits:
        return traits[pin_type]
    alias_target = aliases.get(pin_type)
    if alias_target and alias_target in traits:
        return traits[alias_target]
    raise ExportError(f"Missing RegUsageTraits for '{pin_type}' (namespace master)")


def fmt_token(val: Any) -> str:
    """Render a token for hashing (mirrors generate_external_io_defines.py)."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if val is None:
        return "0"
    return str(val)


def canonical_pin(pin: Dict[str, Any]) -> str:
    """Canonical string for hashing (exclude hash pins we add later)."""
    args = pin.get("args") or []
    if isinstance(args, list):
        args_repr = ",".join(fmt_token(a) for a in args)
    else:
        args_repr = fmt_token(args) if args else ""
    return "|".join([
        pin["name"],
        pin["type"],
        str(pin.get("pin", "")),
        args_repr,
    ])


def fnv1a32(parts: Iterable[str]) -> int:
    """Compute a 32-bit FNV-1a hash from an iterable of string parts."""
    h = FNV_OFFSET
    for part in parts:
        for byte in part.encode("utf-8"):
            h ^= byte
            h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h or 0xFFFFFFFF


def compute_board_hash(board: Dict[str, Any], pins: Iterable[Dict[str, Any]]) -> int:
    """Compute the same board hash as OGM_Portable's generator."""
    parts = [
        f"board:{board['name']}",
        f"addr:{board['address']}",
        f"zone:{board.get('zone', 0)}",
        f"reset:{board.get('reset_on_init', False)}",
    ]
    for pin in pins:
        parts.append(canonical_pin(pin))
    return fnv1a32(parts)


def normalize_args(raw: Any) -> List[Any]:
    """Normalize pin args into a list (empty if none)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    return [raw]


def pin_requires_number(pin_type: str) -> bool:
    """Return True if the pin type requires a concrete pin number."""
    return pin_type.upper() in PIN_REQUIRED_TYPES


def build_board_pins(board: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return board pins with optional BOARD_STATS appended."""
    pins = list(board.get("pins", []))
    if board.get("has_stats", False):
        if not any(p.get("type") == "BOARD_STATS" for p in pins):
            pins.append({"name": f"board_stats_{board['name']}", "type": "BOARD_STATS", "pin": 0})
    return pins


def ensure_hash_pin_free(pins: Iterable[Dict[str, Any]]) -> None:
    """Reject pin lists that already use pin number 1 (reserved for PIN_HASH)."""
    for pin in pins:
        if pin.get("pin") == 1:
            raise ExportError(f"Pin '{pin.get('name', '<unnamed>')}' already uses pin 1; reserved for PIN_HASH")


def build_layout(
    board: Dict[str, Any],
    traits: Dict[str, Dict[str, int]],
    aliases: Dict[str, str],
    network_baud: int,
    source_paths: Dict[str, str],
) -> Dict[str, Any]:
    """Assemble the pinmap JSON structure for a single board."""
    pins = build_board_pins(board)
    ensure_hash_pin_free(pins)
    hash_val = compute_board_hash(board, pins)

    pins_with_hash = [
        {"name": "board_hash", "type": "PIN_HASH", "pin": 1, "args": [hash_val]},
        *pins,
    ]

    index = {"coils": 0, "discretes": 0, "input_regs": 0, "holding_regs": 0}
    pin_records: List[Dict[str, Any]] = []

    for pin in pins_with_hash:
        pin_type = pin.get("type")
        if not pin_type:
            raise ExportError(f"Pin missing type on board {board.get('name')}")
        if pin_requires_number(pin_type) and "pin" not in pin:
            raise ExportError(f"Pin {pin.get('name', '<unnamed>')} ({pin_type}) requires a 'pin' field")

        usage = resolve_trait(pin_type, traits, aliases)
        record = {
            "name": pin.get("name", ""),
            "type": pin_type,
            "pin": pin.get("pin"),
            "args": normalize_args(pin.get("args")),
            "coils": [index["coils"], usage["coils"]],
            "discretes": [index["discretes"], usage["discretes"]],
            "input_regs": [index["input_regs"], usage["input_regs"]],
            "holding_regs": [index["holding_regs"], usage["holding_regs"]],
        }
        pin_records.append(record)

        index["coils"] += usage["coils"]
        index["discretes"] += usage["discretes"]
        index["input_regs"] += usage["input_regs"]
        index["holding_regs"] += usage["holding_regs"]

    return {
        "schema_version": 1,
        "generated_at": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "source": source_paths,
        "network_baud": int(network_baud),
        "hash": hash_val,
        "id": f"PINS_{board['name'].upper()}",
        "label": board.get("name", ""),
        "kind": "board",
        "address": int(board.get("address", 0)),
        "zone": int(board.get("zone", 0)),
        "reset_on_init": bool(board.get("reset_on_init", False)),
        "has_stats": bool(board.get("has_stats", False)),
        "external_management": bool(board.get("external_management", False)),
        "totals": {
            "coils": index["coils"],
            "discretes": index["discretes"],
            "input_regs": index["input_regs"],
            "holding_regs": index["holding_regs"],
        },
        "pins": pin_records,
    }


def select_board(data: Dict[str, Any], name: str | None, address: int | None) -> Dict[str, Any]:
    """Select a board definition by name or address."""
    boards = data.get("boards", [])
    if not isinstance(boards, list):
        raise ExportError("ExternalIODefines.yaml must define a list of boards")

    candidates = boards
    if name is not None:
        candidates = [b for b in candidates if b.get("name") == name]
    if address is not None:
        candidates = [b for b in candidates if int(b.get("address", -1)) == address]

    if not candidates:
        raise ExportError("No matching board found")
    if len(candidates) > 1:
        raise ExportError("Multiple boards matched; use --name or --address to disambiguate")
    return candidates[0]


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for export_pinmap.py."""
    parser = argparse.ArgumentParser(description="Export OGM pinmap JSON from ExternalIODefines.yaml")
    parser.add_argument("--config", default="config/ExternalIODefines.yaml", help="Path to ExternalIODefines.yaml")
    parser.add_argument("--traits", default="config/PinTraits.yaml", help="Path to PinTraits.yaml")
    parser.add_argument(
        "--custom-traits",
        default="config/CustomSlaveDefines/PinTraits.yaml",
        help="Path to custom PinTraits.yaml",
    )
    parser.add_argument("--name", help="Board name to export")
    parser.add_argument("--address", type=int, help="Board Modbus address to export")
    parser.add_argument("--output", help="Output JSON path (default: out/pinmap_<name|addr>.json)")
    parser.add_argument("--skip-external", action="store_true", help="Skip boards marked external_management")
    return parser.parse_args()


def main() -> int:
    """CLI entry point."""
    args = parse_args()
    if args.name is None and args.address is None:
        raise ExportError("Provide --name or --address")

    config_path = Path(args.config)
    traits_paths = [Path(args.traits), Path(args.custom_traits)]

    config = load_yaml(config_path)
    ensure_version(config, config_path)
    traits, aliases = load_traits(traits_paths)

    board = select_board(config, args.name, args.address)
    if args.skip_external and board.get("external_management", False):
        raise ExportError(f"Board '{board.get('name')}' is marked external_management; rerun without --skip-external")

    source_paths = {
        "external_io_defines": str(config_path),
        "pin_traits": str(traits_paths[0]),
        "custom_pin_traits": str(traits_paths[1]),
    }

    layout = build_layout(board, traits, aliases, config.get("network_baud", 0), source_paths)
    rendered = json.dumps(layout, indent=2, sort_keys=False)

    if args.output == "-":
        print(rendered)
        return 0

    if args.output:
        out_path = Path(args.output)
    else:
        suffix = str(board.get("address")) if args.address is not None else str(board.get("name"))
        out_path = Path("out") / f"pinmap_{suffix}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExportError as exc:
        raise SystemExit(f"export_pinmap.py: {exc}")
