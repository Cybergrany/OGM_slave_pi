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


def compute_child_hash(child: Dict[str, Any], parent: Dict[str, Any], pins: Iterable[Dict[str, Any]]) -> int:
    """Compute the same child hash as OGM_Portable's generator."""
    parts = [
        f"child:{child['name']}",
        f"parent:{parent['name']}",
        f"addr:{child['downstream_address']}",
        f"stats:{child.get('has_stats', False)}",
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


def build_child_pins(child: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return bridge child pins with optional BOARD_STATS appended."""
    pins = list(child.get("pins", []))
    if child.get("has_stats", False):
        if not any(p.get("type") == "BOARD_STATS" for p in pins):
            pins.append({"name": f"bridge_stats_{child['name']}", "type": "BOARD_STATS", "pin": 0})
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


def build_child_layout(
    bridge: Dict[str, Any],
    child: Dict[str, Any],
    traits: Dict[str, Dict[str, int]],
    aliases: Dict[str, str],
    network_baud: int,
    source_paths: Dict[str, str],
) -> Dict[str, Any]:
    """Assemble the pinmap JSON structure for a single bridge child."""
    pins = build_child_pins(child)
    ensure_hash_pin_free(pins)
    hash_val = compute_child_hash(child, bridge, pins)
    child_hash_name = f"child_hash_{child['name']}"

    pins_with_hash = [
        {"name": child_hash_name, "type": "PIN_HASH", "pin": 1, "args": [hash_val]},
        *pins,
    ]

    index = {"coils": 0, "discretes": 0, "input_regs": 0, "holding_regs": 0}
    pin_records: List[Dict[str, Any]] = []

    for pin in pins_with_hash:
        pin_type = pin.get("type")
        if not pin_type:
            raise ExportError(f"Pin missing type on child {child.get('name')}")
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

    bridge_name = bridge.get("name", "")
    child_name = child.get("name", "")
    return {
        "schema_version": 1,
        "generated_at": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "source": source_paths,
        "network_baud": int(network_baud),
        "hash": hash_val,
        "id": f"PINS_{bridge_name.upper()}_{child_name.upper()}",
        "label": child_name,
        "kind": "bridge_child",
        "bridge": {
            "name": bridge_name,
            "address": int(bridge.get("address", 0)),
        },
        "address": int(child.get("downstream_address", 0)),
        "zone": int(bridge.get("zone", 0)),
        "reset_on_init": bool(child.get("reset_on_init", False)),
        "has_stats": bool(child.get("has_stats", False)),
        "external_management": bool(child.get("external_management", False)),
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


def select_child(
    data: Dict[str, Any],
    child_name: str | None,
    child_address: int | None,
    bridge_name: str | None,
    bridge_address: int | None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Select a bridge child definition by name/address with optional bridge filter."""
    bridges = data.get("bridges", [])
    if not isinstance(bridges, list):
        raise ExportError("ExternalIODefines.yaml must define a list of bridges")

    candidates: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for bridge in bridges:
        if bridge_name is not None and bridge.get("name") != bridge_name:
            continue
        if bridge_address is not None and int(bridge.get("address", -1)) != bridge_address:
            continue
        for child in bridge.get("children", []) or []:
            if child_name is not None and child.get("name") != child_name:
                continue
            if child_address is not None and int(child.get("downstream_address", -1)) != child_address:
                continue
            candidates.append((bridge, child))

    if not candidates:
        raise ExportError("No matching bridge child found")
    if len(candidates) > 1:
        names = ", ".join(f"{b.get('name')}/{c.get('name')}" for b, c in candidates)
        raise ExportError(f"Multiple bridge children matched; use --bridge-name/--bridge-address to disambiguate ({names})")
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
    parser.add_argument("--child-name", help="Bridge child name to export")
    parser.add_argument("--child-address", type=int, help="Bridge child downstream address to export")
    parser.add_argument("--bridge-name", help="Bridge name to disambiguate child selection")
    parser.add_argument("--bridge-address", type=int, help="Bridge Modbus address to disambiguate child selection")
    parser.add_argument("--output", help="Output JSON path (default: out/pinmap_<name|addr>.json)")
    parser.add_argument("--skip-external", action="store_true", help="Skip boards marked external_management")
    return parser.parse_args()


def main() -> int:
    """CLI entry point."""
    args = parse_args()
    wants_child = args.child_name is not None or args.child_address is not None
    wants_board = args.name is not None or args.address is not None
    if not wants_child and not wants_board:
        raise ExportError("Provide --name/--address for boards or --child-name/--child-address for bridge children")
    if wants_child and wants_board:
        raise ExportError("Choose either board selection (--name/--address) or child selection (--child-name/--child-address)")

    config_path = Path(args.config)
    traits_paths = [Path(args.traits), Path(args.custom_traits)]

    config = load_yaml(config_path)
    ensure_version(config, config_path)
    traits, aliases = load_traits(traits_paths)

    source_paths = {
        "external_io_defines": str(config_path),
        "pin_traits": str(traits_paths[0]),
        "custom_pin_traits": str(traits_paths[1]),
    }
    if wants_child:
        bridge, child = select_child(
            config,
            args.child_name,
            args.child_address,
            args.bridge_name,
            args.bridge_address,
        )
        if args.skip_external and child.get("external_management", False):
            raise ExportError(
                f"Bridge child '{bridge.get('name')}/{child.get('name')}' is marked external_management; "
                "rerun without --skip-external"
            )
        layout = build_child_layout(bridge, child, traits, aliases, config.get("network_baud", 0), source_paths)
    else:
        board = select_board(config, args.name, args.address)
        if args.skip_external and board.get("external_management", False):
            raise ExportError(f"Board '{board.get('name')}' is marked external_management; rerun without --skip-external")
        layout = build_layout(board, traits, aliases, config.get("network_baud", 0), source_paths)
    rendered = json.dumps(layout, indent=2, sort_keys=False)

    if args.output == "-":
        print(rendered)
        return 0

    if args.output:
        out_path = Path(args.output)
    else:
        if wants_child:
            suffix = str(child.get("downstream_address")) if args.child_address is not None else str(child.get("name"))
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
