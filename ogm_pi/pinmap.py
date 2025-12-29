"""Pinmap loader for OGM_slave_pi.

This module parses the exported pinmap JSON and provides lookup helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
import json


@dataclass(frozen=True)
class RegSpan:
    """Span of registers within a Modbus table."""

    start: int
    count: int


@dataclass(frozen=True)
class PinRecord:
    """Single pin entry with register spans and metadata."""

    name: str
    type: str
    pin: Any
    args: List[Any]
    coils: RegSpan
    discretes: RegSpan
    input_regs: RegSpan
    holding_regs: RegSpan


@dataclass
class PinMap:
    """Parsed pinmap with lookup helpers and raw JSON snapshot."""

    raw: Dict[str, Any]
    pins: List[PinRecord]
    pins_by_name: Dict[str, PinRecord]

    @classmethod
    def load(cls, path: str | Path) -> "PinMap":
        """Load pinmap JSON from disk."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        pins: List[PinRecord] = []
        pins_by_name: Dict[str, PinRecord] = {}

        for entry in data.get("pins", []):
            args = entry.get("args", [])
            if args is None:
                args = []
            elif not isinstance(args, list):
                args = [args]
            record = PinRecord(
                name=entry.get("name", ""),
                type=entry.get("type", ""),
                pin=entry.get("pin"),
                args=list(args),
                coils=_span(entry.get("coils")),
                discretes=_span(entry.get("discretes")),
                input_regs=_span(entry.get("input_regs")),
                holding_regs=_span(entry.get("holding_regs")),
            )
            if record.name in pins_by_name:
                raise ValueError(f"Duplicate pin name '{record.name}' in pinmap")
            pins.append(record)
            pins_by_name[record.name] = record

        return cls(raw=data, pins=pins, pins_by_name=pins_by_name)

    def find_pin(self, name: str) -> PinRecord:
        """Return a PinRecord by name (raises KeyError if missing)."""
        return self.pins_by_name[name]

    @property
    def totals(self) -> Dict[str, int]:
        """Return totals by register type."""
        return dict(self.raw.get("totals", {}))

    @property
    def address(self) -> int:
        """Return Modbus slave address from the pinmap."""
        return int(self.raw.get("address", 0))

    @property
    def hash(self) -> int:
        """Return board hash from the pinmap."""
        return int(self.raw.get("hash", 0))


def _span(value: Any) -> RegSpan:
    """Parse a [start, count] list into a RegSpan."""
    if not isinstance(value, list) or len(value) != 2:
        return RegSpan(0, 0)
    return RegSpan(int(value[0]), int(value[1]))
