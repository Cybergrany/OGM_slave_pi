"""Register store for OGM_slave_pi.

This maintains coil/discrete/input/holding arrays and exposes helpers for
reading/writing by pin spans.
"""

from __future__ import annotations

from typing import Any, Dict, List
import threading

from .pinmap import PinMap, PinRecord, RegSpan


class RegisterStore:
    """Thread-safe storage for Modbus register tables."""

    def __init__(self, totals: Dict[str, int]) -> None:
        self.coils = [0] * int(totals.get("coils", 0))
        self.discretes = [0] * int(totals.get("discretes", 0))
        self.input_regs = [0] * int(totals.get("input_regs", 0))
        self.holding_regs = [0] * int(totals.get("holding_regs", 0))
        self._lock = threading.Lock()

    def get_pin(self, pin: PinRecord) -> Dict[str, List[int]]:
        """Return all register values for the requested pin."""
        with self._lock:
            return self._get_pin_unlocked(pin)

    def set_pin(self, pin: PinRecord, values: Dict[str, Any]) -> Dict[str, List[int]]:
        """Write register values for the requested pin and return the new state."""
        with self._lock:
            for reg_name, payload in values.items():
                if reg_name == "coils":
                    self._write_span(self.coils, pin.coils, payload, reg_name, coerce_bit)
                elif reg_name == "discretes":
                    self._write_span(self.discretes, pin.discretes, payload, reg_name, coerce_bit)
                elif reg_name == "input_regs":
                    self._write_span(self.input_regs, pin.input_regs, payload, reg_name, coerce_reg)
                elif reg_name == "holding_regs":
                    self._write_span(self.holding_regs, pin.holding_regs, payload, reg_name, coerce_reg)
                else:
                    raise ValueError(f"Unknown register type '{reg_name}'")
            return self._get_pin_unlocked(pin)

    def snapshot_tables(self) -> Dict[str, List[int]]:
        """Return copies of the register tables (used for Modbus sync)."""
        with self._lock:
            return {
                "coils": list(self.coils),
                "discretes": list(self.discretes),
                "input_regs": list(self.input_regs),
                "holding_regs": list(self.holding_regs),
            }

    def update_tables(self, tables: Dict[str, List[int]]) -> None:
        """Replace register tables from a Modbus backend snapshot."""
        with self._lock:
            self._apply_table(self.coils, tables.get("coils"), coerce_bit, "coils")
            self._apply_table(self.discretes, tables.get("discretes"), coerce_bit, "discretes")
            self._apply_table(self.input_regs, tables.get("input_regs"), coerce_reg, "input_regs")
            self._apply_table(self.holding_regs, tables.get("holding_regs"), coerce_reg, "holding_regs")

    def _get_pin_unlocked(self, pin: PinRecord) -> Dict[str, List[int]]:
        """Return pin values without acquiring the lock (caller holds lock)."""
        values: Dict[str, List[int]] = {}
        if pin.coils.count:
            values["coils"] = self._read_span(self.coils, pin.coils)
        if pin.discretes.count:
            values["discretes"] = self._read_span(self.discretes, pin.discretes)
        if pin.input_regs.count:
            values["input_regs"] = self._read_span(self.input_regs, pin.input_regs)
        if pin.holding_regs.count:
            values["holding_regs"] = self._read_span(self.holding_regs, pin.holding_regs)
        return values

    def seed_pin_hash(self, pinmap: PinMap) -> None:
        """Populate the PIN_HASH input registers from the pinmap hash value."""
        try:
            pin = pinmap.find_pin("board_hash")
        except KeyError:
            return
        if pin.input_regs.count < 2:
            return
        value = int(pinmap.hash) & 0xFFFFFFFF
        lo = value & 0xFFFF
        hi = (value >> 16) & 0xFFFF
        with self._lock:
            self.input_regs[pin.input_regs.start] = lo
            self.input_regs[pin.input_regs.start + 1] = hi

    @staticmethod
    def _read_span(buffer: List[int], span: RegSpan) -> List[int]:
        """Read a span from a register buffer."""
        if span.count == 0:
            return []
        return list(buffer[span.start : span.start + span.count])

    @staticmethod
    def _write_span(
        buffer: List[int],
        span: RegSpan,
        payload: Any,
        reg_name: str,
        coercer,
    ) -> None:
        """Write a span to a register buffer, validating size and type."""
        if span.count == 0:
            raise ValueError(f"Pin has no {reg_name} span")
        values = normalize_values(payload, span.count)
        coerced = [coercer(v) for v in values]
        buffer[span.start : span.start + span.count] = coerced

    @staticmethod
    def _apply_table(buffer: List[int], values: List[Any] | None, coercer, name: str) -> None:
        """Replace a full register table with validated values."""
        if values is None:
            return
        if len(values) != len(buffer):
            raise ValueError(f"Expected {len(buffer)} {name} entries, got {len(values)}")
        buffer[:] = [coercer(v) for v in values]


def normalize_values(payload: Any, expected: int) -> List[Any]:
    """Normalize payload to a list and validate against the expected length."""
    if isinstance(payload, list):
        values = payload
    else:
        values = [payload]
    if len(values) != expected:
        raise ValueError(f"Expected {expected} values, got {len(values)}")
    return values


def coerce_bit(value: Any) -> int:
    """Coerce a boolean-like value into 0/1."""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return 1 if int(value) else 0
    raise ValueError(f"Invalid bit value: {value!r}")


def coerce_reg(value: Any) -> int:
    """Coerce a register value to a 0..65535 integer."""
    if isinstance(value, bool):
        value = 1 if value else 0
    if isinstance(value, (int, float)):
        value = int(value)
        if 0 <= value <= 0xFFFF:
            return value
    raise ValueError(f"Invalid register value: {value!r}")
