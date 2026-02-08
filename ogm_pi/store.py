"""Register store for OGM_slave_pi.

This maintains coil/discrete/input/holding arrays and exposes helpers for
reading/writing by pin spans.
"""

from __future__ import annotations

from typing import Any, Dict, List
import logging
import threading

from .pinmap import PinMap, PinRecord, RegSpan

LOGGER = logging.getLogger(__name__)


class RegisterStore:
    """Thread-safe storage for Modbus register tables."""

    def __init__(self, totals: Dict[str, int]) -> None:
        self.coils = [0] * int(totals.get("coils", 0))
        self.discretes = [0] * int(totals.get("discretes", 0))
        self.input_regs = [0] * int(totals.get("input_regs", 0))
        self.holding_regs = [0] * int(totals.get("holding_regs", 0))
        self._lock = threading.Lock()
        self._dirty_updates: Dict[str, Dict[int, int]] = {
            "coils": {},
            "discretes": {},
            "input_regs": {},
            "holding_regs": {},
        }

    def get_pin(self, pin: PinRecord) -> Dict[str, List[int]]:
        """Return all register values for the requested pin."""
        with self._lock:
            return self._get_pin_unlocked(pin)

    def set_pin(self, pin: PinRecord, values: Dict[str, Any]) -> Dict[str, List[int]]:
        """Write register values for the requested pin and return the new state."""
        with self._lock:
            for reg_name, payload in values.items():
                if reg_name == "coils":
                    self._write_span(self.coils, pin.coils, payload, reg_name, coerce_bit, track_dirty=True)
                elif reg_name == "discretes":
                    self._write_span(self.discretes, pin.discretes, payload, reg_name, coerce_bit, track_dirty=True)
                elif reg_name == "input_regs":
                    self._write_span(
                        self.input_regs,
                        pin.input_regs,
                        payload,
                        reg_name,
                        coerce_reg,
                        track_dirty=True,
                    )
                elif reg_name == "holding_regs":
                    self._write_span(
                        self.holding_regs,
                        pin.holding_regs,
                        payload,
                        reg_name,
                        coerce_reg,
                        track_dirty=True,
                    )
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

    def update_tables(self, tables: Dict[str, List[int]], *, track_dirty: bool = True) -> None:
        """Replace register tables from a Modbus backend snapshot."""
        with self._lock:
            self._apply_table(self.coils, tables.get("coils"), coerce_bit, "coils", track_dirty=track_dirty)
            self._apply_table(self.discretes, tables.get("discretes"), coerce_bit, "discretes", track_dirty=track_dirty)
            self._apply_table(
                self.input_regs,
                tables.get("input_regs"),
                coerce_reg,
                "input_regs",
                track_dirty=track_dirty,
            )
            self._apply_table(
                self.holding_regs,
                tables.get("holding_regs"),
                coerce_reg,
                "holding_regs",
                track_dirty=track_dirty,
            )

    def apply_index_updates(self, updates: Dict[str, List[tuple[int, int]]], *, track_dirty: bool = True) -> None:
        """Apply sparse index updates (used for Modbus-originated changes)."""
        with self._lock:
            self._apply_index_updates(
                self.coils,
                updates.get("coils"),
                coerce_bit,
                "coils",
                track_dirty=track_dirty,
            )
            self._apply_index_updates(
                self.discretes,
                updates.get("discretes"),
                coerce_bit,
                "discretes",
                track_dirty=track_dirty,
            )
            self._apply_index_updates(
                self.input_regs,
                updates.get("input_regs"),
                coerce_reg,
                "input_regs",
                track_dirty=track_dirty,
            )
            self._apply_index_updates(
                self.holding_regs,
                updates.get("holding_regs"),
                coerce_reg,
                "holding_regs",
                track_dirty=track_dirty,
            )

    def read_registers(self, reg_name: str, span: RegSpan) -> List[int]:
        """Read a span from a register table by name."""
        with self._lock:
            buffer = self._select_buffer(reg_name)
            return self._read_span(buffer, span)

    def read_register_index(self, reg_name: str, idx: int) -> int:
        """Read a single register value by table name and absolute index."""
        with self._lock:
            buffer = self._select_buffer(reg_name)
            index = int(idx)
            if index < 0 or index >= len(buffer):
                raise ValueError(f"Index {index} out of range for {reg_name} table")
            return int(buffer[index])

    def write_registers(self, reg_name: str, span: RegSpan, payload: Any) -> None:
        """Write a span to a register table by name."""
        with self._lock:
            buffer, coercer = self._select_buffer(reg_name, with_coercer=True)
            self._write_span(buffer, span, payload, reg_name, coercer, track_dirty=True)

    def write_register_index(self, reg_name: str, idx: int, value: Any) -> None:
        """Write a single register value by table name and absolute index."""
        with self._lock:
            buffer, coercer = self._select_buffer(reg_name, with_coercer=True)
            index = int(idx)
            if index < 0 or index >= len(buffer):
                raise ValueError(f"Index {index} out of range for {reg_name} table")
            coerced = coercer(value)
            if buffer[index] == coerced:
                return
            buffer[index] = coerced
            self._record_update_unlocked(reg_name, index, coerced)

    def consume_dirty_updates(self, names: List[str] | tuple[str, ...] | None = None) -> Dict[str, List[tuple[int, int]]]:
        """Return and clear pending sparse updates since the last consume."""
        with self._lock:
            selected = names if names is not None else tuple(self._dirty_updates.keys())
            consumed: Dict[str, List[tuple[int, int]]] = {}
            for name in selected:
                pending = self._dirty_updates.get(name)
                if not pending:
                    continue
                consumed[name] = sorted(pending.items())
                pending.clear()
            return consumed

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
        pin = pinmap.pins_by_name.get("board_hash")
        if pin is None:
            for candidate in pinmap.pins:
                if candidate.type == "PIN_HASH":
                    pin = candidate
                    break
        if pin is None:
            return
        if pin.input_regs.count != 2:
            LOGGER.warning(
                "PIN_HASH pin '%s' must use exactly 2 input regs (got %s); skipping hash seed",
                pin.name or "<unnamed>",
                pin.input_regs.count,
            )
            return
        value = int(pinmap.hash) & 0xFFFFFFFF
        lo = value & 0xFFFF
        hi = (value >> 16) & 0xFFFF
        with self._lock:
            idx0 = pin.input_regs.start
            idx1 = idx0 + 1
            if self.input_regs[idx0] != lo:
                self.input_regs[idx0] = lo
                self._record_update_unlocked("input_regs", idx0, lo)
            if self.input_regs[idx1] != hi:
                self.input_regs[idx1] = hi
                self._record_update_unlocked("input_regs", idx1, hi)

    @staticmethod
    def _read_span(buffer: List[int], span: RegSpan) -> List[int]:
        """Read a span from a register buffer."""
        if span.count == 0:
            return []
        return list(buffer[span.start : span.start + span.count])

    def _write_span(
        self,
        buffer: List[int],
        span: RegSpan,
        payload: Any,
        reg_name: str,
        coercer,
        *,
        track_dirty: bool,
    ) -> None:
        """Write a span to a register buffer, validating size and type."""
        if span.count == 0:
            raise ValueError(f"Pin has no {reg_name} span")
        values = normalize_values(payload, span.count)
        coerced = [coercer(v) for v in values]
        for offset, value in enumerate(coerced):
            idx = span.start + offset
            if buffer[idx] == value:
                continue
            buffer[idx] = value
            if track_dirty:
                self._record_update_unlocked(reg_name, idx, value)

    def _select_buffer(self, reg_name: str, with_coercer: bool = False):
        """Return the backing buffer (and coercer optionally) for a register table name."""
        if reg_name == "coils":
            return (self.coils, coerce_bit) if with_coercer else self.coils
        if reg_name == "discretes":
            return (self.discretes, coerce_bit) if with_coercer else self.discretes
        if reg_name == "input_regs":
            return (self.input_regs, coerce_reg) if with_coercer else self.input_regs
        if reg_name == "holding_regs":
            return (self.holding_regs, coerce_reg) if with_coercer else self.holding_regs
        raise ValueError(f"Unknown register type '{reg_name}'")

    def _apply_table(
        self,
        buffer: List[int],
        values: List[Any] | None,
        coercer,
        name: str,
        *,
        track_dirty: bool,
    ) -> None:
        """Replace a full register table with validated values."""
        if values is None:
            return
        if len(values) != len(buffer):
            raise ValueError(f"Expected {len(buffer)} {name} entries, got {len(values)}")
        coerced = [coercer(v) for v in values]
        for idx, value in enumerate(coerced):
            if buffer[idx] == value:
                continue
            buffer[idx] = value
            if track_dirty:
                self._record_update_unlocked(name, idx, value)

    def _apply_index_updates(
        self,
        buffer: List[int],
        updates: List[tuple[int, int]] | None,
        coercer,
        name: str,
        *,
        track_dirty: bool,
    ) -> None:
        """Apply sparse updates to a register buffer."""
        if not updates:
            return
        max_index = len(buffer) - 1
        for idx, value in updates:
            if idx < 0 or idx > max_index:
                raise ValueError(f"Index {idx} out of range for {name} table")
            coerced = coercer(value)
            if buffer[idx] == coerced:
                continue
            buffer[idx] = coerced
            if track_dirty:
                self._record_update_unlocked(name, idx, coerced)

    def _record_update_unlocked(self, table: str, idx: int, value: int) -> None:
        pending = self._dirty_updates.get(table)
        if pending is None:
            return
        pending[idx] = int(value)


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


def crc16_modbus_words(lo: int, hi: int) -> int:
    """Compute CRC16 (Modbus) over two 16-bit words (lo, hi)."""
    crc = 0xFFFF
    for byte in (lo & 0xFF, (lo >> 8) & 0xFF, hi & 0xFF, (hi >> 8) & 0xFF):
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if (crc & 1) else (crc >> 1)
    return crc & 0xFFFF
