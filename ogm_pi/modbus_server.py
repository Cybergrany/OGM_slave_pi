"""Modbus RTU backend for OGM_slave_pi.

Uses pylibmodbus (libmodbus binding) to serve RTU registers. The backend keeps
RegisterStore as the canonical state and emits change events for master-writable
registers (coils + holding_regs) when a Modbus write changes values.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from .pinmap import PinMap, PinRecord
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)

WATCH_TYPES = ("coils", "holding_regs")

FALLBACK_BLOCK_TYPES = {
    "coils": 1,
    "discretes": 2,
    "holding_regs": 3,
    "input_regs": 4,
}


@dataclass
class ChangeSet:
    """Sparse index updates plus the corresponding event payloads."""

    updates: Dict[str, List[tuple[int, int]]]
    events: List[Dict[str, Any]]


class ChangeTracker:
    """Detect master-originated changes and build event payloads."""

    def __init__(self, pinmap: PinMap) -> None:
        totals = pinmap.totals
        self._pins_by_name = pinmap.pins_by_name
        self._coil_index = self._build_index_map(pinmap.pins, totals.get("coils", 0), "coils")
        self._holding_index = self._build_index_map(pinmap.pins, totals.get("holding_regs", 0), "holding_regs")
        self._seq = 0

    def diff(self, before: Dict[str, List[int]], after: Dict[str, List[int]]) -> ChangeSet:
        """Compute sparse updates and change events between two table snapshots."""
        updates: Dict[str, List[tuple[int, int]]] = {"coils": [], "holding_regs": []}
        changed: Dict[str, Set[str]] = {}

        self._scan_table(
            "coils",
            before.get("coils", []),
            after.get("coils", []),
            self._coil_index,
            updates,
            changed,
        )
        self._scan_table(
            "holding_regs",
            before.get("holding_regs", []),
            after.get("holding_regs", []),
            self._holding_index,
            updates,
            changed,
        )

        events: List[Dict[str, Any]] = []
        for name, types in changed.items():
            pin = self._pins_by_name.get(name)
            if pin is None:
                continue
            values: Dict[str, List[int]] = {}
            if "coils" in types:
                values["coils"] = self._slice_values(after.get("coils", []), pin.coils.start, pin.coils.count)
            if "holding_regs" in types:
                values["holding_regs"] = self._slice_values(
                    after.get("holding_regs", []), pin.holding_regs.start, pin.holding_regs.count
                )
            if not values:
                continue
            self._seq += 1
            events.append(
                {
                    "event": "change",
                    "seq": self._seq,
                    "source": "modbus",
                    "name": name,
                    "types": sorted(types),
                    "values": values,
                }
            )

        return ChangeSet(updates=updates, events=events)

    @staticmethod
    def _build_index_map(pins: List[PinRecord], size: int, span_attr: str) -> List[Optional[PinRecord]]:
        """Build a lookup table from register index to PinRecord."""
        if size <= 0:
            return []
        index: List[Optional[PinRecord]] = [None] * size
        for pin in pins:
            span = getattr(pin, span_attr)
            if span.count <= 0:
                continue
            start = max(0, span.start)
            end = min(size, span.start + span.count)
            for idx in range(start, end):
                index[idx] = pin
        return index

    @staticmethod
    def _scan_table(
        name: str,
        before: List[int],
        after: List[int],
        index_map: List[Optional[PinRecord]],
        updates: Dict[str, List[tuple[int, int]]],
        changed: Dict[str, Set[str]],
    ) -> None:
        """Compare two tables and update the change tracking structures."""
        if not before or not after:
            return
        max_len = min(len(before), len(after), len(index_map) if index_map else len(after))
        if max_len <= 0:
            return
        for idx in range(max_len):
            old_val = before[idx]
            new_val = after[idx]
            if old_val == new_val:
                continue
            updates[name].append((idx, new_val))
            pin = index_map[idx] if idx < len(index_map) else None
            if pin is not None:
                changed.setdefault(pin.name, set()).add(name)

    @staticmethod
    def _slice_values(values: List[int], start: int, count: int) -> List[int]:
        """Return a slice from a Modbus table, handling empty spans."""
        if count <= 0:
            return []
        return list(values[start : start + count])


class ModbusBackend:
    """Abstract Modbus backend interface."""

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        pass


class NullBackend(ModbusBackend):
    """No-op backend for IPC-only operation."""

    def start(self) -> None:
        LOGGER.info("Modbus backend disabled; IPC-only mode")


class PylibmodbusAdapter:
    """Thin adapter over the pylibmodbus RTU server API."""

    def __init__(
        self,
        serial: str,
        baud: int,
        parity: str,
        data_bits: int,
        stop_bits: int,
        slave_address: int,
        totals: Dict[str, int],
    ) -> None:
        try:
            import pylibmodbus as modbus
        except ImportError as exc:
            raise RuntimeError("pylibmodbus is required; install it with pip") from exc

        self._mod = modbus
        self._server = self._create_server(serial, baud, parity, data_bits, stop_bits)
        self._slave = self._init_slave(slave_address)
        self._block_sizes = {
            "coils": int(totals.get("coils", 0)),
            "discretes": int(totals.get("discretes", 0)),
            "input_regs": int(totals.get("input_regs", 0)),
            "holding_regs": int(totals.get("holding_regs", 0)),
        }
        self._register_blocks()

    def _create_server(self, serial: str, baud: int, parity: str, data_bits: int, stop_bits: int):
        server_cls = None
        for name in ("ModbusRtuServer", "ModbusRTUServer", "ModbusServer"):
            if hasattr(self._mod, name):
                server_cls = getattr(self._mod, name)
                break
        if server_cls is None:
            raise RuntimeError("pylibmodbus RTU server class not found (expected ModbusRtuServer)")

        try:
            server = server_cls(serial, baud, parity, data_bits, stop_bits)
        except TypeError:
            server = server_cls(
                serial,
                baudrate=baud,
                parity=parity,
                data_bits=data_bits,
                stop_bits=stop_bits,
            )

        if hasattr(server, "start"):
            server.start()
        elif hasattr(server, "listen"):
            server.listen()
        return server

    def _init_slave(self, slave_address: int):
        slave = None
        if hasattr(self._server, "add_slave"):
            try:
                slave = self._server.add_slave(slave_address)
            except TypeError:
                self._server.add_slave(slave_address)
        if slave is None and hasattr(self._server, "get_slave"):
            slave = self._server.get_slave(slave_address)
        if slave is None and hasattr(self._server, "set_slave"):
            self._server.set_slave(slave_address)
            slave = self._server
        return slave if slave is not None else self._server

    def _register_blocks(self) -> None:
        for name, count in self._block_sizes.items():
            if count <= 0:
                continue
            block_type = self._resolve_block_type(name, FALLBACK_BLOCK_TYPES[name])
            target = self._slave if self._slave is not None else self._server
            if hasattr(target, "add_block"):
                target.add_block(name, block_type, 0, count)
            else:
                raise RuntimeError("pylibmodbus adapter requires add_block() support")

    def _resolve_block_type(self, name: str, fallback: int) -> int:
        aliases = {
            "coils": ["COILS", "COIL"],
            "discretes": ["DISCRETE_INPUTS", "DISCRETE_IN", "INPUT_BITS"],
            "input_regs": ["INPUT_REGISTERS", "INPUT_REGS", "INPUT_REGISTER"],
            "holding_regs": ["HOLDING_REGISTERS", "HOLDING_REGS", "HOLDING_REGISTER"],
        }
        for attr in aliases.get(name, []):
            if hasattr(self._mod, attr):
                return int(getattr(self._mod, attr))
        return fallback

    def handle_once(self) -> None:
        if hasattr(self._server, "handle_request"):
            self._server.handle_request()
        elif hasattr(self._server, "receive"):
            self._server.receive()
        elif hasattr(self._server, "serve_once"):
            self._server.serve_once()
        else:
            raise RuntimeError("pylibmodbus adapter requires handle_request()/receive() support")

    def write_tables(self, tables: Dict[str, list[int]], names: Iterable[str] | None = None) -> None:
        """Write the provided register tables into the Modbus server blocks."""
        target_names = list(names) if names is not None else list(self._block_sizes.keys())
        for name in target_names:
            count = self._block_sizes.get(name, 0)
            if count <= 0:
                continue
            values = tables.get(name)
            if values is None:
                continue
            self._set_values(name, values)

    def read_tables(self, names: Iterable[str] | None = None) -> Dict[str, list[int]]:
        """Read selected register tables from the Modbus server blocks."""
        target_names = list(names) if names is not None else list(self._block_sizes.keys())
        tables: Dict[str, list[int]] = {}
        for name in target_names:
            count = self._block_sizes.get(name, 0)
            if count <= 0:
                continue
            tables[name] = list(self._get_values(name, count))
        return tables

    def close(self) -> None:
        if hasattr(self._server, "close"):
            self._server.close()
        elif hasattr(self._server, "stop"):
            self._server.stop()

    def _set_values(self, name: str, values: list[int]) -> None:
        target = self._slave if self._slave is not None else self._server
        if hasattr(target, "set_values"):
            target.set_values(name, 0, values)
            return
        if name in {"coils", "discretes"} and hasattr(target, "set_bits"):
            target.set_bits(0, values)
            return
        if name in {"input_regs", "holding_regs"} and hasattr(target, "set_registers"):
            target.set_registers(0, values)
            return
        raise RuntimeError("pylibmodbus adapter requires set_values() support")

    def _get_values(self, name: str, count: int) -> list[int]:
        target = self._slave if self._slave is not None else self._server
        if hasattr(target, "get_values"):
            return list(target.get_values(name, 0, count))
        if name in {"coils", "discretes"} and hasattr(target, "get_bits"):
            return list(target.get_bits(0, count))
        if name in {"input_regs", "holding_regs"} and hasattr(target, "get_registers"):
            return list(target.get_registers(0, count))
        raise RuntimeError("pylibmodbus adapter requires get_values() support")


class LibModbusBackend(ModbusBackend):
    """pylibmodbus RTU backend with a change-detecting sync loop."""

    def __init__(
        self,
        store: RegisterStore,
        pinmap: PinMap,
        serial: str,
        baud: int,
        slave_address: int,
        parity: str = "N",
        data_bits: int = 8,
        stop_bits: int = 1,
        event_sink: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
        error_handler: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        self._store = store
        self._pinmap = pinmap
        self._serial = serial
        self._baud = baud
        self._slave_address = slave_address
        self._parity = parity
        self._data_bits = data_bits
        self._stop_bits = stop_bits
        self._adapter: Optional[PylibmodbusAdapter] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._tracker = ChangeTracker(pinmap)
        self._event_sink = event_sink
        self._error_handler = error_handler

    def start(self) -> None:
        totals = {
            "coils": len(self._store.coils),
            "discretes": len(self._store.discretes),
            "input_regs": len(self._store.input_regs),
            "holding_regs": len(self._store.holding_regs),
        }
        self._adapter = PylibmodbusAdapter(
            self._serial,
            self._baud,
            self._parity,
            self._data_bits,
            self._stop_bits,
            self._slave_address,
            totals,
        )
        self._thread = threading.Thread(target=self._serve_loop, name="ogm_modbus", daemon=True)
        self._thread.start()
        LOGGER.info("Modbus RTU backend started on %s (addr=%s)", self._serial, self._slave_address)

    def stop(self) -> None:
        self._stop_event.set()
        if self._adapter is not None:
            self._adapter.close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _serve_loop(self) -> None:
        if self._adapter is None:
            return
        while not self._stop_event.is_set():
            try:
                snapshot = self._store.snapshot_tables()
                self._adapter.write_tables(snapshot)
                self._adapter.handle_once()
                updated = self._adapter.read_tables(names=WATCH_TYPES)
                changes = self._tracker.diff(snapshot, updated)
                if changes.updates:
                    self._store.apply_index_updates(changes.updates)
                if changes.events and self._event_sink is not None:
                    self._event_sink(changes.events)
            except Exception as exc:
                LOGGER.exception("Modbus backend error: %s", exc)
                if self._error_handler is not None:
                    try:
                        self._error_handler(exc)
                    except Exception:
                        LOGGER.exception("Modbus error handler failed")
                break


def create_backend(
    store: RegisterStore,
    pinmap: PinMap,
    serial: str,
    baud: int,
    slave_address: int,
    parity: str = "N",
    data_bits: int = 8,
    stop_bits: int = 1,
    disabled: bool = False,
    event_sink: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    error_handler: Optional[Callable[[Exception], None]] = None,
) -> ModbusBackend:
    """Factory for the Modbus backend (null backend when disabled)."""
    if disabled:
        return NullBackend()
    return LibModbusBackend(
        store,
        pinmap,
        serial,
        baud,
        slave_address,
        parity,
        data_bits,
        stop_bits,
        event_sink=event_sink,
        error_handler=error_handler,
    )
