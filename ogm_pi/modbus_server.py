"""Modbus RTU backend for OGM_slave_pi.

Uses a thin ctypes binding over libmodbus for RTU slave handling. The backend
keeps Modbus receive/reply on a tight blocking loop and synchronizes register
changes using sparse index updates to avoid full-table churn.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from .pinmap import PinMap, PinRecord
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)

WATCH_TYPES = ("coils", "holding_regs")
_RTU_MAX_ADU_LENGTH = 260

# libmodbus custom errno values (modbus.h)
_EMBBADCRC = 112345689
_EMBBADDATA = 112345690
_EMBBADEXC = 112345691
_EMBUNKEXC = 112345692
_EMBMDATA = 112345693
_EMBBADSLAVE = 112345694


def _errno_values(*names: str) -> Set[int]:
    values: Set[int] = set()
    for name in names:
        code = getattr(errno, name, None)
        if isinstance(code, int):
            values.add(code)
    return values


_RECOVERABLE_POSIX_ERRNOS = _errno_values("EAGAIN", "EINTR", "ETIMEDOUT")
_REPLY_RECOVERABLE_POSIX_ERRNOS = _RECOVERABLE_POSIX_ERRNOS | _errno_values("EMSGSIZE")
_RECEIVE_RECOVERABLE_LIBMODBUS_ERRNOS = {
    _EMBBADCRC,
    _EMBBADDATA,
    _EMBBADEXC,
    _EMBUNKEXC,
    _EMBBADSLAVE,
}
_REPLY_RECOVERABLE_LIBMODBUS_ERRNOS = {
    _EMBBADDATA,
    _EMBBADEXC,
    _EMBUNKEXC,
    _EMBMDATA,
}
_STOP_INTERRUPT_ERRNOS = _errno_values("EBADF", "ENOTCONN", "EINVAL", "EIO", "EPIPE")


class _ModbusMapping(ctypes.Structure):
    _fields_ = [
        ("nb_bits", ctypes.c_int),
        ("start_bits", ctypes.c_int),
        ("nb_input_bits", ctypes.c_int),
        ("start_input_bits", ctypes.c_int),
        ("nb_input_registers", ctypes.c_int),
        ("start_input_registers", ctypes.c_int),
        ("nb_registers", ctypes.c_int),
        ("start_registers", ctypes.c_int),
        ("tab_bits", ctypes.POINTER(ctypes.c_uint8)),
        ("tab_input_bits", ctypes.POINTER(ctypes.c_uint8)),
        ("tab_input_registers", ctypes.POINTER(ctypes.c_uint16)),
        ("tab_registers", ctypes.POINTER(ctypes.c_uint16)),
    ]


class ModbusBackendError(RuntimeError):
    """Raised for libmodbus backend failures with severity metadata."""

    def __init__(self, message: str, *, fatal: bool, operation: str, errno_code: int | None) -> None:
        super().__init__(message)
        self.fatal = fatal
        self.operation = operation
        self.errno_code = errno_code


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
        return ChangeSet(updates=updates, events=self._build_events(changed, after))

    def events_from_updates(self, updates: Dict[str, List[tuple[int, int]]], tables: Dict[str, List[int]]) -> List[Dict[str, Any]]:
        """Build change events from sparse updates and current table snapshots."""
        changed: Dict[str, Set[str]] = {}

        for idx, _value in updates.get("coils", []):
            pin = self._coil_index[idx] if 0 <= idx < len(self._coil_index) else None
            if pin is not None:
                changed.setdefault(pin.name, set()).add("coils")

        for idx, _value in updates.get("holding_regs", []):
            pin = self._holding_index[idx] if 0 <= idx < len(self._holding_index) else None
            if pin is not None:
                changed.setdefault(pin.name, set()).add("holding_regs")

        return self._build_events(changed, tables)

    def _build_events(self, changed: Dict[str, Set[str]], tables: Dict[str, List[int]]) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for name, types in changed.items():
            pin = self._pins_by_name.get(name)
            if pin is None:
                continue
            values: Dict[str, List[int]] = {}
            if "coils" in types:
                values["coils"] = self._slice_values(tables.get("coils", []), pin.coils.start, pin.coils.count)
            if "holding_regs" in types:
                values["holding_regs"] = self._slice_values(
                    tables.get("holding_regs", []),
                    pin.holding_regs.start,
                    pin.holding_regs.count,
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
        return events

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


class LibModbusAdapter:
    """Thin ctypes wrapper around libmodbus RTU slave APIs."""

    _TABLE_FIELD = {
        "coils": "tab_bits",
        "discretes": "tab_input_bits",
        "input_regs": "tab_input_registers",
        "holding_regs": "tab_registers",
    }

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
        self._serial = serial
        self._sizes = {
            "coils": int(totals.get("coils", 0)),
            "discretes": int(totals.get("discretes", 0)),
            "input_regs": int(totals.get("input_regs", 0)),
            "holding_regs": int(totals.get("holding_regs", 0)),
        }
        self._lib = self._load_library()
        self._configure_symbols()
        self._ctx: Optional[ctypes.c_void_p] = None
        self._mapping: Optional[ctypes.POINTER(_ModbusMapping)] = None
        self._request = (ctypes.c_uint8 * _RTU_MAX_ADU_LENGTH)()

        try:
            self._ctx = self._create_context(serial, baud, parity, data_bits, stop_bits, slave_address)
            self._mapping = self._create_mapping()
            self._validate_mapping()
        except Exception:
            self.close()
            raise

    @staticmethod
    def _load_library() -> ctypes.CDLL:
        candidates: List[str] = []
        found = ctypes.util.find_library("modbus")
        if found:
            candidates.append(found)
        candidates.extend(["libmodbus.so.5", "libmodbus.so"])

        errors: List[str] = []
        for candidate in candidates:
            try:
                return ctypes.CDLL(candidate, use_errno=True)
            except OSError as exc:
                errors.append(f"{candidate}: {exc}")

        detail = "; ".join(errors) if errors else "no load candidates"
        raise RuntimeError(f"Unable to load libmodbus shared library ({detail})")

    def _configure_symbols(self) -> None:
        self._lib.modbus_new_rtu.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char, ctypes.c_int, ctypes.c_int]
        self._lib.modbus_new_rtu.restype = ctypes.c_void_p

        self._lib.modbus_set_slave.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._lib.modbus_set_slave.restype = ctypes.c_int

        self._lib.modbus_connect.argtypes = [ctypes.c_void_p]
        self._lib.modbus_connect.restype = ctypes.c_int

        self._lib.modbus_receive.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8)]
        self._lib.modbus_receive.restype = ctypes.c_int

        self._lib.modbus_reply.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_int,
            ctypes.POINTER(_ModbusMapping),
        ]
        self._lib.modbus_reply.restype = ctypes.c_int

        self._lib.modbus_mapping_new.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        self._lib.modbus_mapping_new.restype = ctypes.POINTER(_ModbusMapping)

        self._lib.modbus_mapping_free.argtypes = [ctypes.POINTER(_ModbusMapping)]
        self._lib.modbus_mapping_free.restype = None

        self._lib.modbus_close.argtypes = [ctypes.c_void_p]
        self._lib.modbus_close.restype = None

        self._lib.modbus_free.argtypes = [ctypes.c_void_p]
        self._lib.modbus_free.restype = None

        self._lib.modbus_strerror.argtypes = [ctypes.c_int]
        self._lib.modbus_strerror.restype = ctypes.c_char_p

    def _create_context(
        self,
        serial: str,
        baud: int,
        parity: str,
        data_bits: int,
        stop_bits: int,
        slave_address: int,
    ) -> ctypes.c_void_p:
        serial_bytes = serial.encode("utf-8")
        parity_byte = (parity or "N").strip().upper().encode("ascii", "ignore")[:1] or b"N"

        ctx = self._lib.modbus_new_rtu(serial_bytes, int(baud), parity_byte, int(data_bits), int(stop_bits))
        if not ctx:
            self._raise_modbus_error("new_rtu")

        if self._lib.modbus_set_slave(ctx, int(slave_address)) == -1:
            self._raise_modbus_error("set_slave")

        if self._lib.modbus_connect(ctx) == -1:
            self._raise_modbus_error("connect")

        return ctypes.c_void_p(ctx)

    def _create_mapping(self) -> ctypes.POINTER(_ModbusMapping):
        mapping = self._lib.modbus_mapping_new(
            self._sizes["coils"],
            self._sizes["discretes"],
            self._sizes["holding_regs"],
            self._sizes["input_regs"],
        )
        if not mapping:
            self._raise_modbus_error("mapping_new")
        return mapping

    def _validate_mapping(self) -> None:
        if self._mapping is None:
            raise RuntimeError("libmodbus mapping is not initialized")

        mapping = self._mapping.contents
        expected = {
            "coils": self._sizes["coils"],
            "discretes": self._sizes["discretes"],
            "input_regs": self._sizes["input_regs"],
            "holding_regs": self._sizes["holding_regs"],
        }

        if (
            mapping.start_bits != 0
            or mapping.start_input_bits != 0
            or mapping.start_input_registers != 0
            or mapping.start_registers != 0
            or mapping.nb_bits != expected["coils"]
            or mapping.nb_input_bits != expected["discretes"]
            or mapping.nb_input_registers != expected["input_regs"]
            or mapping.nb_registers != expected["holding_regs"]
        ):
            raise RuntimeError(
                "libmodbus mapping layout mismatch; expected starts=0 and counts "
                f"{expected}, got coils={mapping.nb_bits}, discretes={mapping.nb_input_bits}, "
                f"input_regs={mapping.nb_input_registers}, holding_regs={mapping.nb_registers}"
            )

        for table_name in self._sizes:
            pointer = self._table_pointer(table_name)
            if self._sizes[table_name] > 0 and not bool(pointer):
                raise RuntimeError(f"libmodbus mapping pointer missing for {table_name}")

    def _table_pointer(self, name: str):
        if self._mapping is None:
            raise RuntimeError("libmodbus mapping is not initialized")
        field = self._TABLE_FIELD[name]
        return getattr(self._mapping.contents, field)

    def _normalize_value(self, table: str, value: int) -> int:
        if table in {"coils", "discretes"}:
            return 1 if int(value) else 0
        return int(value) & 0xFFFF

    def _is_recoverable_errno(self, code: int, operation: str) -> bool:
        if operation == "receive":
            return code in _RECOVERABLE_POSIX_ERRNOS or code in _RECEIVE_RECOVERABLE_LIBMODBUS_ERRNOS
        if operation == "reply":
            return code in _REPLY_RECOVERABLE_POSIX_ERRNOS or code in _REPLY_RECOVERABLE_LIBMODBUS_ERRNOS
        return False

    def _error_message(self, code: int) -> str:
        try:
            msg = self._lib.modbus_strerror(code)
        except Exception:
            msg = None
        if not msg:
            return f"errno {code}"
        if isinstance(msg, bytes):
            return msg.decode("utf-8", errors="replace")
        return str(msg)

    def _raise_modbus_error(self, operation: str) -> None:
        code = int(ctypes.get_errno())
        fatal = not self._is_recoverable_errno(code, operation)
        message = f"libmodbus {operation} failed (errno={code}: {self._error_message(code)})"
        raise ModbusBackendError(message, fatal=fatal, operation=operation, errno_code=code)

    def apply_full_tables(self, tables: Dict[str, List[int]]) -> None:
        """Copy full register tables into libmodbus mapping memory."""
        for name, size in self._sizes.items():
            if size <= 0:
                continue
            values = tables.get(name)
            if values is None:
                raise RuntimeError(f"Missing table '{name}' while initializing libmodbus mapping")
            if len(values) != size:
                raise RuntimeError(f"Expected {size} values for {name}, got {len(values)}")

            pointer = self._table_pointer(name)
            for idx in range(size):
                pointer[idx] = self._normalize_value(name, values[idx])

    def apply_sparse_updates(self, updates: Dict[str, List[tuple[int, int]]]) -> None:
        """Apply sparse index/value updates to libmodbus mapping memory."""
        for name, pairs in updates.items():
            size = self._sizes.get(name, 0)
            if size <= 0 or not pairs:
                continue
            pointer = self._table_pointer(name)
            for idx, value in pairs:
                if idx < 0 or idx >= size:
                    raise RuntimeError(f"Store update index {idx} out of range for {name} ({size})")
                pointer[idx] = self._normalize_value(name, value)

    def collect_span_updates(self, table: str, spans: Iterable[tuple[int, int]], shadow: List[int]) -> List[tuple[int, int]]:
        """Read mapping values for touched spans and return sparse updates vs shadow."""
        size = self._sizes.get(table, 0)
        if size <= 0:
            return []
        if len(shadow) != size:
            raise RuntimeError(f"Shadow table size mismatch for {table}: expected {size}, got {len(shadow)}")

        pointer = self._table_pointer(table)
        changed: Dict[int, int] = {}

        for start, count in spans:
            if count <= 0:
                continue
            lo = max(0, int(start))
            hi = min(size, int(start) + int(count))
            if hi <= lo:
                continue
            for idx in range(lo, hi):
                value = self._normalize_value(table, int(pointer[idx]))
                if shadow[idx] == value:
                    continue
                shadow[idx] = value
                changed[idx] = value

        return sorted(changed.items())

    def receive_request(self) -> tuple[int, bytes]:
        """Block waiting for a Modbus RTU request and return (length, bytes)."""
        if self._ctx is None:
            raise RuntimeError("libmodbus context is not initialized")
        rc = self._lib.modbus_receive(self._ctx, self._request)
        if rc == -1:
            self._raise_modbus_error("receive")
        if rc <= 0:
            return 0, b""
        return int(rc), bytes(self._request[:rc])

    def reply(self, request_len: int) -> None:
        """Reply to the last request using current libmodbus mapping values."""
        if self._ctx is None or self._mapping is None:
            raise RuntimeError("libmodbus adapter is not initialized")
        rc = self._lib.modbus_reply(self._ctx, self._request, int(request_len), self._mapping)
        if rc == -1:
            self._raise_modbus_error("reply")

    def interrupt(self) -> None:
        """Interrupt a blocking receive by closing the RTU context descriptor."""
        if self._ctx is None:
            return
        try:
            self._lib.modbus_close(self._ctx)
        except Exception:
            pass

    def close(self) -> None:
        """Release libmodbus resources."""
        if self._mapping is not None:
            try:
                self._lib.modbus_mapping_free(self._mapping)
            except Exception:
                pass
            self._mapping = None

        if self._ctx is not None:
            try:
                self._lib.modbus_close(self._ctx)
            except Exception:
                pass
            try:
                self._lib.modbus_free(self._ctx)
            except Exception:
                pass
            self._ctx = None


def _u16_be(payload: bytes, offset: int) -> int:
    if offset + 1 >= len(payload):
        return 0
    return (int(payload[offset]) << 8) | int(payload[offset + 1])


def _extract_write_spans(request: bytes) -> Dict[str, List[tuple[int, int]]]:
    """Parse writable spans touched by a Modbus request ADU."""
    if len(request) < 2:
        return {}

    fc = int(request[1])

    # Write single coil
    if fc == 0x05 and len(request) >= 6:
        return {"coils": [(_u16_be(request, 2), 1)]}

    # Write single holding register
    if fc == 0x06 and len(request) >= 6:
        return {"holding_regs": [(_u16_be(request, 2), 1)]}

    # Write multiple coils
    if fc == 0x0F and len(request) >= 6:
        quantity = _u16_be(request, 4)
        if quantity > 0:
            return {"coils": [(_u16_be(request, 2), quantity)]}
        return {}

    # Write multiple holding registers
    if fc == 0x10 and len(request) >= 6:
        quantity = _u16_be(request, 4)
        if quantity > 0:
            return {"holding_regs": [(_u16_be(request, 2), quantity)]}
        return {}

    # Mask write register
    if fc == 0x16 and len(request) >= 6:
        return {"holding_regs": [(_u16_be(request, 2), 1)]}

    # Read/write multiple registers (write span starts at bytes 6/8)
    if fc == 0x17 and len(request) >= 10:
        quantity = _u16_be(request, 8)
        if quantity > 0:
            return {"holding_regs": [(_u16_be(request, 6), quantity)]}

    return {}


class LibModbusBackend(ModbusBackend):
    """Direct libmodbus RTU backend with sparse register synchronization."""

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
        self._adapter: Optional[LibModbusAdapter] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._tracker = ChangeTracker(pinmap)
        self._event_sink = event_sink
        self._error_handler = error_handler
        self._shadow: Dict[str, List[int]] = {"coils": [], "holding_regs": []}
        self._recoverable_error_count = 0

    def start(self) -> None:
        totals = {
            "coils": len(self._store.coils),
            "discretes": len(self._store.discretes),
            "input_regs": len(self._store.input_regs),
            "holding_regs": len(self._store.holding_regs),
        }

        self._adapter = LibModbusAdapter(
            self._serial,
            self._baud,
            self._parity,
            self._data_bits,
            self._stop_bits,
            self._slave_address,
            totals,
        )

        initial = self._store.snapshot_tables()
        self._adapter.apply_full_tables(initial)
        self._shadow["coils"] = list(initial.get("coils", []))
        self._shadow["holding_regs"] = list(initial.get("holding_regs", []))

        # Flush any startup writes from the store; initial mapping now reflects state.
        self._store.consume_dirty_updates()

        self._thread = threading.Thread(target=self._serve_loop, name="ogm_modbus", daemon=True)
        self._thread.start()
        LOGGER.info("Modbus RTU backend started on %s (addr=%s)", self._serial, self._slave_address)

    def stop(self) -> None:
        self._stop_event.set()
        if self._adapter is not None:
            self._adapter.interrupt()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._adapter is not None:
            self._adapter.close()

    def _sync_store_to_mapping(self) -> None:
        if self._adapter is None:
            return

        pending = self._store.consume_dirty_updates()
        if not pending:
            return

        self._adapter.apply_sparse_updates(pending)
        for name in WATCH_TYPES:
            shadow = self._shadow.get(name)
            if shadow is None:
                continue
            for idx, value in pending.get(name, []):
                if 0 <= idx < len(shadow):
                    shadow[idx] = int(value)

    def _apply_master_write_updates(self, request: bytes) -> None:
        if self._adapter is None:
            return

        touched = _extract_write_spans(request)
        if not touched:
            return

        updates: Dict[str, List[tuple[int, int]]] = {}
        for name in WATCH_TYPES:
            spans = touched.get(name)
            if not spans:
                continue
            table_updates = self._adapter.collect_span_updates(name, spans, self._shadow[name])
            if table_updates:
                updates[name] = table_updates

        if not updates:
            return

        self._store.apply_index_updates(updates, track_dirty=False)
        if self._event_sink is not None:
            events = self._tracker.events_from_updates(updates, self._shadow)
            if events:
                self._event_sink(events)

    def _handle_fatal_error(self, exc: Exception) -> None:
        LOGGER.exception("Fatal Modbus backend error: %s", exc)
        if self._error_handler is not None:
            try:
                self._error_handler(exc)
            except Exception:
                LOGGER.exception("Modbus error handler failed")

    def _log_recoverable_error(self, exc: ModbusBackendError) -> None:
        self._recoverable_error_count += 1
        count = self._recoverable_error_count
        if count == 1 or count == 10 or (count % 100) == 0:
            LOGGER.warning(
                "Recoverable Modbus %s error (%s total): %s",
                exc.operation,
                count,
                exc,
            )
        else:
            LOGGER.debug("Recoverable Modbus %s error: %s", exc.operation, exc)

    def _serve_loop(self) -> None:
        if self._adapter is None:
            return

        while not self._stop_event.is_set():
            try:
                req_len, request = self._adapter.receive_request()
                if req_len <= 0:
                    continue

                # Bring libmodbus mapping up to date right before replying.
                self._sync_store_to_mapping()

                self._adapter.reply(req_len)
                self._apply_master_write_updates(request)

            except ModbusBackendError as exc:
                if self._stop_event.is_set() and (exc.errno_code in _STOP_INTERRUPT_ERRNOS):
                    break
                if not exc.fatal:
                    self._log_recoverable_error(exc)
                    continue
                self._handle_fatal_error(exc)
                break

            except Exception as exc:
                self._handle_fatal_error(exc)
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
