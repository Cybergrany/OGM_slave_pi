"""Modbus RTU backend for OGM_slave_pi.

Uses pylibmodbus (libmodbus binding) to serve RTU registers. The backend keeps
RegisterStore as the canonical state and syncs tables around each request.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional

from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)

FALLBACK_BLOCK_TYPES = {
    "coils": 1,
    "discretes": 2,
    "holding_regs": 3,
    "input_regs": 4,
}


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

    def write_tables(self, tables: Dict[str, list[int]]) -> None:
        for name, count in self._block_sizes.items():
            if count <= 0:
                continue
            values = tables.get(name)
            if values is None:
                continue
            self._set_values(name, values)

    def read_tables(self) -> Dict[str, list[int]]:
        tables: Dict[str, list[int]] = {}
        for name, count in self._block_sizes.items():
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
    """pylibmodbus RTU backend with a simple sync loop."""

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
                tables = self._store.snapshot_tables()
                self._adapter.write_tables(tables)
                self._adapter.handle_once()
                updates = self._adapter.read_tables()
                self._store.update_tables(updates)
            except Exception as exc:
                LOGGER.exception("Modbus backend error: %s", exc)
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
) -> ModbusBackend:
    """Factory for the Modbus backend (null backend when disabled)."""
    if disabled:
        return NullBackend()
    return LibModbusBackend(store, pinmap, serial, baud, slave_address, parity, data_bits, stop_bits)
