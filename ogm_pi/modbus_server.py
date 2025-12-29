"""Modbus RTU backend shim for OGM_slave_pi.

This file defines a small interface so the IPC and register store can be
implemented independently of the chosen libmodbus Python binding.
"""

from __future__ import annotations

import logging
from typing import Optional

from .pinmap import PinMap
from .store import RegisterStore

LOGGER = logging.getLogger(__name__)


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


class LibModbusBackend(ModbusBackend):
    """Placeholder libmodbus backend.

    Wire this up to your preferred libmodbus binding (e.g. pylibmodbus)
    by mapping RegisterStore buffers into the Modbus tables.
    """

    def __init__(self, store: RegisterStore, pinmap: PinMap, serial: str, baud: int, slave_address: int) -> None:
        self._store = store
        self._pinmap = pinmap
        self._serial = serial
        self._baud = baud
        self._slave_address = slave_address
        self._server = None

    def start(self) -> None:
        raise RuntimeError(
            "LibModbusBackend is a placeholder. Install a libmodbus binding and "
            "implement start()/stop() to serve RTU registers."
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
            except Exception:
                pass


def create_backend(
    store: RegisterStore,
    pinmap: PinMap,
    serial: str,
    baud: int,
    slave_address: int,
    disabled: bool = False,
) -> ModbusBackend:
    """Factory for the Modbus backend (null backend when disabled)."""
    if disabled:
        return NullBackend()
    return LibModbusBackend(store, pinmap, serial, baud, slave_address)
