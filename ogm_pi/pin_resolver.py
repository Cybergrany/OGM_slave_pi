"""Fast pin-name to handle resolver for IPC/runtime clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .pinmap import PinMap, PinRecord


@dataclass(frozen=True)
class HandleInfo:
    """Resolved pin handle metadata exposed over IPC."""

    handle: int
    name: str
    type: str
    pin: Any
    args: List[Any]
    coils: List[int]
    discretes: List[int]
    input_regs: List[int]
    holding_regs: List[int]
    gpio_line: Optional[int]


class PinResolver:
    """Resolve pin names once and use integer handles in hot paths."""

    def __init__(self, pinmap: PinMap) -> None:
        self._pinmap = pinmap
        self._pins_by_handle: List[Optional[PinRecord]] = [None]
        self._handle_by_name: Dict[str, int] = {}

        for idx, pin in enumerate(pinmap.pins, start=1):
            if pin.name in self._handle_by_name:
                raise ValueError(f"Duplicate pin name {pin.name} in resolver")
            self._pins_by_handle.append(pin)
            self._handle_by_name[pin.name] = idx

    def handle_for_name(self, name: str) -> int:
        handle = self._handle_by_name.get(str(name))
        if handle is None:
            raise KeyError(f"Unknown pin name {name}")
        return handle

    def pin_for_handle(self, handle: int) -> PinRecord:
        idx = int(handle)
        if idx <= 0 or idx >= len(self._pins_by_handle):
            raise KeyError(f"Unknown pin handle {handle}")
        pin = self._pins_by_handle[idx]
        if pin is None:
            raise KeyError(f"Unknown pin handle {handle}")
        return pin

    def gpio_line_for_handle(self, handle: int) -> Optional[int]:
        return resolve_gpio_line(self.pin_for_handle(handle).pin)

    def resolve_names(self, names: List[Any]) -> List[HandleInfo]:
        resolved: List[HandleInfo] = []
        for raw in names:
            name = str(raw)
            handle = self.handle_for_name(name)
            resolved.append(self.describe_handle(handle))
        return resolved

    def describe_handle(self, handle: int) -> HandleInfo:
        pin = self.pin_for_handle(handle)
        return HandleInfo(
            handle=int(handle),
            name=pin.name,
            type=pin.type,
            pin=pin.pin,
            args=list(pin.args),
            coils=[pin.coils.start, pin.coils.count],
            discretes=[pin.discretes.start, pin.discretes.count],
            input_regs=[pin.input_regs.start, pin.input_regs.count],
            holding_regs=[pin.holding_regs.start, pin.holding_regs.count],
            gpio_line=resolve_gpio_line(pin.pin),
        )


def resolve_gpio_line(pin: Any) -> Optional[int]:
    """Resolve a pin token into a BCM GPIO line if possible."""
    if isinstance(pin, int):
        return pin
    if isinstance(pin, str):
        stripped = pin.strip()
        upper = stripped.upper()
        if upper.startswith("GPIO") and upper[4:].isdigit():
            return int(upper[4:])
        if stripped.isdigit():
            return int(stripped)
    return None
