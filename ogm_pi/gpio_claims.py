"""GPIO ownership tracking to prevent line collisions between runtime and apps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set
import threading


class GpioClaimError(RuntimeError):
    """Raised when a GPIO claim violates ownership rules."""


@dataclass(frozen=True)
class GpioClaim:
    line: int
    owner: str


class GpioClaimRegistry:
    """Track GPIO line ownership with hard-fail collision semantics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner_by_line: Dict[int, str] = {}
        self._lines_by_owner: Dict[str, Set[int]] = {}

    def claim_line(self, owner: str, line: int) -> None:
        if not owner:
            raise GpioClaimError("GPIO owner must be non-empty")
        idx = int(line)
        with self._lock:
            existing = self._owner_by_line.get(idx)
            if existing is not None and existing != owner:
                raise GpioClaimError(f"GPIO line {idx} already claimed by {existing}")
            self._owner_by_line[idx] = owner
            self._lines_by_owner.setdefault(owner, set()).add(idx)

    def release_owner(self, owner: str) -> None:
        with self._lock:
            lines = self._lines_by_owner.pop(owner, set())
            for line in lines:
                existing = self._owner_by_line.get(line)
                if existing == owner:
                    self._owner_by_line.pop(line, None)

    def owner_for_line(self, line: int) -> Optional[str]:
        with self._lock:
            return self._owner_by_line.get(int(line))

    def is_line_claimed_by_prefix(self, line: int, prefix: str) -> bool:
        owner = self.owner_for_line(line)
        return bool(owner and owner.startswith(prefix))

    def claims_for_owner(self, owner: str) -> Set[int]:
        with self._lock:
            return set(self._lines_by_owner.get(owner, set()))

    def snapshot(self) -> list[GpioClaim]:
        with self._lock:
            return [GpioClaim(line=line, owner=owner) for line, owner in sorted(self._owner_by_line.items())]
