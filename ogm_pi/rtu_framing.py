"""Bounded, best-effort RTU framing for a byte stream without wire timestamps.

Shapes identify boundaries, not supported operations. Never search an unknown
or damaged payload for embedded ADUs. Recovery needs a host-observed idle event;
it cannot reconstruct historical T3.5 gaps lost by the serial interface.
"""

from enum import Enum, auto
from typing import Callable

MAX_ADU_LENGTH = 256
MAX_BUFFER = 16 * MAX_ADU_LENGTH


class Shape(Enum):
    NEED_MORE = auto()
    UNKNOWN = auto()
    INVALID = auto()


Length = int | Shape
LengthFn = Callable[[bytes], Length]


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def _bounded(length: int) -> Length:
    return length if 4 <= length <= MAX_ADU_LENGTH else Shape.INVALID


def _diagnostic_length(data: bytes) -> Length:
    if len(data) < 4:
        return Shape.NEED_MORE
    subfunction = int.from_bytes(data[2:4], "big")
    # Return Query Data (0) and reserved subfunctions have no fixed length.
    fixed = 1 <= subfunction <= 4 or 10 <= subfunction <= 18 or subfunction == 20
    return 8 if fixed else Shape.UNKNOWN


def standard_request_length(data: bytes) -> Length:
    if len(data) < 2:
        return Shape.NEED_MORE
    fc = data[1]
    if fc in (1, 2, 3, 4, 5, 6):
        return 8
    if fc in (7, 11, 12, 17):
        return 4
    if fc == 8:
        return _diagnostic_length(data)
    if fc in (15, 16):
        return _bounded(9 + data[6]) if len(data) >= 7 else Shape.NEED_MORE
    if fc in (20, 21):
        return _bounded(5 + data[2]) if len(data) >= 3 else Shape.NEED_MORE
    if fc == 22:
        return 10
    if fc == 23:
        return _bounded(13 + data[10]) if len(data) >= 11 else Shape.NEED_MORE
    if fc == 24:
        return 6
    if fc == 43:
        if len(data) < 3:
            return Shape.NEED_MORE
        return 7 if data[2] == 14 else Shape.UNKNOWN
    return Shape.UNKNOWN


def standard_response_length(data: bytes) -> Length:
    if len(data) < 2:
        return Shape.NEED_MORE
    fc = data[1]
    if fc & 0x80:
        return 5
    if fc in (1, 2, 3, 4, 12, 17, 20, 21, 23):
        return _bounded(5 + data[2]) if len(data) >= 3 else Shape.NEED_MORE
    if fc in (5, 6, 11, 15, 16):
        return 8
    if fc == 7:
        return 5
    if fc == 8:
        return _diagnostic_length(data)
    if fc == 22:
        return 10
    if fc == 24:
        return _bounded(6 + int.from_bytes(data[2:4], "big")) if len(data) >= 4 else Shape.NEED_MORE
    if fc == 43:
        if len(data) < 3:
            return Shape.NEED_MORE
        if data[2] != 14:
            return Shape.UNKNOWN
        if len(data) < 8:
            return Shape.NEED_MORE
        offset = 8
        for _ in range(data[7]):
            if offset + 4 > MAX_ADU_LENGTH:  # object header plus frame CRC
                return Shape.INVALID
            if len(data) < offset + 2:
                return Shape.NEED_MORE
            offset += 2 + data[offset + 1]
            if offset + 2 > MAX_ADU_LENGTH:
                return Shape.INVALID
        return offset + 2
    return Shape.UNKNOWN


def _length(data: bytes, standard: LengthFn, extensions: tuple[LengthFn, ...]) -> Length:
    result = standard(data)
    if result is Shape.UNKNOWN:
        for extension in extensions:
            result = extension(data)
            if result is not Shape.UNKNOWN:
                break
    return _bounded(result) if isinstance(result, int) else result


class RtuFramer:
    def __init__(self, address: int, *, custom_requests: tuple[LengthFn, ...] = (),
                 custom_responses: tuple[LengthFn, ...] = ()) -> None:
        self.address = address
        self.custom_requests = custom_requests
        self.custom_responses = custom_responses
        self.buffer = bytearray()
        self.discarding = False
        self.stats = dict.fromkeys((
            "rx_ok", "rx_foreign_frames", "rx_broadcasts", "rx_custom_ignored",
            "rx_crc_bad", "rx_len_reject", "rx_unknown", "rx_stale_local",
            "rx_partial_timeout_drops", "rx_overflows", "rx_resync_bytes",
        ), 0)

    def feed(self, chunk: bytes) -> None:
        if self.discarding:
            self.stats["rx_resync_bytes"] += len(chunk)
        elif len(self.buffer) + len(chunk) > MAX_BUFFER:
            self._discard("rx_overflows")
            self.stats["rx_resync_bytes"] += len(chunk)
        else:
            self.buffer.extend(chunk)

    def _discard(self, reason: str) -> None:
        self.stats[reason] += 1
        self.stats["rx_resync_bytes"] += len(self.buffer)
        self.buffer.clear()
        self.discarding = True

    def idle(self) -> None:
        """Called only after the serial reader observes its recovery idle period."""
        if self.buffer:
            self._discard("rx_partial_timeout_drops")
        self.discarding = False

    def pop(self) -> bytes | None:
        """Return a local/broadcast ADU, skipping foreign and stale local frames."""
        while self.buffer and not self.discarding:
            if self.buffer[0] > 247:
                self._discard("rx_len_reject")
                return None
            data = bytes(self.buffer[:MAX_ADU_LENGTH])
            foreign = data[0] not in (0, self.address)
            shapes = [_length(data, standard_request_length, self.custom_requests)]
            if foreign:
                shapes.append(_length(data, standard_response_length, self.custom_responses))
            lengths = sorted({s for s in shapes if isinstance(s, int)})
            # Try both foreign interpretations before deciding the head is bad.
            length = next((n for n in lengths if len(data) >= n and crc16(data[:n]) == 0), None)
            if length is None:
                waiting = Shape.NEED_MORE in shapes or any(n > len(data) for n in lengths)
                if waiting and len(data) < MAX_ADU_LENGTH:
                    return None
                reason = "rx_crc_bad" if lengths else (
                    "rx_len_reject" if Shape.INVALID in shapes or waiting else "rx_unknown")
                self._discard(reason)
                return None

            frame = data[:length]
            del self.buffer[:length]
            if foreign:
                self.stats["rx_foreign_frames"] += 1
                continue
            if frame[0] != 0 and self.buffer:
                # Later bus traffic means the master may have moved on. Do not
                # mutate registers or send an unmatchable late response.
                self.stats["rx_stale_local"] += 1
                continue
            return frame
        return None

    def format_stats(self) -> str:
        return " ".join(f"{key}={value}" for key, value in self.stats.items())
