"""OGM wire extensions. Recognition here does not enable command execution."""

from .rtu_framing import Length, Shape

# These functions are understood solely so their complete frames can be skipped.
FRAMING_ONLY_FUNCTIONS = frozenset({69})


def request_length(data: bytes) -> Length:
    if len(data) < 2:
        return Shape.NEED_MORE
    if data[1] != 69:
        return Shape.UNKNOWN
    if len(data) < 4:
        return Shape.NEED_MORE
    # [address][69][target][inner FC][inner data...][CRC]
    if data[3] in (5, 6):
        return 10
    if data[3] in (15, 16):
        return 11 + data[8] if len(data) >= 9 else Shape.NEED_MORE
    return Shape.UNKNOWN
