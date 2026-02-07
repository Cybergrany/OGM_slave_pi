#!/usr/bin/env python3
"""uart_modbus_sniffer.py

Modbus RTU sniffer focused on robustness on Linux UARTs where reads can coalesce
multiple frames.

Key behavior:
- Maintains a byte buffer.
- Repeatedly tries to parse a frame at the head of the buffer.
- If CRC matches for an expected frame length, consumes the frame.
- If not, drops 1 byte and retries (resync).

This avoids false CRC failures when multiple frames arrive back-to-back in one
read(), and it is resilient to imperfect gap timing in userspace.

Typical (master->slave request sniffing):
  python3 uart_modbus_sniffer.py --port /dev/serial0 --baud 250000 \
    --parity N --data-bits 8 --stop-bits 1 --expected-id 99 --assume-requests

You can still set --frame-gap-us to additionally force a flush on idle, but the
parser no longer relies on it for correctness.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional, Tuple

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Try: sudo apt install python3-serial", file=sys.stderr)
    raise


def crc16_modbus(data: bytes) -> int:
    """Compute Modbus RTU CRC16 (poly 0xA001), returns 16-bit int."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def u16_le(lo: int, hi: int) -> int:
    return (hi << 8) | lo


def hexdump_angle(data: bytes, limit: int = 256) -> str:
    # <63><04>... style
    if len(data) > limit:
        data = data[:limit]
        suffix = "..."
    else:
        suffix = ""
    return "".join(f"<{b:02X}>" for b in data) + suffix


def parse_expected_len(buf: bytearray, assume_requests: bool) -> Optional[int]:
    """Return expected RTU frame length from header at buf[0:], if determinable.

    This is not a full Modbus RTU implementation; it targets common function
    codes and uses the RTU length rules.

    If assume_requests=True, interpret FCs as master->slave requests.
    If assume_requests=False, interpret FCs as slave->master responses.
    """
    if len(buf) < 2:
        return None

    fc = buf[1]

    # Exception response: addr, fc|0x80, exc_code, crc_lo, crc_hi
    if (fc & 0x80) != 0:
        return 5

    # Most common fixed-length requests/responses
    if fc in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06):
        # Requests are always 8 bytes.
        # Responses for 0x05/0x06 are also 8 bytes, but for 0x01-0x04 they are variable.
        if assume_requests:
            return 8
        else:
            if fc in (0x05, 0x06):
                return 8
            # Read responses: addr, fc, byte_count, data..., crc
            if len(buf) < 3:
                return None
            byte_count = buf[2]
            return 5 + byte_count

    # Write Multiple Coils / Registers (requests variable, responses 8)
    if fc in (0x0F, 0x10):
        if assume_requests:
            # addr, fc, start_hi, start_lo, qty_hi, qty_lo, byte_count, data..., crc
            if len(buf) < 7:
                return None
            byte_count = buf[6]
            return 9 + byte_count
        else:
            return 8

    # Mask Write Register (0x16) request/response are 10 bytes
    if fc == 0x16:
        return 10

    # Read/Write Multiple Registers (0x17) request variable, response variable
    if fc == 0x17:
        if assume_requests:
            # addr, fc, read_start(2), read_qty(2), write_start(2), write_qty(2), byte_count(1), write_data..., crc(2)
            if len(buf) < 11:
                return None
            byte_count = buf[10]
            return 13 + byte_count
        else:
            # addr, fc, byte_count, data..., crc
            if len(buf) < 3:
                return None
            byte_count = buf[2]
            return 5 + byte_count

    # Unknown FC: can't infer length safely.
    return None


def try_consume_frame(
    buf: bytearray,
    assume_requests: bool,
) -> Optional[Tuple[bytes, bool, int, int]]:
    """Try to parse and consume one frame from the start of buf.

    Returns (frame_bytes, crc_ok, recv_crc, calc_crc) if a full frame is present.
    Returns None if not enough bytes or cannot infer length.

    Does NOT drop bytes on CRC failure; caller decides whether to resync.
    """
    exp_len = parse_expected_len(buf, assume_requests)
    if exp_len is None:
        return None
    if len(buf) < exp_len:
        return None

    frame = bytes(buf[:exp_len])
    recv_crc = u16_le(frame[-2], frame[-1])
    calc_crc = crc16_modbus(frame[:-2])
    crc_ok = (recv_crc == calc_crc)
    return frame, crc_ok, recv_crc, calc_crc


def describe_frame(frame: bytes) -> str:
    if len(frame) < 2:
        return ""
    addr = frame[0]
    fc = frame[1]

    # Exception
    if (fc & 0x80) != 0 and len(frame) >= 5:
        exc = frame[2]
        return f"addr={addr:3d} fc=0x{fc:02X} exc=0x{exc:02X}"

    # Common requests
    if fc in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06) and len(frame) >= 8:
        # Read: addr, fc, start_hi, start_lo, qty_hi, qty_lo, crc...
        if fc in (0x01, 0x02, 0x03, 0x04):
            start = (frame[2] << 8) | frame[3]
            qty = (frame[4] << 8) | frame[5]
            return f"addr={addr:3d} fc=0x{fc:02X} start={start} qty={qty}"
        # Write single coil/register
        val = (frame[4] << 8) | frame[5]
        reg = (frame[2] << 8) | frame[3]
        return f"addr={addr:3d} fc=0x{fc:02X} reg={reg} val=0x{val:04X}"

    # Read responses (addr, fc, byte_count, ...)
    if fc in (0x01, 0x02, 0x03, 0x04) and len(frame) >= 5:
        byte_count = frame[2]
        return f"addr={addr:3d} fc=0x{fc:02X} bytes={byte_count}"

    return f"addr={addr:3d} fc=0x{fc:02X}"


def open_serial(args) -> serial.Serial:
    parity_map = {
        "N": serial.PARITY_NONE,
        "E": serial.PARITY_EVEN,
        "O": serial.PARITY_ODD,
        "M": serial.PARITY_MARK,
        "S": serial.PARITY_SPACE,
    }
    bytesize_map = {
        5: serial.FIVEBITS,
        6: serial.SIXBITS,
        7: serial.SEVENBITS,
        8: serial.EIGHTBITS,
    }
    stop_map = {
        1: serial.STOPBITS_ONE,
        2: serial.STOPBITS_TWO,
    }

    try:
        ser = serial.Serial(
            port=args.port,
            baudrate=int(args.baud),
            parity=parity_map[args.parity],
            bytesize=bytesize_map[int(args.data_bits)],
            stopbits=stop_map[int(args.stop_bits)],
            timeout=0.02,        # short blocking read
            write_timeout=0.0,
            exclusive=True,
        )
    except TypeError:
        # exclusive not supported on some pyserial builds
        ser = serial.Serial(
            port=args.port,
            baudrate=int(args.baud),
            parity=parity_map[args.parity],
            bytesize=bytesize_map[int(args.data_bits)],
            stopbits=stop_map[int(args.stop_bits)],
            timeout=0.02,
            write_timeout=0.0,
        )

    # Try to reduce buffering latency
    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    except Exception:
        pass

    return ser


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", required=True, type=int)
    ap.add_argument("--parity", default="N", choices=["N", "E", "O", "M", "S"])
    ap.add_argument("--data-bits", default=8, type=int, choices=[5, 6, 7, 8])
    ap.add_argument("--stop-bits", default=1, type=int, choices=[1, 2])

    ap.add_argument("--expected-id", type=int, default=None, help="If set, mark frames whose addr matches")
    ap.add_argument("--assume-requests", action="store_true", help="Parse as master->slave requests (recommended)")
    ap.add_argument("--assume-responses", action="store_true", help="Parse as slave->master responses")

    ap.add_argument("--frame-gap-us", type=int, default=0,
                    help="Optional: if >0, flush current buffer as a 'frame' after this idle gap (us). Parser still does CRC-based splitting.")

    ap.add_argument("--max-buffer", type=int, default=4096)
    ap.add_argument("--print-raw-limit", type=int, default=256)

    args = ap.parse_args()

    assume_requests = True
    if args.assume_responses:
        assume_requests = False
    if args.assume_requests:
        assume_requests = True

    ser = open_serial(args)

    t0 = time.monotonic()
    last_byte_t = None  # type: Optional[float]

    buf = bytearray()
    frame_idx = 0
    dropped = 0
    crc_bad = 0

    def flush_due_to_gap(now_t: float) -> bool:
        if args.frame_gap_us <= 0:
            return False
        if last_byte_t is None:
            return False
        gap_s = args.frame_gap_us / 1_000_000.0
        return (now_t - last_byte_t) >= gap_s

    try:
        while True:
            now = time.monotonic()

            # Optional gap-based flush: if there's data in the buffer but we haven't
            # received anything for a while, attempt parsing aggressively.
            if buf and flush_due_to_gap(now):
                # No special action needed: parsing below will run.
                pass

            n = ser.in_waiting
            if n <= 0:
                # Still parse buffered data in case buffer already has full frames.
                pass
            else:
                chunk = ser.read(n)
                if chunk:
                    buf.extend(chunk)
                    last_byte_t = now

            # Prevent unbounded growth in the face of noise
            if len(buf) > args.max_buffer:
                # Drop oldest half
                drop_n = len(buf) // 2
                del buf[:drop_n]
                dropped += drop_n

            # Parse as many frames as possible
            made_progress = True
            while made_progress:
                made_progress = False

                res = try_consume_frame(buf, assume_requests=assume_requests)
                if res is None:
                    break

                frame, ok, recv_crc, calc_crc = res
                if ok:
                    frame_idx += 1
                    addr = frame[0] if len(frame) else None
                    fc = frame[1] if len(frame) > 1 else None
                    id_match = (args.expected_id is not None and addr == args.expected_id)

                    t_rel = time.monotonic() - t0
                    status = "OK" if ok else "BAD"
                    match_txt = "match" if id_match else "-"

                    # Print line
                    desc = describe_frame(frame)
                    sys.stdout.write(
                        f"[{frame_idx:06d}] t={t_rel:9.3f}s len={len(frame):3d} "
                        f"{desc} crc={status} recv=0x{recv_crc:04X} calc=0x{calc_crc:04X} id={match_txt} "
                        f"data={hexdump_angle(frame, limit=args.print_raw_limit)}\n"
                    )
                    sys.stdout.flush()

                    # Consume
                    del buf[:len(frame)]
                    made_progress = True
                else:
                    # Resync: drop one byte and retry
                    crc_bad += 1
                    dropped += 1
                    del buf[0]
                    made_progress = True

            # Avoid busy loop
            if n <= 0 and not buf:
                time.sleep(0.002)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            ser.close()
        except Exception:
            pass

        t_run = time.monotonic() - t0
        sys.stderr.write(
            f"\nStopped. runtime={t_run:.2f}s frames_ok={frame_idx} crc_resync_events={crc_bad} bytes_dropped={dropped}\n"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
