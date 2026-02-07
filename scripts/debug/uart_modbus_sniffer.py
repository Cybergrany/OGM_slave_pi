#!/usr/bin/env python3
"""Raw UART/Modbus RTU sniffer for Raspberry Pi troubleshooting.

Reads bytes from a serial port, splits traffic into frames using an idle gap,
and prints each frame with Modbus CRC validation.
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from dataclasses import dataclass
from typing import Optional

try:
    import serial
except ImportError as exc:  # pragma: no cover - runtime guard
    raise SystemExit(
        "pyserial is required. Install with: pip install pyserial"
    ) from exc


def modbus_crc16(data: bytes) -> int:
    """Compute Modbus CRC16 (poly 0xA001, init 0xFFFF)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def format_angle_hex(data: bytes) -> str:
    return "".join(f"<{b:02X}>" for b in data)


def parse_int_auto(text: str) -> int:
    return int(text, 0)


def bits_per_char(data_bits: int, parity: str, stop_bits: int) -> int:
    parity_bits = 0 if parity.upper() == "N" else 1
    return 1 + data_bits + parity_bits + stop_bits


@dataclass
class SnifferConfig:
    port: str
    baud: int
    parity: str
    data_bits: int
    stop_bits: int
    frame_gap_us: int
    read_timeout_s: float
    max_frames: int
    max_seconds: float
    expected_id: Optional[int]
    chunk_max: int


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Standalone UART/Modbus RTU sniffer (frame + CRC view)."
    )
    parser.add_argument("--port", default="/dev/serial0", help="Serial port path")
    parser.add_argument("--baud", type=int, default=250000, help="Baud rate")
    parser.add_argument(
        "--parity",
        default="N",
        choices=("N", "E", "O", "n", "e", "o"),
        help="Parity",
    )
    parser.add_argument(
        "--data-bits",
        type=int,
        default=8,
        choices=(5, 6, 7, 8),
        help="Data bits",
    )
    parser.add_argument(
        "--stop-bits",
        type=int,
        default=1,
        choices=(1, 2),
        help="Stop bits",
    )
    parser.add_argument(
        "--frame-gap-us",
        type=int,
        default=None,
        help="Idle gap to terminate a frame (microseconds). Default: auto",
    )
    parser.add_argument(
        "--read-timeout-ms",
        type=int,
        default=20,
        help="Serial read timeout in milliseconds",
    )
    parser.add_argument(
        "--max-frames",
        type=int,
        default=0,
        help="Stop after N frames (0 = unlimited)",
    )
    parser.add_argument(
        "--max-seconds",
        type=float,
        default=0.0,
        help="Stop after N seconds (0 = unlimited)",
    )
    parser.add_argument(
        "--expected-id",
        type=parse_int_auto,
        default=None,
        help="Expected slave id (for hinting), accepts decimal or 0x..",
    )
    parser.add_argument(
        "--chunk-max",
        type=int,
        default=256,
        help="Maximum bytes read per poll",
    )
    return parser


def to_serial_parity(parity: str) -> str:
    p = parity.upper()
    if p == "E":
        return serial.PARITY_EVEN
    if p == "O":
        return serial.PARITY_ODD
    return serial.PARITY_NONE


def to_serial_bytesize(bits: int) -> int:
    if bits == 5:
        return serial.FIVEBITS
    if bits == 6:
        return serial.SIXBITS
    if bits == 7:
        return serial.SEVENBITS
    return serial.EIGHTBITS


def to_serial_stopbits(bits: int) -> float:
    return serial.STOPBITS_TWO if bits == 2 else serial.STOPBITS_ONE


def describe_frame(
    idx: int,
    frame: bytes,
    elapsed_s: float,
    expected_id: Optional[int],
) -> str:
    addr = frame[0] if frame else None
    fc = frame[1] if len(frame) >= 2 else None

    if len(frame) >= 4:
        recv_crc = frame[-2] | (frame[-1] << 8)
        calc_crc = modbus_crc16(frame[:-2])
        crc_status = "OK" if recv_crc == calc_crc else "BAD"
        crc_part = f"{crc_status} recv=0x{recv_crc:04X} calc=0x{calc_crc:04X}"
    else:
        crc_part = "N/A (len<4)"

    id_hint = ""
    if expected_id is not None and addr is not None:
        if addr == expected_id:
            id_hint = " id=match"
        elif addr == 0:
            id_hint = " id=broadcast"
        else:
            id_hint = f" id=mismatch(expected={expected_id})"

    return (
        f"[{idx:06d}] t={elapsed_s:9.3f}s len={len(frame):3d} "
        f"addr={addr if addr is not None else -1:3d} "
        f"fc=0x{fc:02X} " if fc is not None else
        f"[{idx:06d}] t={elapsed_s:9.3f}s len={len(frame):3d} addr= -1 fc=-- "
    ) + f"crc={crc_part}{id_hint} data={format_angle_hex(frame)}"


def main() -> int:
    args = build_arg_parser().parse_args()

    parity = args.parity.upper()
    bits = bits_per_char(args.data_bits, parity, args.stop_bits)
    char_us = (bits * 1_000_000.0) / max(1, args.baud)
    auto_gap = max(2_000, int(char_us * 8.0))
    gap_us = args.frame_gap_us if args.frame_gap_us is not None else auto_gap

    cfg = SnifferConfig(
        port=args.port,
        baud=args.baud,
        parity=parity,
        data_bits=args.data_bits,
        stop_bits=args.stop_bits,
        frame_gap_us=int(gap_us),
        read_timeout_s=max(0.001, args.read_timeout_ms / 1000.0),
        max_frames=max(0, int(args.max_frames)),
        max_seconds=max(0.0, float(args.max_seconds)),
        expected_id=args.expected_id,
        chunk_max=max(1, int(args.chunk_max)),
    )

    running = True

    def stop_handler(_signum: int, _frame) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    print(
        f"Opening {cfg.port} @ {cfg.baud} {cfg.data_bits}{cfg.parity}{cfg.stop_bits} "
        f"(frame_gap_us={cfg.frame_gap_us}, read_timeout_ms={int(cfg.read_timeout_s * 1000)})"
    )
    if cfg.expected_id is not None:
        print(f"Expected slave id hint: {cfg.expected_id}")

    try:
        ser = serial.Serial(
            port=cfg.port,
            baudrate=cfg.baud,
            bytesize=to_serial_bytesize(cfg.data_bits),
            parity=to_serial_parity(cfg.parity),
            stopbits=to_serial_stopbits(cfg.stop_bits),
            timeout=cfg.read_timeout_s,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
            exclusive=True,
        )
    except Exception as exc:
        print(f"Failed to open serial port {cfg.port}: {exc}", file=sys.stderr)
        return 2

    start_ns = time.perf_counter_ns()
    frame = bytearray()
    last_rx_ns = 0
    frame_count = 0

    try:
        while running:
            if cfg.max_seconds > 0.0:
                if (time.perf_counter_ns() - start_ns) / 1e9 >= cfg.max_seconds:
                    print("Reached --max-seconds, exiting.")
                    break

            want = ser.in_waiting
            if want <= 0:
                want = 1
            else:
                want = min(want, cfg.chunk_max)

            block = ser.read(want)
            now_ns = time.perf_counter_ns()

            if block:
                frame.extend(block)
                last_rx_ns = now_ns
                continue

            if frame and last_rx_ns:
                idle_us = (now_ns - last_rx_ns) / 1000.0
                if idle_us >= cfg.frame_gap_us:
                    frame_count += 1
                    elapsed_s = (now_ns - start_ns) / 1e9
                    print(describe_frame(frame_count, bytes(frame), elapsed_s, cfg.expected_id), flush=True)
                    frame.clear()
                    last_rx_ns = 0
                    if cfg.max_frames > 0 and frame_count >= cfg.max_frames:
                        print("Reached --max-frames, exiting.")
                        break
    finally:
        if frame:
            frame_count += 1
            elapsed_s = (time.perf_counter_ns() - start_ns) / 1e9
            print(describe_frame(frame_count, bytes(frame), elapsed_s, cfg.expected_id), flush=True)
        try:
            ser.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

