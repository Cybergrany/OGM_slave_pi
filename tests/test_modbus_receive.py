"""Exercise the production receive loop with scripted serial delivery, not hardware."""

import ctypes
import errno
import os
import queue
import threading
import tty
import unittest
from unittest.mock import Mock, patch

from ogm_pi import modbus_server as server
from ogm_pi.pinmap import PinMap, PinRecord, RegSpan
from ogm_pi.store import RegisterStore


class EndOfInput(Exception):
    pass


def adu(payload):
    payload = bytes(payload)
    return payload + server.LibModbusAdapter._crc16_modbus(payload).to_bytes(2, "little")


class SerialInput:
    """Bytes are ready immediately; None represents an observed 21 ms idle."""

    def __init__(self, events):
        self.events = list(events)
        self.now = 1.0

    def select(self, readers, writers, errors, timeout):
        if self.events and self.events[0] is not None:
            return readers, [], []
        if timeout == 0:
            return [], [], []
        if not self.events:
            raise EndOfInput
        self.events.pop(0)
        self.now += 0.021
        return [], [], []

    def read(self, fd, limit):
        event = self.events.pop(0)
        self.assert_bytes(event)
        if len(event) > limit:
            self.events.insert(0, event[limit:])
        self.now += 0.0001
        return event[:limit]

    @staticmethod
    def assert_bytes(event):
        assert isinstance(event, bytes)


def make_adapter(address):
    cls = server.LibModbusAdapter
    with patch.object(cls, "_load_library", return_value=Mock()), \
         patch.object(cls, "_configure_symbols"), \
         patch.object(cls, "_create_context", return_value=1), \
         patch.object(cls, "_create_mapping", return_value=Mock()), \
         patch.object(cls, "_validate_mapping"):
        adapter = cls("/dev/test", 250000, "N", 8, 1, address, {},
                      log_every_recoverable_error=True)
    adapter._fd = 123
    return adapter


class ReceiveTests(unittest.TestCase):
    def receive(self, adapter, events):
        serial = SerialInput(events)
        with patch.object(server.select, "select", side_effect=serial.select), \
             patch.object(server.os, "read", side_effect=serial.read), \
             patch.object(server.time, "monotonic", side_effect=lambda: serial.now):
            return adapter.receive_request()

    def test_valid_foreign_frames_cannot_hide_pi_read(self):
        prefixes = [
            bytes.fromhex("00 45 19 06 00 12 00 31 bf 17"),
            bytes.fromhex("28 04 0e 00 17 00 17 00 64 00 00 00 0f 00 16 00 10 37 17"),
            adu([25, 6, 0, 18, 0, 49]),
        ]
        for address in (41, 42):
            for count in (1, 15):
                request = adu([address, 4, 0, 72 if address == 41 else 74, 0, count])
                for prefix in prefixes:
                    self.assertEqual(server.LibModbusAdapter._crc16_modbus(prefix), 0)
                    for chunks in ([prefix + request], [prefix, request]):
                        with self.subTest(address=address, count=count,
                                          prefix=prefix.hex(), chunks=len(chunks)):
                            self.assertEqual(self.receive(make_adapter(address), chunks),
                                             (len(request), request))

    def test_earlier_local_write_is_not_dispatched(self):
        stale = adu([41, 6, 0, 49, 0, 1])
        current = adu([41, 6, 0, 50, 0, 2])
        self.assertEqual(self.receive(make_adapter(41), [stale + current]),
                         (len(current), current))

    def test_unknown_payload_is_not_searched_for_a_local_write(self):
        embedded = adu([41, 6, 0, 49, 0, 1])
        unknown = adu(bytes([25, 0x60, 0, 0]) + embedded + b"\x00\x00")
        current = adu([41, 4, 0, 72, 0, 15])
        self.assertEqual(self.receive(make_adapter(41), [unknown, None, current]),
                         (len(current), current))

    def test_kernel_buffered_trailing_bytes_also_suppress_stale_write(self):
        stale = adu([41, 6, 0, 49, 0, 1])
        current = adu([41, 6, 0, 50, 0, 2])
        adapter = make_adapter(41)
        self.assertEqual(self.receive(adapter, [stale, current[:1], current[1:]]),
                         (len(current), current))
        self.assertEqual(adapter._framer.stats["rx_stale_local"], 1)

    def test_each_byte_fragment_and_idle_wait_do_not_delay_a_complete_request(self):
        frame = adu([41, 6, 0, 50, 0, 2])
        self.assertEqual(self.receive(make_adapter(41), [None] + [bytes([b]) for b in frame]),
                         (len(frame), frame))

    def test_fc69_addressed_to_pi_remains_framing_only(self):
        current = adu([41, 4, 0, 0, 0, 1])
        for outer in (0, 41):
            adapter = make_adapter(41)
            custom = adu([outer, 69, 41, 6, 0, 0, 0, 9])
            self.assertEqual(self.receive(adapter, [custom, None, current]),
                             (len(current), current))
            self.assertEqual(adapter._framer.stats["rx_custom_ignored"], 1)
            adapter._lib.modbus_reply.assert_not_called()

    def test_broadcast_suppression_and_fresh_reply_are_preserved(self):
        adapter = make_adapter(41)
        broadcast = adu([0, 6, 0, 0, 0, 7])
        length, frame = self.receive(adapter, [broadcast])
        adapter.reply(length)
        adapter._lib.modbus_reply.assert_not_called()
        current = adu([41, 6, 0, 0, 0, 8])
        length, frame = self.receive(adapter, [current])
        adapter._lib.modbus_reply.return_value = 8
        adapter.reply(length)
        adapter._lib.modbus_reply.assert_called_once()
        self.assertEqual(bytes(adapter._request[:length]), current)
        self.assertFalse(adapter._suppress_reply)

    def test_recovery_summaries_are_independent_of_reply_errors_and_rate_limited(self):
        adapter = make_adapter(41)
        with patch.object(server.LOGGER, "warning") as warning, \
             patch.object(server.time, "monotonic", return_value=1.0) as clock:
            adapter._log_rx_stats()
            warning.assert_not_called()
            adapter._framer.feed(b"\x19\x60")
            adapter._framer.pop()
            adapter._log_rx_stats()
            self.assertEqual(warning.call_count, 1)
            adapter._framer.feed(b"discarded noise")
            adapter._log_rx_stats()
            self.assertEqual(warning.call_count, 1)
            clock.return_value = 6.0
            adapter._log_rx_stats()
            self.assertEqual(warning.call_count, 2)
            clock.return_value = 12.0
            adapter._log_rx_stats()
            self.assertEqual(warning.call_count, 2)

    def test_io_error_and_eof_are_not_hidden_by_recovery(self):
        for code in (errno.EINTR, errno.EIO):
            adapter = make_adapter(41)
            with patch.object(server.select, "select", side_effect=OSError(code, "test")):
                with self.assertRaises(server.ModbusBackendError) as raised:
                    adapter.receive_request()
            self.assertEqual(raised.exception.errno_code, code)
            self.assertEqual(raised.exception.fatal, code == errno.EIO)
        adapter = make_adapter(41)
        with patch.object(server.select, "select", return_value=([123], [], [])), \
             patch.object(server.os, "read", return_value=b""):
            with self.assertRaises(server.ModbusBackendError) as raised:
                adapter.receive_request()
        self.assertTrue(raised.exception.fatal)

    @unittest.skipUnless(hasattr(os, "openpty"), "requires a POSIX pseudoterminal")
    def test_real_tty_readiness_and_buffered_receive(self):
        current = adu([41, 4, 0, 72, 0, 15])
        prefixes = [
            bytes.fromhex("00 45 19 06 00 12 00 31 bf 17"),
            adu([41, 6, 0, 0, 0, 99]),
        ]
        for prefix in prefixes:
            with self.subTest(prefix=prefix.hex()):
                master, slave = os.openpty()
                tty.setraw(slave)
                adapter = make_adapter(41)
                adapter._fd = slave
                result = queue.Queue()

                def receive():
                    try:
                        result.put(adapter.receive_request())
                    except Exception as exc:
                        result.put(exc)

                thread = threading.Thread(target=receive, daemon=True)
                try:
                    os.write(master, prefix + current)
                    thread.start()
                    received = result.get(timeout=2.0)
                    self.assertEqual(received, (len(current), current))
                finally:
                    os.close(master)  # Also interrupts the reader on a failed test.
                    thread.join(timeout=1.0)
                    os.close(slave)
                self.assertFalse(thread.is_alive())

    def test_backend_delivers_only_fresh_write_to_mapping_store_and_ipc(self):
        pin = PinRecord(name="slot", type="AUDIO_PI_SLOT", pin=0, args=[],
                        coils=RegSpan(0, 0), discretes=RegSpan(0, 0),
                        input_regs=RegSpan(0, 0), holding_regs=RegSpan(0, 9))
        totals = dict(coils=0, discretes=0, input_regs=0, holding_regs=9)
        pinmap = PinMap(raw={"address": 41, "totals": totals}, pins=[pin], pins_by_name={"slot": pin})
        store = RegisterStore(totals)
        events = []
        backend = server.LibModbusBackend(store, pinmap, "/dev/test", 250000, 41,
                                         event_sink=events.extend)
        adapter = make_adapter(41)
        backend._adapter = adapter
        backend._shadow = {"coils": [], "holding_regs": [0] * 9}
        adapter._sizes = totals
        registers = (ctypes.c_uint16 * 9)()
        mapping = server._ModbusMapping()
        mapping.tab_registers = registers
        adapter._mapping = ctypes.pointer(mapping)
        stale = adu([41, 6, 0, 0, 0, 99])
        current = adu([41, 16, 0, 0, 0, 9, 18] + list(bytes.fromhex("000100020003000400050006000700080009")))
        writes = []

        def reply(ctx, request, length, mapping_ptr):
            writes.append(bytes(request[:length]))
            # Simulate only the libmodbus C boundary. The production adapter,
            # span extraction, shadow, store and event tracker are all exercised.
            for i in range(9):
                mapping_ptr.contents.tab_registers[i] = i + 1
            backend._stop_event.set()
            return 8

        adapter._lib.modbus_reply.side_effect = reply
        serial = SerialInput([stale + current])
        with patch.object(server.select, "select", side_effect=serial.select), \
             patch.object(server.os, "read", side_effect=serial.read), \
             patch.object(server.time, "monotonic", side_effect=lambda: serial.now):
            backend._serve_loop()
        self.assertEqual(writes, [current])
        self.assertEqual(store.holding_regs, list(range(1, 10)))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["changed_offsets"], {"holding_regs": list(range(9))})
        self.assertEqual(events[0]["values"]["holding_regs"], list(range(1, 10)))
        self.assertEqual(store.consume_dirty_updates(), {})


if __name__ == "__main__":
    unittest.main()
