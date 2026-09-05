import unittest

from ogm_pi.ogm_rtu_shapes import request_length as ogm_request_length
from ogm_pi.rtu_framing import (
    MAX_ADU_LENGTH, MAX_BUFFER, RtuFramer, Shape, crc16,
    standard_request_length, standard_response_length,
)


def adu(payload):
    payload = bytes(payload)
    return payload + crc16(payload).to_bytes(2, "little")


REQUEST_PDUS = [
    *[bytes([fc, 0, 0, 0, 1]) for fc in (1, 2, 3, 4)],
    bytes.fromhex("05 0000 ff00"), bytes.fromhex("06 0000 1234"),
    *[bytes([fc]) for fc in (7, 11, 12, 17)],
    bytes.fromhex("08 0001 0000"),
    bytes.fromhex("0f 0000 0009 02 5501"),
    bytes.fromhex("10 0000 0002 04 00110022"),
    bytes.fromhex("14 07 06 0001 0000 0001"),
    bytes.fromhex("15 09 06 0001 0000 0001 1234"),
    bytes.fromhex("16 0000 ff00 00ff"),
    bytes.fromhex("17 0000 0001 0002 0001 02 1234"),
    bytes.fromhex("18 0000"), bytes.fromhex("2b 0e 01 00"),
]
RESPONSE_PDUS = [
    bytes.fromhex("01 01 01"), bytes.fromhex("02 01 00"),
    bytes.fromhex("03 02 1234"), bytes.fromhex("04 02 5678"),
    bytes.fromhex("05 0000 ff00"), bytes.fromhex("06 0000 1234"),
    bytes.fromhex("07 00"), bytes.fromhex("08 0001 0000"),
    bytes.fromhex("0b 0000 0001"), bytes.fromhex("0c 06 0000 0001 0002"),
    bytes.fromhex("0f 0000 0009"), bytes.fromhex("10 0000 0002"),
    bytes.fromhex("11 03 01 ff 00"), bytes.fromhex("14 04 03 06 1234"),
    bytes.fromhex("15 09 06 0001 0000 0001 1234"),
    bytes.fromhex("16 0000 ff00 00ff"), bytes.fromhex("17 02 1234"),
    bytes.fromhex("18 0004 0001 002a"),
    bytes.fromhex("2b 0e 01 01 00 00 02 00 03 616263 01 02 6465"),
    bytes.fromhex("84 02"), bytes.fromhex("90 03"),
]


class FramingTests(unittest.TestCase):
    def make_framer(self):
        return RtuFramer(41, custom_requests=(ogm_request_length,))

    def assert_fragmented_stream(self, wire, expected):
        for split in range(len(wire) + 1):
            with self.subTest(wire=wire.hex(), split=split):
                parser = self.make_framer()
                outputs = []
                for chunk in (wire[:split], wire[split:]):
                    parser.feed(chunk)
                    while (frame := parser.pop()) is not None:
                        outputs.append(frame)
                self.assertEqual(outputs, expected)
                self.assertFalse(parser.discarding)
                self.assertFalse(parser.buffer)
                self.assertEqual(parser.stats["rx_crc_bad"], 0)

    def test_standard_requests_at_every_split(self):
        for pdu in REQUEST_PDUS:
            frame = adu(b"\x29" + pdu)
            self.assertEqual(standard_request_length(frame), len(frame))
            self.assert_fragmented_stream(frame, [frame])

    def test_foreign_requests_responses_and_exceptions_at_every_split(self):
        local = adu([41, 4, 0, 72, 0, 15])
        for pdu in REQUEST_PDUS + RESPONSE_PDUS:
            foreign = adu(b"\x28" + pdu)
            self.assert_fragmented_stream(foreign + local, [local])

    def test_standard_response_shapes(self):
        for pdu in RESPONSE_PDUS:
            frame = adu(b"\x28" + pdu)
            self.assertEqual(standard_response_length(frame), len(frame))

    def test_fc69_variants_at_every_split(self):
        local = adu([41, 4, 0, 72, 0, 15])
        for inner in ("05 0000 ff00", "06 0012 0031", "0f 0000 0009 02 5501",
                      "10 0000 0002 04 00110022"):
            foreign = adu(b"\x00\x45\x19" + bytes.fromhex(inner))
            self.assertEqual(standard_request_length(foreign), Shape.UNKNOWN)
            self.assertEqual(ogm_request_length(foreign), len(foreign))
            self.assert_fragmented_stream(foreign + local, [foreign, local])

    def test_foreign_read_response_waits_past_bad_request_prefix(self):
        frame = adu(b"\x28" + RESPONSE_PDUS[-3])
        parser = self.make_framer()
        parser.feed(frame[:8])
        self.assertIsNone(parser.pop())
        self.assertFalse(parser.discarding)
        parser.feed(frame[8:])
        self.assertIsNone(parser.pop())
        self.assertEqual(parser.stats["rx_foreign_frames"], 1)

    def test_local_fc16_never_split_at_crc_valid_response_prefix(self):
        # The byte count is also the first CRC byte of an eight-byte prefix.
        prefix = bytes.fromhex("29 10 0000 0007")
        for start in range(65536):
            prefix = bytes([41, 16]) + start.to_bytes(2, "big") + b"\x00\x07"
            prefix_crc = crc16(prefix).to_bytes(2, "little")
            if prefix_crc[0] == 14:
                break
        frame = adu(prefix + b"\x0e" + prefix_crc[1:] + bytes(13))
        self.assertEqual(crc16(frame[:8]), 0)
        self.assert_fragmented_stream(frame, [frame])

    def test_unknown_diagnostics_and_mei_are_not_guessed(self):
        for pdu in (bytes.fromhex("08 0000 12345678"), bytes.fromhex("2b 0d 0000"), b"\x60\x00\x00"):
            parser = self.make_framer()
            parser.feed(adu(b"\x28" + pdu))
            self.assertIsNone(parser.pop())
            self.assertTrue(parser.discarding)
            self.assertEqual(parser.stats["rx_unknown"], 1)

    def test_unknown_and_corrupt_payloads_cannot_execute_embedded_writes(self):
        local = adu([41, 6, 0, 1, 0, 5])
        bad_crc = bytearray(adu([25, 6, 0, 0, 0, 1]))
        bad_crc[-1] ^= 1
        for prefix in (b"\xff\x00", b"\x19\x60", bytes(bad_crc)):
            parser = self.make_framer()
            parser.feed(prefix + local)
            self.assertIsNone(parser.pop())
            parser.feed(local)
            self.assertIsNone(parser.pop())
            parser.idle()
            parser.feed(local)
            self.assertEqual(parser.pop(), local)

    def test_partial_and_overflow_recover_only_after_idle(self):
        local = adu([41, 4, 0, 0, 0, 1])
        parser = self.make_framer()
        parser.feed(local[:5])
        self.assertIsNone(parser.pop())
        parser.idle()
        self.assertEqual(parser.stats["rx_partial_timeout_drops"], 1)
        parser.feed(b"x" * (MAX_BUFFER + 1) + local)
        self.assertIsNone(parser.pop())
        self.assertLessEqual(len(parser.buffer), MAX_BUFFER)
        self.assertEqual(parser.stats["rx_overflows"], 1)
        parser.feed(local)
        self.assertIsNone(parser.pop())
        parser.idle()
        parser.feed(local)
        self.assertEqual(parser.pop(), local)

    def test_maximum_frames_and_oversized_headers(self):
        frame = adu(bytes([41, 16, 0, 0, 0, 123, 246]) + bytes(246))
        self.assertEqual(len(frame), 255)
        self.assert_fragmented_stream(frame, [frame])
        for header in (bytes([41, 16, 0, 0, 0, 128, 255]),
                       bytes([40, 43, 14, 1, 1, 0, 0, 1, 0, 255])):
            parser = self.make_framer()
            parser.feed(header + bytes(MAX_ADU_LENGTH))
            self.assertIsNone(parser.pop())
            self.assertTrue(parser.discarding)

    def test_custom_hooks_do_not_override_standard_shapes(self):
        calls = []

        def custom(data):
            calls.append(data)
            return 6 if data[1] == 0x61 else Shape.UNKNOWN

        parser = RtuFramer(41, custom_requests=(custom,))
        local = adu([41, 4, 0, 0, 0, 1])
        parser.feed(local)
        self.assertEqual(parser.pop(), local)
        self.assertFalse(calls)
        extension = adu([41, 0x61, 0, 1])
        parser.feed(extension)
        self.assertEqual(parser.pop(), extension)

    def test_many_foreign_frames_remain_bounded(self):
        parser = self.make_framer()
        foreign = adu([40, 6, 0, 0, 0, 1])
        local = adu([41, 4, 0, 0, 0, 1])
        parser.feed(foreign * 500 + local)
        self.assertEqual(parser.pop(), local)
        self.assertEqual(parser.stats["rx_foreign_frames"], 500)
        self.assertFalse(parser.buffer)


if __name__ == "__main__":
    unittest.main()
