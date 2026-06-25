import json
import queue
import threading
import unittest

from ogm_pi.ipc_server import IPCServer, Subscriber
from ogm_pi.pinmap import PinMap, PinRecord, RegSpan
from ogm_pi.store import RegisterStore


def make_pinmap() -> PinMap:
    pins = [
        PinRecord(
            name="audio_ctrl",
            type="AUDIO_PI_CTRL",
            pin=0,
            args=[16, 0],
            coils=RegSpan(0, 0),
            discretes=RegSpan(0, 0),
            input_regs=RegSpan(0, 6),
            holding_regs=RegSpan(0, 4),
        ),
        PinRecord(
            name="audio_slot_01",
            type="AUDIO_PI_SLOT",
            pin=0,
            args=[],
            coils=RegSpan(0, 0),
            discretes=RegSpan(0, 0),
            input_regs=RegSpan(6, 4),
            holding_regs=RegSpan(4, 9),
        ),
        PinRecord(
            name="RESET",
            type="BOARD_RESET",
            pin=0,
            args=[],
            coils=RegSpan(0, 1),
            discretes=RegSpan(0, 0),
            input_regs=RegSpan(0, 0),
            holding_regs=RegSpan(0, 0),
        ),
    ]
    raw = {
        "address": 41,
        "hash": 1,
        "pins": [],
        "totals": {
            "coils": 1,
            "discretes": 0,
            "input_regs": 10,
            "holding_regs": 13,
        },
    }
    return PinMap(raw=raw, pins=pins, pins_by_name={pin.name: pin for pin in pins})


def make_server(*, event_log_max: int = 8, subscriber_queue_max: int = 8) -> IPCServer:
    pinmap = make_pinmap()
    return IPCServer(
        RegisterStore(pinmap.totals),
        pinmap,
        "/tmp/ogm_pi_test.sock",
        event_log_max=event_log_max,
        subscriber_queue_max=subscriber_queue_max,
    )


class FakeConn:
    def __init__(self) -> None:
        self.lines: "queue.Queue[bytes]" = queue.Queue()

    def sendall(self, data: bytes) -> None:
        self.lines.put(data)

    def close(self) -> None:
        pass


def read_json(conn: FakeConn) -> dict:
    try:
        raw = conn.lines.get(timeout=1.0)
    except queue.Empty as exc:
        raise AssertionError("expected JSON line, got timeout") from exc
    return json.loads(raw.decode("utf-8"))


class SubscribeHarness:
    def __init__(self, server: IPCServer, request: dict) -> None:
        self.server = server
        self.conn = FakeConn()
        self.thread = threading.Thread(
            target=server._handle_subscribe,
            args=(self.conn, request),
            daemon=True,
        )
        self.thread.start()

    def close(self) -> None:
        self.conn.close()
        self.server.stop()
        self.thread.join(timeout=1.5)


class IPCServerEventStreamTest(unittest.TestCase):
    def test_app_reload_passes_optional_app_name(self) -> None:
        server = make_server()
        seen: list[str | None] = []
        server.set_app_reload_handler(lambda name: seen.append(name) or {"name": name or ""})

        response = server._handle_request({"id": 1, "cmd": "app_reload", "name": "cctv_station"})

        self.assertTrue(response["ok"])
        self.assertEqual(seen, ["cctv_station"])
        self.assertEqual(response["app"]["name"], "cctv_station")

    def test_app_reload_without_name_reloads_all(self) -> None:
        server = make_server()
        seen: list[str | None] = []
        server.set_app_reload_handler(lambda name: seen.append(name) or {"scope": "all" if name is None else name})

        response = server._handle_request({"id": 1, "cmd": "app_reload"})

        self.assertTrue(response["ok"])
        self.assertEqual(seen, [None])
        self.assertEqual(response["app"]["scope"], "all")

    def test_publish_events_assigns_ipc_seq_and_replays_since(self) -> None:
        server = make_server()
        server.publish_events(
            [
                {
                    "event": "change",
                    "seq": 99,
                    "source": "modbus",
                    "name": "audio_slot_01",
                    "types": ["holding_regs"],
                    "changed_offsets": {"holding_regs": [6]},
                    "values": {"holding_regs": [1, 0, 0, 0, 0, 2, 7, 0, 1]},
                }
            ]
        )

        harness = SubscribeHarness(
            server,
            {
                "id": 1,
                "cmd": "subscribe",
                "events": ["change"],
                "types": ["holding_regs"],
                "names": ["audio_slot_01"],
                "since_ipc_seq": 0,
            },
        )
        try:
            ack = read_json(harness.conn)
            event = read_json(harness.conn)
            since = server._get_pin("audio_slot_01", since=98)
        finally:
            harness.close()

        self.assertTrue(ack["ok"])
        self.assertEqual(ack["ipc_seq"], 1)
        self.assertEqual(ack["replayed"], 1)
        self.assertEqual(event["ipc_seq"], 1)
        self.assertEqual(event["seq"], 99)
        self.assertEqual(event["name"], "audio_slot_01")
        self.assertTrue(since["changed"])
        self.assertEqual(since["last_seq"], 99)
        self.assertEqual(since["last_ipc_seq"], 1)

    def test_replay_unavailable_is_rejected(self) -> None:
        server = make_server(event_log_max=1)
        for idx in range(2):
            server.publish_events(
                [
                    {
                        "event": "change",
                        "source": "modbus",
                        "name": "audio_slot_01",
                        "types": ["holding_regs"],
                        "changed_offsets": {"holding_regs": [6]},
                        "values": {"holding_regs": [idx, 0, 0, 0, 0, 2, idx + 1, 0, 1]},
                    }
                ]
            )

        harness = SubscribeHarness(
            server,
            {
                "id": 2,
                "cmd": "subscribe",
                "events": ["change"],
                "types": ["holding_regs"],
                "names": ["audio_slot_01"],
                "since_ipc_seq": 0,
            },
        )
        try:
            response = read_json(harness.conn)
        finally:
            harness.close()

        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "replay_unavailable")
        self.assertEqual(response["current_ipc_seq"], 2)
        self.assertEqual(response["oldest_ipc_seq"], 2)

    def test_ipc_set_publishes_change_event_with_offsets(self) -> None:
        server = make_server()
        harness = SubscribeHarness(
            server,
            {
                "id": 3,
                "cmd": "subscribe",
                "events": ["change"],
                "types": ["holding_regs"],
                "names": ["audio_slot_01"],
            },
        )
        try:
            ack = read_json(harness.conn)
            updated = server._set_pin(
                "audio_slot_01",
                {"holding_regs": [1, 0, 0, 0, 0, 2, 7, 0, 1]},
            )
            event = read_json(harness.conn)
            since = server._get_pin("audio_slot_01", since=0)
        finally:
            harness.close()

        self.assertTrue(ack["ok"])
        self.assertEqual(updated["name"], "audio_slot_01")
        self.assertEqual(event["source"], "ipc")
        self.assertEqual(event["ipc_seq"], 1)
        self.assertEqual(event["changed_offsets"]["holding_regs"], [0, 5, 6, 8])
        self.assertEqual(event["values"]["holding_regs"], [1, 0, 0, 0, 0, 2, 7, 0, 1])
        self.assertTrue(since["changed"])
        self.assertEqual(since["last_ipc_seq"], 1)

    def test_ipc_set_many_idempotent_write_does_not_publish_event(self) -> None:
        server = make_server()
        handle = server._resolver.handle_for_name("audio_slot_01")
        write = {
            "handle": handle,
            "values": {"holding_regs": [1, 0, 0, 0, 0, 2, 7, 0, 1]},
        }

        server._set_many([write])
        server._set_many([write])

        self.assertEqual(len(server._event_log), 1)

    def test_board_reset_matches_even_with_name_and_type_filters(self) -> None:
        server = make_server()
        harness = SubscribeHarness(
            server,
            {
                "id": 4,
                "cmd": "subscribe",
                "events": ["board_reset"],
                "types": ["holding_regs"],
                "names": ["audio_slot_01"],
            },
        )
        try:
            ack = read_json(harness.conn)
            server.publish_events([{"event": "board_reset", "source": "runtime", "reason": "test"}])
            event = read_json(harness.conn)
        finally:
            harness.close()

        self.assertTrue(ack["ok"])
        self.assertEqual(event["event"], "board_reset")
        self.assertEqual(event["ipc_seq"], 1)

    def test_subscriber_overflow_reports_terminal_error(self) -> None:
        sub = Subscriber(
            conn=FakeConn(),
            events={"change"},
            types={"holding_regs"},
            names=None,
            queue=queue.Queue(maxsize=1),
        )
        self.assertTrue(sub.enqueue({"event": "change", "ipc_seq": 1, "types": ["holding_regs"]}))
        self.assertFalse(sub.enqueue({"event": "change", "ipc_seq": 2, "types": ["holding_regs"]}))
        error = sub.queue.get_nowait()

        self.assertTrue(sub.closed)
        self.assertEqual(error["event"], "subscription_error")
        self.assertEqual(error["error"], "queue_overflow")
        self.assertEqual(error["overflow_at_ipc_seq"], 2)


if __name__ == "__main__":
    unittest.main()
