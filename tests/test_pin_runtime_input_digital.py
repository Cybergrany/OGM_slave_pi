from types import SimpleNamespace
import unittest

from ogm_pi.gpio import NullGpioAdapter
from ogm_pi.pin_runtime import InputDigital
from ogm_pi.pinmap import PinRecord, RegSpan
from ogm_pi.store import RegisterStore


LINE = 7


def make_input(args=None, *, pressed=False):
    gpio = NullGpioAdapter()
    gpio.write(LINE, not pressed)
    pin = PinRecord(
        name="button",
        type="INPUT_DIGITAL",
        pin=LINE,
        args=list(args or []),
        coils=RegSpan(0, 0),
        discretes=RegSpan(0, 1),
        input_regs=RegSpan(0, 0),
        holding_regs=RegSpan(0, 0),
    )
    store = RegisterStore({"coils": 0, "discretes": 1, "input_regs": 0, "holding_regs": 0})
    handler = InputDigital(pin, store, SimpleNamespace(gpio=gpio))
    return handler, store, gpio


def set_pressed(gpio: NullGpioAdapter, pressed: bool) -> None:
    gpio.write(LINE, not pressed)


def read_discrete(store: RegisterStore) -> int:
    return store.read_register_index("discretes", 0)


class InputDigitalTimingTest(unittest.TestCase):
    def test_legacy_input_follows_raw_gpio_immediately(self) -> None:
        handler, store, gpio = make_input([])

        handler.update(0.0)
        self.assertEqual(read_discrete(store), 0)

        set_pressed(gpio, True)
        handler.update(0.01)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.02)
        self.assertEqual(read_discrete(store), 0)

    def test_invalid_timing_args_fall_back_to_legacy_behavior(self) -> None:
        with self.assertLogs("ogm_pi.pin_runtime", level="WARNING"):
            handler, store, gpio = make_input([200])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.01)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.02)
        self.assertEqual(read_discrete(store), 0)

    def test_latch_stretches_short_press(self) -> None:
        handler, store, gpio = make_input([200, 0])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.25)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.26)
        self.assertEqual(read_discrete(store), 1)

        handler.update(0.449)
        self.assertEqual(read_discrete(store), 1)

        handler.update(0.451)
        self.assertEqual(read_discrete(store), 0)

    def test_latch_does_not_delay_release_after_minimum_hold(self) -> None:
        handler, store, gpio = make_input([200, 0])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.25)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.501)
        self.assertEqual(read_discrete(store), 0)

    def test_rising_debounce_suppresses_short_press(self) -> None:
        handler, store, gpio = make_input([0, 50])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.10)
        self.assertEqual(read_discrete(store), 0)

        set_pressed(gpio, False)
        handler.update(0.12)
        handler.update(0.20)
        self.assertEqual(read_discrete(store), 0)

    def test_rising_debounce_reports_stable_press_and_releases_immediately(self) -> None:
        handler, store, gpio = make_input([0, 50])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.10)
        handler.update(0.149)
        self.assertEqual(read_discrete(store), 0)

        handler.update(0.151)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.152)
        self.assertEqual(read_discrete(store), 0)

    def test_rapid_changes_preserve_minimum_reported_state_time(self) -> None:
        handler, store, gpio = make_input([200, 0])

        handler.update(0.0)
        set_pressed(gpio, True)
        handler.update(0.25)
        self.assertEqual(read_discrete(store), 1)

        set_pressed(gpio, False)
        handler.update(0.26)
        handler.update(0.451)
        self.assertEqual(read_discrete(store), 0)

        set_pressed(gpio, True)
        handler.update(0.452)
        self.assertEqual(read_discrete(store), 0)

        handler.update(0.653)
        self.assertEqual(read_discrete(store), 1)


if __name__ == "__main__":
    unittest.main()
