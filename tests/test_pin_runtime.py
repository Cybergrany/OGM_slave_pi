import time
import unittest
from typing import Dict

from ogm_pi.gpio import GpioAdapter
from ogm_pi.pin_runtime import InputDigital
from ogm_pi.pinmap import PinRecord, RegSpan
from ogm_pi.store import RegisterStore


class FakeGpioAdapter(GpioAdapter):
    def __init__(self) -> None:
        self.values: Dict[int, int] = {}
        self.inputs: Dict[int, bool] = {}

    def setup_input(self, line: int, pull_up: bool = True) -> None:
        self.inputs[line] = pull_up
        self.values.setdefault(line, 1 if pull_up else 0)

    def setup_output(self, line: int, initial: bool = False, open_drain: bool = False) -> bool:
        self.values[line] = 1 if initial else 0
        return open_drain

    def read(self, line: int) -> int:
        return int(self.values.get(line, 0))

    def write(self, line: int, value: bool) -> None:
        self.values[line] = 1 if value else 0

    def set_line(self, line: int, value: int) -> None:
        self.values[line] = 1 if value else 0


class RuntimeStub:
    def __init__(self, gpio: FakeGpioAdapter) -> None:
        self.gpio = gpio


def make_input(args=None):
    if args is None:
        args = []
    pin = PinRecord(
        name="button",
        type="INPUT_DIGITAL",
        pin=17,
        args=list(args),
        coils=RegSpan(0, 0),
        discretes=RegSpan(0, 1),
        input_regs=RegSpan(0, 0),
        holding_regs=RegSpan(0, 0),
    )
    store = RegisterStore({"coils": 0, "discretes": 1, "input_regs": 0, "holding_regs": 0})
    gpio = FakeGpioAdapter()
    handler = InputDigital(pin, store, RuntimeStub(gpio))
    return handler, store, gpio


def discrete_value(store: RegisterStore) -> int:
    return store.read_register_index("discretes", 0)


class InputDigitalTimingTest(unittest.TestCase):
    def test_legacy_no_args_tracks_gpio_immediately(self) -> None:
        handler, store, gpio = make_input()
        handler.init()

        self.assertEqual(discrete_value(store), 0)

        gpio.set_line(17, 0)
        handler.update(time.monotonic())
        self.assertEqual(discrete_value(store), 1)

        gpio.set_line(17, 1)
        handler.update(time.monotonic())
        self.assertEqual(discrete_value(store), 0)

    def test_debounce_delays_high_and_reports_low_immediately(self) -> None:
        handler, store, gpio = make_input([0, 100])
        handler.init()
        start = time.monotonic()

        gpio.set_line(17, 0)
        handler.update(start)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.050)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.101)
        self.assertEqual(discrete_value(store), 1)

        gpio.set_line(17, 1)
        handler.update(start + 0.102)
        self.assertEqual(discrete_value(store), 0)

    def test_latch_holds_each_reported_level_for_minimum_duration(self) -> None:
        handler, store, gpio = make_input([500, 0])
        handler.init()
        start = time.monotonic()

        gpio.set_line(17, 0)
        handler.update(start + 0.100)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.400)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.600)
        self.assertEqual(discrete_value(store), 1)

        gpio.set_line(17, 1)
        handler.update(start + 0.700)
        self.assertEqual(discrete_value(store), 1)

        handler.update(start + 1.200)
        self.assertEqual(discrete_value(store), 0)

    def test_combined_debounce_and_latch_delays_high_then_latches_release(self) -> None:
        handler, store, gpio = make_input([300, 100])
        handler.init()
        start = time.monotonic()

        gpio.set_line(17, 0)
        handler.update(start + 0.050)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.151)
        self.assertEqual(discrete_value(store), 0)

        handler.update(start + 0.351)
        self.assertEqual(discrete_value(store), 1)

        gpio.set_line(17, 1)
        handler.update(start + 0.400)
        self.assertEqual(discrete_value(store), 1)

        handler.update(start + 0.700)
        self.assertEqual(discrete_value(store), 0)

    def test_invalid_timing_args_default_to_legacy_behavior(self) -> None:
        handler, store, gpio = make_input(["bad", None])
        handler.init()

        gpio.set_line(17, 0)
        handler.update(time.monotonic())
        self.assertEqual(discrete_value(store), 1)

        gpio.set_line(17, 1)
        handler.update(time.monotonic())
        self.assertEqual(discrete_value(store), 0)


if __name__ == "__main__":
    unittest.main()
