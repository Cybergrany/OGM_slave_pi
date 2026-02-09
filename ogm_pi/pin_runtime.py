"""Runtime pin handlers for OGM_slave_pi."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import logging
import subprocess
import threading
import time

from .custom_loader import load_custom_handlers
from .gpio_claims import GpioClaimError, GpioClaimRegistry
from .gpio import GpioAdapter, NullGpioAdapter
from .pinmap import PinMap, PinRecord, RegSpan
from .store import RegisterStore, crc16_modbus_words

LOGGER = logging.getLogger(__name__)
SHUTDOWN_HELPER = "/usr/local/sbin/ogm_pi_shutdown"
SHUTDOWN_CMD = ["sudo", "-n", SHUTDOWN_HELPER]


def _parse_int_arg(args: List[Any], default: int = 0) -> int:
    if args:
        try:
            return int(args[0])
        except (TypeError, ValueError):
            return default
    return default


def _parse_u32_arg(args: List[Any], default: int = 0) -> int:
    if args:
        try:
            return int(args[0]) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return default
    return default


def _resolve_gpio_line(pin: Any) -> Optional[int]:
    if isinstance(pin, int):
        return pin
    if isinstance(pin, str):
        if pin.upper().startswith("GPIO") and pin[4:].isdigit():
            return int(pin[4:])
    return None


def _encode_u32_with_crc(value: int) -> List[int]:
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF
    crc = crc16_modbus_words(lo, hi)
    return [lo, hi, crc]


def _clamp_u16(value: int) -> int:
    if value < 0:
        return 0
    if value > 0xFFFF:
        return 0xFFFF
    return int(value)


def _mem_available_kb() -> int:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
    except OSError:
        return 0
    return 0


def _cpu_temp_c_x100() -> int:
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r", encoding="utf-8") as handle:
            raw = handle.read().strip()
        if raw and raw.lstrip("-").isdigit():
            millideg = int(raw)
            return _clamp_u16(millideg // 10)
    except OSError:
        return 0
    return 0


def _cpu_load_1m_x100() -> int:
    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as handle:
            parts = handle.read().split()
        if parts:
            return _clamp_u16(int(float(parts[0]) * 100.0))
    except (OSError, ValueError):
        return 0
    return 0


@dataclass
class RegHandle:
    store: RegisterStore
    reg_name: str
    span: RegSpan
    initial: int
    valid: bool = True
    index: int = 0

    def __post_init__(self) -> None:
        if self.span.count != 1:
            LOGGER.warning("Expected 1 %s register, got %s", self.reg_name, self.span.count)
            self.valid = False
            return
        self.index = int(self.span.start)

    def get(self) -> int:
        if not self.valid:
            return self.initial
        return self.store.read_register_index(self.reg_name, self.index)

    def set(self, value: int) -> None:
        if not self.valid:
            return
        self.store.write_register_index(self.reg_name, self.index, value)

    def reset(self) -> None:
        self.set(self.initial)


@dataclass
class TwoWordHandle:
    store: RegisterStore
    reg_name: str
    span: RegSpan
    initial: int
    buf: int = 0
    valid: bool = True

    def __post_init__(self) -> None:
        if self.span.count != 3:
            LOGGER.warning("Expected 3 %s registers for TWO_WORD, got %s", self.reg_name, self.span.count)
            self.valid = False
        self.buf = self.initial

    def get(self) -> int:
        if not self.valid:
            return self.buf
        values = self.store.read_registers(self.reg_name, self.span)
        if len(values) != 3:
            return self.buf
        lo, hi, crc = values
        if crc16_modbus_words(int(lo), int(hi)) == int(crc):
            self.buf = (int(hi) << 16) | int(lo)
        return self.buf

    def set(self, value: int) -> None:
        if not self.valid:
            return
        payload = _encode_u32_with_crc(value & 0xFFFFFFFF)
        self.store.write_registers(self.reg_name, self.span, payload)

    def reset(self) -> None:
        self.set(self.initial)


class PinHandler:
    """Base pin handler."""

    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        self.pin = pin
        self.store = store
        self.runtime = runtime

    def init(self) -> None:
        return

    def update(self, _now: float) -> None:
        return

    def reset(self) -> None:
        return

    def force_safe(self) -> None:
        """Force a safe output state if applicable."""
        return

    def claimed_lines(self) -> List[int]:
        """Return GPIO lines this handler owns, if any."""
        return []


class PlainCoil(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_int_arg(pin.args, 0)
        self.coil = RegHandle(store, "coils", pin.coils, initial)

    def init(self) -> None:
        self.coil.reset()

    def reset(self) -> None:
        self.coil.reset()


class PlainDiscrete(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_int_arg(pin.args, 0)
        self.di = RegHandle(store, "discretes", pin.discretes, initial)

    def init(self) -> None:
        self.di.reset()

    def reset(self) -> None:
        self.di.reset()


class PlainInputReg(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_int_arg(pin.args, 0)
        self.ir = RegHandle(store, "input_regs", pin.input_regs, initial)

    def init(self) -> None:
        self.ir.reset()

    def reset(self) -> None:
        self.ir.reset()


class MetricInputReg(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime", interval_s: float = 1.0) -> None:
        super().__init__(pin, store, runtime)
        self._interval = interval_s
        self._last = 0.0
        self._reg = RegHandle(store, "input_regs", pin.input_regs, 0)

    def update(self, now: float) -> None:
        if now - self._last < self._interval:
            return
        self._last = now
        self._reg.set(self.read_value())

    def read_value(self) -> int:
        raise NotImplementedError

    def reset(self) -> None:
        self._reg.set(0)


class CpuTempInputReg(MetricInputReg):
    def read_value(self) -> int:
        return _cpu_temp_c_x100()


class CpuLoadInputReg(MetricInputReg):
    def read_value(self) -> int:
        return _cpu_load_1m_x100()


class PlainHoldingReg(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_int_arg(pin.args, 0)
        self.hr = RegHandle(store, "holding_regs", pin.holding_regs, initial)

    def init(self) -> None:
        self.hr.reset()

    def reset(self) -> None:
        self.hr.reset()


class PlainInputRegTwoWord(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_u32_arg(pin.args, 0)
        self.reg = TwoWordHandle(store, "input_regs", pin.input_regs, initial)

    def init(self) -> None:
        self.reg.reset()

    def reset(self) -> None:
        self.reg.reset()


class PlainHoldingRegTwoWord(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_u32_arg(pin.args, 0)
        self.reg = TwoWordHandle(store, "holding_regs", pin.holding_regs, initial)

    def init(self) -> None:
        self.reg.reset()

    def reset(self) -> None:
        self.reg.reset()


class PinHash(PinHandler):
    def init(self) -> None:
        self.store.seed_pin_hash(self.runtime.pinmap)

    def reset(self) -> None:
        self.store.seed_pin_hash(self.runtime.pinmap)


class InputDigital(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        self.di = RegHandle(store, "discretes", pin.discretes, 0)
        self._line = _resolve_gpio_line(pin.pin)

    def init(self) -> None:
        if self._line is None:
            LOGGER.warning("InputDigital %s has unsupported pin %r", self.pin.name, self.pin.pin)
            return
        self.runtime.gpio.setup_input(self._line, pull_up=True)
        self.update(time.monotonic())

    def update(self, _now: float) -> None:
        if self._line is None:
            return
        raw = self.runtime.gpio.read(self._line)
        self.di.set(0 if raw else 1)

    def reset(self) -> None:
        self.update(time.monotonic())

    def claimed_lines(self) -> List[int]:
        if self._line is None:
            return []
        return [self._line]


class OutputDigital(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        initial = _parse_int_arg(pin.args, 0)
        self.coil = RegHandle(store, "coils", pin.coils, initial)
        self._line = _resolve_gpio_line(pin.pin)
        self._last = None

    def init(self) -> None:
        if self._line is None:
            LOGGER.warning("OutputDigital %s has unsupported pin %r", self.pin.name, self.pin.pin)
            return
        self.runtime.gpio.setup_output(self._line, bool(self.coil.initial))
        self.coil.reset()
        self.update(time.monotonic())

    def update(self, _now: float) -> None:
        if self._line is None:
            return
        value = bool(self.coil.get())
        if self._last is None or value != self._last:
            self._last = value
            self.runtime.gpio.write(self._line, value)

    def reset(self) -> None:
        self.coil.reset()
        self._last = None
        self.update(time.monotonic())

    def force_safe(self) -> None:
        if self._line is None:
            return
        self.coil.reset()
        safe_val = bool(self.coil.initial)
        self._last = safe_val
        self.runtime.gpio.write(self._line, safe_val)

    def claimed_lines(self) -> List[int]:
        if self._line is None:
            return []
        return [self._line]


class OutputDigitalAutoRelease(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        self.coil = RegHandle(store, "coils", pin.coils, 0)
        self._line = _resolve_gpio_line(pin.pin)
        self._last = None
        self._last_change = 0.0
        self._release_ms = self._parse_release_ms(pin.args)

    @staticmethod
    def _parse_release_ms(args: List[Any]) -> int:
        if not args:
            return 0
        try:
            return max(0, int(args[-1]))
        except (TypeError, ValueError):
            return 0

    def init(self) -> None:
        if self._line is None:
            LOGGER.warning("OutputDigitalAutoRelease %s has unsupported pin %r", self.pin.name, self.pin.pin)
            return
        self.runtime.gpio.setup_output(self._line, False)
        self.coil.reset()
        self._last = bool(self.coil.get())
        self.runtime.gpio.write(self._line, self._last)
        self._last_change = time.monotonic()

    def update(self, now: float) -> None:
        if self._line is None:
            return
        value = bool(self.coil.get())
        if self._last is None or value != self._last:
            self._last = value
            self.runtime.gpio.write(self._line, value)
            if value:
                self._last_change = now

        if self._last and self._release_ms > 0:
            if (now - self._last_change) * 1000.0 >= self._release_ms:
                self.coil.set(0)
                self._last = False
                self.runtime.gpio.write(self._line, False)
                self._last_change = now

    def reset(self) -> None:
        if self._line is None:
            return
        self.coil.reset()
        self._last = bool(self.coil.get())
        self.runtime.gpio.write(self._line, self._last)
        self._last_change = time.monotonic()

    def force_safe(self) -> None:
        if self._line is None:
            return
        self.coil.set(0)
        self._last = False
        self.runtime.gpio.write(self._line, False)

    def claimed_lines(self) -> List[int]:
        if self._line is None:
            return []
        return [self._line]


class BoardReset(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        self.coil = RegHandle(store, "coils", pin.coils, 0)

    def update(self, _now: float) -> None:
        if self.coil.get():
            self.coil.set(0)
            self.runtime.reset_all("board_reset")

    def reset(self) -> None:
        self.coil.set(0)


class BoardShutdown(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime") -> None:
        super().__init__(pin, store, runtime)
        self.coil = RegHandle(store, "coils", pin.coils, 0)
        self.online = RegHandle(store, "discretes", pin.discretes, 1)
        self._command_in_flight = False

    def init(self) -> None:
        self.coil.set(0)
        self.online.set(1)
        self._command_in_flight = False

    def update(self, _now: float) -> None:
        if not self.coil.get():
            return
        self.coil.set(0)
        self.online.set(0)
        if self._command_in_flight:
            LOGGER.warning("BoardShutdown already in flight; ignoring duplicate trigger")
            return
        self._command_in_flight = True
        LOGGER.warning(
            "Board shutdown triggered via BOARD_SHUTDOWN; executing '%s'",
            " ".join(SHUTDOWN_CMD),
        )
        try:
            subprocess.Popen(
                SHUTDOWN_CMD,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as exc:
            self._command_in_flight = False
            LOGGER.exception("Failed to execute shutdown command: %s", exc)

    def reset(self) -> None:
        self.coil.set(0)
        self.online.set(1)
        self._command_in_flight = False


class BoardStats(PinHandler):
    def __init__(self, pin: PinRecord, store: RegisterStore, runtime: "PinRuntime", interval_s: float) -> None:
        super().__init__(pin, store, runtime)
        self._interval = interval_s
        self._last = 0.0

    def init(self) -> None:
        self._write(force=True)

    def update(self, now: float) -> None:
        if now - self._last >= self._interval:
            self._write(force=False, now=now)

    def reset(self) -> None:
        self._write(force=True)

    def _write(self, force: bool, now: Optional[float] = None) -> None:
        if self.pin.input_regs.count != 15:
            LOGGER.warning("BoardStats expects 15 input regs, got %s", self.pin.input_regs.count)
            return
        if now is None:
            now = time.monotonic()
        self._last = now
        version = 1
        ram_kb = _clamp_u16(_mem_available_kb())
        err_count = 0  # TODO: map to libmodbus errors
        err_since_reset = 0  # TODO: map to libmodbus errors
        last_err_code = 0  # TODO: map to libmodbus errors
        overflow_count = 0  # TODO: map to libmodbus errors
        uptime_ms = self.runtime.uptime_ms()
        since_reset_ms = self.runtime.time_since_reset_ms()
        last_err_time = 0

        payload = [
            version,
            ram_kb,
            err_count,
            err_since_reset,
            last_err_code,
            overflow_count,
            *_encode_u32_with_crc(uptime_ms),
            *_encode_u32_with_crc(since_reset_ms),
            *_encode_u32_with_crc(last_err_time),
        ]
        self.store.write_registers("input_regs", self.pin.input_regs, payload)


HANDLER_TYPES = {
    "PLAIN_COIL": PlainCoil,
    "COIL": PlainCoil,
    "PLAIN_DISCRETE_IN": PlainDiscrete,
    "DISCRETE_IN": PlainDiscrete,
    "PLAIN_INPUT_REG": PlainInputReg,
    "INPUT_REG": PlainInputReg,
    "PLAIN_HOLDING_REG": PlainHoldingReg,
    "PLAIN_HOLDINGREG": PlainHoldingReg,
    "HOLDING_REG": PlainHoldingReg,
    "PLAIN_INPUTREG_TWO_WORD": PlainInputRegTwoWord,
    "PLAIN_HOLDINGREG_TWO_WORD": PlainHoldingRegTwoWord,
    "PIN_HASH": PinHash,
    "INPUT_DIGITAL": InputDigital,
    "OUTPUT_DIGITAL": OutputDigital,
    "OUTPUT_DIGITAL_AUTO_RELEASE": OutputDigitalAutoRelease,
    "BOARD_RESET": BoardReset,
    "BOARD_SHUTDOWN": BoardShutdown,
    "BOARD_STATS": BoardStats,
}

METRIC_INPUT_REGS = {
    "pi_cpu_temp_c_x100": CpuTempInputReg,
    "pi_cpu_load_1m_x100": CpuLoadInputReg,
}


class PinRuntime:
    """Runtime loop for GPIO/board logic tied to the register store."""

    def __init__(
        self,
        pinmap: PinMap,
        store: RegisterStore,
        gpio: Optional[GpioAdapter] = None,
        poll_interval: float = 0.02,
        stats_interval: float = 5.0,
        custom_types_dir: Optional[str] = None,
        gpio_claims: Optional[GpioClaimRegistry] = None,
        event_sink: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ) -> None:
        self.pinmap = pinmap
        self.store = store
        self.gpio = gpio or NullGpioAdapter()
        self._gpio_claims = gpio_claims
        self._event_sink = event_sink
        self._poll_interval = poll_interval
        self._stats_interval = stats_interval
        self._handlers: List[PinHandler] = []
        self._handler_types = dict(HANDLER_TYPES)
        self._metric_input_regs = dict(METRIC_INPUT_REGS)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time = time.monotonic()
        self._last_reset_time = self._start_time
        self._reset_lock = threading.Lock()
        self._event_seq = 0
        self._reset_generation = 0
        custom_handlers, custom_metrics = load_custom_handlers(
            custom_types_dir,
            built_in_handlers=self._handler_types.keys(),
            built_in_metrics=self._metric_input_regs.keys(),
        )
        if custom_handlers:
            LOGGER.info("Loaded %s custom handler type(s)", len(custom_handlers))
            self._handler_types.update(custom_handlers)
        if custom_metrics:
            LOGGER.info("Loaded %s custom metric pin binding(s)", len(custom_metrics))
            self._metric_input_regs.update(custom_metrics)
        self._build_handlers()
        self._claim_handler_lines()

    def _build_handlers(self) -> None:
        for pin in self.pinmap.pins:
            metric_cls = self._metric_input_regs.get(pin.name)
            if metric_cls is not None:
                if pin.type not in ("PLAIN_INPUT_REG", "INPUT_REG"):
                    LOGGER.warning("Metric pin %s should use PLAIN_INPUT_REG (found %s)", pin.name, pin.type)
                self._handlers.append(metric_cls(pin, self.store, self))
                continue
            handler_cls = self._handler_types.get(pin.type)
            if handler_cls is None:
                LOGGER.debug("Skipping unsupported pin type %s (%s)", pin.type, pin.name)
                continue
            if handler_cls is BoardStats:
                handler = handler_cls(pin, self.store, self, self._stats_interval)
            else:
                handler = handler_cls(pin, self.store, self)
            self._handlers.append(handler)

    def _claim_handler_lines(self) -> None:
        """Claim GPIO lines used by built-in handlers up front."""
        if self._gpio_claims is None:
            return
        for handler in self._handlers:
            for line in handler.claimed_lines():
                owner = f"pin:{handler.pin.name}"
                try:
                    self._gpio_claims.claim_line(owner, line)
                except GpioClaimError as exc:
                    raise RuntimeError(f"GPIO claim collision for {owner} on line {line}: {exc}") from exc

    def force_safe_outputs(self, reason: str = "") -> None:
        """Force all output pins to their safe state."""
        if reason:
            LOGGER.warning("Forcing outputs to safe state (%s)", reason)
        for handler in self._handlers:
            try:
                handler.force_safe()
            except Exception as exc:
                LOGGER.exception("Failed to set safe output (%s): %s", handler.pin.name, exc)

    def start(self) -> None:
        for handler in self._handlers:
            handler.init()
        if self.pinmap.raw.get("reset_on_init", False):
            self.reset_all("init")
        self._thread = threading.Thread(target=self._loop, name="ogm_pin_runtime", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def reset_all(self, reason: str = "") -> None:
        if not self._reset_lock.acquire(blocking=False):
            return
        try:
            LOGGER.info("Board reset triggered (%s)", reason or "manual")
            self._last_reset_time = time.monotonic()
            self._reset_generation += 1
            for handler in self._handlers:
                handler.reset()
            self.store.seed_pin_hash(self.pinmap)
            self._emit_event(
                "board_reset",
                {
                    "source": "runtime",
                    "reason": reason or "manual",
                    "reset_generation": self._reset_generation,
                    "ts_ms": int(time.time() * 1000),
                },
            )
        finally:
            self._reset_lock.release()

    @property
    def reset_generation(self) -> int:
        return int(self._reset_generation)

    def uptime_ms(self) -> int:
        return int((time.monotonic() - self._start_time) * 1000)

    def time_since_reset_ms(self) -> int:
        return int((time.monotonic() - self._last_reset_time) * 1000)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            start = time.monotonic()
            for handler in self._handlers:
                try:
                    handler.update(start)
                except Exception as exc:
                    LOGGER.exception("Pin handler error (%s): %s", handler.pin.name, exc)
            elapsed = time.monotonic() - start
            sleep_for = self._poll_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

    def _emit_event(self, event: str, payload: Dict[str, Any]) -> None:
        if self._event_sink is None:
            return
        self._event_seq += 1
        out = {"event": event, "seq": self._event_seq}
        out.update(payload)
        self._event_sink([out])
