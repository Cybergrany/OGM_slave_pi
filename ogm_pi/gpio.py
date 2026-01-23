"""GPIO adapter for OGM_slave_pi (libgpiod-backed)."""

from __future__ import annotations

from typing import Any, Dict, Optional
import logging

LOGGER = logging.getLogger(__name__)


class GpioAdapter:
    """Abstract GPIO adapter."""

    def setup_input(self, line: int, pull_up: bool = True) -> None:
        raise NotImplementedError

    def setup_output(self, line: int, initial: bool = False) -> None:
        raise NotImplementedError

    def read(self, line: int) -> int:
        raise NotImplementedError

    def write(self, line: int, value: bool) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return


class NullGpioAdapter(GpioAdapter):
    """No-op GPIO adapter for development."""

    def __init__(self) -> None:
        self._values: Dict[int, int] = {}

    def setup_input(self, line: int, pull_up: bool = True) -> None:
        self._values.setdefault(line, 1 if pull_up else 0)

    def setup_output(self, line: int, initial: bool = False) -> None:
        self._values[line] = 1 if initial else 0

    def read(self, line: int) -> int:
        return int(self._values.get(line, 0))

    def write(self, line: int, value: bool) -> None:
        self._values[line] = 1 if value else 0


class LibgpiodAdapter(GpioAdapter):
    """libgpiod-backed GPIO adapter (supports v1/v2 APIs)."""

    def __init__(self, chip: str = "/dev/gpiochip0", consumer: str = "ogm_pi") -> None:
        self._chip_path = chip
        self._consumer = consumer
        self._backend = ""
        self._requests: Dict[int, Any] = {}
        self._lines: Dict[int, Any] = {}
        self._chip: Optional[Any] = None
        self._gpiod = self._load_gpiod()
        self._init_backend()

    def _load_gpiod(self):
        try:
            import gpiod
        except ImportError as exc:
            raise RuntimeError("gpiod is required for GPIO access (install python3-libgpiod)") from exc
        return gpiod

    def _init_backend(self) -> None:
        if hasattr(self._gpiod, "request_lines"):
            self._backend = "v2"
            line_mod = getattr(self._gpiod, "line", None)
            self._Direction = getattr(self._gpiod, "LineDirection", None) or getattr(line_mod, "Direction", None)
            self._Bias = getattr(self._gpiod, "LineBias", None) or getattr(line_mod, "Bias", None)
            self._Value = getattr(self._gpiod, "LineValue", None) or getattr(line_mod, "Value", None)
            self._LineSettings = getattr(self._gpiod, "LineSettings", None) or getattr(line_mod, "LineSettings", None)
            if not all((self._Direction, self._Bias, self._Value, self._LineSettings)):
                raise RuntimeError("Unsupported gpiod v2 API")
        else:
            self._backend = "v1"
            self._chip = self._gpiod.Chip(self._chip_path)

    def setup_input(self, line: int, pull_up: bool = True) -> None:
        if self._backend == "v2":
            bias = self._Bias.PULL_UP if pull_up else self._Bias.AS_IS
            settings = self._LineSettings(direction=self._Direction.INPUT, bias=bias)
            req = self._gpiod.request_lines(
                self._chip_path,
                consumer=self._consumer,
                config={line: settings},
            )
            self._requests[line] = req
            return

        flags = 0
        if pull_up and hasattr(self._gpiod, "LINE_REQ_FLAG_BIAS_PULL_UP"):
            flags = self._gpiod.LINE_REQ_FLAG_BIAS_PULL_UP
        line_obj = self._chip.get_line(line)
        line_obj.request(consumer=self._consumer, type=self._gpiod.LINE_REQ_DIR_IN, flags=flags)
        self._lines[line] = line_obj

    def setup_output(self, line: int, initial: bool = False) -> None:
        if self._backend == "v2":
            value = self._encode_value(initial)
            settings = self._LineSettings(direction=self._Direction.OUTPUT, output_value=value)
            req = self._gpiod.request_lines(
                self._chip_path,
                consumer=self._consumer,
                config={line: settings},
            )
            self._requests[line] = req
            return

        line_obj = self._chip.get_line(line)
        defaults = [1 if initial else 0]
        line_obj.request(
            consumer=self._consumer,
            type=self._gpiod.LINE_REQ_DIR_OUT,
            default_vals=defaults,
        )
        self._lines[line] = line_obj

    def read(self, line: int) -> int:
        if self._backend == "v2":
            req = self._requests[line]
            return int(self._decode_value(req, line))
        return int(self._lines[line].get_value())

    def write(self, line: int, value: bool) -> None:
        if self._backend == "v2":
            req = self._requests[line]
            encoded = self._encode_value(value)
            if hasattr(req, "set_value"):
                try:
                    req.set_value(line, encoded)
                except TypeError:
                    req.set_value(encoded)
                return
            if hasattr(req, "set_values"):
                req.set_values({line: encoded})
                return
            raise RuntimeError("Unsupported gpiod request API for set_value")

        self._lines[line].set_value(1 if value else 0)

    def close(self) -> None:
        for req in self._requests.values():
            if hasattr(req, "release"):
                try:
                    req.release()
                except OSError:
                    pass
        for line in self._lines.values():
            try:
                line.release()
            except OSError:
                pass
        if self._chip is not None:
            try:
                self._chip.close()
            except OSError:
                pass

    def _encode_value(self, value: bool):
        if hasattr(self, "_Value") and self._Value is not None:
            return self._Value.ACTIVE if value else self._Value.INACTIVE
        return 1 if value else 0

    def _decode_value(self, req, line: int) -> int:
        if hasattr(req, "get_value"):
            try:
                value = req.get_value(line)
            except TypeError:
                value = req.get_value()
            return self._value_to_int(value)
        if hasattr(req, "get_values"):
            values = req.get_values()
            if isinstance(values, dict):
                return self._value_to_int(values.get(line, 0))
            if values:
                return self._value_to_int(values[0])
        raise RuntimeError("Unsupported gpiod request API for get_value")

    def _value_to_int(self, value: Any) -> int:
        if hasattr(self, "_Value") and self._Value is not None:
            if value == self._Value.ACTIVE:
                return 1
            if value == self._Value.INACTIVE:
                return 0
        return 1 if int(value) else 0
