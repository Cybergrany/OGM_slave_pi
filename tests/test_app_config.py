import unittest

from ogm_pi.app_supervisor import MultiAppSupervisor
from ogm_pi.daemon import (
    APP_CONFIG_UPGRADE_MESSAGE,
    ConfigLoadError,
    build_app_supervisors,
    validate_app_config_schema,
)
from ogm_pi.gpio_claims import GpioClaimError, GpioClaimRegistry
from ogm_pi.pin_resolver import PinResolver
from ogm_pi.pinmap import PinMap, PinRecord, RegSpan


def make_pinmap() -> PinMap:
    pins = [
        PinRecord(
            name="GPIO_A",
            type="GPIO_TEST",
            pin=5,
            args=[],
            coils=RegSpan(0, 0),
            discretes=RegSpan(0, 0),
            input_regs=RegSpan(0, 0),
            holding_regs=RegSpan(0, 0),
        ),
        PinRecord(
            name="GPIO_B",
            type="GPIO_TEST",
            pin=6,
            args=[],
            coils=RegSpan(0, 0),
            discretes=RegSpan(0, 0),
            input_regs=RegSpan(0, 0),
            holding_regs=RegSpan(0, 0),
        ),
    ]
    raw = {
        "address": 41,
        "hash": 123,
        "label": "test board",
        "pins": [],
        "totals": {"coils": 0, "discretes": 0, "input_regs": 0, "holding_regs": 0},
    }
    return PinMap(raw=raw, pins=pins, pins_by_name={pin.name: pin for pin in pins})


def make_app(name: str, *, gpio_bindings: list[str] | None = None) -> dict:
    return {
        "enabled": True,
        "name": name,
        "command": "python3 -c 'import time; time.sleep(1)'",
        "pin_bindings": [],
        "gpio_bindings": list(gpio_bindings or []),
        "env": {},
    }


class AppConfigSchemaTest(unittest.TestCase):
    def test_valid_v2_schema_accepts_apps_mapping(self) -> None:
        validate_app_config_schema({"app_config_version": 2, "apps": {"one": {"name": "one"}}})

    def test_legacy_single_app_config_fails_loudly(self) -> None:
        with self.assertRaises(ConfigLoadError) as ctx:
            validate_app_config_schema({"app_config_version": 2, "app": {"name": "old"}, "apps": {}})
        self.assertIn(APP_CONFIG_UPGRADE_MESSAGE, str(ctx.exception))
        self.assertIn("legacy top-level app", str(ctx.exception))

    def test_missing_version_fails_loudly(self) -> None:
        with self.assertRaises(ConfigLoadError) as ctx:
            validate_app_config_schema({"apps": {}})
        self.assertIn(APP_CONFIG_UPGRADE_MESSAGE, str(ctx.exception))
        self.assertIn("Expected app_config_version", str(ctx.exception))

    def test_app_key_must_match_app_name(self) -> None:
        with self.assertRaises(ConfigLoadError) as ctx:
            validate_app_config_schema({"app_config_version": 2, "apps": {"one": {"name": "two"}}})
        self.assertIn("App key/name mismatch", str(ctx.exception))


class AppSupervisorBuildTest(unittest.TestCase):
    def test_valid_two_app_config_builds_two_supervisors(self) -> None:
        pinmap = make_pinmap()
        supervisors, metas = build_app_supervisors(
            {
                "apps": {
                    "camera": make_app("camera", gpio_bindings=["GPIO_A"]),
                    "audio": make_app("audio", gpio_bindings=["GPIO_B"]),
                }
            },
            pinmap=pinmap,
            resolver=PinResolver(pinmap),
            gpio_claims=GpioClaimRegistry(),
            socket_path="/tmp/ogm_pi.sock",
            apps_dir="/opt/OGM_slave_pi/apps",
        )

        self.assertEqual(supervisors.names, ["camera", "audio"])
        self.assertEqual([meta["name"] for meta in metas], ["camera", "audio"])

    def test_gpio_conflict_across_apps_fails_with_owner_name(self) -> None:
        pinmap = make_pinmap()
        with self.assertRaises(GpioClaimError) as ctx:
            build_app_supervisors(
                {
                    "apps": {
                        "camera": make_app("camera", gpio_bindings=["GPIO_A"]),
                        "audio": make_app("audio", gpio_bindings=["GPIO_A"]),
                    }
                },
                pinmap=pinmap,
                resolver=PinResolver(pinmap),
                gpio_claims=GpioClaimRegistry(),
                socket_path="/tmp/ogm_pi.sock",
                apps_dir="/opt/OGM_slave_pi/apps",
            )
        self.assertIn("already claimed by app:camera", str(ctx.exception))


class FakeSupervisor:
    def __init__(self, name: str) -> None:
        self.name = name
        self.reload_count = 0

    def reload(self) -> dict:
        self.reload_count += 1
        return {"ok": True, "name": self.name}

    def status(self) -> dict:
        return {"name": self.name}


class MultiAppSupervisorTest(unittest.TestCase):
    def test_reload_all_and_reload_one(self) -> None:
        camera = FakeSupervisor("camera")
        audio = FakeSupervisor("audio")
        supervisor = MultiAppSupervisor({"camera": camera, "audio": audio})  # type: ignore[arg-type]

        self.assertEqual(supervisor.reload("audio"), {"ok": True, "name": "audio"})
        self.assertEqual(camera.reload_count, 0)
        self.assertEqual(audio.reload_count, 1)

        result = supervisor.reload()
        self.assertEqual(sorted(result["apps"].keys()), ["audio", "camera"])
        self.assertEqual(camera.reload_count, 1)
        self.assertEqual(audio.reload_count, 2)

    def test_reload_unknown_app_fails(self) -> None:
        supervisor = MultiAppSupervisor({})
        with self.assertRaises(ValueError):
            supervisor.reload("missing")


if __name__ == "__main__":
    unittest.main()
