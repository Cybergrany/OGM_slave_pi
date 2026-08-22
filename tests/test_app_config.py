import os
import signal
import sys
import time
import unittest
from unittest import mock

from ogm_pi.app_supervisor import AppConfig, AppSupervisor, MultiAppSupervisor
from ogm_pi.daemon import (
    APP_CONFIG_UPGRADE_MESSAGE,
    ConfigLoadError,
    build_app_supervisors,
    extend_systemd_stop_timeout,
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


def make_app(
    name: str,
    *,
    pin_bindings: list[object] | None = None,
    gpio_bindings: list[str] | None = None,
) -> dict:
    return {
        "enabled": True,
        "name": name,
        "command": "python3 -c 'import time; time.sleep(1)'",
        "pin_bindings": list(pin_bindings or []),
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

    def test_writable_pin_binding_conflict_fails_loudly(self) -> None:
        pinmap = make_pinmap()
        with self.assertRaises(ValueError) as ctx:
            build_app_supervisors(
                {
                    "apps": {
                        "camera": make_app("camera", pin_bindings=["GPIO_A"]),
                        "audio": make_app("audio", pin_bindings=["GPIO_A"]),
                    }
                },
                pinmap=pinmap,
                resolver=PinResolver(pinmap),
                gpio_claims=GpioClaimRegistry(),
                socket_path="/tmp/ogm_pi.sock",
                apps_dir="/opt/OGM_slave_pi/apps",
            )
        self.assertIn("pin binding write conflict", str(ctx.exception))
        self.assertIn("Use access: read", str(ctx.exception))

    def test_read_only_pin_binding_can_be_shared(self) -> None:
        pinmap = make_pinmap()
        supervisors, metas = build_app_supervisors(
            {
                "apps": {
                    "camera": make_app("camera", pin_bindings=[{"name": "GPIO_A", "access": "read"}]),
                    "audio": make_app("audio", pin_bindings=[{"name": "GPIO_A", "access": "read"}]),
                }
            },
            pinmap=pinmap,
            resolver=PinResolver(pinmap),
            gpio_claims=GpioClaimRegistry(),
            socket_path="/tmp/ogm_pi.sock",
            apps_dir="/opt/OGM_slave_pi/apps",
        )

        self.assertEqual(supervisors.names, ["camera", "audio"])
        self.assertEqual(metas[0]["pin_bindings"][0]["access"], "read")


class AppSupervisorProcessGroupTest(unittest.TestCase):
    def test_spawn_creates_dedicated_process_session(self) -> None:
        supervisor = AppSupervisor(
            AppConfig(enabled=True, name="camera", command="python3 app.py", startup_timeout_ms=0)
        )
        proc = mock.Mock(pid=1234, stdout=None, stderr=None)
        with mock.patch("ogm_pi.app_supervisor.subprocess.Popen", return_value=proc) as popen:
            supervisor._spawn_locked(reason="test")

        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_stop_targets_entire_process_group(self) -> None:
        supervisor = AppSupervisor(
            AppConfig(enabled=True, name="camera", command="python3 app.py", shutdown_timeout_ms=500)
        )
        proc = mock.Mock(pid=4321)
        proc.poll.return_value = None
        signals: list[tuple[int, int]] = []

        def fake_killpg(pgid: int, sig: int) -> None:
            signals.append((pgid, sig))
            if sig == 0:
                raise ProcessLookupError

        with mock.patch("ogm_pi.app_supervisor.os.killpg", side_effect=fake_killpg):
            supervisor._stop_process_group(proc, reason="test", timeout_s=0.5)

        self.assertEqual(signals[0], (4321, signal.SIGTERM))
        self.assertNotIn((4321, signal.SIGKILL), signals)
        proc.wait.assert_called_once()

    def test_reloaded_process_keeps_restart_policy(self) -> None:
        supervisor = AppSupervisor(
            AppConfig(
                enabled=True,
                name="camera",
                command=f"{sys.executable} -c 'import time; time.sleep(60)'",
                restart_policy="always",
                restart_backoff_ms=0,
                startup_timeout_ms=0,
                shutdown_timeout_ms=500,
            )
        )
        supervisor.start()
        try:
            reloaded = supervisor.reload()
            reloaded_pid = int(reloaded["pid"])
            os.killpg(reloaded_pid, signal.SIGTERM)

            deadline = time.monotonic() + 3.0
            restarted_pid = None
            while time.monotonic() < deadline:
                status = supervisor.status()
                candidate = status.get("pid")
                if status.get("alive") and candidate not in {None, reloaded_pid}:
                    restarted_pid = int(candidate)
                    break
                time.sleep(0.02)

            self.assertIsNotNone(restarted_pid)
            self.assertGreaterEqual(supervisor.status()["restart_count"], 1)
        finally:
            supervisor.stop()


class FakeSupervisor:
    def __init__(self, name: str) -> None:
        self.name = name
        self.reload_count = 0
        self.stop_count = 0

    def reload(self) -> dict:
        self.reload_count += 1
        return {"ok": True, "name": self.name}

    def status(self) -> dict:
        return {"name": self.name}

    def stop(self) -> None:
        self.stop_count += 1


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

    def test_stop_resets_operation_timeout_around_each_app(self) -> None:
        camera = FakeSupervisor("camera")
        audio = FakeSupervisor("audio")
        boundaries: list[str] = []
        supervisor = MultiAppSupervisor({"camera": camera, "audio": audio})  # type: ignore[arg-type]

        supervisor.stop(operation_boundary=boundaries.append)

        self.assertEqual(camera.stop_count, 1)
        self.assertEqual(audio.stop_count, 1)
        self.assertEqual(
            boundaries,
            [
                "stop_app:audio:start",
                "stop_app:audio:complete",
                "stop_app:camera:start",
                "stop_app:camera:complete",
            ],
        )


class SystemdStopTimeoutTest(unittest.TestCase):
    def test_extend_stop_timeout_sends_five_second_window(self) -> None:
        with mock.patch("ogm_pi.daemon.notify_systemd", return_value=True) as notify:
            extend_systemd_stop_timeout("stop_app:camera:start")

        message = notify.call_args.args[0]
        self.assertIn("EXTEND_TIMEOUT_USEC=5000000", message)
        self.assertIn("STATUS=Stopping OGM Pi: stop_app:camera:start", message)


if __name__ == "__main__":
    unittest.main()
