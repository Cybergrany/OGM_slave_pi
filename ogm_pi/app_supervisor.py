"""Supervise a child GUI/app process for OGM_slave_pi."""

from __future__ import annotations

import logging
import os
import shlex
import signal
import subprocess
import threading
import time
from typing import IO
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

LOGGER = logging.getLogger(__name__)


@dataclass
class AppConfig:
    enabled: bool = False
    name: str = "default"
    command: str = ""
    cwd: Optional[str] = None
    restart_policy: str = "always"  # always | on-failure | never
    restart_backoff_ms: int = 2000
    startup_timeout_ms: int = 10000
    shutdown_timeout_ms: int = 5000
    env: Dict[str, str] | None = None


class AppSupervisor:
    """Manage child process lifecycle with restart policies."""

    def __init__(self, config: AppConfig, *, extra_env: Optional[Dict[str, str]] = None) -> None:
        self.config = config
        self._extra_env = dict(extra_env or {})
        self._command = self._parse_command(config.command)

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen[str]] = None
        self._suppress_restart_once = False

        self._restart_count = 0
        self._last_exit_code: Optional[int] = None
        self._last_exit_ts_ms: Optional[int] = None

    def _start_output_pumps_locked(self, proc: subprocess.Popen[str]) -> None:
        if proc.stdout is not None:
            thread = threading.Thread(
                target=self._pump_stream,
                args=(proc, proc.stdout, "stdout", logging.INFO),
                name=f"ogm_app_stdout_{proc.pid}",
                daemon=True,
            )
            thread.start()
        if proc.stderr is not None:
            thread = threading.Thread(
                target=self._pump_stream,
                args=(proc, proc.stderr, "stderr", logging.WARNING),
                name=f"ogm_app_stderr_{proc.pid}",
                daemon=True,
            )
            thread.start()

    def _pump_stream(
        self,
        proc: subprocess.Popen[str],
        stream: IO[str],
        stream_name: str,
        level: int,
    ) -> None:
        app_name = self.config.name
        pid = proc.pid
        try:
            for raw_line in iter(stream.readline, ""):
                line = raw_line.rstrip()
                if not line:
                    continue
                LOGGER.log(level, "App[%s pid=%s %s] %s", app_name, pid, stream_name, line)
        except Exception as exc:
            LOGGER.debug("App[%s pid=%s] log pump error on %s: %s", app_name, pid, stream_name, exc)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    @staticmethod
    def _parse_command(command: str | List[str]) -> List[str]:
        if isinstance(command, list):
            parts = [str(part) for part in command if str(part).strip()]
        else:
            parts = shlex.split(str(command))
        if not parts:
            raise ValueError("App command is empty")
        return parts

    def start(self) -> None:
        if not self.config.enabled:
            LOGGER.info("App supervisor disabled (app.enabled=false)")
            return

        with self._lock:
            if self._monitor_thread and self._monitor_thread.is_alive():
                return
            self._stop_event.clear()
            self._spawn_locked(reason="start")
            self._monitor_thread = threading.Thread(target=self._monitor_loop, name="ogm_app_supervisor", daemon=True)
            self._monitor_thread.start()

        timeout_s = max(int(self.config.startup_timeout_ms), 0) / 1000.0
        if timeout_s <= 0:
            return
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                proc = self._process
            if proc is None:
                time.sleep(0.05)
                continue
            rc = proc.poll()
            if rc is None:
                return
            time.sleep(0.05)
        with self._lock:
            proc = self._process
        if proc is None or proc.poll() is not None:
            raise RuntimeError("App process failed to stay alive during startup window")

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._suppress_restart_once = True
            self._stop_process_locked(reason="stop")
        thread = self._monitor_thread
        if thread is not None:
            thread.join(timeout=2.0)

    def reload(self) -> Dict[str, object]:
        if not self.config.enabled:
            raise RuntimeError("App reload requested but app.enabled=false")
        with self._lock:
            self._suppress_restart_once = True
            self._stop_process_locked(reason="reload")
            self._spawn_locked(reason="reload")
            pid = self._process.pid if self._process is not None else None
        return {
            "ok": True,
            "name": self.config.name,
            "pid": pid,
            "restart_count": self._restart_count,
        }

    def status(self) -> Dict[str, object]:
        with self._lock:
            proc = self._process
            pid = proc.pid if proc is not None else None
            alive = bool(proc and proc.poll() is None)
            return {
                "enabled": self.config.enabled,
                "name": self.config.name,
                "pid": pid,
                "alive": alive,
                "restart_count": self._restart_count,
                "last_exit_code": self._last_exit_code,
                "last_exit_ts_ms": self._last_exit_ts_ms,
                "restart_policy": self.config.restart_policy,
            }

    def root_pid(self) -> Optional[int]:
        with self._lock:
            proc = self._process
            if proc is None or proc.poll() is not None:
                return None
            return int(proc.pid)

    def _prepare_child_env(self, env: Dict[str, str], cwd: Optional[str]) -> None:
        home_value = str(env.get("HOME", "")).strip()
        needs_home = (not home_value) or (home_value == "/nonexistent")
        if needs_home:
            base_dir = Path(cwd) if cwd else (Path("/tmp") / f"ogm_pi_app_{self.config.name}")
            runtime_home = base_dir / ".app_home"
            runtime_home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(runtime_home)
            home_value = str(runtime_home)
            LOGGER.info("App[%s] assigned writable HOME=%s", self.config.name, runtime_home)

        if home_value:
            xdg_config = str(env.get("XDG_CONFIG_HOME", "")).strip() or str(Path(home_value) / ".config")
            xdg_cache = str(env.get("XDG_CACHE_HOME", "")).strip() or str(Path(home_value) / ".cache")
            Path(xdg_config).mkdir(parents=True, exist_ok=True)
            Path(xdg_cache).mkdir(parents=True, exist_ok=True)
            env.setdefault("XDG_CONFIG_HOME", xdg_config)
            env.setdefault("XDG_CACHE_HOME", xdg_cache)

    def _spawn_locked(self, *, reason: str) -> None:
        env = os.environ.copy()
        if self.config.env:
            for key, value in self.config.env.items():
                env[str(key)] = str(value)
        for key, value in self._extra_env.items():
            env[str(key)] = str(value)

        cwd = self.config.cwd or None
        self._prepare_child_env(env, cwd)
        LOGGER.info("Starting app process (%s): %s", reason, " ".join(self._command))
        self._process = subprocess.Popen(
            self._command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            start_new_session=True,
        )
        self._start_output_pumps_locked(self._process)

    @staticmethod
    def _process_group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _stop_process_group(self, proc: subprocess.Popen[str], *, reason: str, timeout_s: float) -> None:
        pgid = proc.pid
        LOGGER.info("Stopping app process group (%s) pgid=%s", reason, pgid)
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return

        deadline = time.monotonic() + max(timeout_s, 0.0)
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        while self._process_group_exists(pgid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if not self._process_group_exists(pgid):
            return

        LOGGER.warning("App process group did not exit in time; killing pgid=%s", pgid)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            return
        if proc.poll() is None:
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                LOGGER.error("App process leader remained after SIGKILL pid=%s", proc.pid)

    def _stop_process_locked(self, *, reason: str) -> None:
        proc = self._process
        if proc is None:
            return

        timeout_s = max(int(self.config.shutdown_timeout_ms), 0) / 1000.0
        try:
            self._stop_process_group(proc, reason=reason, timeout_s=timeout_s)
        finally:
            self._process = None

    def _monitor_loop(self) -> None:
        backoff_s = max(int(self.config.restart_backoff_ms), 0) / 1000.0
        while not self._stop_event.is_set():
            with self._lock:
                proc = self._process
            if proc is None:
                time.sleep(0.1)
                continue

            rc = proc.poll()
            if rc is None:
                time.sleep(0.2)
                continue

            cleanup_timeout_s = min(max(int(self.config.shutdown_timeout_ms), 0) / 1000.0, 1.0)
            self._stop_process_group(proc, reason="leader_exit", timeout_s=cleanup_timeout_s)

            suppress = False
            with self._lock:
                if proc is self._process:
                    self._process = None
                self._last_exit_code = int(rc)
                self._last_exit_ts_ms = int(time.time() * 1000)
                suppress = self._suppress_restart_once
                if suppress:
                    self._suppress_restart_once = False

            if self._stop_event.is_set():
                continue
            if suppress:
                continue

            should_restart = self._should_restart(rc)
            if not should_restart:
                LOGGER.warning("App exited (rc=%s) and restart policy %s prevents restart", rc, self.config.restart_policy)
                continue

            LOGGER.warning("App exited (rc=%s); restarting after %.3fs", rc, backoff_s)
            if backoff_s > 0:
                deadline = time.monotonic() + backoff_s
                while not self._stop_event.is_set() and time.monotonic() < deadline:
                    time.sleep(0.05)
            if self._stop_event.is_set():
                continue

            with self._lock:
                if self._process is None and not self._stop_event.is_set():
                    self._restart_count += 1
                    self._spawn_locked(reason="policy_restart")

    def _should_restart(self, rc: int) -> bool:
        policy = (self.config.restart_policy or "always").strip().lower()
        if policy == "never":
            return False
        if policy == "on-failure":
            return rc != 0
        return True


class MultiAppSupervisor:
    """Coordinate multiple per-app supervisors through one runtime path."""

    def __init__(self, supervisors: Dict[str, AppSupervisor]) -> None:
        self._supervisors = dict(supervisors)

    def __bool__(self) -> bool:
        return bool(self._supervisors)

    @property
    def names(self) -> list[str]:
        return list(self._supervisors.keys())

    def start(self) -> None:
        started: list[AppSupervisor] = []
        try:
            for name, supervisor in self._supervisors.items():
                LOGGER.info("Starting supervised app: %s", name)
                supervisor.start()
                started.append(supervisor)
        except Exception:
            for supervisor in reversed(started):
                try:
                    supervisor.stop()
                except Exception:
                    LOGGER.exception("Failed to stop app after multi-app startup error")
            raise

    def stop(self) -> None:
        for name, supervisor in reversed(list(self._supervisors.items())):
            try:
                LOGGER.info("Stopping supervised app: %s", name)
                supervisor.stop()
            except Exception:
                LOGGER.exception("Failed to stop supervised app: %s", name)

    def reload(self, name: Optional[str] = None) -> Dict[str, object]:
        target = str(name or "").strip()
        if target:
            supervisor = self._supervisors.get(target)
            if supervisor is None:
                raise ValueError(f"Unknown app '{target}'")
            return supervisor.reload()

        results: Dict[str, object] = {}
        for app_name, supervisor in self._supervisors.items():
            results[app_name] = supervisor.reload()
        return {"ok": True, "apps": results}

    def status(self) -> Dict[str, object]:
        return {
            "ok": True,
            "apps": {name: supervisor.status() for name, supervisor in self._supervisors.items()},
        }

    def resolve_peer_app(self, pid: int) -> Optional[str]:
        roots = {
            int(root_pid): name
            for name, supervisor in self._supervisors.items()
            for root_pid in [supervisor.root_pid()]
            if root_pid is not None
        }
        current = int(pid)
        seen: set[int] = set()
        while current > 1 and current not in seen:
            owner = roots.get(current)
            if owner is not None:
                return owner
            seen.add(current)
            current = _read_ppid(current)
        return None


def _read_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{int(pid)}/status", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("PPid:"):
                    return int(line.split(":", 1)[1].strip())
    except Exception:
        return 0
    return 0
