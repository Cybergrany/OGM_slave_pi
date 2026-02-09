"""Supervise a child GUI/app process for OGM_slave_pi."""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass
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

    def _spawn_locked(self, *, reason: str) -> None:
        env = os.environ.copy()
        if self.config.env:
            for key, value in self.config.env.items():
                env[str(key)] = str(value)
        for key, value in self._extra_env.items():
            env[str(key)] = str(value)

        cwd = self.config.cwd or None
        LOGGER.info("Starting app process (%s): %s", reason, " ".join(self._command))
        self._process = subprocess.Popen(
            self._command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )

    def _stop_process_locked(self, *, reason: str) -> None:
        proc = self._process
        if proc is None:
            return

        timeout_s = max(int(self.config.shutdown_timeout_ms), 0) / 1000.0
        LOGGER.info("Stopping app process (%s) pid=%s", reason, proc.pid)
        try:
            proc.terminate()
            proc.wait(timeout=timeout_s if timeout_s > 0 else None)
        except subprocess.TimeoutExpired:
            LOGGER.warning("App process did not exit in time; killing pid=%s", proc.pid)
            proc.kill()
            proc.wait(timeout=2.0)
        except ProcessLookupError:
            pass
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
