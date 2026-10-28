"""Managed, opt-in Objection sessions for the Mobile Android panel."""
from __future__ import annotations

import atexit
import os
import re
import shlex
import shutil
import subprocess
import threading
from datetime import datetime, timezone

from app.services.mobile import MobileResult, run_command

TITLE = "Root Detection Bypass via Objection"
COMMAND = "android root disable"
START_TIMEOUT = 20
SESSION_TIMEOUT = 3600
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class RootSession:
    def __init__(self, package: str, serial: str, argv: list[str]):
        self.package, self.serial, self.argv = package, serial, argv
        self.started = datetime.now(timezone.utc).isoformat()
        self.state = "STARTING"
        self.message = "Waiting for Objection to register root detection hooks."
        self.lock = threading.RLock()
        self.ready = threading.Event()
        self.child = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, shell=False,
            env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"},
        )
        self.timer = threading.Timer(SESSION_TIMEOUT, self.stop)
        self.timer.daemon = True
        self.timer.start()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        # Drain continuously, keeping only a bounded parsing window. Raw tool
        # output can contain application data, so it is never stored or shown.
        window = ""
        try:
            while chunk := self.child.stdout.read1(4096):
                window = (window + _ANSI.sub("", chunk.decode("utf-8", "replace")))[-8192:]
                lower = window.lower()
                if any(text in lower for text in (
                    "traceback (most recent call last)", "error overriding",
                    "frida agent exception", "unable to connect", "server or gadget is not running",
                    "unknown or ambiguous command", "error:",
                )):
                    self.stop("BYPASS_FAILED", "Objection reported an error. Check Frida compatibility and the running app.")
                    return
                if "session detach message" in lower or "process crash report" in lower:
                    self.stop("SESSION_ENDED", "The app or device disconnected; hooks are no longer active.")
                    return
                if re.search(r"Registering job [^\r\n]+\. Name: root-detection-disable\b", window):
                    with self.lock:
                        if self.state == "STARTING":
                            self.state = "HOOKS_ACTIVE_UNVERIFIED"
                            self.message = "Objection registered root detection hooks. Verify the app manually; bypass is not confirmed."
                            self.ready.set()
        except (OSError, ValueError):
            self.stop("BYPASS_FAILED", "Unable to read the Objection session.")
        finally:
            self.stop("SESSION_ENDED", "Objection exited; hooks are no longer active.")
            self.child.stdout.close()

    def stop(self, state: str = "SESSION_ENDED", message: str = "Session closed (application shutdown or one-hour limit).") -> None:
        with self.lock:
            if self.state not in {"BYPASS_FAILED", "SESSION_ENDED"}:
                self.state, self.message = state, message
            self.timer.cancel()
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=3)
            if self.child.stdin:
                self.child.stdin.close()
            self.ready.set()

    def result(self) -> MobileResult:
        with self.lock:
            if self.child.poll() is not None and self.state not in {"BYPASS_FAILED", "SESSION_ENDED"}:
                self.stop("SESSION_ENDED", "Objection exited; hooks are no longer active.")
            return MobileResult(
                self.state == "HOOKS_ACTIVE_UNVERIFIED", TITLE, shlex.join(self.argv),
                f"UTC: {self.started}\nPackage: {self.package}\nDevice: {self.serial}\n"
                f"Mode: attach\nCommand: {COMMAND}\nState: {self.state}\n{self.message}",
            )


class ObjectionRootBypass:
    def __init__(self):
        self.lock = threading.RLock()
        self.sessions: dict[tuple[str, str], RootSession] = {}

    def start(self, package: str) -> MobileResult:
        package = package.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
            return self._failure("Enter a valid Android package name, for example com.example.app.")
        with self.lock:
            for executable, instruction in (
                ("adb", "Install Android SDK platform-tools."),
                ("objection", "Install objection in your tool environment: pip install objection."),
                ("frida-ps", "Install frida-tools in your tool environment: pip install frida-tools."),
            ):
                if not shutil.which(executable):
                    return self._failure(f"{executable} is missing from PATH. {instruction}")
            devices = run_command(["adb", "devices"], timeout=10)
            if not devices.ok:
                return self._failure("ADB device discovery failed. Check the ADB connection.")
            connected = [line.split() for line in devices.output.splitlines()
                         if line.strip() and not line.startswith(("List of devices", "*"))]
            selected = os.environ.get("ANDROID_SERIAL", "").strip()
            if selected:
                connected = [row for row in connected if row[0] == selected]
            if len(connected) != 1 or len(connected[0]) < 2 or connected[0][1] != "device":
                return self._failure("Connect and authorize one Android device. For multiple devices, set ANDROID_SERIAL before starting DroidBoard.")
            serial = connected[0][0]
            key = (serial, package)
            existing = self.sessions.get(key)
            if existing and existing.result().ok:
                return existing.result()
            # A process listing checks Frida without starting, rooting, or
            # installing anything on the device.
            frida = run_command(["frida-ps", "-D", serial], timeout=10)
            if not frida.ok:
                return self._failure("Frida cannot connect. Prepare a compatible Frida-server on the test device and start the target app manually.")
            help_result = run_command(["objection", "--help"], timeout=10)
            start_help = run_command(["objection", "start", "--help"], timeout=10)
            if (not help_result.ok or not start_help.ok
                    or not all(flag in help_result.output for flag in ("--name", "--serial"))
                    or "--startup-command" not in start_help.output):
                return self._failure("This Objection version must support --name, --serial and start --startup-command. Update Objection.")
            argv = ["objection", "--serial", serial, "--name", package,
                    "start", "--startup-command", COMMAND]
            try:
                current = RootSession(package, serial, argv)
            except OSError:
                return self._failure("Unable to start Objection. Check its installation.")
            self.sessions[key] = current
            try:
                if not current.ready.wait(START_TIMEOUT):
                    current.stop("BYPASS_FAILED", "Timed out waiting for hook registration. Check the running app and Frida setup.")
            except BaseException:
                current.stop()
                raise
            return current.result()

    def status(self, package: str) -> MobileResult | None:
        with self.lock:
            matches = [value for (_, name), value in self.sessions.items() if name == package]
            return matches[-1].result() if matches else None

    def stop(self) -> None:
        with self.lock:
            for current in self.sessions.values():
                current.stop()

    @staticmethod
    def _failure(message: str) -> MobileResult:
        return MobileResult(False, TITLE, COMMAND, f"State: PRECHECK_FAILED\n{message}")


root_bypass = ObjectionRootBypass()
atexit.register(root_bypass.stop)
