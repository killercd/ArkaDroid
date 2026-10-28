"""Install and start the matching Frida server on an Android test emulator."""
from __future__ import annotations

import lzma
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from app.services.mobile import MobileResult, run_command
from app.services.frida_runtime import PROBE_CODE, VERSION_CODE, objection_python

TITLE = "Install Frida"
REMOTE_PATH = "/data/local/tmp/frida-server"
LOG_PATH = "/data/local/tmp/frida-server.log"
START_COMMAND = f"nohup {REMOTE_PATH} >{LOG_PATH} 2>&1 </dev/null &"
ARCHITECTURES = {"x86": "x86", "x86_64": "x86_64", "armeabi-v7a": "arm", "arm64-v8a": "arm64"}
INSTALL_LOCK = threading.Lock()


def _download_server(version: str, arch: str, destination: Path) -> None:
    url = (f"https://github.com/frida/frida/releases/download/{version}/"
           f"frida-server-{version}-android-{arch}.xz")
    request = urllib.request.Request(url, headers={"User-Agent": "DroidBoard"})
    with urllib.request.urlopen(request, timeout=30) as response:
        with lzma.LZMAFile(response) as archive, destination.open("wb") as output:
            size = 0
            while chunk := archive.read(1024 * 1024):
                size += len(chunk)
                if size > 128 * 1024 * 1024:
                    raise ValueError("The Frida server download exceeds the size limit.")
                output.write(chunk)
    if not size:
        raise ValueError("The Frida server download is empty.")


def install_frida() -> MobileResult:
    if not INSTALL_LOCK.acquire(blocking=False):
        return MobileResult(False, TITLE, "", "Another Frida installation is in progress.")
    try:
        return _install_frida()
    finally:
        INSTALL_LOCK.release()


def _install_frida() -> MobileResult:
    commands = []

    def execute(argv: list[str], timeout: int = 15) -> MobileResult:
        result = run_command(argv, timeout=timeout)
        commands.append(result.command)
        return result

    def finish(ok: bool, message: str) -> MobileResult:
        return MobileResult(ok, TITLE, "\n".join(commands), message)

    for executable in ("adb", "objection"):
        if not shutil.which(executable):
            return finish(False, f"{executable} is missing from PATH. Install Android SDK platform-tools and Objection first.")
    runtime = objection_python()
    if not runtime:
        return finish(False, "Cannot locate Objection's Python environment. Install Objection with pip/pipx and ensure its launcher is on PATH.")
    devices = execute(["adb", "devices"])
    if not devices.ok:
        return finish(False, f"ADB discovery failed: {devices.output[:1000]}")
    rows = [line.split() for line in devices.output.splitlines()
            if line.strip() and not line.startswith(("List of devices", "*"))]
    selected = os.environ.get("ANDROID_SERIAL", "").strip()
    if selected:
        rows = [row for row in rows if row[0] == selected]
    if len(rows) != 1 or len(rows[0]) < 2 or rows[0][1] != "device":
        return finish(False, "Connect and authorize one emulator. With multiple devices, set ANDROID_SERIAL before starting DroidBoard.")
    serial = rows[0][0]
    adb = ["adb", "-s", serial]
    emulator = execute([*adb, "shell", "getprop", "ro.kernel.qemu"])
    if not emulator.ok or emulator.output.strip() != "1":
        return finish(False, "Install Frida is supported only on Android emulators.")
    version_result = execute([*runtime, "-c", VERSION_CODE])
    version = version_result.output.strip()
    if not version_result.ok or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return finish(False, f"Cannot determine Objection's Frida version: {version_result.output[:1000]}")
    probe_argv = [*runtime, "-c", PROBE_CODE, serial]
    running = execute([*adb, "shell", "pidof", "frida-server"])
    old_pids = []
    if running.ok and running.output.strip():
        installed = execute([*adb, "shell", REMOTE_PATH, "--version"])
        probe = execute(probe_argv)
        if installed.ok and installed.output.strip() == version and probe.ok:
            return finish(True, f"Frida-server {version} is already reachable on {serial} using Objection's environment. No new server was started.")
        old_pids = running.output.split()
        if not all(pid.isdigit() for pid in old_pids):
            return finish(False, "Cannot determine the running Frida server PID.")
        for pid in old_pids:
            location = execute([*adb, "shell", "readlink", f"/proc/{pid}/exe"])
            if not location.ok or location.output.strip() != REMOTE_PATH:
                return finish(False, "A different Frida server is running. Stop it manually before installing the managed server.")
    abi = execute([*adb, "shell", "getprop", "ro.product.cpu.abi"])
    arch = ARCHITECTURES.get(abi.output.strip()) if abi.ok else None
    if not arch:
        return finish(False, f"Unsupported emulator ABI: {abi.output.strip()[:100]}")

    # Download before changing the emulator. This uses the exact installed
    # client version, never the latest release with potentially incompatible RPCs.
    try:
        with tempfile.TemporaryDirectory(prefix="droidboard-frida-") as directory:
            binary = Path(directory) / "frida-server"
            _download_server(version, arch, binary)
            rooted = execute([*adb, "root"], timeout=30)
            if not rooted.ok:
                return finish(False, f"Cannot enable root ADB on this emulator: {rooted.output[:1000]}")
            ready = execute([*adb, "wait-for-device"], timeout=30)
            uid = execute([*adb, "shell", "id", "-u"]) if ready.ok else ready
            if not uid.ok or uid.output.strip() != "0":
                return finish(False, "This emulator does not allow root ADB. Use a root-capable AOSP/Google APIs emulator image.")
            if old_pids:
                stopped = execute([*adb, "shell", "kill", *old_pids])
                if not stopped.ok:
                    return finish(False, f"Unable to stop the previous Frida server: {stopped.output[:1000]}")
                for _ in range(20):
                    remaining = execute([*adb, "shell", "pidof", "frida-server"])
                    if not remaining.output.strip():
                        break
                    time.sleep(0.1)
                else:
                    return finish(False, "Previous Frida server did not stop. Installation aborted.")
            for argv in (
                [*adb, "push", str(binary), REMOTE_PATH],
                [*adb, "shell", "chmod", "755", REMOTE_PATH],
                # Redirect all standard streams before starting the server.
                # --daemonize leaves the ADB transport open on some emulators.
                [*adb, "shell", START_COMMAND],
            ):
                step = execute(argv, timeout=30)
                if not step.ok:
                    log = execute([*adb, "shell", "tail", "-n", "30", LOG_PATH]) if argv[-1] == START_COMMAND else None
                    return finish(False, f"Failed command: {step.command}\n{step.output[:1000]}\n"
                                  + (f"Server log ({LOG_PATH}):\n{log.output[:1500]}" if log else ""))
    except (OSError, ValueError, EOFError, lzma.LZMAError) as exc:
        return finish(False, f"Unable to download/extract Frida {version} for {arch}: {str(exc)[:500]}")
    for attempt in range(5):
        verified = execute(probe_argv, timeout=10)
        if verified.ok:
            break
        if attempt < 4:
            time.sleep(0.3)
    if not verified.ok:
        log = execute([*adb, "shell", "tail", "-n", "30", LOG_PATH])
        return finish(False, f"Frida was installed but the connection check failed:\n{verified.output[:1000]}\n"
                      f"Server log ({LOG_PATH}):\n{log.output[:1500]}")
    return finish(True, f"Frida-server {version} ({arch}) installed at {REMOTE_PATH} and started on {serial}.\n"
                  f"Connection verified using Objection's environment. Server log: {LOG_PATH}\n"
                  "Open the target app, then click disable root detection.\n"
                  "The server runs until the emulator restarts; its binary remains installed.")
