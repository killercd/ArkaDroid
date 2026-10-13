"""Device discovery and IPA installation for Droidboard."""
from __future__ import annotations

import plistlib
import os
import queue
import re
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from app.services.mobile import MobileResult, run_command

PROMPTS = [
    r"Apple ID: ?",
    r"Password: ?",
    r"A code has been sent to your devices, please type it here \(type `resend` to resend one\): ?",
]
PROMPT_NAMES = ("apple_id", "password", "verification_code")


class InstallJob:
    """One in-memory install; never retain or publish subprocess output/credentials."""

    def __init__(self, owner: str, project_id: int, path: Path, udid: str, mode: str,
                 network: bool = False):
        self.id = secrets.token_urlsafe(24)
        self.owner = owner
        self.project_id = project_id
        self.path = validate_ipa(path)
        self.udid = validate_udid(udid)
        if mode not in {"apple_id", "signed"}:
            raise ValueError("Choose Apple ID signing or an already signed IPA.")
        if mode == "apple_id" and network:
            raise ValueError("Apple ID signing uses a USB-connected device.")
        self.mode, self.network = mode, network
        self.executable = ""
        if mode == "apple_id":
            if os.name == "nt":
                raise ValueError("Integrated Apple ID signing currently requires macOS or Linux.")
            self.executable = shutil.which(os.environ.get("DROIDBOARD_SIDELOADER", "sideloader")) or ""
            if not self.executable:
                raise ValueError("Sideloader CLI is missing. Install Dadoum/Sideloader and set DROIDBOARD_SIDELOADER to its executable (see README).")
            try:
                import pexpect  # noqa: F401
            except ImportError as exc:
                raise ValueError("Install the project's requirements to enable Apple ID signing.") from exc
        self.state = "running"
        self.message = "Preparing installation…"
        self.prompt = ""
        self.challenge = ""
        self.finished_at = 0.0
        self.lock = threading.Lock()
        self.cancelled = threading.Event()
        self.answers: queue.Queue[str] = queue.Queue(maxsize=1)

    def snapshot(self) -> dict:
        with self.lock:
            return {"id": self.id, "state": self.state, "message": self.message,
                    "prompt": self.prompt, "challenge": self.challenge,
                    "cancellable": self.mode == "apple_id"}

    def answer(self, challenge: str, value: str) -> None:
        with self.lock:
            if self.state != "waiting" or not secrets.compare_digest(challenge, self.challenge):
                raise ValueError("This prompt is no longer active. Refresh the installation status.")
            if not value or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("Enter a single non-empty value without control characters.")
            if self.prompt == "verification_code" and value != "resend" and not re.fullmatch(r"\d{6}", value):
                raise ValueError("Enter the six-digit code or resend.")
            self.answers.put_nowait(value)
            self.state, self.prompt, self.challenge = "running", "", ""
            self.message = "Continuing Apple authentication and installation…"

    def finish(self, state: str, message: str) -> None:
        with self.lock:
            self.state, self.message = state, message
            self.prompt = self.challenge = ""
            self.finished_at = time.monotonic()

    def run(self) -> None:
        try:
            # A private snapshot prevents concurrent uploads changing an in-flight IPA.
            with tempfile.TemporaryDirectory(prefix="droidboard-ios-") as directory:
                ipa = Path(directory) / "application.ipa"
                shutil.copyfile(self.path, ipa)
                validate_ipa(ipa)
                if self.mode == "signed":
                    result = install_signed_ipa(ipa, self.udid, network=self.network)
                    self.finish("success" if result.ok else "failed", result.output)
                else:
                    self._run_sideloader(ipa)
        except Exception:
            # Exception text from an interactive child can include its terminal buffer.
            self.finish("failed", "Installation failed. Check the IPA, device connection, and Sideloader setup.")
        finally:
            while not self.answers.empty():
                try:
                    self.answers.get_nowait()
                except queue.Empty:
                    break

    def _run_sideloader(self, ipa: Path) -> None:
        import pexpect

        child = pexpect.spawn(self.executable,
                              ["install", str(ipa), "--udid", self.udid, "-i"],
                              encoding="utf-8", codec_errors="replace", echo=False,
                              timeout=1, maxread=4096, searchwindowsize=8192)
        deadline = time.monotonic() + 1200
        try:
            while time.monotonic() < deadline and not self.cancelled.is_set():
                match = child.expect([*PROMPTS, pexpect.EOF, pexpect.TIMEOUT])
                if match < len(PROMPTS):
                    with self.lock:
                        self.state = "waiting"
                        self.prompt = PROMPT_NAMES[match]
                        self.challenge = secrets.token_urlsafe(16)
                        self.message = {"apple_id": "Enter the Apple ID used to sign the application.",
                                        "password": "Enter your Apple ID password.",
                                        "verification_code": "Enter the code sent by Apple, or resend."}[self.prompt]
                    answer_deadline = min(deadline, time.monotonic() + 300)
                    value = None
                    while time.monotonic() < answer_deadline and not self.cancelled.is_set():
                        try:
                            value = self.answers.get(timeout=0.2)
                            break
                        except queue.Empty:
                            if not child.isalive():
                                break
                    if value is None:
                        self.finish("cancelled" if self.cancelled.is_set() else "failed",
                                    "Installation cancelled." if self.cancelled.is_set() else "Apple authentication timed out or the signer exited.")
                        return
                    child.setecho(False)
                    child.sendline(value)
                    value = None
                elif match == len(PROMPTS):
                    child.close()
                    self.finish("success" if child.exitstatus == 0 else "failed",
                                "IPA signed and installed on the selected device."
                                if child.exitstatus == 0 else
                                "Sideloader failed. Check Apple authentication, account limits, pairing and Developer Mode. Retry with the Sideloader CLI for detailed diagnostics.")
                    return
                else:
                    # Consume bounded chunks without recording any terminal output.
                    child.buffer = child.buffer[-8192:]
            self.finish("cancelled" if self.cancelled.is_set() else "failed",
                        "Installation cancelled." if self.cancelled.is_set() else "Installation timed out after 20 minutes.")
        finally:
            child.close(force=True)


class InstallJobs:
    def __init__(self):
        self.jobs: dict[str, InstallJob] = {}
        self.lock = threading.Lock()

    def start(self, owner: str, project_id: int, path: Path, udid: str, mode: str,
              network: bool = False) -> InstallJob:
        with self.lock:
            self.jobs = {key: job for key, job in self.jobs.items()
                         if not job.finished_at or time.monotonic() - job.finished_at < 3600}
            if any(not job.finished_at for job in self.jobs.values()):
                raise ValueError("An iOS installation is already running. Finish it before starting another.")
            job = InstallJob(owner, project_id, path, udid, mode, network)
            self.jobs[job.id] = job
            threading.Thread(target=job.run, daemon=True, name="ios-install").start()
            return job

    def get(self, job_id: str, owner: str, project_id: int) -> InstallJob | None:
        with self.lock:
            job = self.jobs.get(job_id)
            return job if job and job.owner == owner and job.project_id == project_id else None


def validate_ipa(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.suffix.lower() != ".ipa" or not path.is_file():
        raise ValueError("Select an existing .ipa file.")
    try:
        with zipfile.ZipFile(path) as archive:
            manifests = [item for item in archive.infolist()
                         if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", item.filename)]
            if len(manifests) != 1 or manifests[0].file_size > 1024 * 1024:
                raise ValueError("IPA must contain one application with a valid Info.plist.")
            info = plistlib.loads(archive.read(manifests[0]))
            if not isinstance(info, dict) or not info.get("CFBundleIdentifier") or not info.get("CFBundleExecutable"):
                raise ValueError("IPA is missing its bundle identifier or executable.")
    except (OSError, zipfile.BadZipFile, plistlib.InvalidFileException, RuntimeError) as exc:
        raise ValueError(f"Unable to read IPA: {exc}") from exc
    return path


def validate_udid(udid: str) -> str:
    udid = udid.strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{8}-[0-9a-fA-F]{16})", udid):
        raise ValueError("Select a device using its full UDID.")
    return udid


def devices(*, network: bool = False) -> MobileResult:
    result = run_command(["idevice_id", "--network" if network else "--list"], timeout=20)
    result.title = "iOS devices"
    if result.ok and not result.output.strip():
        result.output = "No devices found. Connect and unlock the iPhone, then accept Trust This Computer."
    elif not result.ok:
        result.output += "\nDevice discovery requires libimobiledevice (macOS: brew install libimobiledevice)."
    return result


def install_signed_ipa(path: Path, udid: str, *, network: bool = False) -> MobileResult:
    path = validate_ipa(path)
    udid = validate_udid(udid)
    # ideviceinstaller 1.2+ uses subcommands; 1.1 uses -i.
    help_result = run_command(["ideviceinstaller", "--help"], timeout=15)
    if not help_result.ok:
        help_result.title = "Install IPA"
        help_result.output += "\nInstall ideviceinstaller (macOS: brew install ideviceinstaller)."
        return help_result
    argv = ["ideviceinstaller", "--udid", udid]
    if network:
        argv.append("--network")
    argv.extend(["install" if "install PATH" in help_result.output else "-i", str(path)])
    result = run_command(argv, timeout=600)
    result.title = "Install IPA"
    if result.ok:
        result.output += "\nIPA installed on the selected device."
    else:
        result.output += "\nCheck pairing, Developer Mode, and that the signature/profile is valid for this device."
    return result
