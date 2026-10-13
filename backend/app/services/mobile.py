from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.services.ca import ensure_ca


ADB_OUTPUT_SIZE = 12000
DEFAULT_AVD = "Pixel_5"
DEFAULT_EMULATOR_START_COMMAND = (
    "emulator -avd Pixel_5 -gpu swiftshader_indirect -no-snapshot "
    "-no-boot-anim -memory 4096 -cores 4 -writable-system"
)
ANDROID_CA_DIR = "/system/etc/security/cacerts"
JADX_LATEST_RELEASE_API = "https://api.github.com/repos/skylot/jadx/releases/latest"
IPA_MAX_EXTRACT_BYTES = 750 * 1024 * 1024
IPA_MAX_FILE_BYTES = 150 * 1024 * 1024


@dataclass
class MobileResult:
    ok: bool
    title: str
    command: str
    output: str = ""
    artifact: str = ""


@dataclass
class ManifestInspection:
    debuggable: bool = False
    min_sdk_version: int = -1
    read_external_storage: bool = False
    write_external_storage: bool = False
    debuggable_evidence: str = ""
    min_sdk_evidence: str = ""
    read_external_storage_evidence: str = ""
    write_external_storage_evidence: str = ""


@dataclass
class RemotePathEntry:
    name: str
    is_dir: bool


@dataclass
class IpaAnalysisContext:
    ipa_path: Path
    output_dir: Path
    extract_dir: Path
    app_dir: Path | None
    info_plist: dict
    executable_path: Path | None
    strings: list[str]


def run_command(argv: list[str], *, timeout: int = 120) -> MobileResult:
    command = _display_command(argv)
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return MobileResult(False, argv[0], command, f"Command not found: {exc.filename}")
    except subprocess.TimeoutExpired as exc:
        output = "".join(value.decode(errors="replace") if isinstance(value, bytes) else value or ""
                         for value in (exc.stdout, exc.stderr))
        return MobileResult(False, argv[0], command, f"Timed out after {timeout}s\n{output}"[:ADB_OUTPUT_SIZE])
    except OSError as exc:
        return MobileResult(False, argv[0], command, f"exec failed: {exc}")

    return MobileResult(completed.returncode == 0, argv[0], command, completed.stdout[:ADB_OUTPUT_SIZE])


def run_detached_command(argv: list[str]) -> MobileResult:
    command = _display_command(argv)
    try:
        subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            close_fds=True,
        )
    except FileNotFoundError as exc:
        return MobileResult(False, argv[0], command, f"Command not found: {exc.filename}")
    except OSError as exc:
        return MobileResult(False, argv[0], command, f"exec failed: {exc}")
    return MobileResult(True, argv[0], command, "Started detached process.")


def start_emulator(avd: str = DEFAULT_AVD) -> MobileResult:
    avd = avd.strip() or DEFAULT_AVD
    return run_detached_command(
        [
            "emulator",
            "-avd",
            avd,
            "-gpu",
            "swiftshader_indirect",
            "-no-snapshot",
            "-no-boot-anim",
            "-memory",
            "4096",
            "-cores",
            "4",
            "-writable-system",
        ]
    )


def start_emulator_with_command(command: str) -> MobileResult:
    command = command.strip() or DEFAULT_EMULATOR_START_COMMAND
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        return MobileResult(False, "start emulator", command, f"Invalid emulator command: {exc}")
    if not argv:
        return MobileResult(False, "start emulator", command, "Emulator command is required.")
    result = run_detached_command(argv)
    result.title = "start emulator"
    return result


def stop_emulator() -> MobileResult:
    result = run_command(["adb", "emu", "kill"], timeout=30)
    result.title = "stop emulator"
    return result


def logcat(lines: int = 500) -> MobileResult:
    lines = max(1, min(lines, 5000))
    result = run_command(["adb", "logcat", "-d", "-v", "time", "-t", str(lines)], timeout=30)
    result.title = "logcat"
    if result.ok and not result.output.strip():
        result.output = "No logcat output."
    return result


def install_apk(apk_path: Path) -> MobileResult:
    return run_command(["adb", "install", "-r", str(apk_path)], timeout=240)


def uninstall_apk(apk_path: Path) -> MobileResult:
    package = get_package_name(apk_path)
    if not package.ok:
        return package
    return run_command(["adb", "uninstall", package.output.strip()])


def get_package_name(apk_path: Path) -> MobileResult:
    result = run_command(["aapt", "dump", "badging", str(apk_path)])
    if not result.ok:
        result.title = "get package"
        return result
    match = re.search(r"package: name='([^']+)'", result.output)
    if match is None:
        return MobileResult(False, "get package", result.command, "Package name not found in aapt output.")
    return MobileResult(True, "get package", result.command, match.group(1))


def inspect_manifest(apk_path: Path) -> MobileResult:
    temp_dir = Path(tempfile.mkdtemp(prefix="arkadroid_manifest_"))
    try:
        decoded = run_command(["apktool", "d", "-f", "-q", "-o", str(temp_dir), str(apk_path)], timeout=240)
        if not decoded.ok:
            decoded.title = "inspect manifest"
            return decoded
        manifest_path = temp_dir / "AndroidManifest.xml"
        try:
            manifest = manifest_path.read_text(encoding="utf-8")
        except OSError as exc:
            return MobileResult(False, "inspect manifest", decoded.command, f"Unable to open manifest: {exc}")
        apktool_yml = _read_text(temp_dir / "apktool.yml")
        inspection = ManifestInspection(
            debuggable=_manifest_has_debuggable_true(manifest),
            min_sdk_version=_manifest_min_sdk_version(manifest, apktool_yml),
            read_external_storage=_manifest_has_permission(manifest, "android.permission.READ_EXTERNAL_STORAGE"),
            write_external_storage=_manifest_has_permission(manifest, "android.permission.WRITE_EXTERNAL_STORAGE"),
            debuggable_evidence=_manifest_debuggable_evidence(manifest),
            min_sdk_evidence=_manifest_min_sdk_evidence(manifest, apktool_yml),
            read_external_storage_evidence=_manifest_permission_evidence(manifest, "android.permission.READ_EXTERNAL_STORAGE"),
            write_external_storage_evidence=_manifest_permission_evidence(manifest, "android.permission.WRITE_EXTERNAL_STORAGE"),
        )
        return MobileResult(True, "inspect manifest", decoded.command, _format_manifest_inspection(inspection))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def unpack_apk(apk_path: Path, destination: Path) -> MobileResult:
    destination = destination.expanduser()
    apktool_dir = destination / "apktool"
    jadx_dir = destination / "jadx"
    destination.mkdir(parents=True, exist_ok=True)

    apktool = run_command(["apktool", "d", "-f", "-o", str(apktool_dir), str(apk_path)], timeout=600)
    apktool.title = "unpack apk"
    if not apktool.ok:
        return apktool

    commands = [apktool.command]
    outputs = [apktool.output.strip(), f"apktool output: {apktool_dir}"]

    jadx_command, jadx_setup = ensure_jadx()
    if jadx_setup:
        outputs.append(jadx_setup.output.strip())
        commands.append(jadx_setup.command)
    if jadx_command is None:
        outputs.append("jadx not available; code decompilation skipped. apktool smali output is available.")
    else:
        jadx = run_command([*jadx_command, "-d", str(jadx_dir), str(apk_path)], timeout=600)
        commands.append(jadx.command)
        if jadx.output.strip():
            outputs.append(jadx.output.strip())
        if jadx.ok:
            outputs.append(f"jadx output: {jadx_dir}")
        else:
            outputs.append("jadx failed; apktool extraction completed.")

    return MobileResult(
        True,
        "unpack apk",
        "\n".join(commands),
        "\n".join(output for output in outputs if output).strip(),
        artifact=str(destination),
    )


def ensure_jadx() -> tuple[list[str] | None, MobileResult | None]:
    env_path = os.environ.get("ARKADROID_JADX", "").strip()
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            return [str(path)], None

    system_jadx = shutil.which("jadx")
    if system_jadx:
        return [system_jadx], None

    managed_jadx = managed_jadx_path()
    if managed_jadx.exists():
        return [str(managed_jadx)], None

    setup = install_managed_jadx()
    if setup.ok and managed_jadx.exists():
        return [str(managed_jadx)], setup
    return None, setup


def managed_jadx_path() -> Path:
    executable = "jadx.bat" if os.name == "nt" else "jadx"
    return get_settings().resolved_data_dir / "tools" / "jadx" / "bin" / executable


def install_managed_jadx() -> MobileResult:
    if shutil.which("java") is None:
        return MobileResult(False, "install jadx", "java", "Java runtime not found; JADX requires Java.")

    tools_dir = get_settings().resolved_data_dir / "tools"
    archive_path = tools_dir / "jadx.zip"
    install_dir = tools_dir / "jadx"
    command = f"download {JADX_LATEST_RELEASE_API}"
    try:
        tools_dir.mkdir(parents=True, exist_ok=True)
        download_url, version = _latest_jadx_zip_asset()
        command = f"download {download_url}"
        urllib.request.urlretrieve(download_url, archive_path)
        shutil.rmtree(install_dir, ignore_errors=True)
        install_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(install_dir)
        executable = managed_jadx_path()
        if executable.exists() and os.name != "nt":
            executable.chmod(executable.stat().st_mode | 0o111)
        if not executable.exists():
            return MobileResult(False, "install jadx", command, f"JADX archive extracted, but executable not found: {executable}")
        return MobileResult(True, "install jadx", command, f"Installed JADX {version} at {install_dir}")
    except Exception as exc:  # noqa: BLE001
        return MobileResult(False, "install jadx", command, f"Unable to install JADX automatically: {exc}")
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass


def _latest_jadx_zip_asset() -> tuple[str, str]:
    with urllib.request.urlopen(JADX_LATEST_RELEASE_API, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    for asset in payload.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name.endswith(".zip") and "jadx" in name.lower() and url:
            return url, payload.get("tag_name", "latest")
    raise RuntimeError("No JADX zip asset found in latest release.")


def set_http_proxy(proxy_address: str) -> MobileResult:
    if not proxy_address.strip():
        return MobileResult(False, "proxy", "adb shell settings put global http_proxy", "Proxy address is required.")
    first = run_command(["adb", "shell", "settings", "put", "global", "http_proxy", proxy_address.strip()])
    if not first.ok:
        first.title = "proxy"
        return first
    second = run_command(["adb", "shell", "settings", "put", "global", "https_proxy", proxy_address.strip()])
    second.title = "proxy"
    second.command = f"{first.command}\n{second.command}"
    second.output = (first.output + second.output).strip() or "Proxy configured."
    return second


def unset_http_proxy() -> MobileResult:
    result = set_http_proxy(":0")
    result.title = "unset proxy"
    if result.ok and not result.output.strip():
        result.output = "Proxy unset."
    return result


def enable_iptables_proxy(proxy_host: str, proxy_port: int) -> MobileResult:
    proxy_host = proxy_host.strip()
    try:
        ipaddress.ip_address(proxy_host)
    except ValueError:
        return MobileResult(False, "firewall proxy", "adb shell iptables", "Proxy IP must be a valid IP address.")
    if proxy_port < 1 or proxy_port > 65535:
        return MobileResult(False, "firewall proxy", "adb shell iptables", "Proxy port must be between 1 and 65535.")

    cleanup_script = _iptables_proxy_cleanup_script()
    setup_script = "\n".join(
        [
            "set -e",
            "iptables -t nat -N ARKADROID_PROXY_OUT",
            "iptables -t nat -N ARKADROID_PROXY_POST",
            "iptables -t nat -A OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT",
            "iptables -t nat -A OUTPUT -p tcp --dport 443 -j ARKADROID_PROXY_OUT",
            f"iptables -t nat -A ARKADROID_PROXY_OUT -p tcp -j DNAT --to-destination {proxy_host}:{proxy_port}",
            "iptables -t nat -A POSTROUTING -p tcp -j ARKADROID_PROXY_POST",
            "iptables -t nat -A ARKADROID_PROXY_POST -p tcp -j MASQUERADE",
            "iptables -t nat -S | grep ARKADROID_PROXY || true",
        ]
    )
    steps = [root(), run_command(["adb", "shell", cleanup_script], timeout=30), run_command(["adb", "shell", setup_script], timeout=30)]
    ok = all(step.ok for step in steps)
    command = "\n".join(step.command for step in steps)
    output = "\n".join(step.output for step in steps if step.output).strip()
    if ok:
        output = output or f"Firewall proxy enabled for TCP 80/443 to {proxy_host}:{proxy_port}."
    return MobileResult(ok, "firewall proxy", command, output)


def disable_iptables_proxy() -> MobileResult:
    steps = [root(), run_command(["adb", "shell", _iptables_proxy_cleanup_script()], timeout=30)]
    ok = all(step.ok for step in steps)
    command = "\n".join(step.command for step in steps)
    output = "\n".join(step.output for step in steps if step.output).strip()
    if ok:
        output = output or "Firewall proxy disabled."
    return MobileResult(ok, "disable firewall proxy", command, output)


def _iptables_proxy_cleanup_script() -> str:
    return "\n".join(
        [
            "iptables -t nat -D OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT 2>/dev/null || true",
            "iptables -t nat -D OUTPUT -p tcp --dport 443 -j ARKADROID_PROXY_OUT 2>/dev/null || true",
            "iptables -t nat -D POSTROUTING -p tcp -j ARKADROID_PROXY_POST 2>/dev/null || true",
            "iptables -t nat -F ARKADROID_PROXY_OUT 2>/dev/null || true",
            "iptables -t nat -F ARKADROID_PROXY_POST 2>/dev/null || true",
            "iptables -t nat -X ARKADROID_PROXY_OUT 2>/dev/null || true",
            "iptables -t nat -X ARKADROID_PROXY_POST 2>/dev/null || true",
        ]
    )


def push_file(source: Path, destination: str) -> MobileResult:
    return run_command(["adb", "push", str(source), destination])


def pull_file(source: str, destination: Path) -> MobileResult:
    return run_command(["adb", "pull", source, str(destination)])


def remote_file_info(path: str) -> MobileResult:
    quoted_path = _shell_quote(path)
    stat_format = "%n\\nType: %F\\nSize: %s bytes\\nOwner: %U\\nGroup: %G\\nMode: %A (%a)\\nModified: %y"
    result = run_command(["adb", "shell", f"stat -c '{stat_format}' {quoted_path}"], timeout=30)
    result.title = "remote file info"
    if result.ok:
        return result
    fallback = run_command(["adb", "shell", f"ls -la {quoted_path}"], timeout=30)
    fallback.title = "remote file info"
    fallback.command = f"{result.command}\n{fallback.command}"
    fallback.output = fallback.output.strip() or result.output
    return fallback


def read_remote_file(path: str, *, max_bytes: int = 65536) -> MobileResult:
    quoted_path = _shell_quote(path)
    result = run_command(["adb", "shell", f"head -c {max_bytes} {quoted_path}"], timeout=30)
    result.title = "remote file view"
    return result


def search_remote_file(path: str, pattern: str) -> MobileResult:
    pattern = pattern.strip()
    if not pattern:
        return MobileResult(False, "remote file search", "adb shell grep", "Search pattern is required.")
    quoted_path = _shell_quote(path)
    quoted_pattern = _shell_quote(pattern)
    result = run_command(["adb", "shell", f"grep -n -I -- {quoted_pattern} {quoted_path} | head -200"], timeout=30)
    result.title = "remote file search"
    if not result.ok and not result.output.strip():
        result.output = "No matches or file is not readable as text."
    return result


def list_remote_dir(path: str) -> tuple[list[RemotePathEntry], MobileResult]:
    quoted_path = _shell_quote(path)
    result = run_command(["adb", "shell", f"cd {quoted_path} && ls -1Ap"], timeout=30)
    entries = [RemotePathEntry("..", True)]
    if not result.ok:
        return entries, result
    for raw_line in result.output.splitlines():
        name = raw_line.strip()
        if not name or name in {".", "./"}:
            continue
        is_dir = name.endswith("/")
        entries.append(RemotePathEntry(name.rstrip("/"), is_dir))
    entries[1:] = sorted(entries[1:], key=lambda item: (not item.is_dir, item.name.lower()))
    return entries, result


def app_sandbox_path(package_name: str) -> str:
    package_name = package_name.strip()
    return f"/data/data/{package_name}" if package_name else "/sdcard"


def root() -> MobileResult:
    return run_command(["adb", "root"])


def remount() -> MobileResult:
    return run_command(["adb", "remount"])


def reboot() -> MobileResult:
    return run_command(["adb", "reboot"])


def android_ca_path(project_id: int) -> Path:
    return get_settings().resolved_data_dir / "certs" / str(project_id) / "android"


def export_android_ca(project_id: int) -> MobileResult:
    cert_pem = ensure_ca(project_id)
    output_dir = android_ca_path(project_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    pem_path = output_dir / "arkadroid-ca.pem"
    pem_path.write_bytes(cert_pem)
    hash_result = run_command(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(pem_path)])
    if not hash_result.ok:
        hash_result.title = "android ca"
        return hash_result
    cert_hash = hash_result.output.splitlines()[0].strip() if hash_result.output.splitlines() else ""
    if not re.fullmatch(r"[0-9a-fA-F]+", cert_hash):
        return MobileResult(False, "android ca", hash_result.command, f"Invalid openssl hash output: {hash_result.output}")
    android_cert_path = output_dir / f"{cert_hash}.0"
    android_cert_path.write_bytes(cert_pem)
    return MobileResult(
        True,
        "android ca",
        hash_result.command,
        f"Android CA exported as {android_cert_path}",
        artifact=str(android_cert_path),
    )


def upload_android_ca(project_id: int) -> MobileResult:
    exported = export_android_ca(project_id)
    if not exported.ok:
        return exported
    local_path = Path(exported.artifact)
    remote_path = f"{ANDROID_CA_DIR}/{local_path.name}"
    steps = [root(), remount(), push_file(local_path, remote_path), run_command(["adb", "shell", "chmod", "644", remote_path])]
    ok = all(step.ok for step in steps)
    command = "\n".join(step.command for step in steps)
    output = "\n".join(step.output for step in steps if step.output).strip()
    if ok:
        output = f"{output}\nUploaded {local_path.name} to {remote_path}".strip()
    return MobileResult(ok, "upload android ca", command, output, artifact=str(local_path))


def project_upload_dir(project_id: int) -> Path:
    path = get_settings().resolved_data_dir / "mobile" / str(project_id) / "uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def project_unpack_dir(project_id: int) -> Path:
    path = get_settings().resolved_data_dir / "mobile" / str(project_id) / "unpacked"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ios_analysis_dir(project_id: int) -> Path:
    path = get_settings().resolved_data_dir / "mobile" / str(project_id) / "ios-analysis"
    path.mkdir(parents=True, exist_ok=True)
    return path


def analyze_ipa(ipa_path: Path, output_dir: Path) -> MobileResult:
    operations = [
        ("Target", ipa_metadata),
        ("Info.plist / ATS / privacy", ipa_plist_analysis),
        ("Provisioning / entitlements", ipa_provisioning_analysis),
        ("Inventory", ipa_inventory),
        ("URLs and secret candidates", ipa_strings_analysis),
    ]
    chunks: list[str] = []
    commands: list[str] = []
    ok = True
    artifact = ""
    for heading, callback in operations:
        result = callback(ipa_path, output_dir)
        ok = ok and result.ok
        artifact = result.artifact or artifact
        commands.append(result.command)
        chunks.append(f"## {heading}\n{result.output.strip()}")
    report = output_dir.expanduser() / "ios-static-report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# iOS Static Security Report\n\n" + "\n\n".join(chunks), encoding="utf-8")
    return MobileResult(ok, "iOS IPA scan", "\n".join(commands), f"{report}\n\n" + "\n\n".join(chunks), artifact=str(report))


def extract_ipa(ipa_path: Path, output_dir: Path) -> MobileResult:
    output_dir = output_dir.expanduser()
    extract_dir = output_dir / "extracted"
    try:
        _safe_extract_zip(ipa_path, extract_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "extract ipa", f"extract {ipa_path}", str(exc))
    apps = sorted(str(path.relative_to(extract_dir)) for path in (extract_dir / "Payload").glob("*.app"))
    output = [f"Extracted to {extract_dir}", "Applications:"]
    output.extend(f"- {app}" for app in apps) if apps else output.append("- none found")
    return MobileResult(True, "extract ipa", f"extract {ipa_path}", "\n".join(output), artifact=str(extract_dir))


def ipa_metadata(ipa_path: Path, output_dir: Path) -> MobileResult:
    try:
        context = _ipa_context(ipa_path, output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "iOS metadata", f"inspect {ipa_path}", str(exc))
    info = context.info_plist
    ipa_sha = _sha256_file(context.ipa_path)
    binary_sha = _sha256_file(context.executable_path) if context.executable_path else ""
    lines = [
        f"IPA: {context.ipa_path}",
        f"IPA SHA-256: {ipa_sha}",
        f"App bundle: {_rel(context.app_dir, context.extract_dir) if context.app_dir else 'not found'}",
        f"Bundle ID: {info.get('CFBundleIdentifier', '-')}",
        f"Name: {info.get('CFBundleDisplayName') or info.get('CFBundleName') or '-'}",
        f"Version: {info.get('CFBundleShortVersionString', '-')}",
        f"Build: {info.get('CFBundleVersion', '-')}",
        f"Minimum iOS: {info.get('MinimumOSVersion', '-')}",
        f"Executable: {_rel(context.executable_path, context.extract_dir) if context.executable_path else 'not found'}",
        f"Executable SHA-256: {binary_sha or '-'}",
        f"Executable type: {_file_type(context.executable_path) if context.executable_path else '-'}",
    ]
    return MobileResult(True, "iOS metadata", f"inspect {ipa_path}", "\n".join(lines), artifact=str(context.output_dir))


def ipa_plist_analysis(ipa_path: Path, output_dir: Path) -> MobileResult:
    try:
        context = _ipa_context(ipa_path, output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "iOS plist analysis", f"plist {ipa_path}", str(exc))
    info = context.info_plist
    ats = info.get("NSAppTransportSecurity") if isinstance(info.get("NSAppTransportSecurity"), dict) else {}
    url_types = info.get("CFBundleURLTypes") if isinstance(info.get("CFBundleURLTypes"), list) else []
    query_schemes = info.get("LSApplicationQueriesSchemes") if isinstance(info.get("LSApplicationQueriesSchemes"), list) else []
    background_modes = info.get("UIBackgroundModes") if isinstance(info.get("UIBackgroundModes"), list) else []
    privacy_keys = sorted(key for key in info if key.startswith("NS") and key.endswith("UsageDescription"))
    findings = ["Info.plist checks:"]
    findings.append(_finding_line("IOS-ATS-001 ATS globally disabled", ats.get("NSAllowsArbitraryLoads") is True))
    findings.append(_finding_line("IOS-ATS-002 WebView arbitrary loads", ats.get("NSAllowsArbitraryLoadsInWebContent") is True))
    findings.append(_finding_line("IOS-STORAGE-001 file sharing enabled", info.get("UIFileSharingEnabled") is True))
    findings.append(_finding_line("IOS-STORAGE-002 documents open in place", info.get("LSSupportsOpeningDocumentsInPlace") is True))
    findings.append("")
    findings.append("ATS domain exceptions:")
    exceptions = ats.get("NSExceptionDomains") if isinstance(ats.get("NSExceptionDomains"), dict) else {}
    if exceptions:
        for domain, values in exceptions.items():
            findings.append(f"- {domain}: {values}")
    else:
        findings.append("- none")
    findings.append("")
    findings.append("Custom URL schemes:")
    schemes: list[str] = []
    for item in url_types:
        if isinstance(item, dict):
            schemes.extend(str(value) for value in item.get("CFBundleURLSchemes", []) if value)
    findings.extend(f"- {scheme}" for scheme in sorted(set(schemes))) if schemes else findings.append("- none")
    findings.append("")
    findings.append("LSApplicationQueriesSchemes:")
    findings.extend(f"- {scheme}" for scheme in query_schemes) if query_schemes else findings.append("- none")
    findings.append("")
    findings.append("Background modes:")
    findings.extend(f"- {mode}" for mode in background_modes) if background_modes else findings.append("- none")
    findings.append("")
    findings.append("Privacy usage descriptions:")
    findings.extend(f"- {key}: {info.get(key)}" for key in privacy_keys) if privacy_keys else findings.append("- none")
    findings.append("")
    manifests = sorted(context.app_dir.rglob("PrivacyInfo.xcprivacy")) if context.app_dir else []
    findings.append("Privacy manifests:")
    findings.extend(f"- {_rel(path, context.extract_dir)}" for path in manifests) if manifests else findings.append("- none")
    return MobileResult(True, "iOS plist analysis", f"plist {ipa_path}", "\n".join(findings), artifact=str(context.output_dir))


def ipa_provisioning_analysis(ipa_path: Path, output_dir: Path) -> MobileResult:
    try:
        context = _ipa_context(ipa_path, output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "iOS provisioning", f"provision {ipa_path}", str(exc))
    profile = context.app_dir / "embedded.mobileprovision" if context.app_dir else None
    lines = ["Provisioning profile:"]
    profile_plist = _read_mobileprovision(profile) if profile and profile.exists() else {}
    if profile_plist:
        entitlements = profile_plist.get("Entitlements") if isinstance(profile_plist.get("Entitlements"), dict) else {}
        lines.extend(
            [
                f"Name: {profile_plist.get('Name', '-')}",
                f"Team: {profile_plist.get('TeamName', '-')}",
                f"UUID: {profile_plist.get('UUID', '-')}",
                f"Expiration: {profile_plist.get('ExpirationDate', '-')}",
                _finding_line("IOS-SIGN-001 provisioned devices present", bool(profile_plist.get("ProvisionedDevices"))),
                _finding_line("IOS-SIGN-001 provisions all devices", profile_plist.get("ProvisionsAllDevices") is True),
                "",
                "Entitlements:",
            ]
        )
        if entitlements:
            for key in sorted(entitlements):
                lines.append(f"- {key}: {entitlements[key]}")
            lines.append("")
            lines.append(_finding_line("IOS-ENT-001 get-task-allow enabled", entitlements.get("get-task-allow") is True))
            lines.append(_finding_line("IOS-ENT-002 keychain groups present", bool(entitlements.get("keychain-access-groups"))))
            lines.append(_finding_line("IOS-ENT-003 application groups present", bool(entitlements.get("com.apple.security.application-groups"))))
            lines.append(_finding_line("IOS-ENT-004 associated domains present", bool(entitlements.get("com.apple.developer.associated-domains"))))
        else:
            lines.append("- none parsed")
    else:
        lines.append("- embedded.mobileprovision not found or not parseable on this Linux host")
    return MobileResult(True, "iOS provisioning", f"provision {ipa_path}", "\n".join(lines), artifact=str(context.output_dir))


def ipa_inventory(ipa_path: Path, output_dir: Path) -> MobileResult:
    try:
        context = _ipa_context(ipa_path, output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "iOS inventory", f"inventory {ipa_path}", str(exc))
    app_dir = context.app_dir
    sections: list[str] = []
    if app_dir is None:
        return MobileResult(False, "iOS inventory", f"inventory {ipa_path}", "Application bundle not found.")
    patterns = {
        "Frameworks": ["Frameworks/*.framework", "Frameworks/*.dylib"],
        "Extensions": ["PlugIns/*.appex"],
        "Certificates / keys": ["**/*.cer", "**/*.crt", "**/*.der", "**/*.pem", "**/*.p12", "**/*.pfx", "**/*.key"],
        "Databases": ["**/*.sqlite", "**/*.sqlite3", "**/*.db", "**/*.realm"],
        "Web assets": ["**/*.html", "**/*.js", "**/*.jsbundle", "**/*.map"],
        "Archives / backups": ["**/*.zip", "**/*.tar", "**/*.gz", "**/*.bak", "**/*~"],
        "Environment / config": ["**/.env", "**/*.env", "**/*config*.json", "**/*config*.plist"],
    }
    for title, globs in patterns.items():
        matches: list[Path] = []
        for pattern in globs:
            matches.extend(app_dir.glob(pattern))
        sections.append(f"{title}:")
        sections.extend(f"- {_rel(path, context.extract_dir)}" for path in sorted(set(matches))[:200]) if matches else sections.append("- none")
        sections.append("")
    return MobileResult(True, "iOS inventory", f"inventory {ipa_path}", "\n".join(sections).strip(), artifact=str(context.output_dir))


def ipa_strings_analysis(ipa_path: Path, output_dir: Path) -> MobileResult:
    try:
        context = _ipa_context(ipa_path, output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return MobileResult(False, "iOS strings", f"strings {ipa_path}", str(exc))
    strings = context.strings
    urls = sorted(set(_extract_urls(strings)))[:200]
    ips = sorted(set(_extract_ips(strings)))[:200]
    secrets = _secret_candidates(strings)[:200]
    api_hits = _interesting_api_hits(strings)
    lines = ["URLs:"]
    lines.extend(f"- {url}" for url in urls) if urls else lines.append("- none")
    lines.append("")
    lines.append("Hardcoded IP addresses:")
    lines.extend(f"- {ip}" for ip in ips) if ips else lines.append("- none")
    lines.append("")
    lines.append("Secret candidates:")
    lines.extend(f"- {item}" for item in secrets) if secrets else lines.append("- none")
    lines.append("")
    lines.append("Security API indicators:")
    lines.extend(f"- {item}" for item in api_hits) if api_hits else lines.append("- none")
    return MobileResult(True, "iOS strings", f"strings {ipa_path}", "\n".join(lines), artifact=str(context.output_dir))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _display_command(argv: list[str]) -> str:
    return " ".join(_quote_arg(arg) for arg in argv)


def _quote_arg(value: str) -> str:
    if not value:
        return "''"
    if re.fullmatch(r"[A-Za-z0-9_./:=,+@%-]+", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _manifest_has_debuggable_true(manifest: str) -> bool:
    return re.search(r'android:debuggable\s*=\s*"true(?:"|\s)', manifest, re.IGNORECASE) is not None


def _manifest_debuggable_evidence(manifest: str) -> str:
    return _manifest_line_for_match(manifest, r'android:debuggable\s*=\s*"true(?:"|\s)', re.IGNORECASE)


def _manifest_min_sdk_version(manifest: str, apktool_yml: str = "") -> int:
    match = re.search(r'android:minSdkVersion\s*=\s*"(\d+)', manifest)
    if match:
        return int(match.group(1))
    match = re.search(r"\bminSdkVersion:\s*'?(\d+)'?", apktool_yml)
    return int(match.group(1)) if match else -1


def _manifest_min_sdk_evidence(manifest: str, apktool_yml: str = "") -> str:
    evidence = _manifest_line_for_match(manifest, r'android:minSdkVersion\s*=\s*"\d+')
    if evidence:
        return evidence
    evidence = _manifest_line_for_match(apktool_yml, r"\bminSdkVersion:\s*'?\d+'?")
    return f"apktool.yml: {evidence}" if evidence else ""


def _manifest_has_permission(manifest: str, permission: str) -> bool:
    return any(permission in match.group(0) for match in re.finditer(r"<uses-permission\b[^>]*>", manifest))


def _manifest_permission_evidence(manifest: str, permission: str) -> str:
    for match in re.finditer(r"<uses-permission\b[^>]*>", manifest):
        if permission in match.group(0):
            return _single_line(match.group(0))
    return ""


def _manifest_line_for_match(manifest: str, pattern: str, flags: int = 0) -> str:
    match = re.search(pattern, manifest, flags)
    if match is None:
        return ""
    start = manifest.rfind("\n", 0, match.start()) + 1
    end = manifest.find("\n", match.end())
    if end == -1:
        end = len(manifest)
    return _single_line(manifest[start:end])


def _single_line(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _format_manifest_inspection(inspection: ManifestInspection) -> str:
    min_sdk_old = inspection.min_sdk_version >= 0 and inspection.min_sdk_version < 30
    min_sdk = str(inspection.min_sdk_version) if inspection.min_sdk_version >= 0 else "not found"
    lines = [
        "Manifest inspection:",
        f'android:debuggable="true": {_finding(inspection.debuggable)}',
    ]
    if inspection.debuggable_evidence:
        lines.append(f"  {inspection.debuggable_evidence}")
    lines.append(f"android:minSdkVersion: {min_sdk}")
    lines.append(f"android:minSdkVersion < 30: {_finding(min_sdk_old) if inspection.min_sdk_version >= 0 else 'unknown'}")
    if min_sdk_old and inspection.min_sdk_evidence:
        lines.append(f"  {inspection.min_sdk_evidence}")
    lines.append(f"READ_EXTERNAL_STORAGE permission: {_finding(inspection.read_external_storage)}")
    if inspection.read_external_storage_evidence:
        lines.append(f"  {inspection.read_external_storage_evidence}")
    lines.append(f"WRITE_EXTERNAL_STORAGE permission: {_finding(inspection.write_external_storage)}")
    if inspection.write_external_storage_evidence:
        lines.append(f"  {inspection.write_external_storage_evidence}")
    return "\n".join(lines)


def _finding(found: bool) -> str:
    return "FOUND" if found else "not found"


def _ipa_context(ipa_path: Path, output_dir: Path) -> IpaAnalysisContext:
    ipa_path = ipa_path.expanduser()
    if not ipa_path.exists() or not ipa_path.is_file():
        raise ValueError("IPA file is required.")
    output_dir = output_dir.expanduser()
    extract_dir = output_dir / "extracted"
    _safe_extract_zip(ipa_path, extract_dir)
    app_dir = _main_app_dir(extract_dir)
    info_plist = _read_plist(app_dir / "Info.plist") if app_dir else {}
    executable_path = None
    executable = info_plist.get("CFBundleExecutable") if isinstance(info_plist, dict) else None
    if app_dir and executable:
        candidate = app_dir / str(executable)
        executable_path = candidate if candidate.exists() else None
    strings = _collect_ipa_strings(app_dir) if app_dir else []
    return IpaAnalysisContext(ipa_path, output_dir, extract_dir, app_dir, info_plist, executable_path, strings)


def _safe_extract_zip(ipa_path: Path, destination: Path) -> None:
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    total = 0
    with zipfile.ZipFile(ipa_path) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name or name.endswith("/"):
                continue
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts:
                raise ValueError(f"Unsafe IPA member path: {name}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f"Symlink entries are not extracted: {name}")
            total += info.file_size
            if info.file_size > IPA_MAX_FILE_BYTES:
                raise ValueError(f"IPA member is too large: {name}")
            if total > IPA_MAX_EXTRACT_BYTES:
                raise ValueError("IPA expanded size is too large.")
            target = (destination / name).resolve()
            if root not in target.parents and target != root:
                raise ValueError(f"Unsafe IPA member path: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as handle:
                shutil.copyfileobj(source, handle)


def _main_app_dir(extract_dir: Path) -> Path | None:
    payload = extract_dir / "Payload"
    apps = sorted(path for path in payload.glob("*.app") if path.is_dir())
    if not apps:
        return None
    for app in apps:
        info = _read_plist(app / "Info.plist")
        if info.get("CFBundleExecutable"):
            return app
    return apps[0]


def _read_plist(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def _read_mobileprovision(path: Path | None) -> dict:
    if path is None:
        return {}
    try:
        data = path.read_bytes()
    except OSError:
        return {}
    start = data.find(b"<?xml")
    end = data.rfind(b"</plist>")
    if start == -1 or end == -1:
        return {}
    try:
        value = plistlib.loads(data[start : end + len(b"</plist>")])
        return value if isinstance(value, dict) else {}
    except (plistlib.InvalidFileException, ValueError):
        return {}


def _collect_ipa_strings(app_dir: Path, *, max_files: int = 300, max_strings: int = 25000) -> list[str]:
    values: list[str] = []
    count = 0
    for path in app_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > IPA_MAX_FILE_BYTES:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        count += 1
        values.extend(_ascii_strings(blob))
        if count >= max_files or len(values) >= max_strings:
            break
    return values[:max_strings]


def _ascii_strings(blob: bytes, *, min_length: int = 4) -> list[str]:
    found: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                found.append(current.decode("ascii", errors="ignore"))
            current.clear()
    if len(current) >= min_length:
        found.append(current.decode("ascii", errors="ignore"))
    return found


def _extract_urls(values: list[str]) -> list[str]:
    urls: list[str] = []
    pattern = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>\\)]+", re.IGNORECASE)
    for value in values:
        urls.extend(match.rstrip(".,;") for match in pattern.findall(value))
    return urls


def _extract_ips(values: list[str]) -> list[str]:
    ips: list[str] = []
    pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    for value in values:
        for match in pattern.findall(value):
            if not match.startswith(("127.", "0.", "255.")):
                ips.append(match)
    return ips


def _secret_candidates(values: list[str]) -> list[str]:
    patterns = [
        ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
        ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
        ("Private key marker", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("Authorization header", re.compile(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)),
    ]
    hits: list[str] = []
    for value in values:
        for label, pattern in patterns:
            for match in pattern.findall(value):
                hits.append(f"{label}: {_redact_secret(match)}")
    return sorted(set(hits))


def _interesting_api_hits(values: list[str]) -> list[str]:
    needles = [
        "SecItemAdd",
        "SecItemCopyMatching",
        "SecTrustEvaluate",
        "SecTrustEvaluateWithError",
        "WKWebView",
        "UIWebView",
        "evaluateJavaScript",
        "CC_MD5",
        "CC_SHA1",
        "kCCAlgorithmDES",
        "UIPasteboard",
        "NSLog",
        "dlopen",
        "ptrace",
    ]
    hits = sorted({needle for needle in needles for value in values if needle in value})
    return hits


def _redact_secret(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"


def _sha256_file(path: Path | None) -> str:
    if path is None:
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_type(path: Path | None) -> str:
    if path is None:
        return ""
    result = run_command(["file", str(path)], timeout=30)
    return result.output.strip() if result.ok else result.output.strip() or "unknown"


def _rel(path: Path | None, root: Path) -> str:
    if path is None:
        return "-"
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _finding_line(label: str, found: bool) -> str:
    return f"{label}: {_finding(found)}"
