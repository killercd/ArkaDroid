import io
import lzma

import pytest

from app.services import frida_install as module
from app.services.mobile import MobileResult


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: f"/tools/{name}")
    monkeypatch.setattr(module, "objection_python", lambda: ["objection-python"])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    calls, downloads = [], []
    responses = {
        ("adb", "devices"): (True, "List of devices attached\nemulator-5554\tdevice\n"),
        ("shell", "getprop", "ro.kernel.qemu"): (True, "1\n"),
        ("objection-python", "-c", module.VERSION_CODE): (True, "17.9.11\n"),
        ("shell", module.REMOTE_PATH, "--version"): (True, "17.9.11\n"),
        ("shell", "pidof", "frida-server"): (False, ""),
        ("shell", "getprop", "ro.product.cpu.abi"): (True, "x86_64\n"),
        ("shell", "id", "-u"): (True, "0\n"),
    }
    probes = [True]

    def execute(argv, **kwargs):
        calls.append(argv)
        key = tuple(argv[3:]) if argv[:3] == ["adb", "-s", "emulator-5554"] else tuple(argv)
        if argv == ["objection-python", "-c", module.PROBE_CODE, "emulator-5554"]:
            ok, output = probes.pop(0) if len(probes) > 1 else probes[0], ""
        else:
            ok, output = responses.get(key, (True, ""))
        if key == ("shell", "kill", "123"):
            responses[("shell", "pidof", "frida-server")] = (False, "")
        return MobileResult(ok, "", " ".join(argv), output)

    def download(version, arch, destination):
        downloads.append((version, arch, destination))
        destination.write_bytes(b"fake-server")

    monkeypatch.setattr(module, "run_command", execute)
    monkeypatch.setattr(module, "_download_server", download)
    return calls, downloads, responses, probes


def test_install_matches_version_and_arch_and_verifies_connection(environment):
    calls, downloads, _, _ = environment
    result = module.install_frida()
    assert result.ok
    assert "Connection verified" in result.output
    assert downloads[0][:2] == ("17.9.11", "x86_64")
    assert not downloads[0][2].exists()  # Temporary download is removed.
    adb = ["adb", "-s", "emulator-5554"]
    assert [*adb, "root"] in calls
    assert [*adb, "wait-for-device"] in calls
    assert [*adb, "push", str(downloads[0][2]), module.REMOTE_PATH] in calls
    assert [*adb, "shell", module.START_COMMAND] in calls
    assert calls[-1] == ["objection-python", "-c", module.PROBE_CODE, "emulator-5554"]


@pytest.mark.parametrize("abi, arch", [("x86", "x86"), ("arm64-v8a", "arm64"), ("armeabi-v7a", "arm")])
def test_architecture_mapping(environment, abi, arch):
    _, downloads, responses, _ = environment
    responses[("shell", "getprop", "ro.product.cpu.abi")] = (True, abi)
    assert module.install_frida().ok
    assert downloads[0][1] == arch


def test_already_running_server_is_reused(environment):
    calls, downloads, responses, probes = environment
    responses[("shell", "pidof", "frida-server")] = (True, "123")
    probes[:] = [True]
    assert module.install_frida().ok
    assert not downloads
    assert not any("root" in argv or "push" in argv for argv in calls)


def test_unreachable_running_server_is_not_overwritten(environment):
    _, downloads, responses, probes = environment
    probes[:] = [False]
    responses[("shell", "pidof", "frida-server")] = (True, "123")
    result = module.install_frida()
    assert not result.ok
    assert "different Frida server" in result.output
    assert not downloads


@pytest.mark.parametrize("devices", ["", "emulator-5554\toffline", "emulator-5554\tdevice\nemulator-5556\tdevice"])
def test_missing_or_ambiguous_device_is_rejected(environment, devices):
    calls, downloads, responses, _ = environment
    responses[("adb", "devices")] = (True, devices)
    assert not module.install_frida().ok
    assert len(calls) == 1
    assert not downloads


def test_selected_serial_is_honored(environment, monkeypatch):
    _, _, responses, _ = environment
    responses[("adb", "devices")] = (True, "emulator-5554\tdevice\nemulator-5556\tdevice")
    monkeypatch.setenv("ANDROID_SERIAL", "emulator-5554")
    assert module.install_frida().ok


def test_physical_device_is_rejected(environment):
    calls, downloads, responses, _ = environment
    responses[("shell", "getprop", "ro.kernel.qemu")] = (True, "0")
    assert "only on Android emulators" in module.install_frida().output
    assert not downloads
    assert not any("root" in argv for argv in calls)


@pytest.mark.parametrize("key, response, message", [
    (("adb", "devices"), (False, "error"), "ADB discovery failed"),
    (("objection-python", "-c", module.VERSION_CODE), (True, "unknown"), "Cannot determine"),
    (("shell", "getprop", "ro.product.cpu.abi"), (True, "mips"), "Unsupported"),
    (("root",), (False, "not allowed"), "Cannot enable root"),
    (("shell", "id", "-u"), (True, "2000"), "does not allow root"),
    (("shell", "chmod", "755", module.REMOTE_PATH), (False, "denied"), "Failed command"),
    (("shell", module.START_COMMAND), (False, "bind failed"), "bind failed"),
])
def test_failures_are_reported(environment, key, response, message):
    calls, _, responses, _ = environment
    responses[key] = response
    result = module.install_frida()
    assert not result.ok
    assert message in result.output
    if key != ("shell", module.START_COMMAND):
        assert ["adb", "-s", "emulator-5554", "shell", module.START_COMMAND] not in calls


def test_failed_connection_after_start_is_not_success(environment):
    _, _, responses, probes = environment
    responses[("shell", "tail", "-n", "30", module.LOG_PATH)] = (True, "bind: Address already in use")
    probes[:] = [False]
    result = module.install_frida()
    assert not result.ok
    assert "connection check failed" in result.output
    assert "Address already in use" in result.output


def test_connection_is_retried_during_startup(environment):
    _, _, _, probes = environment
    probes[:] = [False, True]
    assert module.install_frida().ok


def test_managed_server_is_upgraded_to_objection_version(environment):
    calls, downloads, responses, _ = environment
    responses[("shell", "pidof", "frida-server")] = (True, "123")
    responses[("shell", module.REMOTE_PATH, "--version")] = (True, "17.9.1\n")
    responses[("shell", "readlink", "/proc/123/exe")] = (True, module.REMOTE_PATH)
    assert module.install_frida().ok
    assert downloads[0][:2] == ("17.9.11", "x86_64")
    assert ["adb", "-s", "emulator-5554", "shell", "kill", "123"] in calls
    assert not any(argv[0] == "frida-ps" for argv in calls)


def test_unknown_objection_runtime_is_actionable(environment, monkeypatch):
    monkeypatch.setattr(module, "objection_python", lambda: None)
    result = module.install_frida()
    assert not result.ok
    assert "Objection's Python environment" in result.output
    assert not environment[0]


def test_download_error_does_not_change_emulator(environment, monkeypatch):
    calls, _, _, _ = environment

    def fail(*args):
        raise EOFError("truncated archive")

    monkeypatch.setattr(module, "_download_server", fail)
    result = module.install_frida()
    assert not result.ok
    assert "truncated archive" in result.output
    assert not any("root" in argv or "push" in argv for argv in calls)


def test_missing_tool_is_reported(environment, monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    assert "missing from PATH" in module.install_frida().output
    assert not environment[0]


def test_concurrent_install_is_rejected(environment):
    with module.INSTALL_LOCK:
        assert "in progress" in module.install_frida().output
    assert not environment[0]


def test_download_uses_exact_official_asset_and_extracts(tmp_path, monkeypatch):
    urls = []

    def open_url(request, timeout):
        urls.append(request.full_url)
        return io.BytesIO(lzma.compress(b"server-binary"))

    monkeypatch.setattr(module.urllib.request, "urlopen", open_url)
    path = tmp_path / "server"
    module._download_server("17.9.1", "x86_64", path)
    assert path.read_bytes() == b"server-binary"
    assert urls == ["https://github.com/frida/frida/releases/download/17.9.1/frida-server-17.9.1-android-x86_64.xz"]
