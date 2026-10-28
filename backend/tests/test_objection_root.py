import subprocess
import sys

import pytest

from app.services import objection_root as module
from app.services.mobile import MobileResult


MARKER = "Registering job abc123. Name: root-detection-disable"


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: f"/tools/{name}")

    def run(argv, **kwargs):
        output = {
            ("adb", "devices"): "List of devices attached\nphone-1\tdevice\n",
            ("frida-ps", "-D", "phone-1"): "PID Name\n123 Test",
            ("objection", "--help"): "--name --serial",
            ("objection", "start", "--help"): "--startup-command",
        }[tuple(argv)]
        return MobileResult(True, "", "", output)

    monkeypatch.setattr(module, "run_command", run)
    value = module.ObjectionRootBypass()
    yield value
    value.stop()


@pytest.mark.parametrize("package", ["", "com", "com.app;id", "com.app$(id)", "-n com.app", "com.app\nother"])
def test_invalid_package_never_runs_commands(manager, monkeypatch, package):
    monkeypatch.setattr(module, "run_command", lambda *a, **k: pytest.fail("unexpected command"))
    assert "PRECHECK_FAILED" in manager.start(package).output


@pytest.mark.parametrize("tool", ["adb", "objection", "frida-ps"])
def test_missing_tool_is_actionable(manager, monkeypatch, tool):
    monkeypatch.setattr(module.shutil, "which", lambda name: None if name == tool else name)
    result = manager.start("com.example.app")
    assert not result.ok
    assert f"{tool} is missing" in result.output
    assert not manager.sessions


@pytest.mark.parametrize("devices", ["", "one\tdevice\ntwo\tdevice", "one\tunauthorized", "one\toffline"])
def test_device_preflight(manager, monkeypatch, devices):
    monkeypatch.setattr(module, "run_command", lambda *a, **k: MobileResult(True, "", "", devices))
    assert "Connect and authorize" in manager.start("com.example.app").output


def fake_objection(monkeypatch, code):
    """Run a harmless local child to exercise real pipes and process cleanup."""
    original = subprocess.Popen
    calls = []

    def launch(argv, **kwargs):
        calls.append(argv)
        assert kwargs["shell"] is False
        return original([sys.executable, "-u", "-c", code], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", launch)
    return calls


def test_hooks_are_unverified_and_session_is_reused(manager, monkeypatch):
    calls = fake_objection(monkeypatch, f"print({MARKER!r}, flush=True); import time; time.sleep(60)")
    result = manager.start("com.example.app")
    assert result.ok
    assert "HOOKS_ACTIVE_UNVERIFIED" in result.output
    assert "BYPASS_CONFIRMED" not in result.output
    assert calls == [["objection", "--serial", "phone-1", "--name", "com.example.app",
                      "start", "--startup-command", "android root disable"]]
    assert manager.start("com.example.app").ok
    assert len(calls) == 1
    child = manager.sessions[("phone-1", "com.example.app")].child
    assert child.poll() is None
    manager.stop()
    assert child.poll() is not None
    assert "SESSION_ENDED" in manager.status("com.example.app").output


@pytest.mark.parametrize("message, expected", [
    ("Traceback (most recent call last):", "BYPASS_FAILED"),
    ("(session detach message) device-lost", "SESSION_ENDED"),
    ("Running a startup command... android root disable", "SESSION_ENDED"),
])
def test_error_disconnect_or_exit_never_claims_hooks(manager, monkeypatch, message, expected):
    fake_objection(monkeypatch, f"print({message!r}, flush=True)")
    result = manager.start("com.example.app")
    assert not result.ok
    assert expected in result.output
    assert manager.sessions[("phone-1", "com.example.app")].child.poll() is not None


def test_startup_timeout_kills_child(manager, monkeypatch):
    monkeypatch.setattr(module, "START_TIMEOUT", 0.05)
    fake_objection(monkeypatch, "import time; time.sleep(60)")
    result = manager.start("com.example.app")
    assert not result.ok
    assert "Timed out" in result.output
    assert manager.sessions[("phone-1", "com.example.app")].child.poll() is not None


def test_session_lifetime_closes_hooks(manager, monkeypatch):
    monkeypatch.setattr(module, "SESSION_TIMEOUT", 0.2)
    fake_objection(monkeypatch, f"print({MARKER!r}, flush=True); import time; time.sleep(60)")
    assert manager.start("com.example.app").ok
    current = manager.sessions[("phone-1", "com.example.app")]
    current.child.wait(timeout=3)
    assert not current.result().ok


def test_interruption_cleans_up_child(manager, monkeypatch):
    fake_objection(monkeypatch, "import time; time.sleep(60)")
    original_wait = module.threading.Event.wait

    def wait(event, timeout=None):
        if timeout == module.START_TIMEOUT:
            raise KeyboardInterrupt
        return original_wait(event, timeout)

    monkeypatch.setattr(module.threading.Event, "wait", wait)
    with pytest.raises(KeyboardInterrupt):
        manager.start("com.example.app")
    assert manager.sessions[("phone-1", "com.example.app")].child.poll() is not None


def test_frida_failure_does_not_start_objection(manager, monkeypatch):
    original = module.run_command
    monkeypatch.setattr(module, "run_command", lambda argv, **kw:
                        MobileResult(False, "", "", "") if argv[0] == "frida-ps" else original(argv, **kw))
    assert "Frida cannot connect" in manager.start("com.example.app").output
    assert not manager.sessions


def test_old_objection_is_rejected(manager, monkeypatch):
    original = module.run_command
    monkeypatch.setattr(module, "run_command", lambda argv, **kw:
                        MobileResult(False, "", "", "") if argv[0] == "objection" else original(argv, **kw))
    assert "Update Objection" in manager.start("com.example.app").output
    assert not manager.sessions


def test_selected_serial_is_used(manager, monkeypatch):
    monkeypatch.setenv("ANDROID_SERIAL", "phone-1")
    original = module.run_command
    monkeypatch.setattr(module, "run_command", lambda argv, **kw:
                        MobileResult(True, "", "", "phone-2\tdevice\nphone-1\tdevice")
                        if argv == ["adb", "devices"] else original(argv, **kw))
    calls = fake_objection(monkeypatch, f"print({MARKER!r}, flush=True); import time; time.sleep(60)")
    assert manager.start("com.example.app").ok
    assert calls[0][2] == "phone-1"


def test_no_objection_process_without_explicit_request(monkeypatch):
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("unexpected process"))
    manager = module.ObjectionRootBypass()
    assert manager.status("com.example.app") is None
    manager.stop()


def test_launch_failure_is_reported(manager, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(module.subprocess, "Popen", fail)
    result = manager.start("com.example.app")
    assert not result.ok
    assert "Unable to start Objection" in result.output
    assert not manager.sessions
