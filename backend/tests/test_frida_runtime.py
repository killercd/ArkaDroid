from app.services import frida_runtime as module


def test_pipx_interpreter_is_taken_from_launcher(tmp_path, monkeypatch):
    launcher = tmp_path / "objection"
    launcher.write_text("#!/opt/pipx/objection/bin/python\nfrom objection.console.cli import cli\n")
    monkeypatch.setattr(module.shutil, "which", lambda name: str(launcher))
    assert module.objection_python() == ["/opt/pipx/objection/bin/python"]


def test_windows_virtualenv_interpreter(tmp_path, monkeypatch):
    launcher = tmp_path / "objection.exe"
    launcher.write_bytes(b"MZ\x00\xfflauncher")
    python = tmp_path / "python.exe"
    python.touch()
    monkeypatch.setattr(module.shutil, "which", lambda name: str(launcher))
    assert module.objection_python() == [str(python)]


def test_missing_or_unknown_launcher_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    assert module.objection_python() is None
    launcher = tmp_path / "objection"
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setattr(module.shutil, "which", lambda name: str(launcher))
    assert module.objection_python() is None
