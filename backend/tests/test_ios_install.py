import io
import json
import plistlib
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import ios_install as ios
from app.services import mobile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import droidboard.app as board
from app.db.session import Base
from app.models.projects import Project

UDID = "00008110-001234567890ABCD"


@pytest.fixture
def ipa(tmp_path):
    path = tmp_path / "app with spaces.ipa"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "test.demo", "CFBundleExecutable": "Demo"}))
        archive.writestr("Payload/Demo.app/Demo", b"executable")
    return path


@pytest.mark.parametrize("help_text,command", [("install PATH", "install"), ("-i, --install", "-i")])
def test_signed_install_supports_installer_versions(ipa, monkeypatch, help_text, command):
    calls = []
    def run(argv, *, timeout):
        calls.append((argv, timeout))
        return mobile.MobileResult(True, "test", "", help_text if "--help" in argv else "Complete")
    monkeypatch.setattr(ios, "run_command", run)
    assert ios.install_signed_ipa(ipa, UDID, network=True).ok
    assert calls[-1] == (["ideviceinstaller", "--udid", UDID, "--network", command, str(ipa)], 600)


def test_invalid_ipa_or_device_never_runs_installer(tmp_path, ipa, monkeypatch):
    monkeypatch.setattr(ios, "run_command", lambda *a, **k: pytest.fail("must not execute"))
    bad = tmp_path / "bad.ipa"
    bad.write_text("not an archive")
    with pytest.raises(ValueError):
        ios.install_signed_ipa(bad, UDID)
    with pytest.raises(ValueError):
        ios.install_signed_ipa(ipa, "--help")


def test_installer_failure_not_reported_as_success(ipa, monkeypatch):
    monkeypatch.setattr(ios, "run_command", lambda argv, **kw: mobile.MobileResult(
        "--help" in argv, "installer", "", "install PATH" if "--help" in argv else "Invalid signature"))
    result = ios.install_signed_ipa(ipa, UDID)
    assert not result.ok
    assert "Invalid signature" in result.output


def test_timeout_handles_bytes(monkeypatch):
    def timeout(*a, **kw):
        raise subprocess.TimeoutExpired(a[0], 1, output=b"partial output")
    monkeypatch.setattr(mobile.subprocess, "run", timeout)
    result = mobile.run_command(["ideviceinstaller"], timeout=1)
    assert not result.ok and "partial output" in result.output


def wait_for(job, state):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        snapshot = job.snapshot()
        if snapshot["state"] == state:
            return snapshot
        time.sleep(0.01)
    pytest.fail(f"Expected {state}, got {job.snapshot()}")


@pytest.fixture
def signer(tmp_path, monkeypatch):
    executable = tmp_path / "sideloader"
    executable.write_text(f"#!{sys.executable}\n" + '''
import sys
def ask(prompt):
    print(prompt, end='', flush=True)
    return input()
email = ask('Apple ID: ')
password = ask('Password: ')
code = ask('A code has been sent to your devices, please type it here (type `resend` to resend one): ')
if code == 'resend':
    code = ask('A code has been sent to your devices, please type it here (type `resend` to resend one): ')
print(password, code)  # Even a misbehaving child must not leak secrets to snapshots.
sys.exit(0 if email == 'test@example.com' and password == 'private-password' and code == '123456' else 1)
''')
    executable.chmod(0o755)
    monkeypatch.setenv("DROIDBOARD_SIDELOADER", str(executable))
    return executable


def test_real_pty_authentication_resend_and_no_secret_output(ipa, signer):
    job = ios.InstallJob("owner", 1, ipa, UDID, "apple_id")
    thread = threading.Thread(target=job.run)
    thread.start()
    try:
        for prompt, answer in [("apple_id", "test@example.com"), ("password", "private-password"),
                               ("verification_code", "resend"), ("verification_code", "123456")]:
            snapshot = wait_for(job, "waiting")
            assert snapshot["prompt"] == prompt
            with pytest.raises(ValueError):
                job.answer("stale-challenge", answer)
            job.answer(snapshot["challenge"], answer)
        snapshot = wait_for(job, "success")
        assert "private-password" not in json.dumps(snapshot)
        assert "123456" not in json.dumps(snapshot)
        assert job.answers.empty()
    finally:
        job.cancelled.set()
        thread.join(5)
    assert not thread.is_alive()


def test_cancel_during_authentication(ipa, signer):
    job = ios.InstallJob("owner", 1, ipa, UDID, "apple_id")
    thread = threading.Thread(target=job.run)
    thread.start()
    try:
        wait_for(job, "waiting")
        job.cancelled.set()
        wait_for(job, "cancelled")
    finally:
        job.cancelled.set()
        thread.join(5)
    assert not thread.is_alive()


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'board.sqlite3'}")
    sessions = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(board, "SessionLocal", sessions)
    monkeypatch.setattr(board, "init_db", lambda: None)
    with sessions() as db:
        project = Project(name="ios", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id
    app = board.create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    html = client.get(f"/?project_id={project_id}&tab=mobile&mobile_os=ios").get_data(as_text=True)
    assert "Install IPA on iPhone / iPad" in html
    with client.session_transaction() as session:
        token = session["ios_install_csrf"]
    return client, project_id, token


def test_device_route_does_not_require_ipa(client, monkeypatch):
    client, project, _ = client
    monkeypatch.setattr(ios, "devices", lambda **kw: mobile.MobileResult(True, "devices", "", UDID))
    response = client.get(f"/mobile/ios/devices?project_id={project}")
    assert response.json["devices"] == [UDID]


def test_route_upload_csrf_status_and_owner_isolation(client, ipa, monkeypatch, tmp_path):
    client, project, token = client
    calls = []
    monkeypatch.setattr(mobile, "project_upload_dir", lambda _: tmp_path)
    def install(path, udid, **kw):
        calls.append((path.read_bytes(), udid))
        return mobile.MobileResult(True, "Install", "", "Installed")
    monkeypatch.setattr(ios, "install_signed_ipa", install)
    url = f"/mobile/ios/install?project_id={project}"
    assert client.post(url, data={"ipa_path": str(ipa)}).status_code == 403
    response = client.post(url, data={"csrf_token": token, "mode": "signed", "udid": UDID,
                                     "ipa_file": (io.BytesIO(ipa.read_bytes()), "upload.ipa")})
    assert response.status_code == 202
    status_url = f"/mobile/ios/install/{response.json['job']['id']}?project_id={project}"
    for _ in range(100):
        status = client.get(status_url)
        if status.json["job"]["state"] == "success":
            break
        time.sleep(0.01)
    assert status.json["job"]["state"] == "success"
    assert status.headers["Cache-Control"] == "no-store"
    assert calls == [(ipa.read_bytes(), UDID)]
    with client.session_transaction() as session:
        session["ios_install_owner"] = "another-browser"
    assert client.get(status_url).status_code == 404


def test_missing_signer_and_remote_plain_http_fail_cleanly(client, ipa, monkeypatch):
    client, project, token = client
    monkeypatch.setenv("DROIDBOARD_SIDELOADER", "/does/not/exist")
    data = {"csrf_token": token, "mode": "apple_id", "udid": UDID, "ipa_path": str(ipa)}
    response = client.post(f"/mobile/ios/install?project_id={project}", data=data)
    assert response.status_code == 400 and "missing" in response.json["error"]
    response = client.post(f"/mobile/ios/install?project_id={project}", data=data,
                           environ_overrides={"REMOTE_ADDR": "192.168.1.10"})
    assert response.status_code == 400 and "HTTPS" in response.json["error"]
