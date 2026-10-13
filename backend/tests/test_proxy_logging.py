import threading
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db.session as session_module
from app.db.session import Base
from app.models.call_log import CallLog
from app.models.http import HttpExchange
from app.models.projects import Project
from app.services.proxy import ProxyController


def test_proxy_persists_request_and_response_logs(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(session_module, "SessionLocal", testing_session)
    monkeypatch.setattr("app.services.proxy.SessionLocal", testing_session)

    with testing_session() as db:
        project = Project(name="test", proxy_config={"port": 8080})
        db.add(project)
        db.commit()
        project_id = project.id

    ProxyController()._persist_exchange(
        project_id=project_id,
        method="GET",
        url="http://example.test/resource?term=ProbeValue",
        request_headers={"Host": "example.test", "X-Token": "HeaderProbe"},
        request_body=b"",
        response_headers={"Content-Type": "text/plain"},
        response_body=b"ok probevalue headerprobe",
        status_code=200,
        duration_ms=12,
    )

    with testing_session() as db:
        exchange = db.query(HttpExchange).one()
        logs = db.query(CallLog).order_by(CallLog.id).all()

    assert exchange.response_raw.endswith("\n\nok probevalue headerprobe")
    assert exchange.missing_sec_headers == (
        "Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, "
        "Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, X-Frame-Options"
    )
    assert exchange.reflecte_params == ""
    assert [log.operation.split()[0] for log in logs] == ["request", "response"]
    assert logs[0].payload["raw"].startswith("GET http://example.test/resource?term=ProbeValue HTTP/1.1")
    assert logs[1].payload["status_code"] == 200
    assert logs[1].payload["raw"].endswith("\n\nok probevalue headerprobe")


def test_proxy_intercept_queues_and_resolves_edited_request():
    controller = ProxyController()
    controller.set_intercept_enabled(True)
    decisions = []

    thread = threading.Thread(
        target=lambda: decisions.append(
            controller._intercept_request(1, "GET", "http://example.test/api", {"Host": "example.test"}, b"")
        )
    )
    thread.start()

    deadline = time.time() + 2
    items = []
    while time.time() < deadline:
        items = controller.intercept_snapshot(1)
        if items:
            break
        time.sleep(0.01)

    assert len(items) == 1
    assert items[0].direction == "request"
    edited = "POST http://example.test/edited HTTP/1.1\nHost: example.test\n\nchanged=1"
    assert controller.resolve_intercept(items[0].id, "forward", edited)

    thread.join(timeout=2)

    assert not thread.is_alive()
    assert decisions[0].action == "forward"
    assert decisions[0].raw == edited


def test_proxy_intercept_parses_relative_edited_request_with_host_header():
    controller = ProxyController()

    method, url, headers, body = controller._parse_intercepted_request(
        "POST /edited?q=1 HTTP/1.1\nHost: example.test\nContent-Type: text/plain\n\nchanged",
        "GET",
        "https://original.test/api",
    )

    assert method == "POST"
    assert url == "https://example.test/edited?q=1"
    assert headers["Content-Type"] == "text/plain"
    assert body == b"changed"


def test_proxy_unmodified_intercept_decision_preserves_binary_body():
    controller = ProxyController()
    body = b"\x12\xf9\x0e\x00\xffcaptcha"

    raw = controller._raw_request("POST", "https://example.test/api", {"Content-Type": "application/x-protobuffer"}, body)
    decision = controller._intercept_request(1, "POST", "https://example.test/api", {}, body)

    assert decision.modified is False
    assert b"\xef\xbf\xbd" not in raw.encode()
    assert controller._parse_intercepted_request(raw, "POST", "https://example.test/api")[3] == body


def test_proxy_parses_sni_from_tls_client_hello():
    host = b"api.example.test"
    sni_extension = (
        b"\x00\x00"
        + (len(host) + 5).to_bytes(2, "big")
        + (len(host) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(host).to_bytes(2, "big")
        + host
    )
    extensions = sni_extension
    body = (
        b"\x03\x03"
        + (b"\x00" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    assert ProxyController()._parse_tls_sni(record) == "api.example.test"
