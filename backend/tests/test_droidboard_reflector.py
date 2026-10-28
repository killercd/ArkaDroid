import sys
import threading
import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import droidboard.app as droidboard_app
from app.db.session import Base
from app.models.authorize import AuthorizeExchange
from app.models.http import HttpExchange
from app.models.projects import Project
from app.models.repeater import RepeaterRequest
from app.services.proxy import proxy_controller


def test_droidboard_toggles_reflector(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        f"/reflector/toggle?project_id={project_id}&tab=exchanges",
        data={"enabled": "on", "unique_request": "on"},
    )

    assert response.status_code == 302
    with testing_session() as db:
        project = db.get(Project, project_id)
        assert project.proxy_config["reflect_enabled"] is True
        assert project.proxy_config["reflect_unique_request"] is True

    response = client.post(f"/reflector/toggle?project_id={project_id}&tab=exchanges", data={"enabled": "off"})

    assert response.status_code == 302
    with testing_session() as db:
        project = db.get(Project, project_id)
        assert project.proxy_config["reflect_enabled"] is False
        assert project.proxy_config["reflect_unique_request"] is False


def test_droidboard_toggles_invisible_proxy_mode(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None
    proxy_controller.state.running = False
    proxy_controller.state.invisible_proxy = False
    proxy_controller.state.listen_host = "127.0.0.1"

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(f"/proxy/config?project_id={project_id}&tab=exchanges", data={"invisible_proxy": "on"})

    assert response.status_code == 302
    assert proxy_controller.state.invisible_proxy is True
    with testing_session() as db:
        project = db.get(Project, project_id)
        assert project.proxy_config["invisible_proxy"] is True

    response = client.post(f"/proxy/config?project_id={project_id}&tab=exchanges", data={})

    assert response.status_code == 302
    assert proxy_controller.state.invisible_proxy is False
    with testing_session() as db:
        project = db.get(Project, project_id)
        assert project.proxy_config["invisible_proxy"] is False


def test_droidboard_proxy_start_saves_invisible_mode(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    monkeypatch.setattr(proxy_controller, "start", lambda db: setattr(proxy_controller.state, "running", True) or proxy_controller.state)
    proxy_controller.state.active_project_id = None
    proxy_controller.state.running = False
    proxy_controller.state.invisible_proxy = False
    proxy_controller.state.listen_host = "127.0.0.1"

    with testing_session() as db:
        project = Project(name="board", proxy_config={"port": 8080})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        f"/proxy/start?project_id={project_id}&tab=exchanges",
        data={
            "invisible_proxy_present": "1",
            "invisible_proxy": "on",
            "listen_all_interfaces_present": "1",
            "listen_all_interfaces": "on",
        },
    )

    assert response.status_code == 302
    assert proxy_controller.state.invisible_proxy is True
    assert proxy_controller.state.listen_host == "0.0.0.0"
    with testing_session() as db:
        project = db.get(Project, project_id)
        assert project.proxy_config["invisible_proxy"] is True
        assert project.proxy_config["listen_all_interfaces"] is True


def test_droidboard_async_post_returns_json_redirect(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(
        "/projects/create",
        data={"name": "async-board", "port": "8081"},
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["redirect"].endswith("/?project_id=1")
    assert payload["messages"] == [{"category": "success", "message": "Created and opened project #1."}]


def test_droidboard_mobile_page_exposes_logcat_action(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=mobile").get_data(as_text=True)

    assert "/mobile/logcat" in html
    assert 'name="lines"' in html
    assert "Logcat" in html
    assert "data-remote-browser-open" in html
    assert "data-remote-path-input" in html
    assert "/mobile/disable-root-detection" in html
    assert 'name="package"' in html
    assert "disable root detection" in html
    assert "/mobile/install-frida" in html
    assert "Install Frida" in html
    monkeypatch.setattr(droidboard_app, "install_frida", lambda:
                        droidboard_app.mobile_service.MobileResult(True, "Install Frida", "", "Connection verified."))
    response = client.post(f"/mobile/install-frida?project_id={project_id}", follow_redirects=True)
    assert response.status_code == 200
    assert "Connection verified." in response.get_data(as_text=True)

    packages = []

    def start_bypass(package):
        packages.append(package)
        return droidboard_app.mobile_service.MobileResult(
            True, droidboard_app.ROOT_BYPASS_TITLE, "android root disable", "HOOKS_ACTIVE_UNVERIFIED")

    monkeypatch.setattr(droidboard_app.root_bypass, "start", start_bypass)
    response = client.post(f"/mobile/disable-root-detection?project_id={project_id}",
                           data={"package": "com.example.app"}, follow_redirects=True)
    assert response.status_code == 200
    assert packages == ["com.example.app"]
    assert "HOOKS_ACTIVE_UNVERIFIED" in response.get_data(as_text=True)
    monkeypatch.setattr(droidboard_app.root_bypass, "status", lambda package:
                        droidboard_app.mobile_service.MobileResult(
                            False, droidboard_app.ROOT_BYPASS_TITLE, "android root disable", "SESSION_ENDED"))
    html = client.get(f"/?project_id={project_id}&tab=mobile").get_data(as_text=True)
    assert "SESSION_ENDED" in html
    assert "HOOKS_ACTIVE_UNVERIFIED" not in html


def test_droidboard_remote_file_browser_lists_device_path(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    def fake_list_remote_dir(path):
        assert path == "/sdcard/Download"
        return (
            [
                droidboard_app.mobile_service.RemotePathEntry("..", True),
                droidboard_app.mobile_service.RemotePathEntry("apps", True),
                droidboard_app.mobile_service.RemotePathEntry("notes.txt", False),
            ],
            droidboard_app.mobile_service.MobileResult(True, "adb", "adb shell ls", "apps/\nnotes.txt\n"),
        )

    monkeypatch.setattr(droidboard_app.mobile_service, "list_remote_dir", fake_list_remote_dir)
    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get(f"/mobile/remote-files?project_id={project_id}&path=/sdcard/Download")

    assert response.status_code == 200
    assert response.get_json() == {
        "ok": True,
        "path": "/sdcard/Download",
        "parent": "/sdcard",
        "entries": [
            {"name": "apps", "path": "/sdcard/Download/apps", "is_dir": True},
            {"name": "notes.txt", "path": "/sdcard/Download/notes.txt", "is_dir": False},
        ],
    }


def test_droidboard_shows_expandable_curl_commands_without_clipboard(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        exchange = HttpExchange(
            project_id=project.id,
            method="GET",
            host="example.test",
            port=80,
            path="/api",
            query="id=1",
            request_raw="GET /api?id=1 HTTP/1.1\nHost: example.test\n\n",
            response_raw="HTTP 200\n\nok",
            status_code=200,
            response_size=2,
            duration_ms=1,
        )
        db.add(exchange)
        db.flush()
        repeater = RepeaterRequest(
            project_id=project.id,
            source_exchange_id=exchange.id,
            name="repeat",
            method="GET",
            url="http://example.test/api?id=1",
            request_raw=exchange.request_raw,
            response_raw="HTTP 200\n\nok",
            status_code=200,
            response_size=2,
            duration_ms=1,
            error="",
        )
        authorize = AuthorizeExchange(
            project_id=project.id,
            source_exchange_id=exchange.id,
            user_name="user",
            method="GET",
            url="http://example.test/api?id=1",
            request_raw=exchange.request_raw,
            response_raw="HTTP 200\n\nok",
            status_code=200,
            response_size=2,
            duration_ms=1,
            error="",
        )
        db.add_all([repeater, authorize])
        db.commit()
        project_id = project.id
        exchange_id = exchange.id
        authorize_id = authorize.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    exchanges = client.get(f"/?project_id={project_id}&tab=exchanges").get_data(as_text=True)
    repeater = client.get(f"/?project_id={project_id}&tab=repeater").get_data(as_text=True)
    authorize = client.get(f"/?project_id={project_id}&tab=authorize").get_data(as_text=True)

    assert "navigator.clipboard" not in exchanges
    assert "onclick=\"showCurl(this)\"" in exchanges
    assert "id=\"curl-http-exchange-" in exchanges
    assert "id=\"curl-repeater-" in repeater
    assert "id=\"curl-authorize-" in authorize
    assert "GET /api?id=1 HTTP/1.1" not in exchanges
    assert "GET /api?id=1 HTTP/1.1" not in authorize
    assert 'class="async-raw-details"' in exchanges

    exchange_raw = client.get(f"/raw/http-exchange/{exchange_id}?project_id={project_id}").get_json()
    authorize_raw = client.get(f"/raw/authorize/{authorize_id}?project_id={project_id}").get_json()
    assert exchange_raw["request_raw"].startswith("GET /api?id=1")
    assert authorize_raw["response_raw"] == "HTTP 200\n\nok"


def test_droidboard_exchange_to_repeater_keeps_all_repeater_tabs(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        first = HttpExchange(
            project_id=project.id,
            method="GET",
            host="one.test",
            port=80,
            path="/one",
            query="",
            request_raw="GET /one HTTP/1.1\nHost: one.test\n\n",
            response_raw="HTTP 200\n\nok",
            status_code=200,
            response_size=2,
            duration_ms=1,
        )
        second = HttpExchange(
            project_id=project.id,
            method="POST",
            host="two.test",
            port=80,
            path="/two",
            query="",
            request_raw="POST /two HTTP/1.1\nHost: two.test\n\n",
            response_raw="HTTP 201\n\nok",
            status_code=201,
            response_size=2,
            duration_ms=1,
        )
        db.add_all([first, second])
        db.commit()
        project_id = project.id
        exchange_ids = [first.id, second.id]

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    for exchange_id in exchange_ids:
        response = client.post(f"/exchanges/{exchange_id}/to-repeater", follow_redirects=False)
        assert response.status_code == 302
        assert "repeater_q" not in response.headers["Location"]

    with testing_session() as db:
        assert db.query(RepeaterRequest).filter(RepeaterRequest.project_id == project_id).count() == 2

    html = client.get(f"/?project_id={project_id}&tab=repeater").get_data(as_text=True)

    assert html.count('data-repeater-tab="repeater-panel-') == 2
    assert "GET /one HTTP/1.1" in html
    assert "POST /two HTTP/1.1" in html


def test_droidboard_clear_repeater_removes_all_project_tabs(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        other_project = Project(name="other", proxy_config={})
        db.add_all([project, other_project])
        db.flush()
        db.add_all(
            [
                RepeaterRequest(project_id=project.id, method="GET", url="http://one.test", request_raw="GET / HTTP/1.1\n\n"),
                RepeaterRequest(project_id=project.id, method="POST", url="http://two.test", request_raw="POST / HTTP/1.1\n\n"),
                RepeaterRequest(project_id=other_project.id, method="GET", url="http://other.test", request_raw="GET / HTTP/1.1\n\n"),
            ]
        )
        db.commit()
        project_id = project.id
        other_project_id = other_project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    page = client.get(f"/?project_id={project_id}&tab=repeater").get_data(as_text=True)
    assert "/repeater/clear" in page
    assert "Clear" in page

    response = client.post(f"/repeater/clear?project_id={project_id}&tab=repeater", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/?project_id={project_id}&tab=repeater")
    with testing_session() as db:
        assert db.query(RepeaterRequest).filter(RepeaterRequest.project_id == project_id).count() == 0
        assert db.query(RepeaterRequest).filter(RepeaterRequest.project_id == other_project_id).count() == 1


def test_droidboard_dashboard_groups_requests_by_status(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        rows = [
            HttpExchange(
                project_id=project.id,
                method="GET",
                host="example.test",
                port=80,
                path="/ok",
                query="",
                request_raw=(
                    "GET /ok HTTP/1.1\nHost: example.test\nContent-Type: application/json\n\n"
                    '{"email":"dashboard@example.test"}'
                ),
                response_raw="HTTP 200\nContent-Type: application/json\n\nok",
                status_code=200,
                response_size=2,
                duration_ms=1,
            ),
            HttpExchange(
                project_id=project.id,
                method="GET",
                host="example.test",
                port=443,
                path="/app.js",
                query="",
                request_raw="GET /app.js HTTP/1.1\nHost: example.test\n\n",
                response_raw=(
                    "HTTP 200\nContent-Type: application/javascript\n\n"
                    "const hidden = '/api/internal/report.json'; const known = '/ok';"
                ),
                status_code=200,
                response_size=70,
                duration_ms=1,
            ),
            HttpExchange(
                project_id=project.id,
                method="POST",
                host="example.test",
                port=80,
                path="/created",
                query="",
                request_raw="POST /created HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 201\n\nok",
                status_code=201,
                response_size=2,
                duration_ms=1,
            ),
            HttpExchange(
                project_id=project.id,
                method="GET",
                host="example.test",
                port=80,
                path="/missing",
                query="",
                request_raw="GET /missing HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 404\n\nmissing",
                status_code=404,
                response_size=7,
                duration_ms=1,
            ),
        ]
        db.add_all(rows)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=dashboard").get_data(as_text=True)

    assert "Dashboard" in html
    assert "Select a section above" in html
    assert "dashboard_section=status" in html
    assert "dashboard@example.test" not in html
    assert "/api/internal/report.json" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=status").get_data(as_text=True)
    assert "dashboard_status=200" in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=status&dashboard_status=200").get_data(as_text=True)

    assert "/ok" in html
    assert "http://example.test/ok" in html
    assert "https://example.test/app.js" in html
    assert "/created" not in html
    assert "/missing" not in html
    assert "/to-repeater" in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=secrets").get_data(as_text=True)
    assert "dashboard_secret=email" in html
    assert "dashboard@example.test" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=secrets&dashboard_secret=email").get_data(as_text=True)
    assert "dashboard@example.test" in html
    assert "http://example.test/ok" in html
    assert "#1</strong> · GET · <code>http://example.test/ok</code>" in html
    assert 'data-evidence-finding="dashboard@example.test"' in html
    assert "GET /ok HTTP/1.1" not in html
    assert "dashboard_secret=email" not in html.split('class="dashboard-summary-card is-active"', 1)[1].split("</a>", 1)[0]

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=api").get_data(as_text=True)
    assert "API JSON / XML" in html
    assert "http://example.test/ok" in html
    assert "GET /ok HTTP/1.1" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=hidden").get_data(as_text=True)
    assert "/api/internal/report.json" in html
    assert "https://example.test/app.js" in html
    assert "https://example.test/ok" not in html

    raw_response = client.get(f"/dashboard/exchanges/1/raw?project_id={project_id}")
    assert raw_response.status_code == 200
    assert "GET /ok HTTP/1.1" in raw_response.get_json()["request_raw"]


def test_dashboard_detects_secrets_and_json_xml_apis():
    row = HttpExchange(
        id=42,
        project_id=1,
        method="POST",
        host="api.example.test",
        port=443,
        path="/v1/login",
        query="",
        request_raw=(
            "POST /v1/login HTTP/1.1\nContent-Type: application/json\n\n"
            '{"email":"user@example.test","password":"correct-horse-battery"}'
        ),
        response_raw=(
            "HTTP/1.1 200 OK\nContent-Type: application/xml\n\n"
            "<token>Bearer abcdefghijklmnopqrstuvwxyz</token>"
        ),
        status_code=200,
        response_size=1,
        duration_ms=1,
    )

    secret_groups = {
        group["key"]: group for group in droidboard_app._dashboard_secret_groups([row], include_findings_for="email")
    }
    api_count, api_rows = droidboard_app._dashboard_api_rows([row])

    assert secret_groups["email"]["count"] == 1
    assert secret_groups["password"]["count"] == 1
    assert secret_groups["token"]["count"] == 1
    assert api_count == 1
    assert api_rows[0]["formats"] == ["JSON", "XML"]
    assert api_rows[0]["locations"] == ["Request", "Response"]

    duplicate = HttpExchange(
        id=43,
        project_id=1,
        method=row.method,
        host=row.host,
        port=row.port,
        path=row.path,
        query=row.query,
        request_raw=row.request_raw,
        response_raw=row.response_raw,
        status_code=row.status_code,
        response_size=row.response_size,
        duration_ms=row.duration_ms,
    )
    assert droidboard_app._dashboard_unique_response_rows([row, duplicate]) == [row]


def test_droidboard_sends_exchange_to_fuzzer_with_param_prefill(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        exchange = HttpExchange(
            project_id=project.id,
            method="POST",
            host="example.test",
            port=80,
            path="/api",
            query="query=old",
            request_raw=(
                "POST /api?query=old HTTP/1.1\n"
                "Host: example.test\n"
                "Content-Type: application/json\n"
                "\n"
                '{"id":1}'
            ),
            response_raw="HTTP 200\n\nok",
            status_code=200,
            response_size=2,
            duration_ms=1,
        )
        db.add(exchange)
        db.commit()
        project_id = project.id
        exchange_id = exchange.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(f"/exchanges/{exchange_id}/to-fuzzer", follow_redirects=True)
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Request #" in html
    assert "Saved exchange params" not in html
    assert "URL FUZZ marker" not in html
    assert "Fuzz params" not in html
    assert "POST /api?query=old HTTP/1.1" in html
    assert "Raw request" in html


def test_droidboard_sends_repeater_to_fuzzer_with_current_request(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        repeater = RepeaterRequest(
            project_id=project.id,
            source_exchange_id=None,
            name="repeat",
            method="GET",
            url="http://example.test/api?id=1",
            request_raw="GET /api?id=1 HTTP/1.1\nHost: example.test\n\n",
            response_raw="",
            status_code=0,
            response_size=0,
            duration_ms=0,
            error="",
        )
        db.add(repeater)
        db.commit()
        project_id = project.id
        repeater_id = repeater.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    edited_raw = "POST /api HTTP/1.1\nHost: example.test\n\nquery=FUZZ"
    response = client.post(
        f"/repeater/{repeater_id}/to-fuzzer?project_id={project_id}&tab=repeater",
        data={"name": "edited", "method": "POST", "url": "http://example.test/api", "request_raw": edited_raw},
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Saved exchange params" not in html
    assert "URL FUZZ marker" not in html
    assert "Fuzz params" not in html
    assert "query=FUZZ" in html
    with testing_session() as db:
        repeater = db.get(RepeaterRequest, repeater_id)
        assert repeater.name == "edited"
        assert repeater.method == "POST"
        assert repeater.request_raw == edited_raw


def test_droidboard_fuzzer_results_are_paginated_sortable_searchable_and_lazy(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'fuzzer.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    monkeypatch.setattr(droidboard_app, "get_settings", lambda: type("Settings", (), {"droidboard_page_size": 2})())
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="fuzzer-board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    with droidboard_app.FUZZ_LOCK:
        droidboard_app.FUZZ_JOBS.clear()
        droidboard_app.FUZZ_JOB_COUNTER = 1
        droidboard_app.FUZZ_JOBS[1] = {
            "id": 1,
            "project_id": project_id,
            "config": {"range": "1-3", "max_thread": 1, "delay": 0, "show_response": False},
            "status": "done",
            "total": 3,
            "created_at": "now",
            "finished_at": "later",
            "results": [
                _fuzzer_result("1", 404, 12, "https://example.test/a"),
                _fuzzer_result("2", 200, 4, "https://example.test/b"),
                _fuzzer_result("needle", 500, 99, "https://example.test/c"),
            ],
            "error": "",
            "stop_event": threading.Event(),
            "thread": None,
        }

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=fuzzer").get_data(as_text=True)
    assert "Showing page 1 of 2" in html
    assert "https://example.test/c" in html
    assert "https://example.test/b" in html
    assert "https://example.test/a" not in html
    assert "Open to load request and response" in html
    assert "HTTP/1.1 500 OK" not in html
    assert "fuzzer_sort_1=status" in html

    html = client.get(
        f"/?project_id={project_id}&tab=fuzzer&fuzzer_q_1=needle&fuzzer_sort_1=size&fuzzer_order_1=asc"
    ).get_data(as_text=True)
    assert "https://example.test/c" in html
    assert "https://example.test/a" not in html
    assert "Showing page 1 of 1" in html

    raw = client.get(f"/fuzzer/1/results/3/raw?project_id={project_id}")
    assert raw.status_code == 200
    assert raw.json["request_raw"].startswith("GET /needle")
    assert raw.json["response_raw"].startswith("HTTP/1.1 500")


def test_dashboard_groups_fuzzer_results_by_status_and_body_size(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'fuzzer-dashboard.sqlite3'}")
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="fuzzer-dashboard", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    with droidboard_app.FUZZ_LOCK:
        droidboard_app.FUZZ_JOBS.clear()
        droidboard_app.FUZZ_JOB_COUNTER = 1
        droidboard_app.FUZZ_JOBS[1] = {
            "id": 1,
            "project_id": project_id,
            "config": {"range": "1-3", "max_thread": 1, "delay": 0, "show_response": False},
            "status": "done",
            "total": 3,
            "created_at": "now",
            "finished_at": "later",
            "results": [
                _fuzzer_result("1", 200, 10, "https://example.test/a"),
                _fuzzer_result("2", 200, 10, "https://example.test/b"),
                _fuzzer_result("3", 404, 7, "https://example.test/c"),
            ],
            "error": "",
            "stop_event": threading.Event(),
            "thread": None,
        }

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=dashboard").get_data(as_text=True)
    assert "dashboard_section=fuzzer" in html
    assert "https://example.test/a" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=fuzzer").get_data(as_text=True)
    assert "dashboard_fuzzer=200:10" in html
    assert "dashboard_fuzzer=404:7" in html
    assert "https://example.test/a" not in html

    html = client.get(
        f"/?project_id={project_id}&tab=dashboard&dashboard_section=fuzzer&dashboard_fuzzer=200:10"
    ).get_data(as_text=True)
    assert "2 results" in html
    assert "https://example.test/a" in html
    assert "https://example.test/b" in html
    assert "https://example.test/c" not in html


def test_dashboard_reflector_groups_query_post_and_json_values(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'reflector-dashboard.sqlite3'}")
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="reflector-dashboard", proxy_config={})
        db.add(project)
        db.flush()
        project_id = project.id
        rows = [
            HttpExchange(
                project_id=project_id, method="GET", host="example.test", port=80, path="/search", query="q=NeedleQ",
                request_raw="GET /search?q=NeedleQ HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 200\n\nquery value needleq reflected", status_code=200, response_size=29, duration_ms=1,
            ),
            HttpExchange(
                project_id=project_id, method="POST", host="example.test", port=80, path="/form", query="",
                request_raw="POST /form HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\nname=NeedleForm",
                response_raw="HTTP 200\n\nhello NeedleForm", status_code=200, response_size=16, duration_ms=1,
            ),
            HttpExchange(
                project_id=project_id, method="POST", host="example.test", port=80, path="/json", query="",
                request_raw='POST /json HTTP/1.1\nHost: example.test\nContent-Type: application/json\n\n{"user":{"name":"NeedleJson"}}',
                response_raw="HTTP 200\n\njson says NeedleJson", status_code=200, response_size=20, duration_ms=1,
            ),
            HttpExchange(
                project_id=project_id, method="GET", host="example.test", port=80, path="/clean", query="q=SilentNeedle",
                request_raw="GET /clean?q=SilentNeedle HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 200\n\nnothing here", status_code=200, response_size=12, duration_ms=1,
            ),
        ]
        db.add_all(rows)
        db.commit()
        query_id = rows[0].id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=dashboard").get_data(as_text=True)
    assert "dashboard_section=reflector" in html
    assert "NeedleQ" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=reflector").get_data(as_text=True)
    assert "dashboard_reflector=query" in html
    assert "dashboard_reflector=post" in html
    assert "dashboard_reflector=json" in html
    assert "NeedleQ" not in html

    html = client.get(
        f"/?project_id={project_id}&tab=dashboard&dashboard_section=reflector&dashboard_reflector=query"
    ).get_data(as_text=True)
    assert "NeedleQ" in html
    assert "NeedleForm" not in html
    assert f"/dashboard/exchanges/{query_id}/raw?project_id={project_id}" in html
    assert "query value needleq reflected" not in html

    html = client.get(
        f"/?project_id={project_id}&tab=dashboard&dashboard_section=reflector&dashboard_reflector=json"
        ).get_data(as_text=True)
    assert "user.name" in html
    assert "NeedleJson" in html
    assert "SilentNeedle" not in html


def test_dashboard_error_groups_http_500_and_error_signatures(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'error-dashboard.sqlite3'}")
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    errlist = tmp_path / "errlist.txt"
    errlist.write_text("Stack Trace:\nSQL syntax\n", encoding="utf-8")
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    monkeypatch.setattr(droidboard_app, "ERROR_SIGNATURES_PATH", errlist)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="error-dashboard", proxy_config={})
        db.add(project)
        db.flush()
        project_id = project.id
        rows = [
            HttpExchange(
                project_id=project_id, method="GET", host="example.test", port=80, path="/boom", query="",
                request_raw="GET /boom HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 500\n\nplain server failure", status_code=500, response_size=20, duration_ms=1,
            ),
            HttpExchange(
                project_id=project_id, method="GET", host="example.test", port=80, path="/trace", query="",
                request_raw="GET /trace HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 200\n\nlowercase stack trace: details", status_code=200, response_size=30, duration_ms=1,
            ),
            HttpExchange(
                project_id=project_id, method="GET", host="example.test", port=80, path="/ok", query="",
                request_raw="GET /ok HTTP/1.1\nHost: example.test\n\n",
                response_raw="HTTP 200\n\nall good", status_code=200, response_size=8, duration_ms=1,
            ),
        ]
        db.add_all(rows)
        db.commit()
        boom_id = rows[0].id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=dashboard").get_data(as_text=True)
    assert "dashboard_section=error" in html
    assert "plain server failure" not in html

    html = client.get(f"/?project_id={project_id}&tab=dashboard&dashboard_section=error").get_data(as_text=True)
    assert "dashboard_error=status-500" in html
    assert "Stack Trace:" in html
    assert "/boom" not in html

    html = client.get(
        f"/?project_id={project_id}&tab=dashboard&dashboard_section=error&dashboard_error=status-500"
    ).get_data(as_text=True)
    assert "/boom" in html
    assert "/trace" not in html
    assert f"/dashboard/exchanges/{boom_id}/raw?project_id={project_id}" in html
    assert "plain server failure" not in html

    with testing_session() as db:
        stored_rows = db.query(HttpExchange).filter(HttpExchange.project_id == project_id).all()
        signature_key = next(group["key"] for group in droidboard_app._dashboard_error_groups(stored_rows) if group["label"] == "Stack Trace:")
    html = client.get(
        f"/?project_id={project_id}&tab=dashboard&dashboard_section=error&dashboard_error={signature_key}"
    ).get_data(as_text=True)
    assert "/trace" in html
    assert "/ok" not in html
    assert "lowercase stack trace" not in html


def _fuzzer_result(value: str, status: int, size: int, url: str) -> dict:
    return {
        "source": "keyword",
        "name": "FUZZ",
        "value": value,
        "method": "GET",
        "url": url,
        "request_raw": f"GET /{value} HTTP/1.1\nHost: example.test\n\n",
        "source_exchange_id": None,
        "response_raw": f"HTTP/1.1 {status} OK\n\n{'x' * size}",
        "status_code": status,
        "size": size,
        "duration_ms": status,
        "error": "",
    }


def test_droidboard_exchanges_hide_size_ms_security_and_filter_bodies(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.flush()
        request_match = HttpExchange(
            project_id=project.id,
            method="POST",
            host="example.test",
            port=80,
            path="/request-match",
            query="",
            request_raw="POST /request-match HTTP/1.1\nHost: example.test\n\nneedle request body",
            response_raw="HTTP 200\n\nplain",
            status_code=200,
            response_size=5,
            duration_ms=7,
            missing_sec_headers="x-frame-options",
        )
        response_match = HttpExchange(
            project_id=project.id,
            method="GET",
            host="example.test",
            port=80,
            path="/response-match",
            query="",
            request_raw="GET /response-match HTTP/1.1\nHost: example.test\n\nplain",
            response_raw="HTTP 200\n\nneedle response body",
            status_code=200,
            response_size=20,
            duration_ms=9,
            missing_sec_headers="content-security-policy",
        )
        no_match = HttpExchange(
            project_id=project.id,
            method="GET",
            host="example.test",
            port=80,
            path="/no-match",
            query="",
            request_raw="GET /no-match HTTP/1.1\nHost: example.test\n\nplain",
            response_raw="HTTP 200\n\nplain",
            status_code=200,
            response_size=5,
            duration_ms=11,
            missing_sec_headers="strict-transport-security",
        )
        db.add_all([request_match, response_match, no_match])
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=exchanges&body=needle").get_data(as_text=True)

    assert 'name="security"' not in html
    assert ">Security<" not in html
    assert ">Size<" not in html
    assert ">ms<" not in html
    assert 'name="body"' in html
    assert "/request-match" in html
    assert "/response-match" in html
    assert "/no-match" not in html


def test_droidboard_intercept_tab_toggles_resolves_and_clears(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None
    proxy_controller.set_intercept_enabled(False)
    proxy_controller.clear_resolved_intercepts()

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.post(f"/intercept/toggle?project_id={project_id}", data={"enabled": "on"})
    assert response.status_code == 302
    assert proxy_controller.intercept_enabled is True

    decisions = []
    thread = threading.Thread(
        target=lambda: decisions.append(
            proxy_controller._intercept_request(project_id, "GET", "http://example.test/api", {"Host": "example.test"}, b"")
        )
    )
    thread.start()

    deadline = time.time() + 2
    item_id = None
    while time.time() < deadline:
        rows = proxy_controller.intercept_snapshot(project_id)
        if rows:
            item_id = rows[0].id
            break
        time.sleep(0.01)

    assert item_id is not None
    html = client.get(f"/?project_id={project_id}&tab=intercept").get_data(as_text=True)
    assert "Intercept" in html
    assert "pending 1" in html
    assert "http://example.test/api" in html

    edited = "POST http://example.test/edited HTTP/1.1\nHost: example.test\n\nchanged=1"
    response = client.post(
        f"/intercept/{item_id}/resolve?project_id={project_id}",
        data={"action": "forward-edited", "raw": edited},
    )
    assert response.status_code == 302
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert decisions[0].action == "forward"
    assert decisions[0].raw == edited

    response = client.post(f"/intercept/clear?project_id={project_id}")
    assert response.status_code == 302
    assert proxy_controller.intercept_snapshot(project_id) == []
    proxy_controller.set_intercept_enabled(False)


def test_droidboard_mobile_exposes_tui_actions(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    proxy_controller.state.active_project_id = None

    with testing_session() as db:
        project = Project(name="board", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    html = client.get(f"/?project_id={project_id}&tab=mobile").get_data(as_text=True)

    assert "Android" in html
    assert "iOS" in html
    assert "Unset proxy" in html
    assert "Enable firewall" in html
    assert "Disable firewall" in html
    assert "Unpack" in html
    assert "Remote path" in html
    assert "Search pattern" in html

    ios_html = client.get(f"/?project_id={project_id}&tab=mobile&mobile_os=ios").get_data(as_text=True)

    assert "IPA static analysis" in ios_html
    assert "/mobile/ios/scan" in ios_html
    assert "Plist / ATS" in ios_html


def test_droidboard_mobile_result_is_scoped_to_selected_os(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}")
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)

    with testing_session() as db:
        project = Project(name="mobile-scope", proxy_config={})
        db.add(project)
        db.commit()
        project_id = project.id

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as session:
        session["mobile_os"] = "android"
        session["mobile_result_os"] = "android"
        session["mobile_result"] = {
            "ok": True,
            "title": "firewall proxy",
            "command": "adb root",
            "output": "adbd is already running as root",
            "artifact": "",
        }

    ios_html = client.get(f"/?project_id={project_id}&tab=mobile&mobile_os=ios").get_data(as_text=True)

    assert "adbd is already running as root" not in ios_html
    assert "adb root" not in ios_html

    response = client.post(f"/mobile/ios/scan?project_id={project_id}", data={}, follow_redirects=True)
    html = response.get_data(as_text=True)

    assert "IPA file is required." in html
    assert "adbd is already running as root" not in html
    assert "adb root" not in html


def test_dashboard_authorize_matching_responses_and_repeater(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'authorize.sqlite3'}")
    testing_session = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(droidboard_app, "SessionLocal", testing_session)
    monkeypatch.setattr(droidboard_app, "init_db", lambda: None)
    monkeypatch.setattr(proxy_controller.state, "active_project_id", None)
    with testing_session() as db:
        project = Project(name="authorize-dashboard", proxy_config={})
        other = Project(name="other", proxy_config={})
        db.add_all([project, other])
        db.flush()
        project_id, other_id = project.id, other.id
        rows = []
        for source, user, status, body, error, owner in [
            (1, "alice", 200, "matching-body", "", project_id),
            (1, "bob", 200, "matching-body", "", project_id),
            (1, "charlie", 403, "matching-body", "", project_id),
            (1, "dave", 200, "different-body", "", project_id),
            (2, "alice", 200, "matching-body", "", project_id),
            (2, "alice", 200, "matching-body", "", project_id),
            (3, "alice", 0, "", "timeout", project_id),
            (3, "bob", 0, "", "timeout", project_id),
            (1, "outsider", 200, "matching-body", "", other_id),
        ]:
            row = AuthorizeExchange(
                project_id=owner, source_exchange_id=source, user_name=user,
                method="GET", url=f"https://example.test/resource/{source}",
                request_raw=f"GET /resource/{source} HTTP/1.1\r\nHost: example.test\r\nCookie: user={user}\r\n\r\n",
                response_raw=f"HTTP/1.1 {status} OK\r\nX-User: {user}\r\n\r\n{body}" if status else "",
                status_code=status, error=error,
            )
            db.add(row)
            rows.append(row)
        db.commit()
        alice_id = rows[0].id
        alice_request = rows[0].request_raw
        alice_response = rows[0].response_raw

    app = droidboard_app.create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    base = f"/?project_id={project_id}&tab=dashboard"
    assert "resource/1" not in client.get(base).get_data(as_text=True)
    html = client.get(base + "&dashboard_section=authorize").get_data(as_text=True)
    assert "Same Response" in html and "Different Response" in html
    assert "resource/1" not in html
    assert "dashboard_authorize=same" in html and "dashboard_authorize=different" in html
    html = client.get(base + "&dashboard_section=authorize&dashboard_authorize=same").get_data(as_text=True)
    assert "1 groups" in html
    assert "alice" in html and "bob" in html
    assert "resource/1" in html
    for excluded in ["charlie", "dave", "outsider", "resource/2", "resource/3", "matching-body", "Cookie: user="]:
        assert excluded not in html
    assert f'/raw/authorize/{alice_id}?project_id={project_id}' in html
    assert f'/authorize/exchanges/{alice_id}/to-repeater' in html
    active_card = html.split('class="dashboard-summary-card is-active"', 1)[1].split("</a>", 1)[0]
    assert "dashboard_authorize=same" not in active_card
    different_html = client.get(base + "&dashboard_section=authorize&dashboard_authorize=different").get_data(as_text=True)
    assert "1 groups" in different_html
    for included in ["alice", "bob", "charlie", "dave", "resource/1"]:
        assert included in different_html
    for excluded in ["outsider", "resource/2", "resource/3", "matching-body", "Cookie: user="]:
        assert excluded not in different_html
    assert f'/raw/authorize/{alice_id}?project_id={project_id}' in different_html
    assert f'/authorize/exchanges/{alice_id}/to-repeater' in different_html
    raw = client.get(f"/raw/authorize/{alice_id}?project_id={project_id}")
    assert raw.json["request_raw"] == alice_request
    assert raw.json["response_raw"] == alice_response
    assert client.get(f"/raw/authorize/{alice_id}?project_id={other_id}").status_code == 404
    response = client.post(f"/authorize/exchanges/{alice_id}/to-repeater")
    assert response.status_code == 302 and "tab=repeater" in response.location
    with testing_session() as db:
        item = db.query(RepeaterRequest).one()
        assert item.project_id == project_id
        assert item.request_raw == alice_request
        assert item.url == "https://example.test/resource/1"
        assert "alice" in item.name
    empty = client.get(f"/?project_id={other_id}&tab=dashboard&dashboard_section=authorize&dashboard_authorize=same")
    assert "No matching responses" in empty.get_data(as_text=True)
    empty = client.get(f"/?project_id={other_id}&tab=dashboard&dashboard_section=authorize&dashboard_authorize=different")
    assert "No different responses" in empty.get_data(as_text=True)


def test_dashboard_authorize_distinguishes_status_body_and_users():
    def replay(source, user, status=200, body="same"):
        return AuthorizeExchange(source_exchange_id=source, user_name=user,
                                 method="GET", url="https://example.test/", status_code=status,
                                 response_raw=f"HTTP/1.1 {status} OK\r\n\r\n{body}", error="")

    rows = [replay(1, "alice"), replay(1, "bob"),
            replay(2, "alice"), replay(2, "bob", status=403),
            replay(3, "alice"), replay(3, "bob", body="different"),
            replay(4, "alice"), replay(4, "alice", body="different")]
    same = droidboard_app._dashboard_authorize_groups(rows)
    different = droidboard_app._dashboard_authorize_groups(rows, different=True)
    assert [group["source_exchange_id"] for group in same] == [1]
    assert [group["source_exchange_id"] for group in different] == [2, 3]
