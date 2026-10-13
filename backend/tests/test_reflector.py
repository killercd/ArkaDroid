from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.http import HttpExchange
from app.models.projects import Project
from app.services.reflector import run_reflector_replays, set_reflector_enabled


class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/plain"}

    def __init__(self, content: bytes):
        self.content = content


def test_reflector_replays_each_get_parameter_and_updates_exchange(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    calls = []
    markers = iter(["Mark0AA", "Mark1AA"])

    def fake_request(method, url, headers, content, timeout, follow_redirects, verify):
        calls.append({"url": url, "verify": verify})
        body = b"hello Mark1AA" if "name=Mark1AA" in url else b"not reflected"
        return FakeResponse(body)

    monkeypatch.setattr("app.services.reflector.httpx.request", fake_request)
    monkeypatch.setattr("app.services.reflector._random_marker", lambda: next(markers))

    with testing_session() as db:
        project = Project(name="test", proxy_config={})
        db.add(project)
        db.flush()
        set_reflector_enabled(db, project, True)
        exchange = HttpExchange(
            project_id=project.id,
            method="GET",
            host="example.test",
            port=80,
            path="/api",
            query="id=1&name=renato",
            request_raw="GET http://example.test/api?id=1&name=renato HTTP/1.1\n\n",
            response_raw="HTTP 200\n\n",
            status_code=200,
            response_size=0,
            duration_ms=1,
        )
        db.add(exchange)
        db.flush()

        results = run_reflector_replays(
            db,
            project_id=project.id,
            source_exchange_id=exchange.id,
            method="GET",
            url="http://example.test/api?id=1&name=renato",
            request_headers={"Host": "example.test"},
            request_body=b"",
        )
        db.commit()

        saved = db.get(HttpExchange, exchange.id)

    assert len(calls) == 2
    assert "id=Mark0AA&name=renato" in calls[0]["url"]
    assert "id=1&name=Mark1AA" in calls[1]["url"]
    assert [call["verify"] for call in calls] == [False, False]
    assert [(result.name, result.reflected) for result in results] == [("id", False), ("name", True)]
    assert saved.reflecte_params == "active:query:name=Mark1AA"


def test_reflector_unique_request_identifies_reflected_post_parameter(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    calls = []
    markers = iter(["AbCdEfG", "HiJkLmN"])

    def fake_request(method, url, headers, content, timeout, follow_redirects, verify):
        calls.append(content)
        return FakeResponse(b"hello HiJkLmN")

    monkeypatch.setattr("app.services.reflector.httpx.request", fake_request)
    monkeypatch.setattr("app.services.reflector._random_marker", lambda: next(markers))

    with testing_session() as db:
        project = Project(name="test", proxy_config={})
        db.add(project)
        db.flush()
        set_reflector_enabled(db, project, True, unique_request=True)
        exchange = HttpExchange(
            project_id=project.id,
            method="POST",
            host="example.test",
            port=80,
            path="/api",
            query="",
            request_raw="POST http://example.test/api HTTP/1.1\n\nid=1&name=renato",
            response_raw="HTTP 200\n\n",
            status_code=200,
            response_size=0,
            duration_ms=1,
        )
        db.add(exchange)
        db.flush()

        results = run_reflector_replays(
            db,
            project_id=project.id,
            source_exchange_id=exchange.id,
            method="POST",
            url="http://example.test/api",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body=b"id=1&name=renato",
        )
        db.commit()

        saved = db.get(HttpExchange, exchange.id)

    assert calls == [b"id=AbCdEfG&name=HiJkLmN"]
    assert [(result.name, result.reflected) for result in results] == [("id", False), ("name", True)]
    assert saved.reflecte_params == "active:post:name=HiJkLmN"
