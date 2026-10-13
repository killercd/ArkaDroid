from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.authorize import AuthorizeExchange, AuthorizeUser
from app.models.projects import Project
from app.services.authorize import create_authorize_user, run_authorize_replays, set_authorize_enabled


class FakeResponse:
    status_code = 201
    content = b"authorized"
    headers = {"Content-Type": "text/plain"}


def test_create_authorize_user_parses_headers(tmp_path):
    data_file = tmp_path / "mike_data.txt"
    data_file.write_text("Cookie: sid=123\nBearer Token: abc\nX-Role: user\n", encoding="utf-8")
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    with testing_session() as db:
        project = Project(name="test", proxy_config={})
        db.add(project)
        db.flush()
        user = create_authorize_user(db, project.id, "mike", str(data_file))
        headers = user.headers
        db.commit()

    assert headers == {"Cookie": "sid=123", "Authorization": "Bearer abc", "X-Role": "user"}


def test_authorize_replays_unauthenticated_and_users(tmp_path, monkeypatch):
    data_file = tmp_path / "mike_data.txt"
    data_file.write_text("Cookie: sid=123\ncOnTeNt-LeNgTh: 999\nTransfer-Encoding: chunked\n", encoding="utf-8")
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    calls = []

    def fake_request(method, url, headers, content, timeout, follow_redirects, verify):
        calls.append({"method": method, "url": url, "headers": headers, "content": content, "verify": verify})
        return FakeResponse()

    monkeypatch.setattr("app.services.authorize.httpx.request", fake_request)

    with testing_session() as db:
        project = Project(name="test", proxy_config={})
        db.add(project)
        db.flush()
        set_authorize_enabled(db, project, True)
        create_authorize_user(db, project.id, "mike", str(data_file))
        db.commit()
        project_id = project.id

        run_authorize_replays(
            db,
            project_id=project_id,
            source_exchange_id=99,
            method="GET",
            url="http://example.test/admin",
            request_headers={"Cookie": "original=1", "X-Test": "yes"},
            request_body=b"",
        )
        db.commit()

        users = db.query(AuthorizeUser).all()
        entries = db.query(AuthorizeExchange).order_by(AuthorizeExchange.id).all()

    assert [user.name for user in users] == ["mike"]
    assert [entry.user_name for entry in entries] == ["unauthenticated", "mike"]
    assert [call["headers"].get("Cookie") for call in calls] == [None, "sid=123"]
    assert calls[0]["headers"] == {"X-Test": "yes"}
    assert calls[1]["headers"] == {"X-Test": "yes", "Cookie": "sid=123"}
    assert [call["verify"] for call in calls] == [False, False]
