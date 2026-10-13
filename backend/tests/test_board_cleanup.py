from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.authorize import AuthorizeExchange, AuthorizeUser
from app.models.http import HttpExchange
from app.models.projects import Project
from app.models.show_response import ShowResponseLink
from app.services.board_cleanup import clear_authorize_history, clear_http_exchanges


def test_clear_http_exchanges_deletes_only_project_exchanges_and_links(tmp_path):
    testing_session = _testing_session(tmp_path)
    with testing_session() as db:
        project = Project(name="one", proxy_config={})
        other_project = Project(name="two", proxy_config={})
        db.add_all([project, other_project])
        db.flush()
        exchange = _exchange(project.id)
        other_exchange = _exchange(other_project.id)
        db.add_all([exchange, other_exchange])
        db.flush()
        db.add_all(
            [
                ShowResponseLink(
                    token="a",
                    project_id=project.id,
                    source_type="http-exchange",
                    source_id=exchange.id,
                    response_raw="HTTP 200\n\nok",
                ),
                ShowResponseLink(
                    token="b",
                    project_id=other_project.id,
                    source_type="http-exchange",
                    source_id=other_exchange.id,
                    response_raw="HTTP 200\n\nok",
                ),
            ]
        )
        db.commit()
        project_id = project.id

        deleted = clear_http_exchanges(db, project_id)
        db.commit()

        assert deleted == 1
        assert db.query(HttpExchange).count() == 1
        assert db.query(HttpExchange).one().project_id == other_project.id
        assert db.query(ShowResponseLink).count() == 1
        assert db.query(ShowResponseLink).one().token == "b"


def test_clear_authorize_history_keeps_users_and_other_projects(tmp_path):
    testing_session = _testing_session(tmp_path)
    with testing_session() as db:
        project = Project(name="one", proxy_config={})
        other_project = Project(name="two", proxy_config={})
        db.add_all([project, other_project])
        db.flush()
        user = AuthorizeUser(project_id=project.id, name="mike", headers={"Cookie": "sid=1"})
        db.add(user)
        db.flush()
        entry = _authorize_exchange(project.id, user.id, user.name)
        other_entry = _authorize_exchange(other_project.id, None, "unauthenticated")
        db.add_all([entry, other_entry])
        db.flush()
        db.add_all(
            [
                ShowResponseLink(
                    token="a",
                    project_id=project.id,
                    source_type="authorize",
                    source_id=entry.id,
                    response_raw="HTTP 200\n\nok",
                ),
                ShowResponseLink(
                    token="b",
                    project_id=other_project.id,
                    source_type="authorize",
                    source_id=other_entry.id,
                    response_raw="HTTP 200\n\nok",
                ),
            ]
        )
        db.commit()
        project_id = project.id

        deleted = clear_authorize_history(db, project_id)
        db.commit()

        assert deleted == 1
        assert db.query(AuthorizeUser).count() == 1
        assert db.query(AuthorizeExchange).count() == 1
        assert db.query(AuthorizeExchange).one().project_id == other_project.id
        assert db.query(ShowResponseLink).count() == 1
        assert db.query(ShowResponseLink).one().token == "b"


def _testing_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    return testing_session


def _exchange(project_id: int) -> HttpExchange:
    return HttpExchange(
        project_id=project_id,
        method="GET",
        host="example.test",
        port=80,
        path="/",
        query="",
        request_raw="GET / HTTP/1.1",
        response_raw="HTTP 200\n\nok",
        status_code=200,
        response_size=2,
        duration_ms=1,
    )


def _authorize_exchange(project_id: int, user_id: int | None, user_name: str) -> AuthorizeExchange:
    return AuthorizeExchange(
        project_id=project_id,
        source_exchange_id=1,
        user_id=user_id,
        user_name=user_name,
        method="GET",
        url="http://example.test/",
        request_raw="GET http://example.test/ HTTP/1.1",
        response_raw="HTTP 200\n\nok",
        status_code=200,
        response_size=2,
        duration_ms=1,
    )
