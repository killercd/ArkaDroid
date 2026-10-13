from sqlalchemy import create_engine, inspect

from app.db.session import Base
from app.models.show_response import ShowResponseLink
from app.services.show_response import parse_raw_response


def test_show_response_link_table_is_created(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'arkadroid.sqlite3'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    assert "show_response_links" in inspect(engine).get_table_names()


def test_parse_raw_response_keeps_status_headers_and_body():
    status, headers, body = parse_raw_response(
        "HTTP/1.1 201 Created\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 999\r\n"
        "X-Test: yes\r\n"
        "\r\n"
        "<h1>ok</h1>",
        fallback_status=200,
    )

    assert status == 201
    assert body == b"<h1>ok</h1>"
    assert ("Content-Type", "text/html; charset=utf-8") in headers
    assert ("X-Test", "yes") in headers
    assert all(key.lower() != "content-length" for key, _ in headers)


def test_parse_raw_response_uses_text_for_invalid_raw_response():
    status, headers, body = parse_raw_response("network error", fallback_status=0)

    assert status == 200
    assert headers == [("Content-Type", "text/plain; charset=utf-8")]
    assert body == b"network error"


def test_show_response_link_model_fields():
    link = ShowResponseLink(
        token="random-token",
        project_id=1,
        source_type="repeater",
        source_id=7,
        status_code=202,
        response_raw="HTTP 202\n\naccepted",
    )

    assert link.token == "random-token"
    assert link.source_type == "repeater"
    assert link.source_id == 7
