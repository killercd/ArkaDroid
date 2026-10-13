import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import droidboard.app as board
from app.db.session import Base
from app.models.http import HttpExchange
from app.models.projects import Project


@pytest.mark.parametrize('name', [
    'sEt-CoOkIe', 'WWW-Authenticate', 'Proxy-Authenticate', 'Authentication-Info',
    'Proxy-Authentication-Info', 'Authorization', 'X-Auth-Token', 'X-Api-Key',
    'X-CSRFToken', 'X-XSRF-Token', 'X-Session-ID', 'X-Amzn-Oidc-Data',
])
def test_response_auth_headers(name):
    row = HttpExchange(id=1, response_raw=f'HTTP 200\r\n{name}: value\r\n\r\nbody')
    group = board._dashboard_auth_endpoints([row], include_findings=True)
    assert group['count'] == 1
    assert group['findings'][0]['value'] == name


def test_auth_headers_ignore_body_request_and_cors_references():
    row = HttpExchange(
        id=1,
        request_raw='GET / HTTP/1.1\nAuthorization: Bearer secret\n\n',
        response_raw='HTTP 200\nAccess-Control-Allow-Headers: Authorization, X-Auth-Token\n'
                     'Access-Control-Allow-Credentials: true\nContent-Type: text/plain\n\nSet-Cookie: fake',
    )
    assert board._dashboard_auth_endpoints([row])['count'] == 0


def test_auth_category_keeps_all_responses_and_filters_project(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.sqlite3'}")
    factory = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(board, 'SessionLocal', factory)
    monkeypatch.setattr(board, 'init_db', lambda: None)
    with factory() as db:
        project = Project(name='auth', proxy_config={})
        other = Project(name='other', proxy_config={})
        db.add_all([project, other])
        db.flush()
        project_id = project.id
        for owner, path in [(project.id, '/login'), (project.id, '/login'), (other.id, '/excluded')]:
            db.add(HttpExchange(project_id=owner, method='GET', host='example.test', port=443,
                path=path, request_raw='GET / HTTP/1.1\n\n',
                response_raw='HTTP 200\nSet-Cookie: sid=one\nSet-Cookie: other=two\nX-Auth-Token: value\n\nok',
                status_code=200))
        db.commit()
    app = board.create_app()
    app.config['TESTING'] = True
    client = app.test_client()
    response = client.get(f'/?project_id={project_id}&tab=dashboard&dashboard_section=secrets&dashboard_secret=auth_endpoints')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'Auth Endpoints' in html
    assert '2 responses' in html
    assert '/excluded' not in html
    assert 'Set-Cookie, X-Auth-Token' in html
    assert 'Send to Repeater' in html
