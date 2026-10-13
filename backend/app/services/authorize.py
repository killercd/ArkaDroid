from pathlib import Path
from time import perf_counter
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models.authorize import AuthorizeExchange, AuthorizeUser
from app.models.projects import Project
from app.services.call_logger import log_call


SKIPPED_REPLAY_HEADERS = {
    "accept-encoding",
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "transfer-encoding",
}


def parse_authorize_data(path: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("bearer token"):
            token = _line_value(line, "bearer token")
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
            continue
        if lowered.startswith("bearer "):
            headers["Authorization"] = line
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"Invalid line in {path}: {raw_line!r}")
        headers[key.strip()] = value.strip()
    return headers


def create_authorize_user(db: Session, project_id: int, name: str, data_file: str) -> AuthorizeUser:
    user = AuthorizeUser(project_id=project_id, name=name, headers=parse_authorize_data(data_file), source_file=data_file)
    db.add(user)
    db.flush()
    log_call(
        db,
        source="console",
        operation=f"create user {name}",
        project_id=project_id,
        payload={"headers": list(user.headers.keys()), "source_file": data_file},
    )
    return user


def edit_authorize_user(db: Session, project_id: int, name: str, data_file: str) -> AuthorizeUser:
    user = _get_authorize_user(db, project_id, name)
    user.headers = parse_authorize_data(data_file)
    user.source_file = data_file
    db.flush()
    log_call(
        db,
        source="console",
        operation=f"edit user {name}",
        project_id=project_id,
        payload={"headers": list(user.headers.keys()), "source_file": data_file},
    )
    return user


def remove_authorize_user(db: Session, project_id: int, name: str) -> None:
    user = _get_authorize_user(db, project_id, name)
    db.delete(user)
    log_call(db, source="console", operation=f"remove user {name}", project_id=project_id)


def set_authorize_enabled(db: Session, project: Project, enabled: bool) -> None:
    project.proxy_config = {**(project.proxy_config or {}), "authorize_enabled": enabled}
    db.flush()
    log_call(
        db,
        source="console",
        operation=f"authorize {'on' if enabled else 'off'}",
        project_id=project.id,
        payload={"authorize_enabled": enabled},
    )


def is_authorize_enabled(db: Session, project_id: int) -> bool:
    project = db.get(Project, project_id)
    return bool(project and (project.proxy_config or {}).get("authorize_enabled"))


def run_authorize_replays(
    db: Session,
    *,
    project_id: int,
    source_exchange_id: int,
    method: str,
    url: str,
    request_headers: dict[str, Any],
    request_body: bytes,
) -> list[AuthorizeExchange]:
    if not is_authorize_enabled(db, project_id):
        return []

    users = db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id).order_by(AuthorizeUser.name.asc()).all()
    contexts: list[tuple[int | None, str, dict[str, str]]] = [(None, "unauthenticated", {})]
    contexts.extend((user.id, user.name, user.headers) for user in users)

    base_headers = {
        str(key): str(value)
        for key, value in request_headers.items()
        if str(key).lower() not in SKIPPED_REPLAY_HEADERS
    }
    replay_results = []
    for user_id, user_name, user_headers in contexts:
        headers = {
            key: value for key, value in {**base_headers, **user_headers}.items()
            if key.lower() not in {"content-length", "transfer-encoding"}
        }
        started = perf_counter()
        request_raw = _format_request_raw(method, url, headers, request_body)
        error = ""
        try:
            response = httpx.request(
                method,
                url,
                headers=headers,
                content=request_body,
                timeout=30,
                follow_redirects=False,
                verify=False,
            )
            response_body = response.content
            response_headers = dict(response.headers)
            status_code = response.status_code
        except httpx.HTTPError as exc:
            response_body = str(exc).encode()
            response_headers = {"Content-Type": "text/plain"}
            status_code = 0
            error = str(exc)

        replay_results.append(
            {
                "user_id": user_id,
                "user_name": user_name,
                "request_raw": request_raw,
                "response_raw": _format_response_raw(status_code, response_headers, response_body),
                "status_code": status_code,
                "response_size": len(response_body),
                "duration_ms": int((perf_counter() - started) * 1000),
                "error": error,
            }
        )

    entries = []
    for result in replay_results:
        entry = AuthorizeExchange(
            project_id=project_id,
            source_exchange_id=source_exchange_id,
            user_id=result["user_id"],
            user_name=result["user_name"],
            method=method,
            url=url,
            request_raw=result["request_raw"],
            response_raw=result["response_raw"],
            status_code=result["status_code"],
            response_size=result["response_size"],
            duration_ms=result["duration_ms"],
            error=result["error"],
        )
        db.add(entry)
        db.flush()
        log_call(
            db,
            source="authorize",
            operation=f"{result['user_name']} {method} {url}",
            project_id=project_id,
            exchange_id=source_exchange_id,
            status=str(result["status_code"]),
            payload={
                "authorize_exchange_id": entry.id,
                "user_name": result["user_name"],
                "status_code": result["status_code"],
                "response_size": result["response_size"],
                "duration_ms": result["duration_ms"],
                "error": result["error"],
            },
        )
        entries.append(entry)
    return entries


def _get_authorize_user(db: Session, project_id: int, name: str) -> AuthorizeUser:
    user = db.query(AuthorizeUser).filter(AuthorizeUser.project_id == project_id, AuthorizeUser.name == name).one_or_none()
    if user is None:
        raise ValueError(f"Authorize user not found: {name}")
    return user


def _line_value(line: str, prefix: str) -> str:
    if ":" in line:
        return line.split(":", 1)[1].strip()
    return line[len(prefix) :].strip()


def _format_request_raw(method: str, url: str, headers: dict[str, str], body: bytes) -> str:
    header_lines = "\n".join(f"{key}: {value}" for key, value in headers.items())
    return f"{method} {url} HTTP/1.1\n{header_lines}\n\n{body.decode(errors='replace')}"


def _format_response_raw(status_code: int, headers: dict[str, str], body: bytes) -> str:
    header_lines = "\n".join(f"{key}: {value}" for key, value in headers.items())
    return f"HTTP {status_code}\n{header_lines}\n\n{body.decode(errors='replace')}"
