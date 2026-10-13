from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass
from time import perf_counter
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from sqlalchemy.orm import Session

from app.models.http import HttpExchange
from app.models.projects import Project
from app.services.call_logger import log_call


SKIPPED_REPLAY_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "proxy-connection",
    "transfer-encoding",
}


@dataclass(frozen=True)
class ReflectorResult:
    source: str
    name: str
    marker: str
    status_code: int
    reflected: bool
    duration_ms: int
    error: str = ""


def set_reflector_enabled(db: Session, project: Project, enabled: bool, unique_request: bool = False) -> None:
    project.proxy_config = {
        **(project.proxy_config or {}),
        "reflect_enabled": enabled,
        "reflect_unique_request": unique_request,
    }
    db.flush()
    log_call(
        db,
        source="console",
        operation=f"reflect {'on' if enabled else 'off'}",
        project_id=project.id,
        payload={"reflect_enabled": enabled, "reflect_unique_request": unique_request},
    )


def is_reflector_enabled(db: Session, project_id: int) -> bool:
    project = db.get(Project, project_id)
    return bool(project and (project.proxy_config or {}).get("reflect_enabled"))


def run_reflector_replays(
    db: Session,
    *,
    project_id: int,
    source_exchange_id: int,
    method: str,
    url: str,
    request_headers: dict[str, Any],
    request_body: bytes,
) -> list[ReflectorResult]:
    project = db.get(Project, project_id)
    if not project or not (project.proxy_config or {}).get("reflect_enabled"):
        return []

    unique_request = bool((project.proxy_config or {}).get("reflect_unique_request"))
    base_headers = {
        str(key): str(value)
        for key, value in request_headers.items()
        if str(key).lower() not in SKIPPED_REPLAY_HEADERS
    }
    candidates = _candidates(method, url, request_headers, request_body, unique_request)
    results: list[ReflectorResult] = []

    for replay in candidates:
        started = perf_counter()
        error = ""
        response_body = b""
        status_code = 0
        try:
            response = httpx.request(
                method,
                replay["url"],
                headers=base_headers,
                content=replay["body"],
                timeout=30,
                follow_redirects=False,
                verify=False,
            )
            response_body = response.content
            status_code = response.status_code
        except httpx.HTTPError as exc:
            error = str(exc)

        body_text = response_body.decode(errors="replace")
        for source, name, marker in replay["markers"]:
            results.append(
                ReflectorResult(
                    source=source,
                    name=name,
                    marker=marker,
                    status_code=status_code,
                    reflected=marker in body_text,
                    duration_ms=int((perf_counter() - started) * 1000),
                    error=error,
                )
            )

    reflected = [result for result in results if result.reflected]
    if reflected:
        exchange = db.get(HttpExchange, source_exchange_id)
        if exchange is not None:
            active_summary = ", ".join(
                f"active:{result.source}:{result.name}={result.marker}" for result in reflected
            )
            exchange.reflecte_params = _append_summary(exchange.reflecte_params, active_summary)

    for result in results:
        log_call(
            db,
            source="reflector",
            operation=f"{result.source}:{result.name} {method} {url}",
            project_id=project_id,
            exchange_id=source_exchange_id,
            status="reflected" if result.reflected else str(result.status_code),
            message=result.error,
            payload={
                "source": result.source,
                "name": result.name,
                "marker": result.marker,
                "reflected": result.reflected,
                "status_code": result.status_code,
                "duration_ms": result.duration_ms,
                "unique_request": unique_request,
            },
        )
    return results


def _candidates(
    method: str,
    url: str,
    request_headers: dict[str, Any],
    request_body: bytes,
    unique_request: bool,
) -> list[dict[str, object]]:
    if method.upper() == "GET":
        return _query_candidates(url, unique_request)
    if request_body:
        return _body_candidates(url, request_headers, request_body, unique_request)
    return []


def _query_candidates(url: str, unique_request: bool) -> list[dict[str, object]]:
    parsed = urlsplit(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []

    if unique_request:
        markers = [("query", name, _random_marker()) for name, _value in params]
        mutated = [(name, marker) for (_source, name, marker) in markers]
        return [{"url": _replace_query(parsed, mutated), "body": b"", "markers": markers}]

    candidates = []
    for index, (name, _value) in enumerate(params):
        marker = _random_marker()
        mutated = list(params)
        mutated[index] = (name, marker)
        candidates.append({"url": _replace_query(parsed, mutated), "body": b"", "markers": [("query", name, marker)]})
    return candidates


def _body_candidates(
    url: str,
    request_headers: dict[str, Any],
    request_body: bytes,
    unique_request: bool,
) -> list[dict[str, object]]:
    body_text = request_body.decode(errors="replace")
    content_type = _header_value(request_headers, "Content-Type").casefold()
    if _looks_like_form_body(content_type, body_text):
        return _form_body_candidates(url, body_text, unique_request)
    if "json" in content_type:
        return _json_body_candidates(url, body_text, unique_request)
    return []


def _form_body_candidates(url: str, body_text: str, unique_request: bool) -> list[dict[str, object]]:
    params = parse_qsl(body_text, keep_blank_values=True)
    if not params:
        return []

    if unique_request:
        markers = [("post", name, _random_marker()) for name, _value in params]
        body = urlencode([(name, marker) for _source, name, marker in markers]).encode()
        return [{"url": url, "body": body, "markers": markers}]

    candidates = []
    for index, (name, _value) in enumerate(params):
        marker = _random_marker()
        mutated = list(params)
        mutated[index] = (name, marker)
        candidates.append({"url": url, "body": urlencode(mutated).encode(), "markers": [("post", name, marker)]})
    return candidates


def _json_body_candidates(url: str, body_text: str, unique_request: bool) -> list[dict[str, object]]:
    try:
        payload = json.loads(body_text)
    except json.JSONDecodeError:
        return []

    paths = list(_json_scalar_paths(payload))
    if not paths:
        return []

    if unique_request:
        mutated = json.loads(body_text)
        markers = []
        for name, path in paths:
            marker = _random_marker()
            _set_json_path(mutated, path, marker)
            markers.append(("post", name, marker))
        return [{"url": url, "body": json.dumps(mutated).encode(), "markers": markers}]

    candidates = []
    for name, path in paths:
        marker = _random_marker()
        mutated = json.loads(body_text)
        _set_json_path(mutated, path, marker)
        candidates.append({"url": url, "body": json.dumps(mutated).encode(), "markers": [("post", name, marker)]})
    return candidates


def _json_scalar_paths(payload: object, prefix: str = "", path: tuple[object, ...] = ()):
    if isinstance(payload, dict):
        for key, value in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _json_scalar_paths(value, name, (*path, key))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            name = f"{prefix}[{index}]" if prefix else str(index)
            yield from _json_scalar_paths(value, name, (*path, index))
    elif payload is not None:
        yield prefix, path


def _set_json_path(payload: object, path: tuple[object, ...], value: str) -> None:
    current = payload
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


def _replace_query(parsed, params: list[tuple[str, str]]) -> str:
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), parsed.fragment))


def _looks_like_form_body(content_type: str, body_text: str) -> bool:
    return "application/x-www-form-urlencoded" in content_type or "=" in body_text


def _header_value(headers: dict[str, Any], name: str) -> str:
    expected = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == expected:
            return str(value)
    return ""


def _random_marker() -> str:
    alphabet = string.ascii_letters
    return "".join(secrets.choice(alphabet) for _ in range(7))


def _append_summary(current: str, addition: str) -> str:
    if not current:
        return addition
    return f"{current}, {addition}"
