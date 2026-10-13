from __future__ import annotations

import json
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.models.http import HttpExchange
from app.services.repeater import send_repeater_request, split_raw_message


FUZZ_TOKEN = "FUZZ"


@dataclass(frozen=True)
class FuzzSource:
    label: str
    method: str
    url: str
    raw_request: str
    source_exchange_id: int | None = None


@dataclass(frozen=True)
class FuzzAttempt:
    source: str
    name: str
    value: str
    method: str
    url: str
    raw_request: str
    source_exchange_id: int | None = None


def parse_fuzz_range(value: str) -> list[str]:
    start_text, separator, end_text = value.strip().partition("-")
    if not separator or not start_text.isdigit() or not end_text.isdigit():
        raise ValueError("Invalid range: use START-END, for example 1-500.")
    start = int(start_text)
    end = int(end_text)
    if end < start:
        raise ValueError("Invalid range: END must be greater than or equal to START.")
    return [str(item) for item in range(start, end + 1)]


def source_from_exchange(exchange: HttpExchange) -> FuzzSource:
    return FuzzSource(
        label=f"exchange #{exchange.id}",
        method=exchange.method,
        url=exchange_url(exchange),
        raw_request=exchange.request_raw,
        source_exchange_id=exchange.id,
    )


def source_from_url(url: str) -> FuzzSource:
    return FuzzSource(label="url", method="GET", url=url, raw_request=f"GET {url} HTTP/1.1\n\n")


def source_from_request_file(path: Path) -> FuzzSource:
    raw_request = path.read_text(encoding="utf-8")
    method, url = method_and_url(raw_request)
    return FuzzSource(label=str(path), method=method, url=url, raw_request=raw_request)


def force_ssl_source(source: FuzzSource) -> FuzzSource:
    url = force_ssl_url(source.url)
    return FuzzSource(
        label=source.label,
        method=source.method,
        url=url,
        raw_request=replace_request_target(source.raw_request, url),
        source_exchange_id=source.source_exchange_id,
    )


def force_ssl_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        return url
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def exchange_url(exchange: HttpExchange) -> str:
    first_line = exchange.request_raw.splitlines()[0] if exchange.request_raw else ""
    parts = first_line.split()
    if len(parts) >= 2:
        parsed = urlsplit(parts[1])
        if parsed.scheme and parsed.netloc:
            return parts[1]

    query = f"?{exchange.query}" if exchange.query else ""
    scheme = "https" if exchange.port == 443 else "http"
    port = "" if exchange.port in {80, 443} else f":{exchange.port}"
    return f"{scheme}://{exchange.host}{port}{exchange.path or '/'}{query}"


def method_and_url(raw_request: str) -> tuple[str, str]:
    first_line = raw_request.splitlines()[0] if raw_request.splitlines() else ""
    parts = first_line.split()
    if len(parts) < 2:
        raise ValueError("Invalid request: missing request line.")
    method = parts[0].upper()
    target = parts[1]
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        return method, target

    headers = raw_headers(raw_request)
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("Invalid request: relative request target requires a Host header.")
    path = target if target.startswith("/") else f"/{target}"
    return method, f"http://{host}{path}"


def build_keyword_attempts(source: FuzzSource, values: list[str]) -> list[FuzzAttempt]:
    if FUZZ_TOKEN not in source.url and FUZZ_TOKEN not in source.raw_request:
        raise ValueError("FUZZ token not found in URL or request.")
    attempts = []
    for value in values:
        attempts.append(
            FuzzAttempt(
                source="keyword",
                name=FUZZ_TOKEN,
                value=value,
                method=source.method,
                url=source.url.replace(FUZZ_TOKEN, value),
                raw_request=source.raw_request.replace(FUZZ_TOKEN, value),
                source_exchange_id=source.source_exchange_id,
            )
        )
    return attempts


def build_param_attempts(source: FuzzSource, selected_names: set[str], values: list[str]) -> list[FuzzAttempt]:
    attempts = []
    for value in values:
        attempts.extend(_query_attempts(source, selected_names, value))
        attempts.extend(_body_attempts(source, selected_names, value))
    return attempts


def run_attempts(
    attempts: list[FuzzAttempt],
    *,
    max_workers: int = 1,
    delay_ms: int = 0,
    stop_event: threading.Event | None = None,
    proxy: str | None = None,
):
    workers = max(1, max_workers)
    delay_seconds = max(0, delay_ms) / 1000
    stop = stop_event or threading.Event()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        iterator = iter(attempts)
        while not stop.is_set():
            while len(pending) < workers:
                try:
                    attempt = next(iterator)
                except StopIteration:
                    break
                pending.add(executor.submit(_send_attempt, attempt, delay_seconds, stop, proxy))
            if not pending:
                break
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield future.result()


def _send_attempt(attempt: FuzzAttempt, delay_seconds: float, stop: threading.Event, proxy: str | None) -> dict[str, object]:
    if stop.is_set():
        return _skipped_result(attempt)
    started = time.perf_counter()
    try:
        response_raw = send_repeater_request(attempt.method, attempt.url, attempt.raw_request, proxy=proxy)
        body = raw_body(response_raw)
        status_code = response_status(response_raw)
        error = ""
    except Exception as exc:  # noqa: BLE001 - fuzzing output must include target/network failures.
        response_raw = str(exc)
        body = ""
        status_code = 0
        error = str(exc)
    duration_ms = int((time.perf_counter() - started) * 1000)
    if delay_seconds:
        stop.wait(delay_seconds)
    return {
        "source": attempt.source,
        "name": attempt.name,
        "value": attempt.value,
        "method": attempt.method,
        "url": attempt.url,
        "request_raw": attempt.raw_request,
        "source_exchange_id": attempt.source_exchange_id,
        "response_raw": response_raw,
        "status_code": status_code,
        "size": len(body.encode()),
        "duration_ms": duration_ms,
        "error": error,
    }


def _skipped_result(attempt: FuzzAttempt) -> dict[str, object]:
    return {
        "source": attempt.source,
        "name": attempt.name,
        "value": attempt.value,
        "method": attempt.method,
        "url": attempt.url,
        "request_raw": attempt.raw_request,
        "source_exchange_id": attempt.source_exchange_id,
        "response_raw": "",
        "status_code": 0,
        "size": 0,
        "duration_ms": 0,
        "error": "stopped",
    }


def _query_attempts(source: FuzzSource, selected_names: set[str], value: str) -> list[FuzzAttempt]:
    include_all = "*" in selected_names
    parsed = urlsplit(source.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    attempts = []
    for index, (name, _old_value) in enumerate(params):
        if not include_all and name not in selected_names:
            continue
        mutated = list(params)
        mutated[index] = (name, value)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), parsed.fragment))
        attempts.append(
            FuzzAttempt(
                source="query",
                name=name,
                value=value,
                method=source.method,
                url=url,
                raw_request=replace_request_target(source.raw_request, url),
                source_exchange_id=source.source_exchange_id,
            )
        )
    return attempts


def _body_attempts(source: FuzzSource, selected_names: set[str], value: str) -> list[FuzzAttempt]:
    body = raw_body(source.raw_request)
    if not body:
        return []
    content_type = header_value(raw_headers(source.raw_request), "Content-Type").casefold()
    if "json" in content_type:
        return _json_attempts(source, body, selected_names, value)
    return _form_attempts(source, body, selected_names, value)


def _form_attempts(source: FuzzSource, body: str, selected_names: set[str], value: str) -> list[FuzzAttempt]:
    include_all = "*" in selected_names
    params = parse_qsl(body, keep_blank_values=True)
    attempts = []
    for index, (name, _old_value) in enumerate(params):
        if not include_all and name not in selected_names:
            continue
        mutated = list(params)
        mutated[index] = (name, value)
        attempts.append(
            FuzzAttempt(
                source="body",
                name=name,
                value=value,
                method=source.method,
                url=source.url,
                raw_request=replace_raw_body(source.raw_request, urlencode(mutated)),
                source_exchange_id=source.source_exchange_id,
            )
        )
    return attempts


def _json_attempts(source: FuzzSource, body: str, selected_names: set[str], value: str) -> list[FuzzAttempt]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []

    include_all = "*" in selected_names
    attempts = []
    for display_name, key_name, path in json_scalar_paths(payload):
        if not include_all and display_name not in selected_names and key_name not in selected_names:
            continue
        mutated = json.loads(body)
        set_json_path(mutated, path, value)
        attempts.append(
            FuzzAttempt(
                source="body",
                name=display_name,
                value=value,
                method=source.method,
                url=source.url,
                raw_request=replace_raw_body(source.raw_request, json.dumps(mutated)),
                source_exchange_id=source.source_exchange_id,
            )
        )
    return attempts


def json_scalar_paths(payload: object, prefix: str = "", path: tuple[object, ...] = ()):
    if isinstance(payload, dict):
        for key, item in payload.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from json_scalar_paths(item, name, (*path, key))
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            name = f"{prefix}[{index}]" if prefix else str(index)
            yield from json_scalar_paths(item, name, (*path, index))
    elif payload is not None and path:
        yield prefix, str(path[-1]), path


def set_json_path(payload: object, path: tuple[object, ...], value: str) -> None:
    current = payload
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


def raw_headers(raw_request: str) -> dict[str, str]:
    header_text, _body = split_raw_message(raw_request)
    headers = {}
    for line in header_text.replace("\r\n", "\n").split("\n")[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


def raw_body(raw_message: str) -> str:
    return split_raw_message(raw_message)[1]


def replace_raw_body(raw_request: str, body: str) -> str:
    head, separator, _old_body = raw_request.replace("\r\n", "\n").partition("\n\n")
    separator = separator or "\n\n"
    return f"{head}{separator}{body}"


def replace_request_target(raw_request: str, url: str) -> str:
    normalized = raw_request.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if not lines:
        return raw_request
    parts = lines[0].split()
    if len(parts) < 2:
        return raw_request
    parts[1] = url
    lines[0] = " ".join(parts)
    return "\n".join(lines)


def header_value(headers: dict[str, str], name: str) -> str:
    expected = name.casefold()
    for key, value in headers.items():
        if key.casefold() == expected:
            return value
    return ""


def response_status(raw_response: str) -> int:
    first_line = raw_response.splitlines()[0] if raw_response else ""
    for part in first_line.split():
        if part.isdigit():
            return int(part)
    return 0
