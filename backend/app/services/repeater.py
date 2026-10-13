from __future__ import annotations

import base64
import re
from urllib.parse import urlsplit

import httpx

from app.models.http import HttpExchange

SKIPPED_REPEATER_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-connection",
    "transfer-encoding",
    "x-arkadroid-body-encoding",
}

BODY_ENCODING_HEADER = "X-ArkaDroid-Body-Encoding"


def exchange_url(exchange: HttpExchange) -> str:
    first_line = exchange.request_raw.splitlines()[0] if exchange.request_raw else ""
    parts = first_line.split()
    if len(parts) >= 2:
        parsed = urlsplit(parts[1])
        if parsed.scheme and parsed.netloc:
            return parts[1]

    scheme = "https" if exchange.port == 443 else "http"
    query = f"?{exchange.query}" if exchange.query else ""
    port = "" if exchange.port in {80, 443} else f":{exchange.port}"
    return f"{scheme}://{exchange.host}{port}{exchange.path or '/'}{query}"


def split_raw_message(raw: str) -> tuple[str, str]:
    """Split at the first header terminator, preserving all body characters."""
    separator = re.search(r"\r\n\r\n|\n\n", raw)
    if separator is None:
        return raw, ""
    return raw[:separator.start()], raw[separator.end():]


def parse_raw_request(raw_request: str) -> tuple[dict[str, str], bytes]:
    header_text, body = split_raw_message(raw_request)

    headers: dict[str, str] = {}
    for line in header_text.replace("\r\n", "\n").split("\n")[1:]:
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() not in SKIPPED_REPEATER_HEADERS:
            headers[key.strip()] = value.strip()
    encoding = next(
        (value for key, value in raw_headers(raw_request).items() if key.lower() == BODY_ENCODING_HEADER.lower()), ""
    ).lower()
    if encoding == "base64":
        try:
            return headers, base64.b64decode("".join(body.split()), validate=True)
        except ValueError as exc:
            raise ValueError("Invalid base64-encoded request body.") from exc
    return headers, body.encode()


def format_raw_request(method: str, url: str, headers: dict[str, str], body: bytes) -> str:
    """Build an editable raw request without destroying non-UTF-8 body bytes."""
    display_headers = {
        key: value for key, value in headers.items() if key.lower() != BODY_ENCODING_HEADER.lower()
    }
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError:
        display_headers[BODY_ENCODING_HEADER] = "base64"
        body_text = base64.b64encode(body).decode("ascii")
    header_lines = "\n".join(f"{key}: {value}" for key, value in display_headers.items())
    return f"{method} {url} HTTP/1.1\n{header_lines}\n\n{body_text}"


def raw_headers(raw_request: str) -> dict[str, str]:
    header_text, _ = split_raw_message(raw_request)

    headers: dict[str, str] = {}
    for line in header_text.replace("\r\n", "\n").split("\n")[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip()] = value.strip()
    return headers


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


def send_repeater_request(method: str, url: str, raw_request: str, proxy: str | None = None) -> str:
    # Discard edited framing headers: HTTPX computes Content-Length from bytes,
    # including zero for empty POST/PUT/PATCH, for every caller (also Fuzzer).
    headers, body = parse_raw_request(raw_request)
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL: use an absolute URL, for example https://example.com/path")

    kwargs = {"proxy": proxy} if proxy else {}
    response = httpx.request(
        method.upper(),
        url,
        headers=headers,
        content=body,
        timeout=30,
        follow_redirects=False,
        verify=False,
        **kwargs,
    )
    header_lines = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
    response_body = response.content.decode(errors="replace")
    return f"HTTP {response.status_code}\n{header_lines}\n\n{response_body}"
