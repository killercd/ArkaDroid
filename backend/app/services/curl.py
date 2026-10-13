from __future__ import annotations

import os
import shlex
import subprocess
from typing import Protocol
from urllib.parse import urlsplit

from app.services.repeater import split_raw_message


SKIPPED_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-connection",
    "transfer-encoding",
}


class CurlSource(Protocol):
    method: str
    request_raw: str


def split_raw_request(raw_request: str) -> tuple[list[str], str]:
    header_text, body = split_raw_message(raw_request)
    return header_text.replace("\r\n", "\n").split("\n"), body


def request_url(source: CurlSource, first_line: str) -> str:
    parts = first_line.split()
    if len(parts) >= 2:
        parsed = urlsplit(parts[1])
        if parsed.scheme and parsed.netloc:
            return parts[1]

    if hasattr(source, "url"):
        url = getattr(source, "url")
        if url:
            return url

    host = getattr(source, "host", "")
    port = getattr(source, "port", 80)
    scheme = "https" if port == 443 else "http"
    port_text = "" if port in {80, 443} else f":{port}"
    path = getattr(source, "path", "") or "/"
    query = getattr(source, "query", "")
    query_text = f"?{query}" if query else ""
    return f"{scheme}://{host}{port_text}{path}{query_text}"


def build_curl(source: CurlSource) -> str:
    lines, body = split_raw_request(source.request_raw or "")
    first_line = lines[0] if lines else ""
    method = source.method
    parts = first_line.split()
    if parts:
        method = parts[0]

    command = ["curl", "-i", "-X", method.upper(), request_url(source, first_line)]
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() not in SKIPPED_HEADERS:
            command.extend(["-H", f"{key.strip()}: {value.strip()}"])
    if body:
        command.extend(["--data-binary", body])
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return " ".join(shlex.quote(part) for part in command)
