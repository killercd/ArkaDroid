import sys
from dataclasses import dataclass
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.curl import build_curl


@dataclass
class SourceWithHost:
    method: str
    host: str
    port: int
    path: str
    query: str
    request_raw: str


@dataclass
class SourceWithUrl:
    method: str
    url: str
    request_raw: str


def test_build_curl_from_intercepted_exchange_fields():
    source = SourceWithHost(
        method="POST",
        host="example.test",
        port=443,
        path="/api",
        query="debug=1",
        request_raw=(
            "POST /api?debug=1 HTTP/1.1\n"
            "Host: example.test\n"
            "Cookie: sid=1\n"
            "Content-Length: 7\n"
            "X-Test: yes\n"
            "\n"
            "payload"
        ),
    )

    assert build_curl(source) == (
        "curl -i -X POST 'https://example.test/api?debug=1' "
        "-H 'Cookie: sid=1' -H 'X-Test: yes' --data-binary payload"
    )


def test_build_curl_from_repeater_or_authorize_url():
    source = SourceWithUrl(
        method="PATCH",
        url="https://example.test/profile",
        request_raw="PATCH /profile HTTP/1.1\nAuthorization: Bearer token\n\n{}",
    )

    assert build_curl(source) == (
        "curl -i -X PATCH https://example.test/profile "
        "-H 'Authorization: Bearer token' --data-binary '{}'"
    )
