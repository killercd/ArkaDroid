import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from droidboard.app import _dashboard_hidden_endpoints
from app.models.http import HttpExchange


@pytest.mark.parametrize(
    "invalid_url",
    ["http://[broken/api", "http://[not-an-ip]/api", "http://example.com：80/api", "//[broken/api"],
)
def test_hidden_endpoints_skip_malformed_urls(invalid_url):
    source = HttpExchange(
        id=1,
        host="example.com",
        port=443,
        path="/app.js",
        response_raw=(
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
            f'const invalid = "{invalid_url}"; '
            'const hidden = "/api/hidden?mode=test"; '
            'const observed = "/api/observed"; '
            'const duplicate = "https://example.com/api/hidden?mode=test"; '
            'const ipv6 = "https://[::1]/api/valid";'
        ),
    )

    findings = _dashboard_hidden_endpoints([source], [("example.com", "/api/observed")])

    assert {item["url"] for item in findings} == {
        "https://example.com/api/hidden?mode=test",
        "https://[::1]/api/valid",
    }
    assert len(findings) == 2
    assert all(item["source"] is source for item in findings)
