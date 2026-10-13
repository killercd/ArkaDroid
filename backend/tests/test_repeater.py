import pytest

from app.models.http import HttpExchange
from app.services.repeater import exchange_url, format_raw_request, method_and_url, parse_raw_request, send_repeater_request


class FakeResponse:
    status_code = 202
    content = b"accepted"
    headers = {"Content-Type": "text/plain"}


def test_exchange_url_infers_scheme_port_and_query():
    exchange = HttpExchange(
        host="example.test",
        port=8080,
        path="/api",
        query="a=1",
        method="POST",
        request_raw="POST /api?a=1 HTTP/1.1\n\n",
    )

    assert exchange_url(exchange) == "http://example.test:8080/api?a=1"


def test_exchange_url_prefers_saved_absolute_url():
    exchange = HttpExchange(
        host="example.test",
        port=8443,
        path="/api",
        query="a=1",
        method="POST",
        request_raw="POST https://example.test:8443/api?a=1 HTTP/1.1\n\n",
    )

    assert exchange_url(exchange) == "https://example.test:8443/api?a=1"


def test_parse_raw_request_keeps_editable_headers_and_body():
    headers, body = parse_raw_request(
        "POST http://example.test/api HTTP/1.1\n"
        "Host: example.test\n"
        "Cookie: sid=1\n"
        "Content-Length: 7\n"
        "X-Test: yes\n"
        "\n"
        "payload"
    )

    assert headers == {"Cookie": "sid=1", "X-Test": "yes"}
    assert body == b"payload"


def test_binary_request_body_round_trips_through_editable_raw_format():
    body = b"\x0a\x12\xf9\x0eprotobuf\x00\xff"
    raw = format_raw_request("POST", "https://example.test/api", {"Content-Type": "application/x-protobuffer"}, body)

    headers, parsed_body = parse_raw_request(raw)

    assert "X-ArkaDroid-Body-Encoding: base64" in raw
    assert headers == {"Content-Type": "application/x-protobuffer"}
    assert parsed_body == body


def test_method_and_url_prefers_request_line_absolute_url():
    assert method_and_url("PATCH https://example.test/api HTTP/1.1\nHost: ignored.test\n\n") == (
        "PATCH",
        "https://example.test/api",
    )


def test_method_and_url_builds_absolute_url_from_host_header():
    assert method_and_url("DELETE /api?id=1 HTTP/1.1\nHost: example.test:8080\n\n") == (
        "DELETE",
        "http://example.test:8080/api?id=1",
    )


def test_send_repeater_request_uses_method_url_headers_and_body(monkeypatch):
    calls = []

    def fake_request(method, url, headers, content, timeout, follow_redirects, verify, proxy=None):
        calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "content": content,
                "timeout": timeout,
                "follow_redirects": follow_redirects,
                "verify": verify,
                "proxy": proxy,
            }
        )
        return FakeResponse()

    monkeypatch.setattr("app.services.repeater.httpx.request", fake_request)

    response = send_repeater_request(
        "put",
        "https://example.test/api",
        "PUT https://example.test/api HTTP/1.1\nX-Test: yes\n\npayload",
    )

    assert response.endswith("\n\naccepted")
    assert calls == [
        {
            "method": "PUT",
            "url": "https://example.test/api",
            "headers": {"X-Test": "yes"},
            "content": b"payload",
            "timeout": 30,
            "follow_redirects": False,
            "verify": False,
            "proxy": None,
        }
    ]


def test_send_repeater_request_can_use_proxy(monkeypatch):
    calls = []

    def fake_request(method, url, headers, content, timeout, follow_redirects, verify, proxy=None):
        calls.append({"proxy": proxy, "verify": verify})
        return FakeResponse()

    monkeypatch.setattr("app.services.repeater.httpx.request", fake_request)

    send_repeater_request(
        "GET",
        "https://example.test/api",
        "GET https://example.test/api HTTP/1.1\n\n",
        proxy="http://127.0.0.1:8080",
    )

    assert calls == [{"proxy": "http://127.0.0.1:8080", "verify": False}]


def test_send_repeater_request_requires_absolute_url():
    with pytest.raises(ValueError, match="Invalid URL"):
        send_repeater_request("GET", "/relative", "GET /relative HTTP/1.1\n\n")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "GET", "HEAD"])
@pytest.mark.parametrize("payload", ["", "caffè ☕ \r\n\n\nend  \n", "binary"])
def test_outbound_content_length_uses_actual_bytes(monkeypatch, method, payload):
    import httpx

    body = b"\x00\xff\xfe" if payload == "binary" else payload.encode()
    raw = format_raw_request(method, "https://example.test/api", {
        "content-LENGTH": "999", "Content-Length": "1", "Transfer-Encoding": "chunked",
    }, body)
    head, body_text = raw.split("\n\n", 1)
    raw = head.replace("\n", "\r\n") + "\r\n\r\n" + body_text
    captured = []

    def receive(request):
        captured.append(request)
        return httpx.Response(200, content=b"ok")

    def send(method, url, **kwargs):
        kwargs.pop("verify")
        with httpx.Client(transport=httpx.MockTransport(receive)) as client:
            return client.request(method, url, **kwargs)

    monkeypatch.setattr("app.services.repeater.httpx.request", send)
    send_repeater_request(method, "https://example.test/api", raw)
    request = captured[0]
    assert request.content == body
    assert "transfer-encoding" not in request.headers
    if body or method in {"POST", "PUT", "PATCH"}:
        assert request.headers.get_list("content-length") == [str(len(body))]
    else:
        assert "content-length" not in request.headers


def test_crlf_headers_do_not_consume_lf_separator_inside_body():
    headers, body = parse_raw_request(
        "PATCH / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\na\n\nb  \r\n"
    )
    assert headers == {}
    assert body == b"a\n\nb  \r\n"
