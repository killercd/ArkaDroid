from dataclasses import dataclass, field
import errno
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import sys
import threading
import time
from time import perf_counter
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.http import HttpExchange
from app.services.authorize import run_authorize_replays
from app.services.call_logger import log_call
from app.services.ca import ensure_ca, ensure_host_certificate
from app.services.reflector import run_reflector_replays
from app.services.repeater import format_raw_request, parse_raw_request
from app.services.security_headers import missing_owasp_security_headers


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request: object, client_address: tuple[str, int] | str) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, OSError) and exc.errno in {
            errno.EBADF,
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.EPIPE,
            errno.ETIMEDOUT,
        }:
            return
        super().handle_error(request, client_address)


@dataclass
class ProxyState:
    active_project_id: int | None = None
    running: bool = False
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    invisible_proxy: bool = False


@dataclass
class InterceptItem:
    id: int
    project_id: int
    direction: str
    method: str
    url: str
    raw: str
    status_code: int | None = None
    created_at: float = field(default_factory=time.time)
    resolved: bool = False
    action: str | None = None
    edited_raw: str | None = None


@dataclass
class InterceptDecision:
    action: str
    raw: str
    modified: bool = False


class ProxyController:
    def __init__(self) -> None:
        self.state = ProxyState(listen_host=get_settings().proxy_host)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._intercept_enabled = False
        self._intercept_next_id = 1
        self._intercept_items: list[InterceptItem] = []
        self._intercept_condition = threading.Condition()

    def open_project(
        self,
        db: Session,
        project_id: int,
        listen_port: int = 8080,
        listen_host: str | None = None,
        invisible_proxy: bool | None = None,
    ) -> ProxyState:
        self.state.active_project_id = project_id
        self.state.listen_port = listen_port
        if listen_host is not None:
            self.state.listen_host = listen_host
        if invisible_proxy is not None:
            self.state.invisible_proxy = invisible_proxy
        return self.state

    def set_invisible_proxy(self, enabled: bool) -> ProxyState:
        self.state.invisible_proxy = enabled
        return self.state

    def start(self, db: Session) -> ProxyState:
        if self.state.active_project_id is None:
            raise RuntimeError("A project must be opened before starting the proxy.")
        if self.state.running:
            return self.state
        self._server = self._build_server()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.state.running = True
        return self.state

    def stop(self, db: Session) -> ProxyState:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        self._server = None
        self._thread = None
        self.state.running = False
        return self.state

    @property
    def intercept_enabled(self) -> bool:
        with self._intercept_condition:
            return self._intercept_enabled

    def set_intercept_enabled(self, enabled: bool) -> None:
        with self._intercept_condition:
            self._intercept_enabled = enabled
            if not enabled:
                for item in self._intercept_items:
                    if not item.resolved:
                        item.resolved = True
                        item.action = "forward"
                self._intercept_condition.notify_all()

    def intercept_snapshot(self, project_id: int | None = None) -> list[InterceptItem]:
        with self._intercept_condition:
            return [
                InterceptItem(
                    id=item.id,
                    project_id=item.project_id,
                    direction=item.direction,
                    method=item.method,
                    url=item.url,
                    raw=item.raw,
                    status_code=item.status_code,
                    created_at=item.created_at,
                    resolved=item.resolved,
                    action=item.action,
                    edited_raw=item.edited_raw,
                )
                for item in self._intercept_items
                if project_id is None or item.project_id == project_id
            ]

    def resolve_intercept(self, item_id: int, action: str, edited_raw: str | None = None) -> bool:
        if action not in {"forward", "drop"}:
            raise ValueError(f"Unsupported intercept action: {action}")
        with self._intercept_condition:
            for item in self._intercept_items:
                if item.id == item_id and not item.resolved:
                    item.resolved = True
                    item.action = action
                    item.edited_raw = edited_raw
                    self._intercept_condition.notify_all()
                    return True
        return False

    def clear_resolved_intercepts(self, project_id: int | None = None) -> int:
        with self._intercept_condition:
            before = len(self._intercept_items)
            self._intercept_items = [
                item
                for item in self._intercept_items
                if not item.resolved or (project_id is not None and item.project_id != project_id)
            ]
            return before - len(self._intercept_items)

    def _build_server(self) -> ThreadingHTTPServer:
        controller = self

        class ProxyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self) -> None:
                if controller.state.invisible_proxy and controller._connection_looks_like_tls(self.connection):
                    controller._handle_invisible_tls(self)
                    return
                super().handle()

            def do_CONNECT(self) -> None:
                controller._handle_connect(self)

            def do_GET(self) -> None:
                controller._handle_http(self)

            def do_POST(self) -> None:
                controller._handle_http(self)

            def do_PUT(self) -> None:
                controller._handle_http(self)

            def do_PATCH(self) -> None:
                controller._handle_http(self)

            def do_DELETE(self) -> None:
                controller._handle_http(self)

            def do_HEAD(self) -> None:
                controller._handle_http(self)

            def do_OPTIONS(self) -> None:
                controller._handle_http(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        return QuietThreadingHTTPServer((self.state.listen_host, self.state.listen_port), ProxyHandler)

    def _connection_looks_like_tls(self, connection: socket.socket) -> bool:
        try:
            data = connection.recv(1, socket.MSG_PEEK)
        except OSError:
            return False
        return data == b"\x16"

    def _handle_http(self, handler: BaseHTTPRequestHandler) -> None:
        if self.state.active_project_id is None:
            handler.send_error(409, "No active project.")
            return

        if self._is_arkadroid_ca_request(handler.path, handler.headers.get("Host")):
            self._serve_ca_certificate(handler, self.state.active_project_id)
            return

        started = perf_counter()
        body = self._read_body(handler)
        target_url = self._target_url(handler)
        decision = self._intercept_request(
            self.state.active_project_id,
            handler.command,
            target_url,
            dict(handler.headers),
            body,
        )
        if decision.action == "drop":
            self._send_dropped(handler)
            return
        if decision.modified:
            handler.command, target_url, intercepted_headers, body = self._parse_intercepted_request(
                decision.raw, handler.command, target_url
            )
        else:
            intercepted_headers = dict(handler.headers)
        outbound_headers = {
            key: value
            for key, value in intercepted_headers.items()
            if key.lower() not in {"proxy-connection", "connection", "host", "accept-encoding", "content-length"}
        }

        try:
            response = httpx.request(
                handler.command,
                target_url,
                headers=outbound_headers,
                content=body,
                timeout=30,
                follow_redirects=False,
                verify=False,
            )
            response_body = response.content
            response_headers = dict(response.headers)
            response_decision = self._intercept_response(
                self.state.active_project_id,
                handler.command,
                target_url,
                response.status_code,
                response_headers,
                response_body,
            )
            if response_decision.action == "drop":
                self._send_dropped(handler)
                return
            if response_decision.modified:
                status_code, response_headers, response_body = self._parse_intercepted_response(
                    response_decision.raw, response.status_code, response_headers
                )
            else:
                status_code = response.status_code
            handler.send_response(status_code)
            for key, value in response_headers.items():
                if key.lower() not in {"transfer-encoding", "content-encoding", "connection"}:
                    handler.send_header(key, value)
            handler.send_header("Content-Length", str(len(response_body)))
            handler.end_headers()
            if handler.command != "HEAD":
                handler.wfile.write(response_body)
        except httpx.HTTPError as exc:
            response_body = str(exc).encode()
            response_headers = {}
            status_code = 502
            handler.send_error(502, str(exc))

        duration_ms = int((perf_counter() - started) * 1000)
        self._persist_exchange(
            project_id=self.state.active_project_id,
            method=handler.command,
            url=target_url,
            request_headers=intercepted_headers,
            request_body=body,
            response_headers=response_headers,
            response_body=response_body,
            status_code=status_code,
            duration_ms=duration_ms,
        )

    def _handle_connect(self, handler: BaseHTTPRequestHandler) -> None:
        started = perf_counter()
        host, _, port_text = handler.path.partition(":")
        port = int(port_text or "443")

        if self.state.active_project_id is None:
            handler.send_error(409, "No active project.")
            return

        handler.send_response(200, "Connection Established")
        handler.end_headers()

        try:
            tls_socket = self._wrap_client_tls(handler.connection, self.state.active_project_id, host)
            self._handle_https_requests(tls_socket, self.state.active_project_id, host, port)
        except (OSError, ssl.SSLError, httpx.HTTPError) as exc:
            self._persist_exchange(
                project_id=self.state.active_project_id,
                method="CONNECT",
                url=f"https://{host}:{port}/",
                request_headers=dict(handler.headers),
                request_body=b"",
                response_headers={},
                response_body=str(exc).encode(),
                status_code=502,
                duration_ms=int((perf_counter() - started) * 1000),
            )

    def _handle_invisible_tls(self, handler: BaseHTTPRequestHandler) -> None:
        started = perf_counter()
        project_id = self.state.active_project_id
        if project_id is None:
            return
        host = self._peek_tls_sni(handler.connection)
        if not host:
            return
        try:
            tls_socket = self._wrap_client_tls(handler.connection, project_id, host)
            self._handle_https_requests(tls_socket, project_id, host, 443)
        except (OSError, ssl.SSLError, httpx.HTTPError) as exc:
            self._persist_exchange(
                project_id=project_id,
                method="TLS",
                url=f"https://{host}/",
                request_headers={},
                request_body=b"",
                response_headers={},
                response_body=str(exc).encode(),
                status_code=502,
                duration_ms=int((perf_counter() - started) * 1000),
            )

    def _peek_tls_sni(self, connection: socket.socket) -> str | None:
        try:
            data = connection.recv(4096, socket.MSG_PEEK)
        except OSError:
            return None
        return self._parse_tls_sni(data)

    def _parse_tls_sni(self, data: bytes) -> str | None:
        if len(data) < 5 or data[0] != 0x16:
            return None
        record_length = int.from_bytes(data[3:5], "big")
        if len(data) < 5 + record_length:
            return None
        offset = 5
        if len(data) < offset + 4 or data[offset] != 0x01:
            return None
        handshake_length = int.from_bytes(data[offset + 1 : offset + 4], "big")
        offset += 4
        end = offset + handshake_length
        if len(data) < end or offset + 34 > end:
            return None
        offset += 2 + 32
        if offset + 1 > end:
            return None
        session_id_length = data[offset]
        offset += 1 + session_id_length
        if offset + 2 > end:
            return None
        cipher_suites_length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2 + cipher_suites_length
        if offset + 1 > end:
            return None
        compression_methods_length = data[offset]
        offset += 1 + compression_methods_length
        if offset + 2 > end:
            return None
        extensions_length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        extensions_end = min(offset + extensions_length, end)
        while offset + 4 <= extensions_end:
            extension_type = int.from_bytes(data[offset : offset + 2], "big")
            extension_length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            offset += 4
            extension_end = offset + extension_length
            if extension_end > extensions_end:
                return None
            if extension_type == 0:
                return self._parse_tls_sni_extension(data[offset:extension_end])
            offset = extension_end
        return None

    def _parse_tls_sni_extension(self, data: bytes) -> str | None:
        if len(data) < 2:
            return None
        offset = 2
        while offset + 3 <= len(data):
            name_type = data[offset]
            name_length = int.from_bytes(data[offset + 1 : offset + 3], "big")
            offset += 3
            name_end = offset + name_length
            if name_end > len(data):
                return None
            if name_type == 0:
                try:
                    return data[offset:name_end].decode("idna").strip()
                except UnicodeError:
                    return None
            offset = name_end
        return None

    def _target_url(self, handler: BaseHTTPRequestHandler) -> str:
        parsed = urlsplit(handler.path)
        if parsed.scheme and parsed.netloc:
            return handler.path
        host = handler.headers.get("Host", "")
        scheme = "https" if handler.server.server_port == 443 else "http"
        return f"{scheme}://{host}{handler.path}"

    def _read_body(self, handler: BaseHTTPRequestHandler) -> bytes:
        length = int(handler.headers.get("Content-Length", "0") or "0")
        return handler.rfile.read(length) if length else b""

    def _is_arkadroid_ca_request(self, target: str, host_header: str | None = None) -> bool:
        parsed = urlsplit(target)
        path = parsed.path if parsed.scheme else target.split("?", 1)[0]
        host = parsed.hostname or (host_header or "").split(":", 1)[0]
        if host.lower() == "arkadroid" and path in {"", "/"}:
            return True
        return path.rstrip("/") in {"/arkadroid", "/arkadroid/ca", "/arkadroid/ca.crt", "/arkadroid/ca.pem"}

    def _serve_ca_certificate(self, handler: BaseHTTPRequestHandler, project_id: int) -> None:
        cert = ensure_ca(project_id)
        handler.send_response(200)
        handler.send_header("Content-Type", "application/x-x509-ca-cert")
        handler.send_header("Content-Disposition", 'attachment; filename="arkadroid-ca.crt"')
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", str(len(cert)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(cert)

    def _serve_tls_ca_certificate(self, tls_socket: ssl.SSLSocket, version: str, project_id: int) -> None:
        cert = ensure_ca(project_id)
        self._write_tls_http_response(
            tls_socket,
            version,
            200,
            {
                "Content-Type": "application/x-x509-ca-cert",
                "Content-Disposition": 'attachment; filename="arkadroid-ca.crt"',
                "Cache-Control": "no-store",
            },
            cert,
        )

    def _wrap_client_tls(self, connection: socket.socket, project_id: int, host: str) -> ssl.SSLSocket:
        cert_path, key_path = ensure_host_certificate(project_id, host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context.wrap_socket(connection, server_side=True)

    def _handle_https_requests(self, tls_socket: ssl.SSLSocket, project_id: int, host: str, port: int) -> None:
        tls_socket.settimeout(30)
        while True:
            parsed_request = self._read_tls_http_request(tls_socket)
            if parsed_request is None:
                break

            method, target, version, headers, body = parsed_request
            if self._is_arkadroid_ca_request(target, host):
                self._serve_tls_ca_certificate(tls_socket, version, project_id)
                break

            started = perf_counter()
            path = target if target.startswith("/") else urlsplit(target).path or "/"
            query = "" if target.startswith("/") else urlsplit(target).query
            url = f"https://{host}{'' if port == 443 else f':{port}'}{path}"
            if query:
                url = f"{url}?{query}"
            decision = self._intercept_request(project_id, method, url, headers, body)
            if decision.action == "drop":
                self._write_tls_dropped_response(tls_socket, version)
                break
            if decision.modified:
                method, url, intercepted_headers, body = self._parse_intercepted_request(decision.raw, method, url)
            else:
                intercepted_headers = headers
            outbound_headers = {
                key: value
                for key, value in intercepted_headers.items()
                if key.lower() not in {"host", "connection", "proxy-connection", "accept-encoding", "content-length"}
            }

            try:
                response = httpx.request(
                    method,
                    url,
                    headers=outbound_headers,
                    content=body,
                    timeout=30,
                    follow_redirects=False,
                    verify=False,
                )
                response_body = response.content
                response_headers = dict(response.headers)
                response_decision = self._intercept_response(
                    project_id,
                    method,
                    url,
                    response.status_code,
                    response_headers,
                    response_body,
                )
                if response_decision.action == "drop":
                    self._write_tls_dropped_response(tls_socket, version)
                    break
                if response_decision.modified:
                    status_code, response_headers, response_body = self._parse_intercepted_response(
                        response_decision.raw, response.status_code, response_headers
                    )
                else:
                    status_code = response.status_code
                self._write_tls_http_response(tls_socket, version, status_code, response_headers, response_body)
            except httpx.HTTPError as exc:
                response_body = str(exc).encode()
                response_headers = {"Content-Type": "text/plain"}
                self._write_tls_http_response(tls_socket, version, 502, response_headers, response_body)
                status_code = 502

            self._persist_exchange(
                project_id=project_id,
                method=method,
                url=url,
                request_headers=headers,
                request_body=body,
                response_headers=response_headers,
                response_body=response_body,
                status_code=status_code,
                duration_ms=int((perf_counter() - started) * 1000),
            )

            if headers.get("Connection", "").lower() == "close":
                break

    def _read_tls_http_request(
        self, tls_socket: ssl.SSLSocket
    ) -> tuple[str, str, str, dict[str, str], bytes] | None:
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = tls_socket.recv(8192)
            if not chunk:
                return None
            buffer += chunk

        header_bytes, _, remainder = buffer.partition(b"\r\n\r\n")
        header_text = header_bytes.decode("iso-8859-1")
        lines = header_text.split("\r\n")
        if not lines or len(lines[0].split()) < 3:
            return None

        method, target, version = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            key, separator, value = line.partition(":")
            if separator:
                headers[key.strip()] = value.strip()

        content_length = int(headers.get("Content-Length", "0") or "0")
        body = remainder
        while len(body) < content_length:
            chunk = tls_socket.recv(content_length - len(body))
            if not chunk:
                break
            body += chunk
        return method, target, version, headers, body[:content_length]

    def _write_tls_http_response(
        self,
        tls_socket: ssl.SSLSocket,
        version: str,
        status_code: int,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        try:
            reason = HTTPStatus(status_code).phrase
        except ValueError:
            reason = "Unknown"
        response_headers = {
            key: value
            for key, value in headers.items()
            if key.lower() not in {"transfer-encoding", "content-encoding", "connection", "content-length"}
        }
        response_headers["Content-Length"] = str(len(body))
        response_headers["Connection"] = "close"
        header_lines = "".join(f"{key}: {value}\r\n" for key, value in response_headers.items())
        tls_socket.sendall(f"{version} {status_code} {reason}\r\n{header_lines}\r\n".encode("iso-8859-1") + body)

    def _write_tls_dropped_response(self, tls_socket: ssl.SSLSocket, version: str) -> None:
        body = b"Dropped by intercept."
        self._write_tls_http_response(tls_socket, version, 502, {"Content-Type": "text/plain"}, body)

    def _send_dropped(self, handler: BaseHTTPRequestHandler) -> None:
        body = b"Dropped by intercept."
        handler.send_response(502)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    def _intercept_request(
        self,
        project_id: int,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> InterceptDecision:
        raw = self._raw_request(method, url, headers, body)
        return self._wait_for_intercept(project_id, "request", method, url, raw)

    def _intercept_response(
        self,
        project_id: int,
        method: str,
        url: str,
        status_code: int,
        headers: dict[str, str],
        body: bytes,
    ) -> InterceptDecision:
        raw = self._raw_response(status_code, headers, body)
        return self._wait_for_intercept(project_id, "response", method, url, raw, status_code)

    def _wait_for_intercept(
        self,
        project_id: int,
        direction: str,
        method: str,
        url: str,
        raw: str,
        status_code: int | None = None,
    ) -> InterceptDecision:
        with self._intercept_condition:
            if not self._intercept_enabled:
                return InterceptDecision("forward", raw)
            item = InterceptItem(
                id=self._intercept_next_id,
                project_id=project_id,
                direction=direction,
                method=method,
                url=url,
                raw=raw,
                status_code=status_code,
            )
            self._intercept_next_id += 1
            self._intercept_items.append(item)
            self._intercept_condition.notify_all()
            while self._intercept_enabled and not item.resolved:
                self._intercept_condition.wait(timeout=1)
            if not item.resolved:
                return InterceptDecision("forward", raw)
            return InterceptDecision(
                item.action or "forward",
                item.edited_raw if item.edited_raw is not None else raw,
                modified=item.edited_raw is not None,
            )

    def _raw_request(self, method: str, url: str, headers: dict[str, str], body: bytes) -> str:
        return format_raw_request(method, url, headers, body)

    def _raw_response(self, status_code: int, headers: dict[str, str], body: bytes) -> str:
        header_lines = "\n".join(f"{key}: {value}" for key, value in headers.items())
        return f"HTTP {status_code}\n{header_lines}\n\n{body.decode(errors='replace')}"

    def _parse_intercepted_request(self, raw: str, default_method: str, default_url: str) -> tuple[str, str, dict[str, str], bytes]:
        head, _separator, _body_text = raw.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        method = default_method
        url = default_url
        headers: dict[str, str] = {}
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
        for line in lines[1:]:
            key, separator, value = line.partition(":")
            if separator:
                headers[key.strip()] = value.strip()
        url = self._absolute_intercept_url(url, default_url, headers)
        parsed_headers, body = parse_raw_request(raw)
        return method, url, parsed_headers, body

    def _absolute_intercept_url(self, url: str, default_url: str, headers: dict[str, str]) -> str:
        parsed = urlsplit(url)
        if parsed.scheme and parsed.netloc:
            return url
        default = urlsplit(default_url)
        host = self._header_value(headers, "Host") or default.netloc
        scheme = default.scheme or "http"
        path = url if url.startswith("/") else f"/{url}"
        return f"{scheme}://{host}{path}"

    def _header_value(self, headers: dict[str, str], name: str) -> str:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    def _parse_intercepted_response(
        self,
        raw: str,
        default_status_code: int,
        default_headers: dict[str, str],
    ) -> tuple[int, dict[str, str], bytes]:
        head, _separator, body_text = raw.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        status_code = default_status_code
        headers: dict[str, str] = {}
        if lines:
            for part in lines[0].split():
                if part.isdigit():
                    status_code = int(part)
                    break
        for line in lines[1:]:
            key, separator, value = line.partition(":")
            if separator:
                headers[key.strip()] = value.strip()
        return status_code, headers or default_headers, body_text.encode()

    def _persist_exchange(
        self,
        project_id: int,
        method: str,
        url: str,
        request_headers: dict,
        request_body: bytes,
        response_headers: dict,
        response_body: bytes,
        status_code: int,
        duration_ms: int,
    ) -> None:
        parsed = urlsplit(url)
        response_header_lines = "\n".join(f"{key}: {value}" for key, value in response_headers.items())
        request_raw = format_raw_request(method, url, request_headers, request_body)
        response_text = response_body.decode(errors="replace")
        response_raw = f"HTTP {status_code}\n{response_header_lines}\n\n{response_text}"
        missing_sec_headers = missing_owasp_security_headers(url, response_headers)
        db = SessionLocal()
        try:
            exchange = HttpExchange(
                project_id=project_id,
                method=method,
                host=parsed.hostname or "",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                path=parsed.path or "/",
                query=parsed.query,
                request_raw=request_raw,
                response_raw=response_raw,
                missing_sec_headers=missing_sec_headers,
                reflecte_params="",
                status_code=status_code,
                response_size=len(response_body),
                duration_ms=duration_ms,
            )
            db.add(exchange)
            db.flush()
            log_call(
                db,
                source="proxy",
                operation=f"request {method} {parsed.hostname or ''}{parsed.path or '/'}",
                project_id=project_id,
                exchange_id=exchange.id,
                status="received",
                payload={
                    "method": method,
                    "url": url,
                    "headers": dict(request_headers),
                    "body_size": len(request_body),
                    "raw": request_raw,
                },
            )
            log_call(
                db,
                source="proxy",
                operation=f"response {method} {parsed.hostname or ''}{parsed.path or '/'}",
                project_id=project_id,
                exchange_id=exchange.id,
                status=str(status_code),
                payload={
                    "method": method,
                    "url": url,
                    "status_code": status_code,
                    "headers": dict(response_headers),
                    "duration_ms": duration_ms,
                    "response_size": len(response_body),
                    "raw": response_raw,
                },
            )
            run_authorize_replays(
                db,
                project_id=project_id,
                source_exchange_id=exchange.id,
                method=method,
                url=url,
                request_headers=dict(request_headers),
                request_body=request_body,
            )
            run_reflector_replays(
                db,
                project_id=project_id,
                source_exchange_id=exchange.id,
                method=method,
                url=url,
                request_headers=dict(request_headers),
                request_body=request_body,
            )
            db.commit()
        finally:
            db.close()


proxy_controller = ProxyController()
