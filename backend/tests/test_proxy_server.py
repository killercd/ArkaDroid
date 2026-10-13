import errno

from app.services.proxy import QuietThreadingHTTPServer


def test_proxy_server_suppresses_closed_socket_tracebacks(capsys):
    server = QuietThreadingHTTPServer(("127.0.0.1", 0), lambda *args: None)
    try:
        try:
            raise OSError(errno.EBADF, "Bad file descriptor")
        except OSError:
            server.handle_error(object(), ("127.0.0.1", 1))
    finally:
        server.server_close()

    captured = capsys.readouterr()
    assert captured.err == ""
