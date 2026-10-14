"""Desktop shell; backend imports must follow configure_storage()."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import sys
import threading
from urllib.request import urlopen


def configure_storage() -> Path:
    configured = os.environ.get("ARKADROID_PROJECT_ROOT")
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    root = Path(configured).expanduser().resolve() if configured else base / "Droidboard"
    root.mkdir(parents=True, exist_ok=True)
    os.environ["ARKADROID_PROJECT_ROOT"] = str(root)
    return root


def configure_proxy_binding(argv: list[str] | None = None) -> None:
    """Apply desktop command-line overrides before backend settings are loaded."""
    arguments = sys.argv[1:] if argv is None else argv
    if "--proxy-all-interfaces" in arguments or "--alliface" in arguments:
        os.environ["ARKADROID_PROXY_HOST"] = "0.0.0.0"


class LocalServer:
    """Bind an OS-assigned loopback port before opening the window."""

    def __init__(self, app):
        from werkzeug.serving import make_server

        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def run_window(webview, app, root: Path) -> None:
    webview.settings["ALLOW_DOWNLOADS"] = True
    with LocalServer(app) as server:
        webview.create_window(
            "Droidboard", server.url, width=1440, height=960,
            min_size=(960, 640), text_select=True, confirm_close=True,
        )
        webview.start(
            gui="edgechromium", debug=False, private_mode=True,
            storage_path=str(root / "webview"),
        )


def smoke_test(app) -> None:
    """Exercise the frozen backend and packaged assets without opening a GUI."""
    with LocalServer(app) as server:
        with urlopen(server.url, timeout=10) as response:
            if response.status != 200 or b"Board Droid" not in response.read():
                raise RuntimeError("The packaged board did not return the expected page.")
        with urlopen(f"{server.url}/static/board.css", timeout=10) as response:
            if response.status != 200 or len(response.read()) < 100:
                raise RuntimeError("The packaged static assets are unavailable.")


def main() -> int:
    log_path = None
    try:
        root = configure_storage()
        configure_proxy_binding()
        log_path = root / "desktop.log"
        handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
        # PyInstaller --windowed sets these streams to None. Libraries and
        # Werkzeug still expect writable streams for diagnostics.
        if sys.stdout is None:
            sys.stdout = handler.stream
        if sys.stderr is None:
            sys.stderr = handler.stream

        from droidboard.app import app
        from app.db.session import SessionLocal, engine
        from app.services.proxy import proxy_controller

        app.config.update(SECRET_KEY=secrets.token_hex(32), DEBUG=False)
        if "--smoke-test" in sys.argv:
            smoke_test(app)
            engine.dispose()
            return 0
        import webview
        try:
            run_window(webview, app, root)
        finally:
            proxy_controller.set_intercept_enabled(False)
            with SessionLocal() as db:
                proxy_controller.stop(db)
            engine.dispose()
        return 0
    except Exception as exc:
        logging.exception("Droidboard desktop startup failed")
        message = (
            f"Unable to start Droidboard.\n\n{exc}\n\n"
            "Microsoft Edge WebView2 Runtime is required on Windows.\n"
            f"Log: {log_path or 'unavailable'}"
        )
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, message, "Droidboard", 0x10)
        elif sys.stderr is not None:
            print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
