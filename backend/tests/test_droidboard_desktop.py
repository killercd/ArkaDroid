"""Exercise the desktop HTTP lifecycle without a native GUI dependency."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("fail_gui", [False, True])
def test_desktop_serves_board_and_releases_port(tmp_path, fail_gui):
    root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env.pop("ARKADROID_PROJECT_ROOT", None)
    env.pop("DATABASE_URL", None)
    env.pop("DATA_DIR", None)
    env["LOCALAPPDATA"] = str(tmp_path)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root / "backend")])
    script = '''
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import urlsplit
import socket
import sys
from droidboard.desktop import configure_storage, run_window

root = configure_storage()
assert root == Path(sys.argv[1]) / "Droidboard"
from droidboard.app import app
from app.core.config import get_settings
assert get_settings().resolved_data_dir == root / "data"

class FakeWebview:
    settings = {}
    def create_window(self, title, url, **kwargs):
        self.url = url
    def start(self, **kwargs):
        assert kwargs["gui"] == "edgechromium"
        assert self.settings["ALLOW_DOWNLOADS"]
        with urlopen(self.url, timeout=5) as response:
            assert response.status == 200
            assert b"Board Droid" in response.read()
        with urlopen(self.url + "/static/board.css", timeout=5) as response:
            assert response.status == 200
            assert len(response.read()) > 100
        if sys.argv[2] == "True":
            raise RuntimeError("GUI failed")

webview = FakeWebview()
try:
    run_window(webview, app, root)
except RuntimeError as exc:
    assert str(exc) == "GUI failed"
else:
    assert sys.argv[2] == "False"
port = urlsplit(webview.url).port
with socket.socket() as client:
    client.settimeout(1)
    assert client.connect_ex(("127.0.0.1", port)) != 0
assert (root / "data" / "arkadroid.sqlite3").is_file()
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), str(fail_gui)],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
