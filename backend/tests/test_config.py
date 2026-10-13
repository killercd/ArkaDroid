from pathlib import Path
from types import SimpleNamespace

from app.core.config import PROJECT_ROOT, Settings, resolve_app_path, resolve_sqlite_url
import app.core.config as config_module


def test_project_root_points_to_repository_root():
    assert (PROJECT_ROOT / "droidboard" / "app.py").is_file()
    assert (PROJECT_ROOT / "backend" / "app").is_dir()


def test_project_root_can_be_read_from_pip_direct_url(tmp_path, monkeypatch):
    root = tmp_path / "ArkaDroid"
    root.mkdir()
    direct_url = f'{{"dir_info": {{}}, "url": "file://{root}"}}'
    distributions = [
        SimpleNamespace(metadata={"Name": "other"}, read_text=lambda _name: None),
        SimpleNamespace(metadata={"Name": "arkadroid"}, read_text=lambda name: direct_url if name == "direct_url.json" else None),
    ]

    monkeypatch.setattr(config_module, "distributions", lambda: distributions)

    assert config_module._project_root_from_direct_url() == root


def test_resolve_app_path_keeps_relative_paths_stable():
    assert resolve_app_path("./data") == PROJECT_ROOT / "data"


def test_resolve_sqlite_url_makes_default_database_path_absolute():
    assert resolve_sqlite_url("sqlite:///./data/arkadroid.sqlite3") == (
        f"sqlite:///{PROJECT_ROOT / 'data' / 'arkadroid.sqlite3'}"
    )


def test_resolve_sqlite_url_keeps_absolute_and_memory_urls():
    assert resolve_sqlite_url("sqlite:////tmp/arkadroid.sqlite3") == "sqlite:////tmp/arkadroid.sqlite3"
    assert resolve_sqlite_url("sqlite:///:memory:") == "sqlite:///:memory:"
    assert resolve_sqlite_url("postgresql://example/db") == "postgresql://example/db"


def test_resolve_app_path_keeps_absolute_paths():
    assert resolve_app_path("/tmp/arkadroid") == Path("/tmp/arkadroid")


def test_droidboard_page_size_defaults_to_twenty(monkeypatch):
    monkeypatch.delenv("DROIDBOARD_PAGE_SIZE", raising=False)
    assert Settings(_env_file=None).droidboard_page_size == 20


def test_proxy_host_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("ARKADROID_PROXY_HOST", raising=False)
    assert Settings(_env_file=None).proxy_host == "127.0.0.1"
