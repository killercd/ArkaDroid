from functools import lru_cache
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from importlib.metadata import distributions

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _project_root_from_direct_url() -> Path | None:
    for distribution in distributions():
        if distribution.metadata.get("Name") != "arkadroid":
            continue
        direct_url = distribution.read_text("direct_url.json")
        if not direct_url:
            continue
        try:
            payload = json.loads(direct_url)
        except json.JSONDecodeError:
            continue
        parsed = urlparse(payload.get("url", ""))
        if parsed.scheme != "file":
            continue
        path = Path(unquote(parsed.path))
        if path.exists():
            return path.resolve()
    return None


def _project_root() -> Path:
    configured = os.environ.get("ARKADROID_PROJECT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    installed_root = _project_root_from_direct_url()
    if installed_root is not None:
        return installed_root
    return Path(__file__).resolve().parents[3]


PROJECT_ROOT = _project_root()


def resolve_app_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return PROJECT_ROOT / candidate


def resolve_sqlite_url(url: str) -> str:
    if not url.startswith("sqlite:///"):
        return url

    db_path, separator, query = url.removeprefix("sqlite:///").partition("?")
    if db_path in {"", ":memory:"}:
        return url

    if db_path.startswith("/"):
        return url

    return f"sqlite:///{resolve_app_path(db_path)}{separator}{query}"


class Settings(BaseSettings):
    app_name: str = "ArkaDroid"
    app_env: str = Field(default="development", alias="APP_ENV")
    proxy_host: str = Field(default="127.0.0.1", alias="ARKADROID_PROXY_HOST")
    droidboard_page_size: int = Field(default=20, alias="DROIDBOARD_PAGE_SIZE")
    database_url: str = Field(
        default="sqlite:///./data/arkadroid.sqlite3",
        alias="DATABASE_URL",
    )
    data_dir: str = Field(default="./data", alias="DATA_DIR")

    model_config = SettingsConfigDict(env_file=str(PROJECT_ROOT / ".env"), extra="ignore")

    @property
    def resolved_database_url(self) -> str:
        return resolve_sqlite_url(self.database_url)

    @property
    def resolved_data_dir(self) -> Path:
        return resolve_app_path(self.data_dir)


@lru_cache
def get_settings() -> Settings:
    return Settings()
