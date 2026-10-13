from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy import inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
database_url = settings.resolved_database_url
is_sqlite = database_url.startswith("sqlite")
connect_args = {"check_same_thread": False, "timeout": 30} if is_sqlite else {}

if database_url.startswith("sqlite:///"):
    db_path = database_url.removeprefix("sqlite:///")
    if db_path and db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

settings.resolved_data_dir.mkdir(parents=True, exist_ok=True)

engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)


if is_sqlite:

    @event.listens_for(engine, "connect")
    def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_schema_columns()


def _ensure_schema_columns() -> None:
    inspector = inspect(engine)
    if "http_exchanges" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("http_exchanges")}
    with engine.begin() as connection:
        if "missing_sec_headers" not in columns:
            connection.execute(text("ALTER TABLE http_exchanges ADD COLUMN missing_sec_headers TEXT DEFAULT ''"))
        if "reflecte_params" not in columns:
            connection.execute(text("ALTER TABLE http_exchanges ADD COLUMN reflecte_params TEXT DEFAULT ''"))
