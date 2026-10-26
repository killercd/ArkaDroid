from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import OperationalError
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

    _enable_incremental_auto_vacuum_for_new_database()
    Base.metadata.create_all(bind=engine)
    _ensure_schema_columns()


def _enable_incremental_auto_vacuum_for_new_database(db_engine: Engine = engine) -> bool:
    """Prepare a new SQLite database for cheap, explicit space reclamation.

    Existing SQLite databases need a full VACUUM to change from NONE to
    INCREMENTAL, so they are deliberately left alone during application startup.
    """
    if db_engine.dialect.name != "sqlite":
        return False

    with db_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        has_tables = connection.exec_driver_sql(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
        ).first()
        if has_tables is not None:
            return False
        connection.exec_driver_sql("PRAGMA auto_vacuum=INCREMENTAL")
        return connection.exec_driver_sql("PRAGMA auto_vacuum").scalar_one() == 2


def reclaim_sqlite_space(db_engine: Engine = engine) -> int:
    """Reclaim all freelist pages when incremental auto-vacuum is enabled.

    Returns the number of pages removed. A busy database is left untouched; the
    data deletion has already committed and a later cleanup can retry safely.
    """
    if db_engine.dialect.name != "sqlite":
        return 0

    try:
        with db_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            if connection.exec_driver_sql("PRAGMA auto_vacuum").scalar_one() != 2:
                return 0
            before = connection.exec_driver_sql("PRAGMA freelist_count").scalar_one()
            if before == 0:
                return 0
            # sqlite3 exposes one empty result row per reclaimed page, but
            # SQLAlchemy treats this PRAGMA as a rowless statement and only
            # advances it once. Consume it through the DB-API cursor so SQLite
            # runs the operation to completion.
            cursor = connection.connection.driver_connection.cursor()
            try:
                cursor.execute("PRAGMA incremental_vacuum")
                cursor.fetchall()
            finally:
                cursor.close()
            after = connection.exec_driver_sql("PRAGMA freelist_count").scalar_one()
            return max(0, before - after)
    except OperationalError:
        return 0


def compact_sqlite_database(db_engine: Engine = engine) -> None:
    """Compact SQLite and enable incremental auto-vacuum for future deletes."""
    if db_engine.dialect.name != "sqlite":
        raise RuntimeError("Database compaction is only supported for SQLite")

    with db_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql("PRAGMA auto_vacuum=INCREMENTAL")
        connection.exec_driver_sql("VACUUM")


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
