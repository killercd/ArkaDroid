from sqlalchemy import create_engine

from app.db.session import (
    _enable_incremental_auto_vacuum_for_new_database,
    compact_sqlite_database,
    reclaim_sqlite_space,
)


def test_new_database_enables_incremental_auto_vacuum(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'new.sqlite3'}")

    assert _enable_incremental_auto_vacuum_for_new_database(engine) is True

    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA auto_vacuum").scalar_one() == 2


def test_existing_database_requires_explicit_compaction(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'existing.sqlite3'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE records (value TEXT)")

    assert _enable_incremental_auto_vacuum_for_new_database(engine) is False
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA auto_vacuum").scalar_one() == 0

    compact_sqlite_database(engine)

    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA auto_vacuum").scalar_one() == 2


def test_reclaim_sqlite_space_removes_freelist_pages(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'reclaim.sqlite3'}")
    assert _enable_incremental_auto_vacuum_for_new_database(engine) is True
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE records (value BLOB)")
        connection.exec_driver_sql(
            "INSERT INTO records(value) VALUES (?)",
            [(b"x" * 8000,) for _ in range(100)],
        )
        connection.exec_driver_sql("DELETE FROM records")

    removed = reclaim_sqlite_space(engine)

    assert removed > 0
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA freelist_count").scalar_one() == 0
