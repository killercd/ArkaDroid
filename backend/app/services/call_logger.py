from typing import Any

from sqlalchemy.orm import Session

from app.models.call_log import CallLog


def log_call(
    db: Session,
    *,
    source: str,
    operation: str,
    project_id: int | None = None,
    exchange_id: int | None = None,
    status: str = "ok",
    message: str = "",
    payload: dict[str, Any] | None = None,
) -> CallLog:
    entry = CallLog(
        source=source,
        operation=operation,
        project_id=project_id,
        exchange_id=exchange_id,
        status=status,
        message=message,
        payload=payload or {},
    )
    db.add(entry)
    db.flush()
    return entry
