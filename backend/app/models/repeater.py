from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RepeaterRequest(Base):
    __tablename__ = "repeater_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    source_exchange_id: Mapped[int | None] = mapped_column(ForeignKey("http_exchanges.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    method: Mapped[str] = mapped_column(String(12), index=True)
    url: Mapped[str] = mapped_column(String(4096), index=True)
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0, index=True)
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
