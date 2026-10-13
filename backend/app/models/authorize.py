from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AuthorizeUser(Base):
    __tablename__ = "authorize_users"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_authorize_users_project_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    source_file: Mapped[str] = mapped_column(String(2048), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuthorizeExchange(Base):
    __tablename__ = "authorize_exchanges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    source_exchange_id: Mapped[int] = mapped_column(ForeignKey("http_exchanges.id"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("authorize_users.id"), nullable=True, index=True)
    user_name: Mapped[str] = mapped_column(String(160), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    method: Mapped[str] = mapped_column(String(12), index=True)
    url: Mapped[str] = mapped_column(String(4096), index=True)
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
