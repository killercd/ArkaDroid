from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class HttpExchange(Base):
    __tablename__ = "http_exchanges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    method: Mapped[str] = mapped_column(String(12), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(String(2048), index=True)
    query: Mapped[str] = mapped_column(String(2048), default="")
    request_raw: Mapped[str] = mapped_column(Text)
    response_raw: Mapped[str] = mapped_column(Text, default="")
    missing_sec_headers: Mapped[str] = mapped_column(Text, default="")
    reflecte_params: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
