"""SQLAlchemy models for persisted SentinelForge X data."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinelforge.storage.database import Base


class StoredEvent(Base):
    """A validated security event persisted in the database."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    host_id: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )
    category: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        index=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    process_name: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    file_path: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
    )
    raw_data: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
    )
    schema_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
    )
