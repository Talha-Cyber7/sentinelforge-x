"""SQLAlchemy models for persisted SentinelForge X data."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
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


class AlertStatus(StrEnum):
    """Lifecycle states for persisted alerts."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class StoredAlert(Base):
    """An explainable detection alert persisted in the database."""

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )
    detection_id: Mapped[str] = mapped_column(
        String(100),
        index=True,
    )
    detection_name: Mapped[str] = mapped_column(
        String(255),
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        index=True,
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
    )
    event_ids: Mapped[list[str]] = mapped_column(
        JSON,
    )
    group_values: Mapped[dict[str, str]] = mapped_column(
        JSON,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default=AlertStatus.OPEN.value,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
    )
    schema_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
    )
