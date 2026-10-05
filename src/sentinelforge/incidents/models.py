"""Incident models and lifecycle definitions."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinelforge.models.events import Severity


class IncidentStatus(StrEnum):
    """Lifecycle states for an investigation."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(BaseModel):
    """An investigation containing related security alerts."""

    model_config = ConfigDict(extra="forbid")

    incident_id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN
    alert_ids: list[UUID] = Field(min_length=1)
    summary: str = ""
    resolution_notes: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
