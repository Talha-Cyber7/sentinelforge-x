"""Public API response schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from sentinelforge.incidents.models import IncidentStatus
from sentinelforge.models.events import Severity
from sentinelforge.storage.models import AlertStatus


class EventResponse(BaseModel):
    """Public representation of a persisted security event."""

    model_config = ConfigDict(from_attributes=True)

    event_id: UUID
    timestamp: datetime
    host_id: str
    source: str
    category: str
    event_type: str
    action: str
    severity: Severity
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    process_name: str | None
    file_path: str | None
    raw_data: dict[str, object]
    ingested_at: datetime
    schema_version: int


class AlertResponse(BaseModel):
    """Public representation of a persisted detection alert."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: UUID
    detection_id: str
    detection_name: str
    severity: Severity
    triggered_at: datetime
    event_ids: list[UUID]
    group_values: dict[str, str]
    explanation: str
    status: AlertStatus
    created_at: datetime
    schema_version: int


class IncidentResponse(BaseModel):
    """Public representation of a persisted investigation incident."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: UUID
    title: str
    description: str
    severity: Severity
    status: str
    alert_ids: list[UUID]
    summary: str
    resolution_notes: str | None
    created_at: datetime
    updated_at: datetime
    schema_version: int


class IncidentCreateRequest(BaseModel):
    """Request body for creating an investigation incident."""

    title: str
    description: str
    severity: Severity
    alert_ids: list[UUID]
    summary: str = ""


class IncidentStatusUpdateRequest(BaseModel):
    """Request body for changing an incident lifecycle status."""

    status: IncidentStatus
