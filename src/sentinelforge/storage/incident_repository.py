"""Persistence operations for investigation incidents."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from sentinelforge.incidents.models import Incident
from sentinelforge.storage.models import StoredIncident


class IncidentPersistenceError(Exception):
    """Raised when incidents cannot be persisted."""


def _to_stored_incident(incident: Incident) -> StoredIncident:
    """Convert an incident model into a database record."""

    return StoredIncident(
        incident_id=str(incident.incident_id),
        title=incident.title,
        description=incident.description,
        severity=incident.severity.value,
        status=incident.status.value,
        alert_ids=[str(alert_id) for alert_id in incident.alert_ids],
        summary=incident.summary,
        resolution_notes=incident.resolution_notes,
        created_at=incident.created_at.astimezone(UTC),
        updated_at=incident.updated_at.astimezone(UTC),
        schema_version=1,
    )


def persist_incidents(
    session: Session,
    incidents: Sequence[Incident],
) -> int:
    """Persist incidents and return the number saved."""

    records = [_to_stored_incident(incident) for incident in incidents]

    try:
        session.add_all(records)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise IncidentPersistenceError(
            f"Could not persist {len(records)} incidents: {exc}"
        ) from exc

    return len(records)


def list_incidents(
    session: Session,
    *,
    limit: int = 100,
    status: str | None = None,
) -> list[StoredIncident]:
    """Return recent incidents, optionally filtered by status."""

    if limit < 1:
        raise ValueError("limit must be at least 1")

    statement = (
        select(StoredIncident).order_by(StoredIncident.updated_at.desc()).limit(limit)
    )

    if status is not None:
        statement = statement.where(StoredIncident.status == status)

    return list(session.scalars(statement).all())


def get_incident(
    session: Session,
    incident_id: UUID,
) -> StoredIncident | None:
    """Retrieve one incident by identifier."""

    return session.get(StoredIncident, str(incident_id))
