"""Persistence operations for validated security events."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from sentinelforge.models.events import SecurityEvent
from sentinelforge.storage.models import StoredEvent


class EventPersistenceError(Exception):
    """Raised when events cannot be persisted."""


def _to_stored_event(event: SecurityEvent) -> StoredEvent:
    """Convert a validated event into a database record."""

    return StoredEvent(
        event_id=str(event.event_id),
        timestamp=event.timestamp.astimezone(UTC),
        host_id=event.host_id,
        source=event.source.value,
        category=event.category.value,
        event_type=event.event_type,
        action=event.action,
        severity=event.severity.value,
        username=event.username,
        source_ip=(str(event.source_ip) if event.source_ip is not None else None),
        destination_ip=(
            str(event.destination_ip) if event.destination_ip is not None else None
        ),
        process_name=event.process_name,
        file_path=event.file_path,
        raw_data=event.raw_data,
        ingested_at=datetime.now(UTC),
        schema_version=1,
    )


def persist_events(
    session: Session,
    events: Sequence[SecurityEvent],
) -> int:
    """Persist validated events and return the number saved."""

    records = [_to_stored_event(event) for event in events]

    try:
        session.add_all(records)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise EventPersistenceError(
            f"Could not persist {len(records)} events: {exc}"
        ) from exc

    return len(records)


def list_events(
    session: Session,
    *,
    limit: int = 100,
) -> list[StoredEvent]:
    """Return the most recent persisted events."""

    if limit < 1:
        raise ValueError("limit must be at least 1")

    statement = select(StoredEvent).order_by(StoredEvent.timestamp.desc()).limit(limit)

    return list(session.scalars(statement).all())
