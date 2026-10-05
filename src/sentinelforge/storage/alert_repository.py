"""Persistence operations for detection alerts."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from sentinelforge.detection.rules import Alert
from sentinelforge.storage.models import AlertStatus, StoredAlert


class AlertPersistenceError(Exception):
    """Raised when alerts cannot be persisted."""


def _to_stored_alert(alert: Alert) -> StoredAlert:
    """Convert an alert model into a database record."""

    return StoredAlert(
        alert_id=str(alert.alert_id),
        detection_id=alert.detection_id,
        detection_name=alert.detection_name,
        severity=alert.severity.value,
        triggered_at=alert.triggered_at.astimezone(UTC),
        event_ids=[str(event_id) for event_id in alert.event_ids],
        group_values=alert.group_values,
        explanation=alert.explanation,
        status=AlertStatus.OPEN.value,
        created_at=datetime.now(UTC),
        schema_version=1,
    )


def persist_alerts(
    session: Session,
    alerts: Sequence[Alert],
) -> int:
    """Persist alerts and return the number saved."""

    records = [_to_stored_alert(alert) for alert in alerts]

    try:
        session.add_all(records)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise AlertPersistenceError(
            f"Could not persist {len(records)} alerts: {exc}"
        ) from exc

    return len(records)


def list_alerts(
    session: Session,
    *,
    limit: int = 100,
    status: AlertStatus | None = None,
) -> list[StoredAlert]:
    """Return recent alerts, optionally filtered by lifecycle status."""

    if limit < 1:
        raise ValueError("limit must be at least 1")

    statement = (
        select(StoredAlert).order_by(StoredAlert.triggered_at.desc()).limit(limit)
    )

    if status is not None:
        statement = statement.where(StoredAlert.status == status.value)

    return list(session.scalars(statement).all())
