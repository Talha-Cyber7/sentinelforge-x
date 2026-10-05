"""Business rules for incident lifecycle transitions."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelforge.incidents.models import (
    Incident,
    IncidentStatus,
)


class IncidentTransitionError(Exception):
    """Raised when an incident status transition is invalid."""


_ALLOWED_TRANSITIONS: dict[
    IncidentStatus,
    frozenset[IncidentStatus],
] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.CONTAINED,
            IncidentStatus.RESOLVED,
        }
    ),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.RESOLVED}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}


def transition_incident(
    incident: Incident,
    new_status: IncidentStatus,
    *,
    updated_at: datetime | None = None,
) -> Incident:
    """Move an incident to a valid lifecycle state."""

    if incident.status is new_status:
        return incident.model_copy(
            update={
                "updated_at": updated_at or datetime.now(UTC),
            }
        )

    allowed_statuses = _ALLOWED_TRANSITIONS[incident.status]

    if new_status not in allowed_statuses:
        raise IncidentTransitionError(
            f"Cannot transition incident from "
            f"'{incident.status.value}' to '{new_status.value}'"
        )

    return incident.model_copy(
        update={
            "status": new_status,
            "updated_at": updated_at or datetime.now(UTC),
        }
    )
