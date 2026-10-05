"""Tests for controlled incident lifecycle transitions."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinelforge.incidents.models import (
    Incident,
    IncidentStatus,
)
from sentinelforge.incidents.service import (
    IncidentTransitionError,
    transition_incident,
)
from sentinelforge.models.events import Severity


def make_incident(
    *,
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    """Create an incident in a selected lifecycle state."""

    return Incident(
        title="SSH brute-force investigation",
        description="Repeated failed authentication was detected.",
        severity=Severity.HIGH,
        status=status,
        alert_ids=[uuid4()],
    )


def test_valid_transition_updates_status_and_timestamp() -> None:
    """A valid transition should update status and updated_at."""

    original_time = datetime(
        2026,
        10,
        5,
        12,
        0,
        tzinfo=UTC,
    )
    new_time = datetime(
        2026,
        10,
        5,
        12,
        30,
        tzinfo=UTC,
    )

    incident = make_incident()
    transitioned = transition_incident(
        incident,
        IncidentStatus.INVESTIGATING,
        updated_at=new_time,
    )

    assert incident.status is IncidentStatus.OPEN
    assert transitioned.status is IncidentStatus.INVESTIGATING
    assert transitioned.updated_at == new_time
    assert transitioned.created_at != original_time


def test_invalid_transition_raises_error() -> None:
    """An invalid state transition should be rejected."""

    incident = make_incident()

    with pytest.raises(
        IncidentTransitionError,
        match="Cannot transition",
    ):
        transition_incident(
            incident,
            IncidentStatus.CLOSED,
        )


def test_same_status_is_allowed_and_refreshes_timestamp() -> None:
    """Repeating a status should be a safe timestamp update."""

    incident = make_incident()
    new_time = datetime(
        2026,
        10,
        5,
        13,
        0,
        tzinfo=UTC,
    )

    updated = transition_incident(
        incident,
        IncidentStatus.OPEN,
        updated_at=new_time,
    )

    assert updated.status is IncidentStatus.OPEN
    assert updated.updated_at == new_time


def test_closed_incident_cannot_change() -> None:
    """A closed incident should be immutable through this service."""

    incident = make_incident(status=IncidentStatus.CLOSED)

    with pytest.raises(
        IncidentTransitionError,
        match="Cannot transition",
    ):
        transition_incident(
            incident,
            IncidentStatus.OPEN,
        )
