"""Tests for incident models and lifecycle state."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentinelforge.incidents.models import (
    Incident,
    IncidentStatus,
)
from sentinelforge.models.events import Severity


def test_incident_defaults_to_open() -> None:
    """A new incident should begin in the open state."""

    alert_id = uuid4()

    incident = Incident(
        title="SSH brute-force activity",
        description="Repeated failed SSH authentication was detected.",
        severity=Severity.HIGH,
        alert_ids=[alert_id],
    )

    assert incident.status is IncidentStatus.OPEN
    assert incident.alert_ids == [alert_id]
    assert incident.created_at.tzinfo is not None
    assert incident.updated_at.tzinfo is not None


def test_incident_supports_multiple_alerts() -> None:
    """An incident should be able to group multiple related alerts."""

    alert_ids = [uuid4(), uuid4(), uuid4()]

    incident = Incident(
        title="Coordinated authentication activity",
        description="Several related alerts require investigation.",
        severity=Severity.CRITICAL,
        alert_ids=alert_ids,
        status=IncidentStatus.INVESTIGATING,
    )

    assert incident.status is IncidentStatus.INVESTIGATING
    assert incident.alert_ids == alert_ids


def test_incident_requires_at_least_one_alert() -> None:
    """An incident without an alert should be rejected."""

    with pytest.raises(ValidationError, match="alert_ids"):
        Incident(
            title="Invalid incident",
            description="This incident has no supporting alert.",
            severity=Severity.LOW,
            alert_ids=[],
        )


def test_incident_rejects_unknown_fields() -> None:
    """Unexpected fields should not silently enter an incident."""

    with pytest.raises(ValidationError, match="unexpected_field"):
        Incident(
            title="Invalid incident",
            description="This incident contains an unknown field.",
            severity=Severity.LOW,
            alert_ids=[uuid4()],
            unexpected_field="should fail",
        )
