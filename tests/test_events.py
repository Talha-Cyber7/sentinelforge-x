"""Tests for the canonical security event model."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinelforge.models.events import (
    EventCategory,
    EventSource,
    SecurityEvent,
    Severity,
)


def test_valid_event_is_normalised() -> None:
    """A valid event should be accepted and normalised."""

    event = SecurityEvent(
        timestamp=datetime(2026, 10, 4, 14, 2, 11, tzinfo=UTC),
        host_id=" linux-lab-01 ",
        source=EventSource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="authentication_failure",
        action="ssh_login_failed",
        severity=Severity.MEDIUM,
        username="alex",
        source_ip="192.168.56.20",
    )

    assert event.host_id == "linux-lab-01"
    assert event.username == "alex"
    assert str(event.source_ip) == "192.168.56.20"
    assert event.severity is Severity.MEDIUM


def test_timezone_is_required() -> None:
    """Events without timezone-aware timestamps must be rejected."""

    with pytest.raises(ValidationError, match="timezone"):
        SecurityEvent(
            timestamp=datetime(2026, 10, 4, 14, 2, 11),
            host_id="linux-lab-01",
            source=EventSource.SYNTHETIC,
            category=EventCategory.SYSTEM,
            event_type="test_event",
            action="test",
        )


def test_unknown_fields_are_rejected() -> None:
    """Unexpected fields should not silently enter the event model."""

    with pytest.raises(ValidationError, match="unexpected_field"):
        SecurityEvent(
            timestamp=datetime(2026, 10, 4, 14, 2, 11, tzinfo=UTC),
            host_id="linux-lab-01",
            source=EventSource.SYNTHETIC,
            category=EventCategory.SYSTEM,
            event_type="test_event",
            action="test",
            unexpected_field="should fail",
        )