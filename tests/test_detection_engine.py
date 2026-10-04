"""Tests for detection evaluation and alert generation."""

from datetime import UTC, datetime, timedelta

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rules import (
    DetectionRule,
    GroupField,
)
from sentinelforge.models.events import (
    EventCategory,
    EventSource,
    SecurityEvent,
    Severity,
)


def make_event(
    offset_seconds: int,
    *,
    action: str = "ssh_login_failed",
    source_ip: str = "192.168.56.20",
) -> SecurityEvent:
    """Create a synthetic authentication event for testing."""

    timestamp = datetime(2026, 10, 4, 14, 0, tzinfo=UTC) + timedelta(
        seconds=offset_seconds
    )

    return SecurityEvent(
        timestamp=timestamp,
        host_id="linux-lab-01",
        source=EventSource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="authentication_failure",
        action=action,
        severity=Severity.MEDIUM,
        username="alex",
        source_ip=source_ip,
    )


def make_ssh_rule(
    *,
    threshold: int = 5,
    window_seconds: int = 300,
) -> DetectionRule:
    """Create the initial SSH brute-force detection rule."""

    return DetectionRule(
        detection_id="DET-001",
        name="Repeated SSH Authentication Failures",
        description="Detects repeated failed SSH authentication attempts.",
        severity=Severity.HIGH,
        conditions={
            "event_type": "authentication_failure",
            "action": "ssh_login_failed",
        },
        threshold=threshold,
        window_seconds=window_seconds,
        group_by=(
            GroupField.HOST_ID,
            GroupField.SOURCE_IP,
            GroupField.USERNAME,
        ),
        mitre_attack_id="T1110",
    )


def test_alert_is_generated_when_threshold_is_reached() -> None:
    """Five matching events within five minutes should generate one alert."""

    events = [make_event(offset) for offset in (0, 10, 20, 30, 40)]

    alerts = DetectionEngine().evaluate(events, make_ssh_rule())

    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 5
    assert alerts[0].detection_id == "DET-001"
    assert alerts[0].severity is Severity.HIGH
    assert "5 matching events" in alerts[0].explanation


def test_no_alert_is_generated_outside_time_window() -> None:
    """Five events spread beyond the window should not generate an alert."""

    events = [make_event(offset) for offset in (0, 100, 200, 300, 400)]

    alerts = DetectionEngine().evaluate(events, make_ssh_rule())

    assert alerts == []


def test_non_matching_events_are_ignored() -> None:
    """Events with a different action should not count towards a detection."""

    events = [
        make_event(0),
        make_event(10),
        make_event(20),
        make_event(30, action="ssh_login_success"),
        make_event(40),
    ]

    alerts = DetectionEngine().evaluate(
        events,
        make_ssh_rule(threshold=4),
    )

    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 4


def test_different_sources_are_correlated_separately() -> None:
    """Events from different source addresses should use separate groups."""

    events = [
        make_event(0, source_ip="192.168.56.20"),
        make_event(10, source_ip="192.168.56.20"),
        make_event(20, source_ip="192.168.56.20"),
        make_event(0, source_ip="192.168.56.21"),
        make_event(10, source_ip="192.168.56.21"),
    ]

    alerts = DetectionEngine().evaluate(
        events,
        make_ssh_rule(threshold=3),
    )

    assert len(alerts) == 1
    assert alerts[0].group_values["source_ip"] == "192.168.56.20"
