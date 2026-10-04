"""Tests for JSON security-event ingestion."""

import json
from pathlib import Path

import pytest

from sentinelforge.ingestion.json_loader import (
    EventIngestionError,
    load_json_events,
)


def test_loads_a_list_of_valid_events(tmp_path: Path) -> None:
    """A JSON list containing valid events should be loaded successfully."""

    event_data = [
        {
            "timestamp": "2026-10-04T14:02:11Z",
            "host_id": "linux-lab-01",
            "source": "linux_auth",
            "category": "authentication",
            "event_type": "authentication_failure",
            "action": "ssh_login_failed",
            "username": "alex",
            "source_ip": "192.168.56.20",
        },
        {
            "timestamp": "2026-10-04T14:02:23Z",
            "host_id": "linux-lab-01",
            "source": "linux_auth",
            "category": "authentication",
            "event_type": "authentication_failure",
            "action": "ssh_login_failed",
            "username": "alex",
            "source_ip": "192.168.56.20",
        },
    ]

    path = tmp_path / "events.json"
    path.write_text(json.dumps(event_data), encoding="utf-8")

    events = load_json_events(path)

    assert len(events) == 2
    assert events[0].host_id == "linux-lab-01"
    assert str(events[1].source_ip) == "192.168.56.20"


def test_loads_a_single_event_object(tmp_path: Path) -> None:
    """A JSON object containing one event should also be accepted."""

    event_data = {
        "timestamp": "2026-10-04T14:02:11Z",
        "host_id": "linux-lab-01",
        "source": "linux_auth",
        "category": "authentication",
        "event_type": "authentication_failure",
        "action": "ssh_login_failed",
    }

    path = tmp_path / "event.json"
    path.write_text(json.dumps(event_data), encoding="utf-8")

    events = load_json_events(path)

    assert len(events) == 1
    assert events[0].event_type == "authentication_failure"


def test_missing_file_raises_ingestion_error(tmp_path: Path) -> None:
    """A missing file should produce a clear ingestion error."""

    with pytest.raises(EventIngestionError, match="Could not read"):
        load_json_events(tmp_path / "missing.json")


def test_invalid_json_raises_ingestion_error(tmp_path: Path) -> None:
    """Malformed JSON should produce a clear ingestion error."""

    path = tmp_path / "invalid.json"
    path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(EventIngestionError, match="Invalid JSON"):
        load_json_events(path)


def test_invalid_event_raises_ingestion_error(tmp_path: Path) -> None:
    """Invalid event data should be rejected by the canonical model."""

    event_data = {
        "timestamp": "not-a-timestamp",
        "host_id": "linux-lab-01",
        "source": "linux_auth",
        "category": "authentication",
        "event_type": "authentication_failure",
        "action": "ssh_login_failed",
    }

    path = tmp_path / "invalid-event.json"
    path.write_text(json.dumps(event_data), encoding="utf-8")

    with pytest.raises(EventIngestionError, match="failed validation"):
        load_json_events(path)