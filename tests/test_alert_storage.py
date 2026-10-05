"""Tests for SQLite persistence of detection alerts."""

from pathlib import Path

import pytest
from sqlalchemy import create_engine

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.ingestion.json_loader import load_json_events
from sentinelforge.storage.alert_repository import (
    AlertPersistenceError,
    list_alerts,
    persist_alerts,
)
from sentinelforge.storage.database import (
    Base,
    create_session_factory,
    initialise_database,
)
from sentinelforge.storage.models import AlertStatus, StoredAlert

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"
EVENT_PATH = PROJECT_ROOT / "sample-data" / "linux-auth.json"


def create_test_session():
    """Create a clean in-memory SQLite session."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)
    initialise_database(engine)

    session_factory = create_session_factory(engine)
    return session_factory()


def build_alerts():
    """Generate alerts from the committed rule and sample events."""

    rule = load_rule(RULE_PATH)
    events = load_json_events(EVENT_PATH)

    return DetectionEngine().evaluate(events, rule)


def test_persist_and_list_alerts() -> None:
    """Generated alerts should be persisted and retrieved."""

    session = create_test_session()
    alerts = build_alerts()

    saved_count = persist_alerts(session, alerts)
    stored_alerts = list_alerts(session)

    assert saved_count == 1
    assert len(stored_alerts) == 1
    assert isinstance(stored_alerts[0], StoredAlert)
    assert stored_alerts[0].detection_id == "DET-001"
    assert stored_alerts[0].status == AlertStatus.OPEN.value
    assert len(stored_alerts[0].event_ids) == 5

    session.close()


def test_alerts_can_be_filtered_by_status() -> None:
    """Alerts should be filterable by lifecycle status."""

    session = create_test_session()
    persist_alerts(session, build_alerts())

    stored_alert = list_alerts(session)[0]
    stored_alert.status = AlertStatus.INVESTIGATING.value
    session.commit()

    investigating = list_alerts(
        session,
        status=AlertStatus.INVESTIGATING,
    )
    open_alerts = list_alerts(
        session,
        status=AlertStatus.OPEN,
    )

    assert len(investigating) == 1
    assert len(open_alerts) == 0

    session.close()


def test_duplicate_alert_id_raises_persistence_error() -> None:
    """Persisting the same alert twice should fail safely."""

    session = create_test_session()
    alerts = build_alerts()

    persist_alerts(session, alerts)

    with pytest.raises(AlertPersistenceError, match="Could not persist"):
        persist_alerts(session, alerts)

    assert len(list_alerts(session)) == 1

    session.close()
