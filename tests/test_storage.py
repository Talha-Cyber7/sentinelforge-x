"""Tests for SQLite persistence of security events."""

from pathlib import Path

import pytest
from sqlalchemy import create_engine

from sentinelforge.ingestion.json_loader import load_json_events
from sentinelforge.storage.database import (
    Base,
    create_session_factory,
    initialise_database,
)
from sentinelforge.storage.event_repository import (
    EventPersistenceError,
    list_events,
    persist_events,
)
from sentinelforge.storage.models import StoredEvent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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


def test_persist_and_list_events() -> None:
    """Validated events should be persisted and returned in newest order."""

    session = create_test_session()
    events = load_json_events(EVENT_PATH)

    saved_count = persist_events(session, events)
    stored_events = list_events(session)

    assert saved_count == 5
    assert len(stored_events) == 5
    assert isinstance(stored_events[0], StoredEvent)
    assert stored_events[0].event_id == str(events[-1].event_id)
    assert stored_events[0].source_ip == "192.168.56.20"

    session.close()


def test_duplicate_event_id_raises_persistence_error() -> None:
    """Persisting the same event twice should fail safely."""

    session = create_test_session()
    events = load_json_events(EVENT_PATH)

    persist_events(session, events)

    with pytest.raises(EventPersistenceError, match="Could not persist"):
        persist_events(session, events)

    assert len(list_events(session)) == 5

    session.close()


def test_invalid_limit_is_rejected() -> None:
    """The repository should reject non-positive result limits."""

    session = create_test_session()

    with pytest.raises(ValueError, match="at least 1"):
        list_events(session, limit=0)

    session.close()
