"""Tests for SQLite persistence of investigation incidents."""

from datetime import UTC
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from sentinelforge.incidents.models import (
    Incident,
    IncidentStatus,
)
from sentinelforge.incidents.service import IncidentTransitionError
from sentinelforge.models.events import Severity
from sentinelforge.storage.database import (
    Base,
    create_session_factory,
    initialise_database,
)
from sentinelforge.storage.incident_repository import (
    IncidentPersistenceError,
    get_incident,
    list_incidents,
    persist_incidents,
    update_incident_status,
)
from sentinelforge.storage.models import StoredIncident


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


def make_incident(
    *,
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    """Create a synthetic incident for testing."""

    return Incident(
        title="SSH brute-force investigation",
        description="Repeated SSH authentication failures were detected.",
        severity=Severity.HIGH,
        status=status,
        alert_ids=[uuid4()],
        summary="Initial investigation required.",
    )


def test_persist_list_and_get_incident() -> None:
    """Incidents should be persisted, listed and retrieved by ID."""

    session = create_test_session()
    incident = make_incident()

    saved_count = persist_incidents(session, [incident])
    stored_incidents = list_incidents(session)
    stored_incident = get_incident(
        session,
        incident.incident_id,
    )

    assert saved_count == 1
    assert len(stored_incidents) == 1
    assert isinstance(stored_incidents[0], StoredIncident)
    assert stored_incidents[0].title == incident.title
    assert stored_incident is not None
    assert stored_incident.incident_id == str(incident.incident_id)

    session.close()


def test_incidents_can_be_filtered_by_status() -> None:
    """Incidents should be filterable by lifecycle status."""

    session = create_test_session()

    persist_incidents(
        session,
        [
            make_incident(status=IncidentStatus.OPEN),
            make_incident(status=IncidentStatus.CLOSED),
        ],
    )

    closed_incidents = list_incidents(
        session,
        status=IncidentStatus.CLOSED.value,
    )
    open_incidents = list_incidents(
        session,
        status=IncidentStatus.OPEN.value,
    )

    assert len(closed_incidents) == 1
    assert len(open_incidents) == 1
    assert closed_incidents[0].status == "closed"

    session.close()


def test_duplicate_incident_id_raises_persistence_error() -> None:
    """Persisting the same incident twice should fail safely."""

    session = create_test_session()
    incident = make_incident()

    persist_incidents(session, [incident])

    with pytest.raises(
        IncidentPersistenceError,
        match="Could not persist",
    ):
        persist_incidents(session, [incident])

    assert len(list_incidents(session)) == 1

    session.close()


def test_database_status_update_uses_lifecycle_rules() -> None:
    """A valid lifecycle transition should update the stored incident."""

    session = create_test_session()
    incident = make_incident()

    persist_incidents(session, [incident])

    updated = update_incident_status(
        session,
        incident.incident_id,
        IncidentStatus.INVESTIGATING,
    )

    assert updated.status == IncidentStatus.INVESTIGATING.value

    created_at = updated.created_at
    updated_at = updated.updated_at

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)

    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)

    assert updated_at >= created_at

    session.close()


def test_database_status_update_rejects_invalid_transition() -> None:
    """An invalid transition should not modify the stored incident."""

    session = create_test_session()
    incident = make_incident()

    persist_incidents(session, [incident])

    with pytest.raises(
        IncidentTransitionError,
        match="Cannot transition",
    ):
        update_incident_status(
            session,
            incident.incident_id,
            IncidentStatus.CLOSED,
        )

    stored = get_incident(session, incident.incident_id)

    assert stored is not None
    assert stored.status == IncidentStatus.OPEN.value

    session.close()


def test_database_status_update_rejects_unknown_incident() -> None:
    """Updating an unknown incident should produce a clear error."""

    session = create_test_session()

    with pytest.raises(
        IncidentPersistenceError,
        match="was not found",
    ):
        update_incident_status(
            session,
            uuid4(),
            IncidentStatus.INVESTIGATING,
        )

    session.close()
