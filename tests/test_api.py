"""Tests for the SentinelForge X API."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from sentinelforge.api.app import app
from sentinelforge.api.dependencies import get_db
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.incidents.models import (
    Incident,
    IncidentStatus,
)
from sentinelforge.ingestion.json_loader import load_json_events
from sentinelforge.models.events import Severity
from sentinelforge.storage.alert_repository import persist_alerts
from sentinelforge.storage.database import (
    Base,
    create_session_factory,
)
from sentinelforge.storage.event_repository import persist_events
from sentinelforge.storage.incident_repository import (
    persist_incidents,
)

client = TestClient(app)


def test_health_endpoint() -> None:
    """The health endpoint should confirm the service is running."""

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "sentinelforge-api",
        "version": "0.1.0",
    }


def test_openapi_documentation_is_available() -> None:
    """FastAPI should expose the generated OpenAPI document."""

    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "SentinelForge X API"


def test_events_endpoint_returns_persisted_events() -> None:
    """The events endpoint should return persisted events."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    event_path = Path(__file__).resolve().parents[1] / "sample-data" / "linux-auth.json"
    events = load_json_events(event_path)
    persist_events(session, events)

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.get("/events?limit=2")
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 200
    payload = response.json()

    assert len(payload) == 2
    assert payload[0]["host_id"] == "linux-lab-01"
    assert payload[0]["source_ip"] == "192.168.56.20"


def test_alerts_endpoint_returns_persisted_alerts() -> None:
    """The alerts endpoint should return persisted detection alerts."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    project_root = Path(__file__).resolve().parents[1]
    rule_path = project_root / "rules" / "DET-001-ssh-brute-force.yaml"
    event_path = project_root / "sample-data" / "linux-auth.json"

    rule = load_rule(rule_path)
    events = load_json_events(event_path)
    alerts = DetectionEngine().evaluate(events, rule)
    persist_alerts(session, alerts)

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.get("/alerts?limit=1")
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 200

    payload = response.json()

    assert len(payload) == 1
    assert payload[0]["detection_id"] == "DET-001"
    assert payload[0]["status"] == "open"
    assert len(payload[0]["event_ids"]) == 5


def test_incidents_endpoint_returns_persisted_incidents() -> None:
    """The incidents endpoint should return persisted investigations."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    incident = Incident(
        title="SSH brute-force investigation",
        description="Repeated failed authentication was detected.",
        severity=Severity.HIGH,
        alert_ids=[uuid4()],
        summary="Initial investigation required.",
    )
    persist_incidents(session, [incident])

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.get("/incidents?limit=1")
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 200

    payload = response.json()

    assert len(payload) == 1
    assert payload[0]["title"] == "SSH brute-force investigation"
    assert payload[0]["status"] == "open"
    assert len(payload[0]["alert_ids"]) == 1


def test_create_incident_endpoint_persists_incident() -> None:
    """The incident creation endpoint should persist a new incident."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    alert_id = uuid4()

    try:
        response = client.post(
            "/incidents",
            json={
                "title": "SSH brute-force investigation",
                "description": ("Repeated failed authentication was detected."),
                "severity": "high",
                "alert_ids": [str(alert_id)],
                "summary": "Initial investigation required.",
            },
        )
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 201

    payload = response.json()

    assert payload["title"] == "SSH brute-force investigation"
    assert payload["severity"] == "high"
    assert payload["status"] == "open"
    assert payload["alert_ids"] == [str(alert_id)]
    assert payload["schema_version"] == 1


def test_change_incident_status_endpoint() -> None:
    """The API should apply a valid incident status transition."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    incident = Incident(
        title="SSH brute-force investigation",
        description="Repeated failed authentication was detected.",
        severity=Severity.HIGH,
        alert_ids=[uuid4()],
    )
    persist_incidents(session, [incident])

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.patch(
            f"/incidents/{incident.incident_id}/status",
            json={"status": "investigating"},
        )
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 200

    payload = response.json()

    assert payload["incident_id"] == str(incident.incident_id)
    assert payload["status"] == "investigating"


def test_change_incident_status_rejects_invalid_transition() -> None:
    """The API should reject invalid incident status transitions."""

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    session_factory = create_session_factory(engine)
    session = session_factory()

    incident = Incident(
        title="SSH brute-force investigation",
        description="Repeated failed authentication was detected.",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        alert_ids=[uuid4()],
    )
    persist_incidents(session, [incident])

    def override_get_db() -> Generator[Session, None, None]:
        yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.patch(
            f"/incidents/{incident.incident_id}/status",
            json={"status": "closed"},
        )
    finally:
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()

    assert response.status_code == 409
    assert "Cannot transition" in response.json()["detail"]
