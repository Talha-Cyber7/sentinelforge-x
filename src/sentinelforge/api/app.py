"""FastAPI application for SentinelForge X."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinelforge.api.dependencies import get_db
from sentinelforge.api.schemas import (
    AlertResponse,
    EventResponse,
    IncidentCreateRequest,
    IncidentResponse,
    IncidentStatusUpdateRequest,
)
from sentinelforge.incidents.models import Incident, IncidentStatus
from sentinelforge.incidents.service import IncidentTransitionError
from sentinelforge.storage.alert_repository import list_alerts
from sentinelforge.storage.event_repository import (
    list_events,
)
from sentinelforge.storage.incident_repository import (
    get_incident,
    list_incidents,
    persist_incidents,
    update_incident_status,
)
from sentinelforge.storage.models import AlertStatus


class HealthResponse(BaseModel):
    """Response returned by the health endpoint."""

    status: Literal["ok"]
    service: str
    version: str


app = FastAPI(
    title="SentinelForge X API",
    description=(
        "Detection engineering and incident investigation API for SentinelForge X."
    ),
    version="0.1.0",
)


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
)
def health_check() -> HealthResponse:
    """Confirm that the API is running."""

    return HealthResponse(
        status="ok",
        service="sentinelforge-api",
        version="0.1.0",
    )


@app.get(
    "/events",
    response_model=list[EventResponse],
    tags=["events"],
)
def get_events(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=500,
            description="Maximum number of events to return.",
        ),
    ] = 100,
) -> list[EventResponse]:
    """Return the most recent persisted security events."""

    return [
        EventResponse.model_validate(event) for event in list_events(db, limit=limit)
    ]


@app.get(
    "/alerts",
    response_model=list[AlertResponse],
    tags=["alerts"],
)
def get_alerts(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=500,
            description="Maximum number of alerts to return.",
        ),
    ] = 100,
    status: Annotated[
        AlertStatus | None,
        Query(
            description="Filter alerts by lifecycle status.",
        ),
    ] = None,
) -> list[AlertResponse]:
    """Return recent persisted detection alerts."""

    return [
        AlertResponse.model_validate(alert)
        for alert in list_alerts(
            db,
            limit=limit,
            status=status,
        )
    ]


@app.get(
    "/incidents",
    response_model=list[IncidentResponse],
    tags=["incidents"],
)
def get_incidents(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=500,
            description="Maximum number of incidents to return.",
        ),
    ] = 100,
    status: Annotated[
        IncidentStatus | None,
        Query(
            description="Filter incidents by lifecycle status.",
        ),
    ] = None,
) -> list[IncidentResponse]:
    """Return recent investigation incidents."""

    status_value = status.value if status is not None else None

    return [
        IncidentResponse.model_validate(incident)
        for incident in list_incidents(
            db,
            limit=limit,
            status=status_value,
        )
    ]


@app.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=201,
    tags=["incidents"],
)
def create_incident(
    request: IncidentCreateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> IncidentResponse:
    """Create and persist a new investigation incident."""

    incident = Incident(
        title=request.title,
        description=request.description,
        severity=request.severity,
        alert_ids=request.alert_ids,
        summary=request.summary,
    )

    persist_incidents(db, [incident])

    stored_incident = get_incident(
        db,
        incident.incident_id,
    )

    if stored_incident is None:
        raise HTTPException(
            status_code=500,
            detail="Incident was created but could not be retrieved",
        )

    return IncidentResponse.model_validate(stored_incident)


@app.patch(
    "/incidents/{incident_id}/status",
    response_model=IncidentResponse,
    tags=["incidents"],
)
def change_incident_status(
    incident_id: UUID,
    request: IncidentStatusUpdateRequest,
    db: Annotated[Session, Depends(get_db)],
) -> IncidentResponse:
    """Apply a validated lifecycle transition to an incident."""

    if get_incident(db, incident_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' was not found",
        )

    try:
        stored_incident = update_incident_status(
            db,
            incident_id,
            request.status,
        )
    except IncidentTransitionError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return IncidentResponse.model_validate(stored_incident)
