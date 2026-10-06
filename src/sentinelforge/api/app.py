"""FastAPI application for SentinelForge X."""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel


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
