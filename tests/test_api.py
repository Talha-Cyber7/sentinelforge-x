"""Tests for the SentinelForge X API."""

from fastapi.testclient import TestClient

from sentinelforge.api.app import app

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
