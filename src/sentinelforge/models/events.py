"""Canonical security event models used throughout SentinelForge X."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)


class EventSource(StrEnum):
    """Supported origins of security telemetry."""

    LINUX_AUTH = "linux_auth"
    WINDOWS_SECURITY = "windows_security"
    SYSMON = "sysmon"
    NETWORK = "network"
    SYNTHETIC = "synthetic"


class EventCategory(StrEnum):
    """Broad security-relevant event categories."""

    AUTHENTICATION = "authentication"
    ACCOUNT_MANAGEMENT = "account_management"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    SYSTEM = "system"


class Severity(StrEnum):
    """Severity assigned to an event or alert."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """A validated, source-independent security event.

    Raw telemetry from different systems is converted into this model before
    it reaches the detection engine.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    host_id: str = Field(min_length=1, max_length=255)
    source: EventSource
    category: EventCategory
    event_type: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=255)
    severity: Severity = Severity.INFO

    username: str | None = Field(default=None, max_length=255)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    process_name: str | None = Field(default=None, max_length=512)
    file_path: str | None = Field(default=None, max_length=2048)

    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        """Reject timestamps that do not identify a timezone."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")

        return value