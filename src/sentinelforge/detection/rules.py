"""Detection rule and alert models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinelforge.models.events import Severity


class GroupField(StrEnum):
    """Event fields that may be used to correlate repeated activity."""

    HOST_ID = "host_id"
    SOURCE_IP = "source_ip"
    DESTINATION_IP = "destination_ip"
    USERNAME = "username"


class DetectionRule(BaseModel):
    """A version-controlled rule for matching security events."""

    model_config = ConfigDict(extra="forbid")

    detection_id: str = Field(pattern=r"^DET-[0-9]{3,}$")
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    severity: Severity
    conditions: dict[str, str] = Field(min_length=1)
    threshold: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=300, ge=1)
    group_by: tuple[GroupField, ...] = (GroupField.HOST_ID,)
    mitre_attack_id: str | None = Field(
        default=None,
        pattern=r"^T[0-9]{4}(\.[0-9]{3})?$",
    )

    @field_validator("conditions")
    @classmethod
    def condition_fields_must_be_supported(
        cls,
        value: dict[str, str],
    ) -> dict[str, str]:
        """Prevent rules from referencing arbitrary object attributes."""

        supported_fields = {
            "source",
            "category",
            "event_type",
            "action",
            "severity",
            "host_id",
            "username",
            "source_ip",
            "destination_ip",
        }

        unsupported = set(value) - supported_fields

        if unsupported:
            fields = ", ".join(sorted(unsupported))
            raise ValueError(f"Unsupported condition fields: {fields}")

        return value


class Alert(BaseModel):
    """An explainable alert produced by a detection rule."""

    model_config = ConfigDict(extra="forbid")

    alert_id: UUID = Field(default_factory=uuid4)
    detection_id: str
    detection_name: str
    severity: Severity
    triggered_at: datetime
    event_ids: list[UUID] = Field(min_length=1)
    group_values: dict[str, str]
    explanation: str
