"""JSON ingestion for normalised security events."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinelforge.models.events import SecurityEvent


class EventIngestionError(Exception):
    """Raised when security event data cannot be loaded or validated."""


def load_json_events(path: Path) -> list[SecurityEvent]:
    """Load one or more security events from a JSON file.

    A JSON file may contain either:
    - One event object
    - A list of event objects

    Every event is validated through the canonical SecurityEvent model before
    it is returned.
    """

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise EventIngestionError(f"Could not read event file '{path}': {exc}") from exc

    try:
        payload: Any = json.loads(raw_text)
    except JSONDecodeError as exc:
        raise EventIngestionError(
            f"Invalid JSON in '{path}' at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc

    if isinstance(payload, dict):
        records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise EventIngestionError(
            "Event file must contain one JSON object or a list of objects"
        )

    events: list[SecurityEvent] = []

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise EventIngestionError(f"Event at index {index} must be a JSON object")

        try:
            event = SecurityEvent.model_validate(record)
        except ValidationError as exc:
            raise EventIngestionError(
                f"Event at index {index} failed validation: {exc}"
            ) from exc

        events.append(event)

    return events
