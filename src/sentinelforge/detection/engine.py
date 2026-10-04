"""Detection evaluation and explainable alert generation."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from sentinelforge.models.events import SecurityEvent

from .rules import Alert, DetectionRule


def _stringify_event_value(event: SecurityEvent, field: str) -> str | None:
    """Convert a supported event value into a comparable string."""

    value: Any = getattr(event, field, None)

    if value is None:
        return None

    if hasattr(value, "value"):
        return str(value.value)

    return str(value)


def _event_matches_rule(
    event: SecurityEvent,
    rule: DetectionRule,
) -> bool:
    """Return whether an event satisfies every rule condition."""

    return all(
        _stringify_event_value(event, field) == expected
        for field, expected in rule.conditions.items()
    )


def _group_key(
    event: SecurityEvent,
    rule: DetectionRule,
) -> tuple[str, ...]:
    """Create a stable correlation key for an event."""

    return tuple(
        _stringify_event_value(event, field) or "<missing>" for field in rule.group_by
    )


class DetectionEngine:
    """Evaluate detection rules against validated security events."""

    def evaluate(
        self,
        events: Iterable[SecurityEvent],
        rule: DetectionRule,
    ) -> list[Alert]:
        """Evaluate one rule and return explainable alerts.

        Events are ordered by timestamp before correlation. A group generates
        one alert when its matching events reach the configured threshold
        inside the configured time window.
        """

        ordered_events = sorted(events, key=lambda event: event.timestamp)
        matching_events = [
            event for event in ordered_events if _event_matches_rule(event, rule)
        ]

        alerts: list[Alert] = []
        alerted_groups: set[tuple[str, ...]] = set()

        for candidate in matching_events:
            key = _group_key(candidate, rule)

            if key in alerted_groups:
                continue

            window_start = candidate.timestamp - timedelta(seconds=rule.window_seconds)

            evidence = [
                event
                for event in matching_events
                if (
                    _group_key(event, rule) == key
                    and window_start <= event.timestamp <= candidate.timestamp
                )
            ]

            if len(evidence) < rule.threshold:
                continue

            event_ids = [event.event_id for event in evidence]
            group_values = {
                field.value: _stringify_event_value(candidate, field) or "<missing>"
                for field in rule.group_by
            }

            explanation = (
                f"Detection {rule.detection_id} triggered after "
                f"{len(evidence)} matching events were observed within "
                f"{rule.window_seconds} seconds."
            )

            alerts.append(
                Alert(
                    detection_id=rule.detection_id,
                    detection_name=rule.name,
                    severity=rule.severity,
                    triggered_at=evidence[-1].timestamp,
                    event_ids=event_ids,
                    group_values=group_values,
                    explanation=explanation,
                )
            )

            alerted_groups.add(key)

        return alerts
