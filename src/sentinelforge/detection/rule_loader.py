"""Load and validate detection rules from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .rules import DetectionRule


class RuleLoadError(Exception):
    """Raised when a detection rule cannot be loaded or validated."""


def load_rule(path: Path) -> DetectionRule:
    """Load one YAML detection rule and validate its structure."""

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleLoadError(f"Could not read rule file '{path}': {exc}") from exc

    try:
        payload: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"Invalid YAML in rule file '{path}': {exc}") from exc

    if not isinstance(payload, dict):
        raise RuleLoadError("A detection rule file must contain one YAML mapping")

    try:
        return DetectionRule.model_validate(payload)
    except ValidationError as exc:
        raise RuleLoadError(f"Rule validation failed for '{path}': {exc}") from exc
