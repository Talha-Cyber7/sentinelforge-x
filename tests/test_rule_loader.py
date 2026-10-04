"""Tests for YAML detection-rule loading."""

from pathlib import Path

import pytest

from sentinelforge.detection.rule_loader import (
    RuleLoadError,
    load_rule,
)

RULE_PATH = Path("rules/DET-001-ssh-brute-force.yaml")


def test_loads_valid_yaml_rule() -> None:
    """The committed SSH rule should load into a validated model."""

    rule = load_rule(RULE_PATH)

    assert rule.detection_id == "DET-001"
    assert rule.name == "Repeated SSH Authentication Failures"
    assert rule.threshold == 5
    assert rule.window_seconds == 300
    assert rule.mitre_attack_id == "T1110"


def test_missing_rule_file_raises_error(tmp_path: Path) -> None:
    """A missing rule file should produce a clear error."""

    with pytest.raises(RuleLoadError, match="Could not read"):
        load_rule(tmp_path / "missing.yaml")


def test_invalid_yaml_raises_error(tmp_path: Path) -> None:
    """Malformed YAML should produce a clear error."""

    path = tmp_path / "invalid.yaml"
    path.write_text("detection_id: [invalid", encoding="utf-8")

    with pytest.raises(RuleLoadError, match="Invalid YAML"):
        load_rule(path)


def test_invalid_rule_structure_raises_error(tmp_path: Path) -> None:
    """A YAML rule with invalid fields should be rejected."""

    path = tmp_path / "invalid-rule.yaml"
    path.write_text(
        """
detection_id: DET-999
name: Invalid Rule
description: This rule should fail validation.
severity: high
conditions:
  unsupported_field: value
threshold: 1
window_seconds: 60
group_by:
  - host_id
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="Rule validation failed"):
        load_rule(path)
