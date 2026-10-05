"""Tests for labelled quality-dataset loading."""

from pathlib import Path

import pytest

from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.quality.dataset_loader import (
    DatasetLoadError,
    load_test_cases,
)
from sentinelforge.quality.evaluator import DetectionQualityEvaluator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "quality-data" / "ssh-brute-force-cases.json"
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"


def test_loads_quality_dataset() -> None:
    """The committed dataset should load four validated test cases."""

    test_cases = load_test_cases(DATASET_PATH)

    assert len(test_cases) == 4
    assert test_cases[0].case_id == "CASE-001"
    assert test_cases[0].expected_alert is True
    assert len(test_cases[0].events) == 5


def test_dataset_drives_quality_evaluation() -> None:
    """The external dataset should produce expected quality metrics."""

    rule = load_rule(RULE_PATH)
    test_cases = load_test_cases(DATASET_PATH)

    summary = DetectionQualityEvaluator().evaluate(rule, test_cases)

    assert summary.detection_id == "DET-001"
    assert summary.total_cases == 4
    assert summary.true_positives == 1
    assert summary.false_positives == 1
    assert summary.true_negatives == 1
    assert summary.false_negatives == 1
    assert summary.precision == 0.5
    assert summary.recall == 0.5
    assert summary.f1_score == 0.5


def test_missing_dataset_raises_error(tmp_path: Path) -> None:
    """A missing dataset should produce a clear error."""

    with pytest.raises(DatasetLoadError, match="Could not read"):
        load_test_cases(tmp_path / "missing.json")


def test_dataset_must_contain_a_list(tmp_path: Path) -> None:
    """A dataset containing an object instead of a list should fail."""

    path = tmp_path / "invalid.json"
    path.write_text('{"case_id": "CASE-001"}', encoding="utf-8")

    with pytest.raises(DatasetLoadError, match="must contain a JSON list"):
        load_test_cases(path)
