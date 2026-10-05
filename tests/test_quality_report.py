"""Tests for structured detection-quality reports."""

from pathlib import Path

from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.quality.dataset_loader import load_test_cases
from sentinelforge.reporting.quality_report import generate_quality_report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"
DATASET_PATH = PROJECT_ROOT / "quality-data" / "ssh-brute-force-cases.json"


def test_quality_report_contains_evaluation_details() -> None:
    """A report should contain metrics and individual case results."""

    rule = load_rule(RULE_PATH)
    test_cases = load_test_cases(DATASET_PATH)

    report = generate_quality_report(
        rule,
        test_cases,
        dataset_name="ssh-brute-force-cases.json",
    )

    assert report.detection_id == "DET-001"
    assert report.detection_name == "Repeated SSH Authentication Failures"
    assert report.dataset_name == "ssh-brute-force-cases.json"
    assert report.summary.total_cases == 4
    assert len(report.cases) == 4
    assert report.summary.precision == 0.5
    assert report.summary.recall == 0.5
    assert report.summary.f1_score == 0.5


def test_quality_report_contains_recommendations() -> None:
    """A report with errors should contain improvement recommendations."""

    rule = load_rule(RULE_PATH)
    test_cases = load_test_cases(DATASET_PATH)

    report = generate_quality_report(
        rule,
        test_cases,
        dataset_name="ssh-brute-force-cases.json",
    )

    assert len(report.recommendations) >= 2
    assert any(
        "false-positive" in recommendation for recommendation in report.recommendations
    )
    assert any(
        "false-negative" in recommendation for recommendation in report.recommendations
    )


def test_quality_report_has_timestamp_and_identifier() -> None:
    """Reports should have identifiers and timezone-aware timestamps."""

    rule = load_rule(RULE_PATH)
    test_cases = load_test_cases(DATASET_PATH)

    report = generate_quality_report(
        rule,
        test_cases,
        dataset_name="ssh-brute-force-cases.json",
    )

    assert report.report_id is not None
    assert report.generated_at.tzinfo is not None
