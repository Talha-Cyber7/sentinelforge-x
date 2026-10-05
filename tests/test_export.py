"""Tests for JSON and Markdown quality-report exports."""

import json
from pathlib import Path

import pytest

from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.quality.dataset_loader import load_test_cases
from sentinelforge.reporting.export import (
    ReportExportError,
    export_json_report,
    export_markdown_report,
)
from sentinelforge.reporting.quality_report import generate_quality_report

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"
DATASET_PATH = PROJECT_ROOT / "quality-data" / "ssh-brute-force-cases.json"


def build_report():
    """Build a report from the committed rule and dataset."""

    rule = load_rule(RULE_PATH)
    test_cases = load_test_cases(DATASET_PATH)

    return generate_quality_report(
        rule,
        test_cases,
        dataset_name="ssh-brute-force-cases.json",
    )


def test_exports_valid_json_report(tmp_path: Path) -> None:
    """The JSON export should be readable and contain report data."""

    report = build_report()
    output_path = tmp_path / "quality-report.json"

    export_json_report(report, output_path)

    exported = json.loads(output_path.read_text(encoding="utf-8"))

    assert exported["detection_id"] == "DET-001"
    assert exported["summary"]["precision"] == 0.5
    assert len(exported["cases"]) == 4


def test_exports_readable_markdown_report(tmp_path: Path) -> None:
    """The Markdown export should contain useful report sections."""

    report = build_report()
    output_path = tmp_path / "quality-report.md"

    export_markdown_report(report, output_path)

    markdown = output_path.read_text(encoding="utf-8")

    assert "# Detection Quality Report" in markdown
    assert "## Summary" in markdown
    assert "## Case results" in markdown
    assert "## Recommendations" in markdown
    assert "0.5000" in markdown
    assert "CASE-003" in markdown


def test_export_failure_raises_clear_error(tmp_path: Path) -> None:
    """An unwritable destination should produce a clear export error."""

    report = build_report()
    invalid_path = tmp_path / "missing-directory" / "report.json"

    with pytest.raises(ReportExportError, match="Could not write"):
        export_json_report(report, invalid_path)
