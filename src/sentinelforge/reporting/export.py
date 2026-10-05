"""Export quality reports as JSON and Markdown."""

from __future__ import annotations

from pathlib import Path

from sentinelforge.reporting.quality_report import QualityReport


class ReportExportError(Exception):
    """Raised when a quality report cannot be exported."""


def export_json_report(report: QualityReport, path: Path) -> None:
    """Write a quality report as formatted JSON."""

    try:
        path.write_text(
            report.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReportExportError(
            f"Could not write JSON report to '{path}': {exc}"
        ) from exc


def export_markdown_report(report: QualityReport, path: Path) -> None:
    """Write a quality report as a human-readable Markdown document."""

    summary = report.summary

    lines = [
        f"# Detection Quality Report: {report.detection_name}",
        "",
        f"- **Report ID:** `{report.report_id}`",
        f"- **Detection ID:** `{report.detection_id}`",
        f"- **Dataset:** `{report.dataset_name}`",
        f"- **Generated:** `{report.generated_at.isoformat()}`",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total cases | {summary.total_cases} |",
        f"| True positives | {summary.true_positives} |",
        f"| False positives | {summary.false_positives} |",
        f"| True negatives | {summary.true_negatives} |",
        f"| False negatives | {summary.false_negatives} |",
        f"| Precision | {summary.precision:.4f} |",
        f"| Recall | {summary.recall:.4f} |",
        f"| F1 score | {summary.f1_score:.4f} |",
        "",
        "## Case results",
        "",
        "| Case | Expected alert | Actual alert | Classification |",
        "| --- | --- | --- | --- |",
    ]

    for case in report.cases:
        expected = "Yes" if case.expected_alert else "No"
        actual = "Yes" if case.actual_alert else "No"

        lines.append(
            f"| `{case.case_id}` | {expected} | {actual} "
            f"| `{case.classification.value}` |"
        )

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
        ]
    )

    lines.extend(f"- {recommendation}" for recommendation in report.recommendations)

    try:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportExportError(
            f"Could not write Markdown report to '{path}': {exc}"
        ) from exc
