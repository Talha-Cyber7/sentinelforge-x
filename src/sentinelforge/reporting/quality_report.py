"""Generate structured reports from detection-quality evaluations."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinelforge.detection.rules import DetectionRule
from sentinelforge.quality.evaluator import (
    CaseEvaluation,
    DetectionQualityEvaluator,
    DetectionQualitySummary,
    DetectionTestCase,
)


class QualityReport(BaseModel):
    """A reproducible report for one detection-quality evaluation."""

    model_config = ConfigDict(extra="forbid")

    report_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    detection_id: str
    detection_name: str
    dataset_name: str = Field(min_length=1)
    summary: DetectionQualitySummary
    cases: list[CaseEvaluation] = Field(min_length=1)
    recommendations: list[str] = Field(min_length=1)


def _build_recommendations(
    summary: DetectionQualitySummary,
) -> list[str]:
    """Create practical recommendations from quality results."""

    recommendations: list[str] = []

    if summary.false_positives > 0:
        recommendations.append(
            "Review false-positive cases and consider adding context "
            "conditions or approved-activity exceptions."
        )

    if summary.false_negatives > 0:
        recommendations.append(
            "Investigate false-negative cases and consider whether the "
            "threshold, time window or event coverage is too restrictive."
        )

    if summary.precision < 0.8:
        recommendations.append(
            "Precision is below 0.80; investigate alert noise before "
            "increasing the detection severity."
        )

    if summary.recall < 0.8:
        recommendations.append(
            "Recall is below 0.80; investigate missed activity and "
            "consider broadening the detection logic."
        )

    if not recommendations:
        recommendations.append(
            "No classification errors were identified in this dataset."
        )

    return recommendations


def generate_quality_report(
    rule: DetectionRule,
    test_cases: list[DetectionTestCase],
    dataset_name: str,
) -> QualityReport:
    """Evaluate a rule and return a structured quality report."""

    evaluator = DetectionQualityEvaluator()

    case_results = [
        evaluator.evaluate_case(rule, test_case) for test_case in test_cases
    ]

    summary = evaluator.evaluate(rule, test_cases)

    return QualityReport(
        detection_id=rule.detection_id,
        detection_name=rule.name,
        dataset_name=dataset_name,
        summary=summary,
        cases=case_results,
        recommendations=_build_recommendations(summary),
    )
