"""Detection-quality evaluation against labelled test cases."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rules import DetectionRule
from sentinelforge.models.events import SecurityEvent


class CaseClassification(StrEnum):
    """Classification assigned to one labelled detection test case."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"


class DetectionTestCase(BaseModel):
    """A labelled dataset used to evaluate one detection rule."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^CASE-[0-9]{3,}$")
    description: str = Field(min_length=1)
    events: list[SecurityEvent] = Field(min_length=1)
    expected_alert: bool


class CaseEvaluation(BaseModel):
    """The result of evaluating one labelled test case."""

    case_id: str
    description: str
    expected_alert: bool
    actual_alert: bool
    classification: CaseClassification


class DetectionQualitySummary(BaseModel):
    """Aggregate quality metrics for a detection rule."""

    detection_id: str
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float


def _safe_ratio(numerator: float, denominator: float) -> float:
    """Calculate a ratio without raising a division-by-zero error."""

    if denominator == 0:
        return 0.0

    return numerator / denominator


class DetectionQualityEvaluator:
    """Evaluate a detection rule against labelled security-event cases."""

    def __init__(self) -> None:
        self._engine = DetectionEngine()

    def evaluate_case(
        self,
        rule: DetectionRule,
        test_case: DetectionTestCase,
    ) -> CaseEvaluation:
        """Evaluate one labelled test case."""

        alerts = self._engine.evaluate(test_case.events, rule)
        actual_alert = bool(alerts)

        if test_case.expected_alert and actual_alert:
            classification = CaseClassification.TRUE_POSITIVE
        elif not test_case.expected_alert and actual_alert:
            classification = CaseClassification.FALSE_POSITIVE
        elif test_case.expected_alert and not actual_alert:
            classification = CaseClassification.FALSE_NEGATIVE
        else:
            classification = CaseClassification.TRUE_NEGATIVE

        return CaseEvaluation(
            case_id=test_case.case_id,
            description=test_case.description,
            expected_alert=test_case.expected_alert,
            actual_alert=actual_alert,
            classification=classification,
        )

    def evaluate(
        self,
        rule: DetectionRule,
        test_cases: list[DetectionTestCase],
    ) -> DetectionQualitySummary:
        """Evaluate a rule and calculate classification metrics."""

        results = [self.evaluate_case(rule, test_case) for test_case in test_cases]

        true_positives = sum(
            result.classification is CaseClassification.TRUE_POSITIVE
            for result in results
        )
        false_positives = sum(
            result.classification is CaseClassification.FALSE_POSITIVE
            for result in results
        )
        true_negatives = sum(
            result.classification is CaseClassification.TRUE_NEGATIVE
            for result in results
        )
        false_negatives = sum(
            result.classification is CaseClassification.FALSE_NEGATIVE
            for result in results
        )

        precision = _safe_ratio(
            true_positives,
            true_positives + false_positives,
        )
        recall = _safe_ratio(
            true_positives,
            true_positives + false_negatives,
        )
        f1_score = _safe_ratio(
            2 * precision * recall,
            precision + recall,
        )

        return DetectionQualitySummary(
            detection_id=rule.detection_id,
            total_cases=len(test_cases),
            true_positives=true_positives,
            false_positives=false_positives,
            true_negatives=true_negatives,
            false_negatives=false_negatives,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1_score, 4),
        )
