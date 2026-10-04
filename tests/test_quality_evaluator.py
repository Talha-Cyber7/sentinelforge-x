"""Tests for detection-quality evaluation."""

from datetime import UTC, datetime, timedelta

from sentinelforge.detection.rules import (
    DetectionRule,
    GroupField,
)
from sentinelforge.models.events import (
    EventCategory,
    EventSource,
    SecurityEvent,
    Severity,
)
from sentinelforge.quality.evaluator import (
    CaseClassification,
    DetectionQualityEvaluator,
    DetectionTestCase,
)


def make_event(
    offset_seconds: int,
    *,
    action: str = "ssh_login_failed",
) -> SecurityEvent:
    """Create a synthetic event for quality testing."""

    timestamp = datetime(2026, 10, 4, 14, 0, tzinfo=UTC) + timedelta(
        seconds=offset_seconds
    )

    return SecurityEvent(
        timestamp=timestamp,
        host_id="linux-lab-01",
        source=EventSource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="authentication_failure",
        action=action,
        severity=Severity.MEDIUM,
        username="alex",
        source_ip="192.168.56.20",
    )


def make_rule() -> DetectionRule:
    """Create the rule used in quality tests."""

    return DetectionRule(
        detection_id="DET-001",
        name="Repeated SSH Authentication Failures",
        description="Detects repeated failed SSH authentication attempts.",
        severity=Severity.HIGH,
        conditions={
            "event_type": "authentication_failure",
            "action": "ssh_login_failed",
        },
        threshold=5,
        window_seconds=300,
        group_by=(
            GroupField.HOST_ID,
            GroupField.SOURCE_IP,
            GroupField.USERNAME,
        ),
        mitre_attack_id="T1110",
    )


def test_true_positive_case_is_classified_correctly() -> None:
    """Five matching events expected to alert should be a true positive."""

    test_case = DetectionTestCase(
        case_id="CASE-001",
        description="Five failed SSH logins from one source.",
        events=[make_event(offset) for offset in (0, 10, 20, 30, 40)],
        expected_alert=True,
    )

    result = DetectionQualityEvaluator().evaluate_case(
        make_rule(),
        test_case,
    )

    assert result.actual_alert is True
    assert result.classification is CaseClassification.TRUE_POSITIVE


def test_false_negative_case_is_classified_correctly() -> None:
    """Four matching events expected to alert should be a false negative."""

    test_case = DetectionTestCase(
        case_id="CASE-002",
        description="Four failed SSH logins that should be investigated.",
        events=[make_event(offset) for offset in (0, 10, 20, 30)],
        expected_alert=True,
    )

    result = DetectionQualityEvaluator().evaluate_case(
        make_rule(),
        test_case,
    )

    assert result.actual_alert is False
    assert result.classification is CaseClassification.FALSE_NEGATIVE


def test_quality_summary_calculates_metrics() -> None:
    """The evaluator should calculate classification counts and metrics."""

    test_cases = [
        DetectionTestCase(
            case_id="CASE-003",
            description="Known malicious SSH brute-force simulation.",
            events=[make_event(offset) for offset in (0, 10, 20, 30, 40)],
            expected_alert=True,
        ),
        DetectionTestCase(
            case_id="CASE-004",
            description="Approved test activity that should not alert.",
            events=[make_event(offset) for offset in (0, 10, 20, 30, 40)],
            expected_alert=False,
        ),
        DetectionTestCase(
            case_id="CASE-005",
            description="Incomplete activity that should alert but does not.",
            events=[make_event(offset) for offset in (0, 10, 20, 30)],
            expected_alert=True,
        ),
        DetectionTestCase(
            case_id="CASE-006",
            description="Successful login activity with no failed attempts.",
            events=[
                make_event(offset, action="ssh_login_success") for offset in (0, 10, 20)
            ],
            expected_alert=False,
        ),
    ]

    summary = DetectionQualityEvaluator().evaluate(
        make_rule(),
        test_cases,
    )

    assert summary.detection_id == "DET-001"
    assert summary.total_cases == 4
    assert summary.true_positives == 1
    assert summary.false_positives == 1
    assert summary.true_negatives == 1
    assert summary.false_negatives == 1
    assert summary.precision == 0.5
    assert summary.recall == 0.5
    assert summary.f1_score == 0.5
