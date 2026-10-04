"""End-to-end test for the first SentinelForge X detection workflow."""

from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rule_loader import load_rule
from sentinelforge.ingestion.json_loader import load_json_events

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"
EVENT_PATH = PROJECT_ROOT / "sample-data" / "linux-auth.json"


def test_ssh_brute_force_workflow() -> None:
    """The YAML rule should detect the synthetic SSH incident."""

    events = load_json_events(EVENT_PATH)
    rule = load_rule(RULE_PATH)

    alerts = DetectionEngine().evaluate(events, rule)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.detection_id == "DET-001"
    assert alert.detection_name == "Repeated SSH Authentication Failures"
    assert len(alert.event_ids) == 5
    assert alert.group_values["host_id"] == "linux-lab-01"
    assert alert.group_values["source_ip"] == "192.168.56.20"
    assert alert.group_values["username"] == "alex"
    assert "5 matching events" in alert.explanation
