"""Tests for the SentinelForge X command-line interface."""

from pathlib import Path

from sentinelforge.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT_ROOT / "rules" / "DET-001-ssh-brute-force.yaml"
DATASET_PATH = PROJECT_ROOT / "quality-data" / "ssh-brute-force-cases.json"


def test_cli_evaluate_creates_reports(
    tmp_path: Path,
    capsys,
) -> None:
    """The evaluate command should create both report formats."""

    json_path = tmp_path / "reports" / "quality-report.json"
    markdown_path = tmp_path / "reports" / "quality-report.md"

    exit_code = main(
        [
            "evaluate",
            "--rule",
            str(RULE_PATH),
            "--dataset",
            str(DATASET_PATH),
            "--json-out",
            str(json_path),
            "--markdown-out",
            str(markdown_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert json_path.exists()
    assert markdown_path.exists()
    assert "Precision: 0.5000" in captured.out
    assert "F1 score: 0.5000" in captured.out


def test_cli_returns_error_for_missing_rule(
    tmp_path: Path,
    capsys,
) -> None:
    """The evaluate command should fail clearly for a missing rule."""

    json_path = tmp_path / "quality-report.json"
    markdown_path = tmp_path / "quality-report.md"

    exit_code = main(
        [
            "evaluate",
            "--rule",
            str(tmp_path / "missing-rule.yaml"),
            "--dataset",
            str(DATASET_PATH),
            "--json-out",
            str(json_path),
            "--markdown-out",
            str(markdown_path),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.err.startswith("Error: Could not read")
    assert not json_path.exists()
    assert not markdown_path.exists()
