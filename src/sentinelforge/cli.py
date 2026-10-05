"""Command-line interface for SentinelForge X."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sentinelforge.detection.rule_loader import (
    RuleLoadError,
    load_rule,
)
from sentinelforge.quality.dataset_loader import (
    DatasetLoadError,
    load_test_cases,
)
from sentinelforge.reporting.export import (
    ReportExportError,
    export_json_report,
    export_markdown_report,
)
from sentinelforge.reporting.quality_report import generate_quality_report


def build_parser() -> argparse.ArgumentParser:
    """Build the SentinelForge X command-line parser."""

    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description=(
            "Detection engineering and quality evaluation tools for SentinelForge X."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate a detection rule against a labelled dataset.",
    )

    evaluate_parser.add_argument(
        "--rule",
        required=True,
        type=Path,
        help="Path to a YAML detection rule.",
    )

    evaluate_parser.add_argument(
        "--dataset",
        required=True,
        type=Path,
        help="Path to a labelled JSON quality dataset.",
    )

    evaluate_parser.add_argument(
        "--json-out",
        required=True,
        type=Path,
        help="Path for the JSON quality report.",
    )

    evaluate_parser.add_argument(
        "--markdown-out",
        required=True,
        type=Path,
        help="Path for the Markdown quality report.",
    )

    return parser


def run_evaluation(args: argparse.Namespace) -> int:
    """Run one detection-quality evaluation."""

    try:
        rule = load_rule(args.rule)
        test_cases = load_test_cases(args.dataset)

        report = generate_quality_report(
            rule,
            test_cases,
            dataset_name=args.dataset.name,
        )

        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)

        export_json_report(report, args.json_out)
        export_markdown_report(report, args.markdown_out)

    except (
        DatasetLoadError,
        ReportExportError,
        RuleLoadError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    summary = report.summary

    print(f"Detection: {report.detection_name}")
    print(f"Dataset: {report.dataset_name}")
    print(f"Cases: {summary.total_cases}")
    print(f"True positives: {summary.true_positives}")
    print(f"False positives: {summary.false_positives}")
    print(f"True negatives: {summary.true_negatives}")
    print(f"False negatives: {summary.false_negatives}")
    print(f"Precision: {summary.precision:.4f}")
    print(f"Recall: {summary.recall:.4f}")
    print(f"F1 score: {summary.f1_score:.4f}")
    print(f"JSON report: {args.json_out}")
    print(f"Markdown report: {args.markdown_out}")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SentinelForge X command-line interface."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "evaluate":
        return run_evaluation(args)

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
