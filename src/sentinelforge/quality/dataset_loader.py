"""Load labelled detection-quality datasets from JSON files."""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .evaluator import DetectionTestCase


class DatasetLoadError(Exception):
    """Raised when a quality dataset cannot be loaded or validated."""


def load_test_cases(path: Path) -> list[DetectionTestCase]:
    """Load and validate labelled detection test cases from JSON."""

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetLoadError(
            f"Could not read quality dataset '{path}': {exc}"
        ) from exc

    try:
        payload: Any = json.loads(raw_text)
    except JSONDecodeError as exc:
        raise DatasetLoadError(
            f"Invalid JSON in quality dataset '{path}' at "
            f"line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(payload, list):
        raise DatasetLoadError(
            "A quality dataset must contain a JSON list of test cases"
        )

    test_cases: list[DetectionTestCase] = []

    for index, record in enumerate(payload):
        if not isinstance(record, dict):
            raise DatasetLoadError(f"Test case at index {index} must be a JSON object")

        try:
            test_case = DetectionTestCase.model_validate(record)
        except ValidationError as exc:
            raise DatasetLoadError(
                f"Test case at index {index} failed validation: {exc}"
            ) from exc

        test_cases.append(test_case)

    return test_cases
