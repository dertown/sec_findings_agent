"""Shared entry used by custom commands, REST, and the local CLI."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .constants import DEFAULT_WINDOW_MINUTES, INVESTIGATE_THRESHOLD, REVIEW_THRESHOLD
from .demo import sample_findings
from .scoring import analyze_finding, flatten_result


def analyze_records(
    records: Iterable[Mapping[str, Any]],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    investigate_threshold: float = INVESTIGATE_THRESHOLD,
    review_threshold: float = REVIEW_THRESHOLD,
    expand: str = "none",
    max_searches: int = 12,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        result = analyze_finding(
            record,
            window_minutes=window_minutes,
            investigate_threshold=investigate_threshold,
            review_threshold=review_threshold,
            max_searches=max_searches,
        )
        rows.extend(flatten_result(result, expand=expand))
    return rows


def demo_records() -> list[dict[str, Any]]:
    return sample_findings()
