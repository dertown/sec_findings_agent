"""Combine judge votes, adjustments, and overrides into one decision."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..constants import INVESTIGATE_THRESHOLD, REVIEW_THRESHOLD, SCORE_MAX, SCORE_MIN
from ..constants import INVESTIGATION_LABELS
from ..util import clamp
from .base import JudgeResult
from .loader import LoadedJudge, load_judges


def _decision_from_score(score: float, investigate: float, review: float) -> str:
    if score >= investigate:
        return "Yes"
    if score >= review:
        return "Review"
    return "No"


def combine(
    votes: Sequence[JudgeResult],
    *,
    investigate_threshold: float = INVESTIGATE_THRESHOLD,
    review_threshold: float = REVIEW_THRESHOLD,
) -> dict[str, Any]:
    score = 50.0
    weighted_total = 0.0
    weight_sum = 0.0
    for vote in votes:
        if vote.abstain or vote.score is None or vote.mode == "adjust":
            continue
        w = max(vote.weight, 0.0) * max(vote.confidence, 0.05)
        weighted_total += vote.score * w
        weight_sum += w
    if weight_sum:
        score = weighted_total / weight_sum
    for vote in votes:
        if vote.abstain or vote.mode != "adjust":
            continue
        score += vote.adjustment * max(vote.weight, 0.0)
    score = clamp(score, SCORE_MIN, SCORE_MAX)
    decision = _decision_from_score(score, investigate_threshold, review_threshold)
    # Overrides: highest weight * confidence wins among those that fire.
    overrides = [
        vote
        for vote in votes
        if not vote.abstain and vote.mode == "override" and vote.decision
    ]
    overrides.sort(key=lambda v: v.weight * v.confidence, reverse=True)
    override_applied = None
    if overrides:
        top = overrides[0]
        decision = top.decision or decision
        if top.score is not None:
            score = clamp(top.score, SCORE_MIN, SCORE_MAX)
        override_applied = top.name
    return {
        "followup_score": round(score, 1),
        "investigation_required": decision,
        "investigation_label": INVESTIGATION_LABELS.get(decision, decision),
        "override_applied": override_applied,
        "judges": [vote.as_dict() for vote in votes],
        "judge_rationale": [
            f"{vote.name}: {vote.rationale or ('abstain' if vote.abstain else vote.decision or vote.score)}"
            for vote in votes
            if not vote.abstain or vote.error
        ],
    }


def run_judges(
    finding: Mapping[str, Any],
    context: dict[str, Any] | None = None,
    judges: Sequence[LoadedJudge] | None = None,
    home: str | None = None,
) -> dict[str, Any]:
    context = dict(context or {})
    loaded = list(judges if judges is not None else load_judges(home))
    votes: list[JudgeResult] = []
    for item in loaded:
        votes.append(item.judge(finding, context))
    return combine(
        votes,
        investigate_threshold=float(context.get("investigate_threshold") or INVESTIGATE_THRESHOLD),
        review_threshold=float(context.get("review_threshold") or REVIEW_THRESHOLD),
    )
