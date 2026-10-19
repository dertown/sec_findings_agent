"""Judge plugin contract.

A judge looks at a finding, observed evidence, and (optionally) executed
search results, then votes on follow-up. Custom judges live under the app
and are registered in judges.conf — they are trusted admin code, not
untrusted user input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


VALID_DECISIONS = {"Yes", "Review", "No"}
VALID_MODES = {"vote", "adjust", "override"}


@dataclass
class JudgeResult:
    name: str
    score: float | None = None
    decision: str | None = None
    rationale: str = ""
    confidence: float = 0.7
    mode: str = "vote"
    adjustment: float = 0.0
    weight: float = 1.0
    abstain: bool = False
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "decision": self.decision,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "mode": self.mode,
            "adjustment": self.adjustment,
            "weight": self.weight,
            "abstain": self.abstain,
            "error": self.error,
            "extra": self.extra,
        }


class Judge(Protocol):
    name: str
    weight: float
    mode: str

    def judge(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> JudgeResult:
        ...


def coerce_result(name: str, raw: Any, *, weight: float, mode: str) -> JudgeResult:
    if raw is None:
        return JudgeResult(name=name, abstain=True, weight=weight, mode=mode, rationale="abstain")
    if isinstance(raw, JudgeResult):
        raw.name = raw.name or name
        raw.weight = raw.weight if raw.weight else weight
        raw.mode = raw.mode or mode
        return raw
    if not isinstance(raw, Mapping):
        return JudgeResult(name=name, abstain=True, weight=weight, mode=mode, error="judge returned a non-object")
    decision = raw.get("decision")
    if decision in {"yes", "YES"}:
        decision = "Yes"
    elif decision in {"no", "NO"}:
        decision = "No"
    elif decision in {"review", "REVIEW"}:
        decision = "Review"
    if decision not in VALID_DECISIONS:
        decision = None
    score = raw.get("score")
    try:
        score_f = None if score in (None, "") else float(score)
    except (TypeError, ValueError):
        score_f = None
    abstain = bool(raw.get("abstain")) or (score_f is None and decision is None and not raw.get("adjustment"))
    return JudgeResult(
        name=str(raw.get("name") or name),
        score=score_f,
        decision=decision,
        rationale=str(raw.get("rationale") or raw.get("reason") or ""),
        confidence=float(raw.get("confidence") or 0.7),
        mode=str(raw.get("mode") or mode),
        adjustment=float(raw.get("adjustment") or 0.0),
        weight=float(raw.get("weight") or weight),
        abstain=abstain,
        extra={k: v for k, v in raw.items() if k not in {"name", "score", "decision", "rationale", "reason", "confidence", "mode", "adjustment", "weight", "abstain"}},
    )
