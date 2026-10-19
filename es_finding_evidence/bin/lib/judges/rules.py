"""Conf-only rule judges. No Python file required.

Example stanza:

    [always_investigate_critical_tp]
    type = rule
    enabled = 1
    mode = override
    weight = 1.0
    when_urgency = critical
    when_triage_disposition = true_positive
    decision = Yes
    score = 92
    rationale = Policy: critical true positives always investigate
"""

from __future__ import annotations

from typing import Any, Mapping

from ..util import lower_text, to_float
from .base import JudgeResult, VALID_DECISIONS


class RuleJudge:
    def __init__(self, name: str, stanza: Mapping[str, str]):
        self.name = name
        self.stanza = dict(stanza)
        self.weight = to_float(stanza.get("weight"), 1.0)
        self.mode = stanza.get("mode") or "override"

    def judge(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> JudgeResult:
        if not self._matches(finding, context):
            return JudgeResult(name=self.name, abstain=True, mode=self.mode, weight=self.weight)
        decision = self.stanza.get("decision")
        if decision not in VALID_DECISIONS:
            decision = None
        score = self.stanza.get("score")
        return JudgeResult(
            name=self.name,
            score=None if score in (None, "") else to_float(score),
            decision=decision,
            rationale=self.stanza.get("rationale") or f"Rule {self.name} matched.",
            confidence=to_float(self.stanza.get("confidence"), 0.8),
            mode=self.mode,
            adjustment=to_float(self.stanza.get("adjustment"), 0.0),
            weight=self.weight,
        )

    def _matches(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
        triage = finding.get("triage") or {}
        checks = {
            "when_urgency": lower_text(finding.get("urgency")),
            "when_status": lower_text(finding.get("status")),
            "when_disposition": lower_text(finding.get("disposition")),
            "when_triage_disposition": lower_text(triage.get("disposition")),
            "when_asset_priority": lower_text(finding.get("asset_priority")),
            "when_identity_priority": lower_text(finding.get("identity_priority")),
            "when_risk_object_type": lower_text(finding.get("risk_object_type")),
        }
        for key, actual in checks.items():
            expected = lower_text(self.stanza.get(key))
            if expected and actual != expected:
                return False
        min_risk = to_float(self.stanza.get("when_min_risk"), -1)
        if min_risk >= 0 and to_float(finding.get("risk_score")) < min_risk:
            return False
        title_contains = lower_text(self.stanza.get("when_title_contains"))
        if title_contains and title_contains not in lower_text(finding.get("title")):
            return False
        user_in = self.stanza.get("when_user_in")
        if user_in:
            allowed = {part.strip().lower() for part in user_in.split(",") if part.strip()}
            if lower_text(finding.get("user")) not in allowed:
                return False
        return True
