"""Built-in judges used by the backend agent."""

from __future__ import annotations

from typing import Any, Mapping

from ..scoring import analyze_finding
from ..util import lower_text, to_float
from .base import JudgeResult


class FollowupScoreJudge:
    """Wraps the core follow-up scoring model as a vote."""

    name = "followup_score"
    weight = 1.0
    mode = "vote"

    def judge(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> JudgeResult:
        analysis = context.get("analysis")
        extra = context.get("extra_evidence") or []
        if analysis is None:
            analysis = analyze_finding(
                finding,
                already_normalized=True,
                extra_evidence=extra,
                window_minutes=int(context.get("window_minutes") or 60),
                max_searches=int(context.get("max_searches") or 12),
            )
            context["analysis"] = analysis  # type: ignore[index]
        return JudgeResult(
            name=self.name,
            score=float(analysis["followup_score"]),
            decision=str(analysis["investigation_required"]),
            rationale="; ".join(analysis.get("rationale") or [])[:500],
            confidence=0.8,
            mode=self.mode,
            weight=self.weight,
            extra={"source": "builtin_followup_score"},
        )


class TriageGuardrailJudge:
    """Override-style guardrails from the ES Triage agent disposition."""

    name = "triage_guardrail"
    weight = 0.9
    mode = "override"

    def judge(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> JudgeResult:
        triage = finding.get("triage") or {}
        if not triage.get("present"):
            return JudgeResult(name=self.name, abstain=True, mode=self.mode, weight=self.weight, rationale="no triage agent output")
        disp = triage.get("disposition")
        conf = to_float(triage.get("confidence"), 0.0)
        net = to_float((context.get("analysis") or {}).get("evidence_net_weight"), 0.0)
        urgency = lower_text(finding.get("urgency"))
        if disp == "false_positive" and conf >= 0.8 and urgency != "critical":
            return JudgeResult(
                name=self.name,
                score=18,
                decision="No",
                rationale="High-confidence triage agent false positive.",
                confidence=conf,
                mode="override",
                weight=self.weight,
            )
        if disp == "benign_positive" and conf >= 0.85 and urgency not in {"critical"} and net < 10:
            return JudgeResult(
                name=self.name,
                score=22,
                decision="No",
                rationale="High-confidence triage agent benign positive with weak supporting evidence.",
                confidence=conf,
                mode="override",
                weight=self.weight,
            )
        if disp == "true_positive" and conf >= 0.85 and urgency in {"high", "critical"}:
            return JudgeResult(
                name=self.name,
                score=90,
                decision="Yes",
                rationale="High-confidence triage agent true positive on a high/critical finding.",
                confidence=conf,
                mode="override",
                weight=self.weight,
            )
        return JudgeResult(name=self.name, abstain=True, mode=self.mode, weight=self.weight, rationale="no guardrail fired")


class CriticalAssetJudge:
    """Adjust the score up when a critical asset or privileged identity is involved."""

    name = "critical_asset"
    weight = 0.25
    mode = "adjust"

    def judge(self, finding: Mapping[str, Any], context: Mapping[str, Any]) -> JudgeResult:
        asset = lower_text(finding.get("asset_priority"))
        ident = lower_text(finding.get("identity_priority"))
        bump = 0.0
        bits = []
        if asset == "critical":
            bump += 12
            bits.append("critical asset")
        elif asset == "high":
            bump += 6
            bits.append("high-priority asset")
        if ident == "critical":
            bump += 10
            bits.append("critical identity")
        elif ident == "high":
            bump += 5
            bits.append("high-priority identity")
        if not bump:
            return JudgeResult(name=self.name, abstain=True, mode=self.mode, weight=self.weight)
        return JudgeResult(
            name=self.name,
            adjustment=bump,
            score=None,
            rationale="Priority bump: " + ", ".join(bits),
            confidence=0.75,
            mode="adjust",
            weight=self.weight,
        )


BUILTIN = {
    "FollowupScoreJudge": FollowupScoreJudge,
    "TriageGuardrailJudge": TriageGuardrailJudge,
    "CriticalAssetJudge": CriticalAssetJudge,
    "followup_score": FollowupScoreJudge,
    "triage_guardrail": TriageGuardrailJudge,
    "critical_asset": CriticalAssetJudge,
}
