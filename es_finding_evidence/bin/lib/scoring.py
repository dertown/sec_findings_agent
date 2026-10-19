"""Follow-up scoring: should an analyst investigate this finding?"""

from __future__ import annotations

from typing import Any, Mapping

from .constants import (
    COMPONENT_WEIGHTS,
    DEFAULT_WINDOW_MINUTES,
    INVESTIGATE_THRESHOLD,
    INVESTIGATION_LABELS,
    KILLCHAIN_SCORE,
    REVIEW_THRESHOLD,
    SCORE_MAX,
    SCORE_MIN,
    URGENCY_SCORE,
)
from .evidence import collect_observed_evidence, disposition_component, evidence_component_score, net_signed_weight
from .findings import normalize_finding
from .recommendations import recommend_searches
from .util import clamp, lower_text, to_float


def _urgency_component(finding: Mapping[str, Any]) -> float:
    return URGENCY_SCORE.get(lower_text(finding.get("urgency")), URGENCY_SCORE["unknown"])


def _risk_component(finding: Mapping[str, Any]) -> float:
    risk = to_float(finding.get("risk_score"), 0.0)
    if risk > 100:
        # ES risk scores can exceed 100 when modifiers stack.
        risk = 100.0 * (1.0 - 100.0 / (100.0 + risk))
    return clamp(risk)


def _killchain_component(finding: Mapping[str, Any]) -> float:
    phases = [lower_text(p) for p in (finding.get("kill_chain_phases") or [])]
    if not phases:
        techniques = " ".join(lower_text(t) for t in (finding.get("mitre_techniques") or []))
        if "t1048" in techniques or "t1567" in techniques:
            phases.append("exfiltration")
        elif "t1071" in techniques:
            phases.append("command-and-control")
        elif "t1003" in techniques:
            phases.append("credential-access")
        elif "t1021" in techniques:
            phases.append("lateral-movement")
    if not phases:
        return 40.0
    return max(KILLCHAIN_SCORE.get(phase, 40.0) for phase in phases)


def _corroboration_component(finding: Mapping[str, Any], items: list[Mapping[str, Any]]) -> float:
    sources = {item.get("source") for item in items if item.get("source") != "recommended_search"}
    related = int(to_float(finding.get("related_finding_count"), 0))
    tools = len((finding.get("triage") or {}).get("tools") or [])
    count = len(sources) + (1 if related >= 2 else 0) + (1 if tools >= 2 else 0)
    mapping = {0: 22.0, 1: 40.0, 2: 58.0, 3: 74.0}
    return mapping.get(count, 90.0)


def _decision(
    score: float,
    finding: Mapping[str, Any],
    items: list[Mapping[str, Any]],
    investigate_threshold: float,
    review_threshold: float,
) -> tuple[str, str]:
    triage = finding.get("triage") or {}
    disp = triage.get("disposition") if triage.get("present") else finding.get("disposition")
    tconf = to_float((triage or {}).get("confidence"), 0.0)
    net = net_signed_weight(items)
    urgency = lower_text(finding.get("urgency"))
    label = "No"
    if score >= investigate_threshold:
        label = "Yes"
    elif score >= review_threshold:
        label = "Review"

    # Guardrails: do not auto-close critical TPs, and do not escalate clean FPs.
    if disp == "false_positive" and tconf >= 0.8 and net < 15 and urgency not in {"critical"}:
        label = "No"
    if disp == "benign_positive" and tconf >= 0.8 and urgency not in {"critical"}:
        if net < 10:
            label = "No"
        elif label == "Yes" and urgency != "high":
            label = "Review"
    if disp in {"undetermined", "other"} and tconf < 0.6 and urgency not in {"critical", "high"} and net < 150:
        if label == "Yes":
            label = "Review"
    if disp == "true_positive" and tconf >= 0.7:
        if label == "No":
            label = "Review"
        if net > 30:
            label = "Yes"
    if urgency == "critical" and disp != "false_positive" and label == "No":
        label = "Review"

    why = INVESTIGATION_LABELS[label]
    return label, why


def _rationale(finding: Mapping[str, Any], result: Mapping[str, Any]) -> list[str]:
    lines = []
    lines.append(
        f"Follow-up score is {result['followup_score']:.0f}/100 "
        f"({result['investigation_label']})."
    )
    triage = finding.get("triage") or {}
    if triage.get("present"):
        lines.append(
            f"Triage agent disposition is {triage.get('disposition')} "
            f"(confidence {to_float(triage.get('confidence')):.0%})."
        )
        if triage.get("summary"):
            lines.append(f"Agent summary: {triage['summary']}")
    else:
        lines.append("Triage agent enrichment was not present; score uses finding metadata only.")
    breakdown = result.get("score_breakdown") or {}
    lines.append(
        "Score mix: "
        + ", ".join(
            f"{name} {values['score']:.0f}×{values['weight']:.0%}"
            for name, values in breakdown.items()
        )
        + "."
    )
    supporting = [i for i in result.get("evidence") or [] if i.get("signed_weight", 0) > 0]
    refuting = [i for i in result.get("evidence") or [] if i.get("signed_weight", 0) < 0]
    if supporting:
        top = max(supporting, key=lambda i: i.get("signed_weight", 0))
        lines.append(f"Strongest supporting evidence: {top.get('title')} (weight {top.get('signed_weight'):+.1f}).")
    if refuting:
        top = min(refuting, key=lambda i: i.get("signed_weight", 0))
        lines.append(f"Strongest refuting evidence: {top.get('title')} (weight {top.get('signed_weight'):+.1f}).")
    recos = result.get("recommended_searches") or []
    if recos:
        lines.append(
            f"{len(recos)} recommended searches can add up to "
            f"+{result.get('followup_score_ceiling', 0) - result.get('followup_score', 0):.0f} points if they confirm the finding."
        )
    return lines


def _apply_potential(base_score: float, searches: list[Mapping[str, Any]], supporting: bool) -> float:
    delta = 0.0
    for search in searches:
        potential = to_float(search.get("potential_weight"))
        if supporting and search.get("direction") != "refuting":
            delta += potential * 0.03
        if not supporting and search.get("direction") == "refuting":
            delta -= potential * 0.03
    return clamp(base_score + delta, SCORE_MIN, SCORE_MAX)


def analyze_finding(
    record: Mapping[str, Any],
    *,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    investigate_threshold: float = INVESTIGATE_THRESHOLD,
    review_threshold: float = REVIEW_THRESHOLD,
    component_weights: Mapping[str, float] | None = None,
    max_searches: int = 12,
    already_normalized: bool = False,
    extra_evidence: list | None = None,
) -> dict[str, Any]:
    finding = record if already_normalized else normalize_finding(record, window_minutes=window_minutes)
    weights = dict(COMPONENT_WEIGHTS)
    if component_weights:
        weights.update({k: float(v) for k, v in component_weights.items() if k in weights})
    evidence = collect_observed_evidence(finding)
    if extra_evidence:
        evidence = list(evidence) + list(extra_evidence)
    searches = recommend_searches(finding, window_minutes=window_minutes, max_searches=max_searches)

    components = {
        "urgency": {"score": _urgency_component(finding), "weight": weights["urgency"]},
        "risk": {"score": _risk_component(finding), "weight": weights["risk"]},
        "evidence": {"score": evidence_component_score(evidence), "weight": weights["evidence"]},
        "triage": {"score": disposition_component(finding), "weight": weights["triage"]},
        "killchain": {"score": _killchain_component(finding), "weight": weights["killchain"]},
        "corroboration": {"score": _corroboration_component(finding, evidence), "weight": weights["corroboration"]},
    }
    score = sum(values["score"] * values["weight"] for values in components.values())
    score = clamp(score, SCORE_MIN, SCORE_MAX)
    decision, decision_label = _decision(
        score, finding, evidence, investigate_threshold, review_threshold
    )
    ceiling = _apply_potential(score, searches, supporting=True)
    floor = _apply_potential(score, searches, supporting=False)
    result = {
        "finding": finding,
        "followup_score": round(score, 1),
        "followup_score_ceiling": round(ceiling, 1),
        "followup_score_floor": round(floor, 1),
        "investigation_required": decision,
        "investigation_label": decision_label,
        "investigate_threshold": investigate_threshold,
        "review_threshold": review_threshold,
        "evidence": evidence,
        "evidence_net_weight": round(net_signed_weight(evidence), 2),
        "recommended_searches": searches,
        "score_breakdown": {
            name: {
                "score": round(values["score"], 1),
                "weight": values["weight"],
                "contribution": round(values["score"] * values["weight"], 2),
            }
            for name, values in components.items()
        },
    }
    result["rationale"] = _rationale(finding, result)
    return result


def flatten_result(result: Mapping[str, Any], expand: str = "none") -> list[dict[str, Any]]:
    """Turn an analysis result into Splunk rows."""
    finding = result["finding"]
    base = {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "urgency": finding.get("urgency"),
        "status": finding.get("status"),
        "owner": finding.get("owner"),
        "disposition": finding.get("disposition"),
        "risk_score": finding.get("risk_score"),
        "src": finding.get("src"),
        "dest": finding.get("dest"),
        "user": finding.get("user"),
        "src_ip": finding.get("src_ip"),
        "dest_ip": finding.get("dest_ip"),
        "domain": finding.get("domain"),
        "url": finding.get("url"),
        "file_hash": finding.get("file_hash"),
        "process": finding.get("process"),
        "threat_object": finding.get("threat_object"),
        "risk_object": finding.get("risk_object"),
        "mitre_techniques": "\n".join(finding.get("mitre_techniques") or []),
        "kill_chain_phases": "\n".join(finding.get("kill_chain_phases") or []),
        "triage_present": 1 if (finding.get("triage") or {}).get("present") else 0,
        "triage_disposition": (finding.get("triage") or {}).get("disposition"),
        "triage_summary": (finding.get("triage") or {}).get("summary"),
        "triage_justification": (finding.get("triage") or {}).get("justification"),
        "triage_confidence": (finding.get("triage") or {}).get("confidence"),
        "triage_tools": "\n".join((finding.get("triage") or {}).get("connectors_used") or []),
        "followup_score": result["followup_score"],
        "followup_score_ceiling": result["followup_score_ceiling"],
        "followup_score_floor": result["followup_score_floor"],
        "investigation_required": result["investigation_required"],
        "investigation_label": result["investigation_label"],
        "evidence_net_weight": result["evidence_net_weight"],
        "rationale": "\n".join(result.get("rationale") or []),
        "recommended_search_count": len(result.get("recommended_searches") or []),
        "evidence_count": len(result.get("evidence") or []),
        "_time": finding.get("create_time") or 0,
    }
    # JSON companions for dashboards that want the full objects.
    from .util import dumps

    base["score_breakdown_json"] = dumps(result.get("score_breakdown"))
    base["evidence_json"] = dumps(result.get("evidence"))
    base["recommended_searches_json"] = dumps(result.get("recommended_searches"))
    base["finding_json"] = dumps(finding)

    expand = (expand or "none").lower()
    if expand in {"search", "searches"}:
        rows = []
        for search in result.get("recommended_searches") or []:
            row = dict(base)
            row.update(
                {
                    "row_type": "search",
                    "search_name": search.get("search_name"),
                    "search_spl": search.get("search"),
                    "search_purpose": search.get("purpose"),
                    "search_category": search.get("category"),
                    "search_priority": search.get("priority"),
                    "potential_weight": search.get("potential_weight"),
                    "evidence_class": search.get("class"),
                    "evidence_direction": search.get("direction"),
                }
            )
            rows.append(row)
        return rows or [dict(base, row_type="finding")]
    if expand in {"evidence", "weights"}:
        rows = []
        for item in result.get("evidence") or []:
            row = dict(base)
            row.update(
                {
                    "row_type": "evidence",
                    "evidence_title": item.get("title"),
                    "evidence_detail": item.get("detail"),
                    "evidence_class": item.get("class"),
                    "evidence_source": item.get("source"),
                    "evidence_direction": item.get("direction"),
                    "evidence_weight": item.get("weight"),
                    "evidence_signed_weight": item.get("signed_weight"),
                    "evidence_confidence": item.get("confidence"),
                }
            )
            rows.append(row)
        return rows or [dict(base, row_type="finding")]
    return [dict(base, row_type="finding")]
