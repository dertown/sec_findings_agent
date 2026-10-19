"""Build finding enrichment and push it onto the ES finding.

Analysts see this in Mission Control notes and (when configured) additional
fields. The agent does not change owner, status, urgency, or disposition.
"""

from __future__ import annotations

from typing import Any, Mapping

from .util import dumps, to_float

ENRICHMENT_MARKER = "Finding Evidence Agent enrichment"
FIELD_PREFIX = "fea_"


def build_enrichment(row: Mapping[str, Any]) -> dict[str, Any]:
    """Full payload stored in KV and in the finding note JSON fence."""
    return {
        "fea_followup_score": to_float(row.get("followup_score")),
        "fea_investigation_required": row.get("investigation_required") or "",
        "fea_investigation_label": row.get("investigation_label") or "",
        "fea_evidence_net_weight": to_float(row.get("evidence_net_weight")),
        "fea_executed_search_count": int(to_float(row.get("executed_search_count"), 0)),
        "fea_recommended_search_count": int(to_float(row.get("recommended_search_count"), 0)),
        "fea_override_applied": row.get("override_applied") or "",
        "fea_triage_disposition": row.get("triage_disposition") or "",
        "fea_triage_confidence": to_float(row.get("triage_confidence"), 0.0),
        "fea_triage_summary": (row.get("triage_summary") or "")[:500],
        "fea_agent_summary": (row.get("rationale") or "")[:1000],
        "fea_agent_tasks": row.get("agent_tasks") or "",
        "fea_score_breakdown_json": row.get("score_breakdown_json") or "{}",
        "fea_judges_json": row.get("judges_json") or "[]",
        "fea_evidence_json": row.get("evidence_json") or "[]",
        "fea_executed_searches_json": row.get("executed_searches_json") or "[]",
        "fea_recommended_searches_json": row.get("recommended_searches_json") or "[]",
        "fea_enrichment_marker": ENRICHMENT_MARKER,
    }


def compact_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """Scalar fea_* fields written onto the ES finding (JSON blobs live in the note)."""
    return {key: value for key, value in build_enrichment(row).items() if not key.endswith("_json")}


def build_note(row: Mapping[str, Any]) -> str:
    lines = [
        f"## {ENRICHMENT_MARKER}",
        "",
        f"**Follow-up score:** {row.get('followup_score', '')} / 100",
        f"**Investigation:** {row.get('investigation_required', '')} — {row.get('investigation_label', '')}",
        f"**Triage agent:** {row.get('triage_disposition') or 'not run'}",
    ]
    if row.get("override_applied"):
        lines.append(f"**Judge override:** {row.get('override_applied')}")
    if row.get("rationale"):
        lines.extend(["", "### Why", str(row.get("rationale"))])
    evidence = _as_list(row.get("evidence_json"))
    if evidence:
        lines.extend(["", "### Weighted evidence"])
        for item in evidence[:12]:
            signed = to_float(item.get("signed_weight"), 0.0)
            title = item.get("title") or item.get("class")
            lines.append(f"- `{signed:+.1f}` {title}")
    executed = _as_list(row.get("executed_searches_json"))
    if executed:
        lines.extend(["", "### Evidence searches the agent ran"])
        for item in executed[:12]:
            name = item.get("search_name") or item.get("template_id")
            count = item.get("count")
            err = item.get("error")
            if err:
                lines.append(f"- {name}: error {err}")
            else:
                lines.append(f"- {name}: {count} hit(s)")
    recos = _as_list(row.get("recommended_searches_json"))
    if recos and not executed:
        lines.extend(["", "### Recommended evidence searches"])
        for item in recos[:8]:
            lines.append(f"- {item.get('search_name') or item.get('title')}")
    judges = _as_list(row.get("judges_json"))
    if judges:
        lines.extend(["", "### Judges"])
        for item in judges:
            if item.get("abstain") and not item.get("error"):
                continue
            lines.append(
                f"- {item.get('name')}: {item.get('mode')} "
                f"score={item.get('score')} decision={item.get('decision') or ''} "
                f"{item.get('rationale') or ''}".strip()
            )
    lines.extend(["", "```fea-enrichment", dumps(build_enrichment(row))[:6000], "```"])
    return "\n".join(lines)[:12000]


def _as_list(value: Any) -> list[dict[str, Any]]:
    if value in (None, "", "[]"):
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    from .util import try_json

    parsed = try_json(value)
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []
