"""Normalize Splunk ES Triage agent enrichment.

The ES 8.6 Analysis panel exposes summary, justification, tools, evidence,
and analysis details. Those values may arrive as finding fields, notes, or
JSON blobs. This module is liberal about input shape.
"""

from __future__ import annotations

from typing import Any, Mapping

from .constants import TRIAGE_FIELD_ALIASES
from .util import as_list, first_value, lower_text, normalize_disposition, to_float, try_json, unique


def _pick_triage(record: Mapping[str, Any], canonical: str) -> Any:
    return first_value(record, TRIAGE_FIELD_ALIASES.get(canonical, (canonical,)))


def _parse_tools(value: Any) -> list[dict[str, Any]]:
    parsed = try_json(value)
    tools: list[dict[str, Any]] = []
    items = parsed if parsed is not None else as_list(value)
    if isinstance(items, dict):
        items = [items]
    for item in items or []:
        if isinstance(item, str):
            tools.append({"name": item, "result": "", "detail": item})
            continue
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("tool") or item.get("connector") or "").strip()
        result = str(item.get("result") or item.get("verdict") or item.get("status") or "").strip()
        detail = str(item.get("detail") or item.get("output") or item.get("summary") or "").strip()
        tools.append({"name": name or "tool", "result": result, "detail": detail})
    return tools


def _parse_evidence(value: Any) -> list[dict[str, Any]]:
    parsed = try_json(value)
    items = parsed if parsed is not None else as_list(value)
    if isinstance(items, dict):
        items = items.get("items") or items.get("evidence") or [items]
    evidence: list[dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, str):
            evidence.append(
                {
                    "title": item[:120],
                    "detail": item,
                    "direction": _infer_direction(item),
                    "confidence": 0.7,
                    "class": "triage_narrative",
                }
            )
            continue
        if not isinstance(item, Mapping):
            continue
        detail = str(item.get("detail") or item.get("data") or item.get("supporting_data") or item.get("text") or "")
        title = str(item.get("title") or item.get("hypothesis") or item.get("name") or detail[:120])
        direction = str(item.get("direction") or item.get("polarity") or _infer_direction(detail or title))
        evidence.append(
            {
                "title": title or "Triage evidence",
                "detail": detail,
                "direction": "refuting" if lower_text(direction) in {"refute", "refuting", "benign", "false"} else "supporting",
                "confidence": to_float(item.get("confidence"), 0.75),
                "class": str(item.get("class") or item.get("type") or "triage_evidence"),
            }
        )
    return evidence


def _infer_direction(text: str) -> str:
    lowered = lower_text(text)
    refute_markers = (
        "false positive",
        "benign",
        "expected",
        "sanctioned",
        "clean reputation",
        "no malware",
        "not malicious",
        "known admin",
        "scanner",
        "vulnerability scan",
        "change window",
    )
    if any(marker in lowered for marker in refute_markers):
        return "refuting"
    return "supporting"


def _notes_blob(record: Mapping[str, Any]) -> dict[str, Any]:
    """Best-effort parse of finding notes that contain agent JSON or labeled text."""
    notes = as_list(record.get("notes")) + as_list(record.get("comment")) + as_list(record.get("comments"))
    blob: dict[str, Any] = {}
    for note in notes:
        if isinstance(note, Mapping):
            body = note.get("body") or note.get("comment") or note.get("text") or note
        else:
            body = note
        parsed = try_json(body)
        if isinstance(parsed, dict) and any(
            key in parsed for key in ("summary", "justification", "evidence", "disposition", "tools")
        ):
            blob.update(parsed)
            continue
        text = str(body)
        lowered = lower_text(text)
        if "triage agent" in lowered or "ai analysis" in lowered or "analysis panel" in lowered:
            blob.setdefault("analysis_details", text)
    return blob


def normalize_triage(record: Mapping[str, Any]) -> dict[str, Any]:
    nested = record.get("triage") or record.get("ai_analysis") or record.get("analysis") or {}
    if not isinstance(nested, Mapping):
        parsed_nested = try_json(nested)
        nested = parsed_nested if isinstance(parsed_nested, dict) else {}
    notes = _notes_blob(record)

    def take(canonical: str) -> Any:
        return (
            _pick_triage(record, canonical)
            or nested.get(canonical)
            or notes.get(canonical)
            or nested.get(canonical.replace("_", " "))
        )

    disposition_raw = take("disposition")
    summary = str(take("summary") or "").strip()
    justification = str(take("justification") or "").strip()
    details = str(take("analysis_details") or "").strip()
    tools = _parse_tools(take("tools") or nested.get("connectors"))
    evidence = _parse_evidence(take("evidence"))
    confidence = to_float(take("confidence"), 0.0)
    present = bool(
        disposition_raw or summary or justification or details or tools or evidence
    )
    disposition = normalize_disposition(disposition_raw) if present else "undetermined"
    if present and confidence <= 0:
        confidence = 0.7
    return {
        "present": present,
        "disposition": disposition,
        "disposition_raw": str(disposition_raw or ""),
        "summary": summary,
        "justification": justification,
        "tools": tools,
        "evidence": evidence,
        "analysis_details": details,
        "confidence": confidence,
        "connectors_used": unique(tool.get("name", "") for tool in tools),
    }
