"""Normalize ES findings / notables / REST payloads into a canonical record."""

from __future__ import annotations

from typing import Any, Mapping

from .constants import DEFAULT_WINDOW_MINUTES, FIELD_ALIASES
from .triage import normalize_triage
from .util import (
    as_list,
    first_value,
    flatten_annotations,
    looks_like_hash,
    looks_like_ip,
    lower_text,
    normalize_disposition,
    to_epoch,
    to_float,
    unique,
)


def _pick(record: Mapping[str, Any], canonical: str, default: Any = "") -> Any:
    return first_value(record, FIELD_ALIASES.get(canonical, (canonical,)), default)


def _string(record: Mapping[str, Any], canonical: str) -> str:
    value = _pick(record, canonical, "")
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return "" if value is None else str(value).strip()


def extract_entities(record: Mapping[str, Any]) -> dict[str, str]:
    entities = {
        "src": _string(record, "src"),
        "dest": _string(record, "dest"),
        "user": _string(record, "user"),
        "src_user": _string(record, "src_user"),
        "src_ip": _string(record, "src_ip"),
        "dest_ip": _string(record, "dest_ip"),
        "dvc": _string(record, "dvc"),
        "url": _string(record, "url"),
        "domain": _string(record, "domain"),
        "file_hash": _string(record, "file_hash"),
        "file_name": _string(record, "file_name"),
        "process": _string(record, "process"),
        "parent_process": _string(record, "parent_process"),
        "command_line": _string(record, "command_line"),
        "threat_object": _string(record, "threat_object"),
        "threat_object_type": _string(record, "threat_object_type"),
        "risk_object": _string(record, "risk_object"),
        "risk_object_type": _string(record, "risk_object_type"),
    }
    if not entities["user"] and entities["src_user"]:
        entities["user"] = entities["src_user"]
    if entities["src"] and not entities["src_ip"] and looks_like_ip(entities["src"]):
        entities["src_ip"] = entities["src"]
    if entities["dest"] and not entities["dest_ip"] and looks_like_ip(entities["dest"]):
        entities["dest_ip"] = entities["dest"]
    threat = entities["threat_object"]
    threat_type = lower_text(entities["threat_object_type"])
    if threat and looks_like_hash(threat) and not entities["file_hash"]:
        entities["file_hash"] = threat
        if not threat_type:
            entities["threat_object_type"] = "hash"
    if threat and (threat_type in {"ip", "ip_address"} or looks_like_ip(threat)):
        if not entities["dest_ip"]:
            entities["dest_ip"] = threat
        if not threat_type:
            entities["threat_object_type"] = "ip"
    if threat and threat_type in {"domain", "dns", "fqdn"} and not entities["domain"]:
        entities["domain"] = threat
    if threat and threat_type in {"url"} and not entities["url"]:
        entities["url"] = threat
    if not entities["risk_object"]:
        entities["risk_object"] = (
            entities["user"] or entities["src"] or entities["dest"] or entities["dvc"]
        )
        if entities["user"]:
            entities["risk_object_type"] = entities["risk_object_type"] or "user"
        elif entities["src"] or entities["dest"] or entities["dvc"]:
            entities["risk_object_type"] = entities["risk_object_type"] or "system"
    return entities


def normalize_finding(record: Mapping[str, Any], window_minutes: int = DEFAULT_WINDOW_MINUTES) -> dict[str, Any]:
    """Return a canonical finding dict. Extra original keys are preserved under `raw`."""
    annotations = flatten_annotations(record)
    create_time = to_epoch(_pick(record, "create_time", record.get("_time")))
    update_time = to_epoch(_pick(record, "update_time"))
    earliest = to_epoch(record.get("earliest")) or (
        (create_time - window_minutes * 60) if create_time else None
    )
    latest = to_epoch(record.get("latest")) or (
        (create_time + window_minutes * 60) if create_time else None
    )
    finding_id = _string(record, "finding_id") or _string(record, "orig_sid")
    entities = extract_entities(record)
    urgency = lower_text(_string(record, "urgency")) or "unknown"
    if urgency in {"info"}:
        urgency = "informational"
    finding = {
        "finding_id": finding_id,
        "title": _string(record, "title") or "Untitled finding",
        "description": _string(record, "description"),
        "urgency": urgency,
        "severity": lower_text(_string(record, "severity")) or urgency,
        "status": _string(record, "status") or "new",
        "owner": _string(record, "owner") or "unassigned",
        "disposition": normalize_disposition(_pick(record, "disposition")),
        "risk_score": to_float(_pick(record, "risk_score"), 0.0),
        "confidence": to_float(_pick(record, "confidence"), 0.0),
        "impact": to_float(_pick(record, "impact"), 0.0),
        "rule_name": _string(record, "rule_name"),
        "detection_id": _string(record, "detection_id"),
        "asset_priority": lower_text(_string(record, "asset_priority")),
        "identity_priority": lower_text(_string(record, "identity_priority")),
        "create_time": create_time,
        "update_time": update_time,
        "earliest": earliest,
        "latest": latest,
        "index": _string(record, "index") or "notable",
        "orig_sid": _string(record, "orig_sid"),
        "notes": as_list(record.get("notes")),
        "related_finding_count": int(to_float(record.get("related_finding_count"), 0)),
        "mitre_tactics": annotations["mitre_tactics"],
        "mitre_techniques": annotations["mitre_techniques"],
        "kill_chain_phases": annotations["kill_chain_phases"],
        "analytic_stories": annotations["analytic_stories"],
        "triage": normalize_triage(record),
    }
    finding.update(entities)
    return finding
