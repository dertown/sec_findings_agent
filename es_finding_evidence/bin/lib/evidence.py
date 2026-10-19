"""Build weighted evidence items from a finding and its triage enrichment."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .constants import DISPOSITION_SCORE, SOURCE_RELIABILITY
from .util import clamp, lower_text, sha256_id, to_float

_MALICIOUS_TOOL = re.compile(
    r"\b(malicious|malware|suspicious|blocklisted|denylisted|blacklisted|bad reputation|\btor\b|\bc2\b)\b",
    re.I,
)
_CLEAN_TOOL = re.compile(
    r"\b(clean|benign|unlisted|good reputation|allowlisted|allow-?listed|whitelisted|sanctioned)\b",
    re.I,
)

# Base magnitude 0-100. Sign is applied from direction.
EVIDENCE_CLASSES = {
    "threat_intel_match": {"weight": 90, "source": "threat_intel", "direction": "supporting"},
    "malware_hash": {"weight": 95, "source": "threat_intel", "direction": "supporting"},
    "c2_beacon": {"weight": 88, "source": "finding_metadata", "direction": "supporting"},
    "credential_access": {"weight": 84, "source": "finding_metadata", "direction": "supporting"},
    "lateral_movement": {"weight": 82, "source": "finding_metadata", "direction": "supporting"},
    "privileged_account": {"weight": 80, "source": "asset_identity", "direction": "supporting"},
    "critical_asset": {"weight": 78, "source": "asset_identity", "direction": "supporting"},
    "exfiltration": {"weight": 90, "source": "finding_metadata", "direction": "supporting"},
    "related_findings": {"weight": 70, "source": "related_findings", "direction": "supporting"},
    "high_risk_score": {"weight": 72, "source": "finding_metadata", "direction": "supporting"},
    "high_urgency": {"weight": 68, "source": "finding_metadata", "direction": "supporting"},
    "triage_true_positive": {"weight": 86, "source": "triage_agent", "direction": "supporting"},
    "triage_false_positive": {"weight": 70, "source": "triage_agent", "direction": "refuting"},
    "triage_benign": {"weight": 62, "source": "triage_agent", "direction": "refuting"},
    "triage_evidence": {"weight": 58, "source": "triage_agent", "direction": "supporting"},
    "triage_narrative": {"weight": 48, "source": "triage_agent", "direction": "supporting"},
    "soar_malicious": {"weight": 82, "source": "soar_connector", "direction": "supporting"},
    "soar_clean": {"weight": 55, "source": "soar_connector", "direction": "refuting"},
    "known_scanner": {"weight": 60, "source": "finding_metadata", "direction": "refuting"},
    "sanctioned_admin": {"weight": 52, "source": "finding_metadata", "direction": "refuting"},
    "low_confidence_detection": {"weight": 28, "source": "finding_metadata", "direction": "refuting"},
}


def _item(
    finding_id: str,
    evidence_class: str,
    title: str,
    detail: str,
    *,
    direction: str | None = None,
    source: str | None = None,
    weight: float | None = None,
    confidence: float = 0.8,
    search: str | None = None,
    search_name: str | None = None,
    priority: int = 50,
) -> dict[str, Any]:
    meta = EVIDENCE_CLASSES.get(evidence_class, {})
    direction = direction or meta.get("direction") or "supporting"
    source = source or meta.get("source") or "finding_metadata"
    base = float(weight if weight is not None else meta.get("weight", 40))
    reliability = SOURCE_RELIABILITY.get(source, 0.65)
    confidence = clamp(confidence, 0.0, 1.0)
    signed = base * confidence * reliability
    if direction == "refuting":
        signed = -signed
    return {
        "evidence_id": sha256_id(finding_id, evidence_class, title, detail[:80]),
        "class": evidence_class,
        "source": source,
        "title": title,
        "detail": detail,
        "direction": direction,
        "base_weight": round(base, 2),
        "confidence": round(confidence, 3),
        "reliability": reliability,
        "weight": round(abs(signed), 2),
        "signed_weight": round(signed, 2),
        "search": search,
        "search_name": search_name,
        "priority": priority,
    }


def _text_blob(finding: Mapping[str, Any]) -> str:
    triage = finding.get("triage") or {}
    parts = [
        finding.get("title"),
        finding.get("description"),
        finding.get("rule_name"),
        " ".join(finding.get("mitre_techniques") or []),
        " ".join(finding.get("mitre_tactics") or []),
        " ".join(finding.get("kill_chain_phases") or []),
        triage.get("summary"),
        triage.get("justification"),
        triage.get("analysis_details"),
    ]
    return " ".join(str(part or "") for part in parts).lower()


def collect_observed_evidence(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Evidence that already exists on the finding / triage agent output."""
    finding_id = str(finding.get("finding_id") or "")
    items: list[dict[str, Any]] = []
    blob = _text_blob(finding)
    urgency = lower_text(finding.get("urgency"))
    risk = to_float(finding.get("risk_score"))
    confidence = to_float(finding.get("confidence"))
    asset_priority = lower_text(finding.get("asset_priority"))
    identity_priority = lower_text(finding.get("identity_priority"))
    user = str(finding.get("user") or "")
    techniques = [lower_text(t) for t in (finding.get("mitre_techniques") or [])]
    phases = [lower_text(p) for p in (finding.get("kill_chain_phases") or [])]
    threat_type = lower_text(finding.get("threat_object_type"))
    threat_object = str(finding.get("threat_object") or "")

    if urgency in {"critical", "high"}:
        items.append(
            _item(
                finding_id,
                "high_urgency",
                f"Urgency is {urgency}",
                f"Enterprise Security assigned urgency={urgency}.",
                confidence=0.9 if urgency == "critical" else 0.75,
            )
        )
    if risk >= 80:
        items.append(
            _item(
                finding_id,
                "high_risk_score",
                f"Risk score {risk:.0f}",
                "Finding risk score is in the high range used by ES risk-based alerting.",
                confidence=min(1.0, risk / 100.0),
            )
        )
    if asset_priority in {"high", "critical"}:
        items.append(
            _item(
                finding_id,
                "critical_asset",
                f"Asset priority {asset_priority}",
                f"Impacted asset priority is {asset_priority}.",
                confidence=0.85,
            )
        )
    if identity_priority in {"high", "critical"} or lower_text(user) in {
        "administrator",
        "admin",
        "root",
        "domain admin",
        "svc-admin",
    }:
        items.append(
            _item(
                finding_id,
                "privileged_account",
                "Privileged or high-priority identity",
                f"Identity {user or identity_priority} looks privileged or high priority.",
                confidence=0.8,
            )
        )
    if threat_object and threat_type in {"hash", "sha256", "md5", "sha1", "file"}:
        items.append(
            _item(
                finding_id,
                "malware_hash",
                f"Threat object hash {threat_object[:12]}…",
                f"Finding includes file hash threat object {threat_object}.",
                confidence=0.9,
            )
        )
    elif threat_object:
        items.append(
            _item(
                finding_id,
                "threat_intel_match",
                f"Threat object {threat_object}",
                f"Threat object type={threat_type or 'unknown'} value={threat_object}.",
                confidence=0.82,
            )
        )

    if any("credential" in t or t.startswith("t1003") or t.startswith("t1110") for t in techniques) or "credential-access" in phases:
        items.append(
            _item(
                finding_id,
                "credential_access",
                "Credential-access behavior",
                "MITRE mapping indicates credential access.",
                confidence=0.78,
            )
        )
    if any(t.startswith("t1021") or "lateral" in t for t in techniques) or "lateral-movement" in phases:
        items.append(
            _item(
                finding_id,
                "lateral_movement",
                "Lateral-movement behavior",
                "MITRE mapping indicates lateral movement.",
                confidence=0.78,
            )
        )
    if any(t.startswith("t1071") or t.startswith("t1095") or "c2" in t or "command-and-control" in t for t in techniques) or "command-and-control" in phases:
        items.append(
            _item(
                finding_id,
                "c2_beacon",
                "Command-and-control indicators",
                "MITRE mapping indicates C2 or beaconing.",
                confidence=0.8,
            )
        )
    if any(t.startswith("t1048") or t.startswith("t1567") or "exfil" in t for t in techniques) or "exfiltration" in phases:
        items.append(
            _item(
                finding_id,
                "exfiltration",
                "Exfiltration indicators",
                "MITRE mapping indicates data exfiltration.",
                confidence=0.84,
            )
        )

    related = int(to_float(finding.get("related_finding_count"), 0))
    if related >= 2:
        items.append(
            _item(
                finding_id,
                "related_findings",
                f"{related} related findings",
                "Multiple findings involve the same entity in the window.",
                confidence=min(1.0, 0.5 + related / 10.0),
                weight=min(90, 50 + related * 8),
            )
        )

    if 0 < confidence < 40:
        items.append(
            _item(
                finding_id,
                "low_confidence_detection",
                "Detection confidence is low",
                f"Detection confidence={confidence:.0f} reduces follow-up pressure.",
                confidence=0.65,
            )
        )

    if any(token in blob for token in ("vulnerability scanner", "nessus", "qualys", "rapid7", "known scanner")):
        items.append(
            _item(
                finding_id,
                "known_scanner",
                "Known scanner or expected security tool",
                "Narrative matches sanctioned scanner / security-tool activity.",
                confidence=0.8,
            )
        )
    if any(token in blob for token in ("jump host", "psexec expected", "change window", "sanctioned admin")):
        items.append(
            _item(
                finding_id,
                "sanctioned_admin",
                "Sanctioned administrative activity",
                "Narrative matches expected admin / change-control activity.",
                confidence=0.75,
            )
        )

    triage = finding.get("triage") or {}
    if triage.get("present"):
        disp = triage.get("disposition")
        tconf = to_float(triage.get("confidence"), 0.7)
        if disp == "true_positive":
            items.append(
                _item(
                    finding_id,
                    "triage_true_positive",
                    "Triage agent recommends true positive",
                    triage.get("summary") or triage.get("justification") or "Agent disposition is true positive.",
                    confidence=tconf,
                )
            )
        elif disp == "false_positive":
            items.append(
                _item(
                    finding_id,
                    "triage_false_positive",
                    "Triage agent recommends false positive",
                    triage.get("summary") or triage.get("justification") or "Agent disposition is false positive.",
                    confidence=tconf,
                )
            )
        elif disp == "benign_positive":
            items.append(
                _item(
                    finding_id,
                    "triage_benign",
                    "Triage agent recommends benign positive",
                    triage.get("summary") or triage.get("justification") or "Agent disposition is benign positive.",
                    confidence=tconf,
                )
            )
        for ev in triage.get("evidence") or []:
            items.append(
                _item(
                    finding_id,
                    ev.get("class") or "triage_evidence",
                    ev.get("title") or "Triage evidence",
                    ev.get("detail") or "",
                    direction=ev.get("direction") or "supporting",
                    source="triage_agent",
                    weight=to_float(ev.get("weight"), EVIDENCE_CLASSES["triage_evidence"]["weight"]),
                    confidence=to_float(ev.get("confidence"), tconf),
                )
            )
        for tool in triage.get("tools") or []:
            result_text = f"{tool.get('name','')} {tool.get('result','')} {tool.get('detail','')}"
            clean = bool(_CLEAN_TOOL.search(result_text)) or "0/" in result_text.lower()
            malicious = bool(_MALICIOUS_TOOL.search(result_text)) and not clean
            if malicious:
                items.append(
                    _item(
                        finding_id,
                        "soar_malicious",
                        f"SOAR connector {tool.get('name')} flagged malicious",
                        tool.get("detail") or tool.get("result") or "",
                        confidence=0.8,
                    )
                )
            elif clean:
                items.append(
                    _item(
                        finding_id,
                        "soar_clean",
                        f"SOAR connector {tool.get('name')} returned clean",
                        tool.get("detail") or tool.get("result") or "",
                        confidence=0.7,
                    )
                )

    return items


def net_signed_weight(items: list[Mapping[str, Any]]) -> float:
    return sum(to_float(item.get("signed_weight")) for item in items if item.get("source") != "recommended_search")


def evidence_component_score(items: list[Mapping[str, Any]]) -> float:
    """Map signed evidence onto 0-100 with 50 as neutral (no observed evidence)."""
    net = net_signed_weight(items)
    # 100 evidence-points ≈ full swing. Soft-clamp with tanh-like rational function.
    scaled = net / (80.0 + abs(net) / 4.0)
    return clamp(50.0 + 50.0 * scaled)


def disposition_component(finding: Mapping[str, Any]) -> float:
    triage = finding.get("triage") or {}
    if triage.get("present"):
        base = DISPOSITION_SCORE.get(triage.get("disposition"), 50.0)
        conf = to_float(triage.get("confidence"), 0.7)
        return 50.0 + (base - 50.0) * clamp(conf, 0.0, 1.0)
    # Analyst disposition still counts if the agent has not run.
    return DISPOSITION_SCORE.get(finding.get("disposition"), 50.0)
