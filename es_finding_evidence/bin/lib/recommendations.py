"""Generate evidence-gathering SPL from a canonical finding."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .constants import DEFAULT_WINDOW_MINUTES, SOURCE_RELIABILITY
from .templates import SEARCH_TEMPLATES
from .util import epoch_to_splunk, sha256_id, unique

_PLACEHOLDER = re.compile(r"\$([a-zA-Z0-9_]+)\$")


def _has_value(finding: Mapping[str, Any], field: str) -> bool:
    value = finding.get(field)
    if value is None:
        return False
    if isinstance(value, (list, tuple)):
        return any(str(v).strip() for v in value)
    return str(value).strip() not in {"", "none", "null", "*"}


def _mitre_hit(template_mitre: Sequence[str], finding: Mapping[str, Any]) -> bool:
    if not template_mitre:
        return True
    haystack = " ".join(
        unique(
            list(finding.get("mitre_techniques") or [])
            + list(finding.get("mitre_tactics") or [])
            + [str(finding.get("title") or ""), str(finding.get("rule_name") or "")]
        )
    ).lower()
    return any(token.lower() in haystack for token in template_mitre)


def _substitute(spl: str, values: Mapping[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        return values.get(key, "")

    return _PLACEHOLDER.sub(repl, spl)


def _safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace('"', "").replace("\n", " ").replace("|", " ").strip()


def build_placeholder_values(finding: Mapping[str, Any], window_minutes: int = DEFAULT_WINDOW_MINUTES) -> dict[str, str]:
    earliest = finding.get("earliest")
    latest = finding.get("latest")
    values = {
        "finding_id": _safe(finding.get("finding_id")),
        "user": _safe(finding.get("user")),
        "src": _safe(finding.get("src") or finding.get("src_ip") or finding.get("dvc")),
        "dest": _safe(finding.get("dest") or finding.get("dest_ip")),
        "src_ip": _safe(finding.get("src_ip") or finding.get("src")),
        "dest_ip": _safe(finding.get("dest_ip") or finding.get("dest")),
        "dvc": _safe(finding.get("dvc")),
        "url": _safe(finding.get("url")),
        "domain": _safe(finding.get("domain")),
        "file_hash": _safe(finding.get("file_hash")),
        "file_name": _safe(finding.get("file_name")),
        "process": _safe(finding.get("process")),
        "threat_object": _safe(finding.get("threat_object")),
        "risk_object": _safe(finding.get("risk_object")),
        "earliest": epoch_to_splunk(earliest) if earliest else f"-{window_minutes}m",
        "latest": epoch_to_splunk(latest) if latest else "now",
        "window_minutes": str(window_minutes),
    }
    return values


def recommend_searches(
    finding: Mapping[str, Any],
    templates: Sequence[Mapping[str, Any]] | None = None,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    max_searches: int = 12,
) -> list[dict[str, Any]]:
    templates = list(templates or SEARCH_TEMPLATES)
    values = build_placeholder_values(finding, window_minutes)
    finding_id = str(finding.get("finding_id") or "")
    recos: list[dict[str, Any]] = []
    for template in templates:
        requires = template.get("requires") or []
        if isinstance(requires, str):
            requires = [part for part in requires.split(";") if part]
        if requires and not all(_has_value(finding, field) or _has_value(values, field) for field in requires):
            continue
        mitre = template.get("mitre") or []
        if isinstance(mitre, str):
            mitre = [part for part in mitre.split(";") if part]
        # Always keep generic (no MITRE) templates; MITRE-tagged ones still apply
        # when the technique is unknown so analysts are not starved of searches.
        mitre_matched = _mitre_hit(mitre, finding) if mitre else True
        spl = _substitute(str(template.get("spl") or ""), values)
        if "$" in spl and re.search(r"\$[a-zA-Z0-9_]+\$", spl):
            # Drop leftover required placeholders; keep optional empty IN-lists.
            leftover = set(_PLACEHOLDER.findall(spl))
            required_placeholders = set(requires)
            if leftover & required_placeholders:
                continue
        potential = float(template.get("base_weight") or 40)
        recos.append(
            {
                "evidence_id": sha256_id(finding_id, template.get("template_id"), "search"),
                "template_id": template.get("template_id"),
                "search_name": template.get("name"),
                "title": template.get("name"),
                "purpose": template.get("purpose"),
                "category": template.get("category"),
                "class": template.get("evidence_class"),
                "direction": template.get("direction") or "supporting",
                "source": "recommended_search",
                "base_weight": potential,
                "potential_weight": potential,
                "confidence": 0.0,
                "reliability": SOURCE_RELIABILITY["recommended_search"],
                "weight": 0.0,
                "signed_weight": 0.0,
                "priority": int(template.get("priority") or 50),
                "mitre_matched": mitre_matched,
                "search": spl,
                "detail": template.get("purpose"),
            }
        )
    recos.sort(key=lambda row: (0 if row["mitre_matched"] else 1, row["priority"], -row["potential_weight"]))
    # Always include at least a few generic searches even when MITRE did not match.
    selected: list[dict[str, Any]] = []
    for row in recos:
        if len(selected) >= max_searches:
            break
        selected.append(row)
    return selected
