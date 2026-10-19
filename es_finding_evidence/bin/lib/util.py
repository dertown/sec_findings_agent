"""Helpers: field picking, JSON, hashing, time, clamping."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

_DISPOSITION_PATTERNS = (
    ("true_positive", re.compile(r"true\s*positive|suspicious activity|\btp\b", re.I)),
    ("false_positive", re.compile(r"false\s*positive|incorrect analytic|inaccurate data|\bfp\b", re.I)),
    ("benign_positive", re.compile(r"benign|suspicious but expected|expected activity", re.I)),
    ("testing", re.compile(r"\btesting\b", re.I)),
    ("undetermined", re.compile(r"undetermined|unknown|n/?a", re.I)),
    ("other", re.compile(r"\bother\b", re.I)),
)


def first_value(record: Mapping[str, Any], names: Sequence[str], default: Any = None) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
        lower = name.lower()
        for key, value in record.items():
            if str(key).lower() == lower and value not in (None, ""):
                return value
    return default


def as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [v for v in value if v not in (None, "")]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("[") or text.startswith("{"):
            parsed = try_json(text)
            if isinstance(parsed, list):
                return [v for v in parsed if v not in (None, "")]
            if parsed is not None:
                return [parsed]
        if "\n" in text:
            return [part.strip() for part in text.splitlines() if part.strip()]
        if "," in text and not text.startswith("http"):
            return [part.strip() for part in text.split(",") if part.strip()]
        return [text]
    return [value]


def try_json(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"), ensure_ascii=True)


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return float(value)


def to_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_epoch(value: Any) -> float | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        # Splunk sometimes stores epoch millis.
        number = float(value)
        if number > 10_000_000_000:
            return number / 1000.0
        return number
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
        if number > 10_000_000_000:
            return number / 1000.0
        if number > 1_000_000_000:
            return number
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(text.replace("Z", "+0000") if fmt.endswith("%z") and text.endswith("Z") else text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    return None


def epoch_to_splunk(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%m/%d/%Y:%H:%M:%S")


def sha256_id(*parts: Any) -> str:
    material = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def lower_text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def normalize_disposition(value: Any) -> str:
    text = lower_text(value)
    if not text:
        return "undetermined"
    for name, pattern in _DISPOSITION_PATTERNS:
        if pattern.search(text):
            return name
    return "undetermined"


def flatten_annotations(record: Mapping[str, Any]) -> dict[str, list[str]]:
    """Pull MITRE / story annotations from nested ES structures."""
    result = {
        "mitre_tactics": [],
        "mitre_techniques": [],
        "kill_chain_phases": [],
        "analytic_stories": [],
        "cis20": [],
        "nist": [],
    }
    annotations = record.get("annotations")
    parsed = try_json(annotations) if not isinstance(annotations, dict) else annotations
    blobs: list[Any] = [record]
    if isinstance(parsed, dict):
        blobs.append(parsed)
        mitre = parsed.get("mitre_attack")
        if isinstance(mitre, dict):
            blobs.append(mitre)

    def collect(keys: Iterable[str]) -> list[str]:
        found: list[str] = []
        for blob in blobs:
            if not isinstance(blob, Mapping):
                continue
            for key in keys:
                found.extend(str(v) for v in as_list(blob.get(key)))
        # Also check dotted keys on the original record.
        return found

    result["mitre_tactics"] = unique(
        collect(
            (
                "mitre_tactic",
                "mitre_tactics",
                "annotations.mitre_attack.mitre_tactic",
            )
        )
        + as_list(record.get("mitre_tactic"))
        + as_list(record.get("mitre_tactics"))
    )
    result["mitre_techniques"] = unique(
        collect(("mitre_technique", "mitre_techniques", "mitre_attack", "technique"))
        + as_list(record.get("mitre_technique"))
        + as_list(record.get("mitre_techniques"))
        + as_list(record.get("annotations.mitre_attack"))
    )
    result["kill_chain_phases"] = unique(
        collect(("kill_chain_phases", "kill_chain_phase"))
        + as_list(record.get("kill_chain_phases"))
    )
    result["analytic_stories"] = unique(
        collect(("analytic_story", "analytic_stories"))
        + as_list(record.get("analytic_story"))
    )
    return result


def unique(values: Iterable[Any]) -> list[str]:
    seen = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def looks_like_ip(value: str) -> bool:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return True
    if ":" in value and re.search(r"[0-9a-fA-F]:", value):
        return True
    return False


def looks_like_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value or ""))
