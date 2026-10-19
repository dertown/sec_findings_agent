"""Minimal Splunk .conf reader. No interpolation, no external includes."""

from __future__ import annotations

from typing import Any


def parse_conf(text: str) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    current = "default"
    stanzas[current] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            stanzas.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        stanzas[current][key.strip()] = value.strip()
    return stanzas


def load_conf_files(paths: list[str]) -> dict[str, dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                parsed = parse_conf(handle.read())
        except OSError:
            continue
        for name, stanza in parsed.items():
            merged.setdefault(name, {}).update(stanza)
    return merged


def as_bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default
