"""Create/update/delete UI judges. Rule judges live in KV; Python judges are
written only under the app local/judges directory after name and source checks.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Mapping

from .judges.loader import LoadedJudge, FunctionJudge, load_judges
from .judges.rules import RuleJudge
from .paths import app_home, judge_roots, safe_py_path

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,40}$")
FORBIDDEN_RE = re.compile(
    r"\b(subprocess|pickle|ctypes|importlib|socket|shutil|pathlib|urllib|requests|multiprocessing)\b"
    r"|http\.client"
    r"|\beval\s*\(|\bexec\s*\(|__import__"
    r"|os\.system|os\.popen|\bopen\s*\("
    r"|\bimport\s+os\b|\bfrom\s+os\b|\bimport\s+sys\b|\bfrom\s+sys\b"
)


def sanitize_name(name: str) -> str:
    text = (name or "").strip()
    if not NAME_RE.match(text):
        raise ValueError("Judge name must be letters, numbers, underscore, and start with a letter.")
    return text


def validate_python(source: str) -> str:
    text = (source or "").replace("\r\n", "\n")
    if "def judge(" not in text:
        raise ValueError("Python judges must define def judge(finding, evidence, searches, context).")
    match = FORBIDDEN_RE.search(text)
    if match:
        raise ValueError(f"Python judge may not use '{match.group(0).strip()}'.")
    if len(text) > 20000:
        raise ValueError("Python judge is too large.")
    return text


def record_from_payload(payload: Mapping[str, Any], existing: Mapping[str, Any] | None = None) -> dict[str, Any]:
    name = sanitize_name(str(payload.get("name") or (existing or {}).get("name") or ""))
    kind = str(payload.get("type") or payload.get("kind") or (existing or {}).get("type") or "rule").lower()
    if kind not in {"rule", "python"}:
        raise ValueError("UI judges must be type=rule or type=python.")
    record = dict(existing or {})
    record.update(
        {
            "name": name,
            "type": kind,
            "enabled": 1 if str(payload.get("enabled", record.get("enabled", 1))).lower() in {"1", "true", "yes", "on"} else 0,
            "weight": float(payload.get("weight", record.get("weight", 1.0))),
            "mode": str(payload.get("mode") or record.get("mode") or "vote"),
            "source": "ui",
            "updated": time.time(),
            "rationale": str(payload.get("rationale") or record.get("rationale") or ""),
            "decision": str(payload.get("decision") or record.get("decision") or ""),
            "score": payload.get("score", record.get("score") or ""),
            "adjustment": payload.get("adjustment", record.get("adjustment") or 0),
            "confidence": payload.get("confidence", record.get("confidence") or 0.8),
        }
    )
    for key in (
        "when_urgency",
        "when_status",
        "when_disposition",
        "when_triage_disposition",
        "when_asset_priority",
        "when_identity_priority",
        "when_min_risk",
        "when_title_contains",
        "when_user_in",
    ):
        if key in payload or key in record:
            record[key] = str(payload.get(key, record.get(key) or ""))
    if kind == "python":
        source = payload.get("python") or payload.get("source_code") or record.get("python") or ""
        record["python"] = validate_python(str(source))
        record["file"] = f"{name}.py"
        record["function"] = "judge"
    return record


def write_python_file(record: Mapping[str, Any], home: str | None = None) -> str:
    root = app_home(home)
    local_dir = os.path.join(root, "local", "judges")
    os.makedirs(local_dir, exist_ok=True)
    name = sanitize_name(str(record["name"]))
    allowed_root = os.path.realpath(local_dir)
    dest = os.path.realpath(os.path.join(local_dir, f"{name}.py"))
    if dest != allowed_root and not dest.startswith(allowed_root + os.sep):
        raise ValueError("refusing to write judge outside local/judges")
    with open(dest, "w", encoding="utf-8") as handle:
        handle.write(str(record.get("python") or ""))
        if not str(record.get("python") or "").endswith("\n"):
            handle.write("\n")
    return dest


def delete_python_file(name: str, home: str | None = None) -> None:
    root = app_home(home)
    local_dir = os.path.join(root, "local", "judges")
    path = os.path.join(local_dir, f"{sanitize_name(name)}.py")
    real = os.path.realpath(path)
    if real.startswith(os.path.realpath(local_dir) + os.sep) and os.path.isfile(real):
        os.remove(real)


def loaded_from_record(record: Mapping[str, Any]) -> LoadedJudge:
    name = str(record.get("name"))
    kind = str(record.get("type") or "rule")
    weight = float(record.get("weight") or 1.0)
    mode = str(record.get("mode") or "vote")
    enabled = str(record.get("enabled", 1)).lower() in {"1", "true", "yes", "on"}
    if kind == "python":
        # File should already be on disk; FunctionJudge is attached by loader.
        impl = RuleJudge(name, {**record, "type": "rule"})  # placeholder replaced by file load
        return LoadedJudge(name, impl, weight, mode, "python", enabled)
    impl = RuleJudge(name, {k: str(v) for k, v in record.items() if v not in (None, "")})
    return LoadedJudge(name, impl, weight, mode, "rule", enabled)


def merge_kv_judges(base: list[LoadedJudge], records: list[Mapping[str, Any]], home: str | None = None) -> list[LoadedJudge]:
    """Overlay UI/KV judges on top of conf judges (UI wins on the same name)."""
    by_name = {item.name: item for item in base}
    roots = judge_roots(home)
    local_dir = os.path.join(app_home(home), "local", "judges")
    for record in records:
        name = str(record.get("name") or "")
        if not name:
            continue
        kind = str(record.get("type") or "rule")
        weight = float(record.get("weight") or 1.0)
        mode = str(record.get("mode") or "vote")
        enabled = str(record.get("enabled", 1)).lower() in {"1", "true", "yes", "on"}
        if kind == "python":
            try:
                if record.get("python") and not os.path.isfile(os.path.join(local_dir, f"{name}.py")):
                    write_python_file(record, home)
                path = safe_py_path(f"{name}.py", [local_dir] + roots)
                from .judges.loader import _load_function

                fn = _load_function(path, str(record.get("function") or "judge"))
                impl: Any = FunctionJudge(name, fn, weight, mode)
            except Exception as exc:  # noqa: BLE001
                from .judges.loader import _ErrorJudge

                impl = _ErrorJudge(name, str(exc))
                enabled = False
            by_name[name] = LoadedJudge(name, impl, weight, mode, "python", enabled)
        else:
            impl = RuleJudge(name, {k: str(v) for k, v in record.items() if v not in (None, "")})
            by_name[name] = LoadedJudge(name, impl, weight, mode, "rule", enabled)
        by_name[name].source = "ui"  # type: ignore[attr-defined]
    return list(by_name.values())


def describe_all(home: str | None = None, kv_records: list[Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    loaded = load_judges(home)
    if kv_records:
        loaded = merge_kv_judges(loaded, kv_records, home)
    kv_names = {str(r.get("name")) for r in (kv_records or [])}
    rows = []
    for item in loaded:
        row = item.as_dict()
        row["source"] = "ui" if item.name in kv_names else ("builtin" if item.kind == "builtin" else "conf")
        row["editable"] = item.name in kv_names or item.kind in {"rule", "python"} and row["source"] == "ui"
        if item.name in kv_names:
            match = next(r for r in kv_records or [] if r.get("name") == item.name)
            row.update({k: match.get(k) for k in match if k not in row})
            row["editable"] = True
            row["source"] = "ui"
        rows.append(row)
    return rows
