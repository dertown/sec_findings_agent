"""Load judges from judges.conf and local/judges/*.py.

Only Python files under the app's judges directories are importable. There is
no eval() of configuration values and no loading from arbitrary filesystem
paths — that keeps custom judges as admin-shipped code.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any, Callable

from ..confparse import as_bool, as_float, load_conf_files
from ..paths import app_home, conf_paths, judge_roots, safe_py_path
from .base import JudgeResult, coerce_result
from .builtin import BUILTIN
from .rules import RuleJudge


class LoadedJudge:
    def __init__(self, name: str, impl: Any, weight: float, mode: str, kind: str, enabled: bool = True):
        self.name = name
        self.impl = impl
        self.weight = weight
        self.mode = mode
        self.kind = kind
        self.enabled = enabled
        if hasattr(impl, "weight"):
            impl.weight = weight
        if hasattr(impl, "mode"):
            impl.mode = mode
        if hasattr(impl, "name") and not getattr(impl, "name", None):
            impl.name = name

    def judge(self, finding, context) -> JudgeResult:
        if not self.enabled:
            return JudgeResult(name=self.name, abstain=True, rationale="disabled")
        try:
            raw = self.impl.judge(finding, context)
        except Exception as exc:  # noqa: BLE001 - isolate a bad custom judge
            return JudgeResult(name=self.name, abstain=True, error=str(exc), weight=self.weight, mode=self.mode)
        return coerce_result(self.name, raw, weight=self.weight, mode=self.mode)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "weight": self.weight,
            "mode": self.mode,
            "enabled": self.enabled,
        }


class FunctionJudge:
    def __init__(self, name: str, fn: Callable, weight: float, mode: str):
        self.name = name
        self.fn = fn
        self.weight = weight
        self.mode = mode

    def judge(self, finding, context):
        return self.fn(
            finding,
            context.get("evidence") or [],
            context.get("searches") or [],
            context,
        )


def load_judges(home: str | None = None, conf_text: str | None = None) -> list[LoadedJudge]:
    root = app_home(home)
    if conf_text is not None:
        from ..confparse import parse_conf

        stanzas = parse_conf(conf_text)
    else:
        stanzas = load_conf_files(conf_paths("judges.conf", root))
    roots = judge_roots(root)
    loaded: list[LoadedJudge] = []
    seen = set()
    for name, stanza in stanzas.items():
        if name in {"default", ""}:
            continue
        enabled = as_bool(stanza.get("enabled", "1"), True)
        kind = (stanza.get("type") or "builtin").lower()
        weight = as_float(stanza.get("weight"), 1.0)
        mode = stanza.get("mode") or "vote"
        impl: Any
        if kind in {"builtin", "class"}:
            key = stanza.get("class") or stanza.get("function") or name
            cls = BUILTIN.get(key)
            if cls is None:
                continue
            impl = cls()
        elif kind == "rule":
            impl = RuleJudge(name, stanza)
        elif kind == "python":
            rel = stanza.get("file") or stanza.get("path") or f"{name}.py"
            fn_name = stanza.get("function") or "judge"
            try:
                path = safe_py_path(rel, roots)
            except ValueError as exc:
                loaded.append(
                    LoadedJudge(name, _ErrorJudge(name, str(exc)), weight, mode, "python", enabled=False)
                )
                seen.add(name)
                continue
            fn = _load_function(path, fn_name)
            impl = FunctionJudge(name, fn, weight, mode)
        else:
            continue
        loaded.append(LoadedJudge(name, impl, weight, mode, kind, enabled=enabled))
        seen.add(name)

    if as_bool(stanzas.get("default", {}).get("auto_load_local", "1"), True):
        local_dir = os.path.join(root, "local", "judges")
        if os.path.isdir(local_dir):
            for filename in sorted(os.listdir(local_dir)):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                name = filename[:-3]
                if name in seen:
                    continue
                path = safe_py_path(filename, [local_dir])
                try:
                    fn = _load_function(path, "judge")
                except Exception as exc:  # noqa: BLE001
                    loaded.append(LoadedJudge(name, _ErrorJudge(name, str(exc)), 1.0, "vote", "python", enabled=False))
                    continue
                loaded.append(LoadedJudge(name, FunctionJudge(name, fn, 1.0, "vote"), 1.0, "vote", "python", True))
    return loaded


def _load_function(path: str, function_name: str) -> Callable:
    mod_name = f"fea_custom_judge_{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import judge {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    fn = getattr(module, function_name, None)
    if not callable(fn):
        raise ValueError(f"{path} has no callable {function_name}()")
    return fn


class _ErrorJudge:
    def __init__(self, name: str, error: str):
        self.name = name
        self.error = error
        self.weight = 0
        self.mode = "vote"

    def judge(self, finding, context):
        return JudgeResult(name=self.name, abstain=True, error=self.error)


def describe_judges(home: str | None = None) -> list[dict[str, Any]]:
    return [item.as_dict() for item in load_judges(home)]
