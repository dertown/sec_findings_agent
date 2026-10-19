"""Resolve the app home and allowlisted judge directories."""

from __future__ import annotations

import os

APP_ID = "es_finding_evidence"


def app_home(explicit: str | None = None) -> str:
    if explicit:
        return os.path.realpath(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.realpath(os.path.join(here, "..", ".."))
    splunk_home = os.environ.get("SPLUNK_HOME")
    if splunk_home:
        installed = os.path.realpath(os.path.join(splunk_home, "etc", "apps", APP_ID))
        if os.path.isdir(installed):
            return installed
    return bundled


def judge_roots(home: str | None = None) -> list[str]:
    root = app_home(home)
    return [
        os.path.join(root, "local", "judges"),
        os.path.join(root, "judges"),
        os.path.join(root, "bin", "judges"),
    ]


def conf_paths(name: str, home: str | None = None) -> list[str]:
    root = app_home(home)
    return [
        os.path.join(root, "default", name),
        os.path.join(root, "local", name),
    ]


def safe_py_path(path: str, roots: list[str]) -> str:
    """Return a real path only if it is a .py file under an allowlisted root."""
    if os.path.isabs(path):
        candidate = os.path.realpath(path)
    else:
        candidate = ""
        for root in roots:
            trial = os.path.realpath(os.path.join(root, path))
            if os.path.isfile(trial):
                candidate = trial
                break
            trial = os.path.realpath(os.path.join(os.path.dirname(root), path))
            if os.path.isfile(trial):
                candidate = trial
                break
        if not candidate:
            raise ValueError(f"judge file not found: {path}")
    if not candidate.endswith(".py"):
        raise ValueError("custom judges must be .py files")
    allowed = False
    for root in roots:
        real_root = os.path.realpath(root)
        if candidate == real_root or candidate.startswith(real_root + os.sep):
            allowed = True
            break
    if not allowed:
        raise ValueError("custom judge files must live under the app judges directories")
    if not os.path.isfile(candidate):
        raise ValueError(f"judge file not found: {path}")
    return candidate
