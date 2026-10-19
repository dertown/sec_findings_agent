"""Execute recommended SPL on the search head using the Splunk session.

No stored credentials. Jobs go to local splunkd with Authorization: Splunk <session>.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Protocol


class SearchRunner(Protocol):
    def run(self, spl: str, *, timeout: int = 30, max_count: int = 100) -> dict[str, Any]:
        ...


class NullSearchRunner:
    """Used in tests / when run_searches is false."""

    def run(self, spl: str, *, timeout: int = 30, max_count: int = 100) -> dict[str, Any]:
        return {"count": 0, "results": [], "skipped": True, "summary": "searches disabled"}


class DemoSearchRunner:
    """Deterministic hits so the backend agent can be exercised without a search head."""

    def __init__(self, finding: Mapping[str, Any] | None = None):
        self.finding = dict(finding or {})

    def run(self, spl: str, *, timeout: int = 30, max_count: int = 100) -> dict[str, Any]:
        finding_id = str(self.finding.get("finding_id") or "")
        hay = spl.lower()
        # High-fidelity true positives: process / hash / C2 searches hit.
        if finding_id in {"F-1001", "F-1002", "F-1004", "F-1006", "F-1008", "F-1011"}:
            count = 18 if "process" in hay or "hash" in hay or "dest" in hay else 7
            return {"count": count, "results": [{"count": count}], "summary": f"demo hits={count}"}
        if finding_id in {"F-1003", "F-1005", "F-1010"}:
            return {"count": 0, "results": [], "summary": "demo: sanctioned/allowlisted, no suspicious hits"}
        return {"count": 2, "results": [{"count": 2}], "summary": "demo: weak hits"}


class SplunkSearchRunner:
    def __init__(self, splunkd_uri: str, session_key: str, timeout: int = 30, owner: str = "nobody", app: str = "es_finding_evidence"):
        if not session_key:
            raise RuntimeError("Missing Splunk session key; cannot run searches.")
        self.base = splunkd_uri.rstrip("/")
        self.session_key = session_key
        self.timeout = timeout
        self.owner = owner
        self.app = app
        host = urllib.parse.urlparse(self.base).hostname or ""
        if host in {"127.0.0.1", "localhost", "::1"}:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context()

    def run(self, spl: str, *, timeout: int = 30, max_count: int = 100) -> dict[str, Any]:
        search = spl.strip()
        if not search:
            return {"count": 0, "results": [], "error": "empty search"}
        if not search.startswith("|") and not search.lower().startswith("search "):
            search = "search " + search
        # Cap work: oneshot + max_count. Never pass user-supplied URLs.
        data = urllib.parse.urlencode(
            {
                "search": search,
                "output_mode": "json",
                "exec_mode": "oneshot",
                "count": str(max_count),
                "adhoc_search_level": "fast",
            }
        ).encode("utf-8")
        path = f"/servicesNS/{urllib.parse.quote(self.owner)}/{urllib.parse.quote(self.app)}/search/jobs"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={
                "Authorization": f"Splunk {self.session_key}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        started = time.time()
        try:
            with urllib.request.urlopen(request, timeout=min(timeout, self.timeout), context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:400]
            return {"count": 0, "results": [], "error": f"search HTTP {exc.code}: {body}"}
        except urllib.error.URLError as exc:
            return {"count": 0, "results": [], "error": f"search unreachable: {exc}"}
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {"count": 0, "results": [], "error": "search returned non-JSON"}
        results = payload.get("results") if isinstance(payload, dict) else []
        if not isinstance(results, list):
            results = []
        elapsed = round(time.time() - started, 2)
        return {
            "count": len(results),
            "results": results[: max_count],
            "summary": f"{len(results)} events in {elapsed}s",
            "elapsed": elapsed,
        }
