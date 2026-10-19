"""KV store helpers using the Splunk session. No stored credentials."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


class KvCollection:
    def __init__(self, splunkd_uri: str, session_key: str, collection: str, app: str = "es_finding_evidence"):
        if not session_key:
            raise RuntimeError("Missing Splunk session key; cannot use KV store.")
        self.base = splunkd_uri.rstrip("/")
        self.session_key = session_key
        self.collection = collection
        self.app = app
        host = urllib.parse.urlparse(self.base).hostname or ""
        if host in {"127.0.0.1", "localhost", "::1"}:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context()

    def _url(self, key: str = "") -> str:
        path = f"/servicesNS/nobody/{self.app}/storage/collections/data/{self.collection}"
        if key:
            path += "/" + urllib.parse.quote(key, safe="")
        return self.base + path

    def _request(self, method: str, url: str, payload: Mapping[str, Any] | None = None) -> Any:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Splunk {self.session_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"KV {method} {self.collection} failed: {exc.code} {body}") from exc
        if not raw:
            return None
        return json.loads(raw)

    def list(self) -> list[dict[str, Any]]:
        url = self._url() + "?output_mode=json"
        payload = self._request("GET", url)
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        return []

    def put(self, key: str, record: Mapping[str, Any]) -> None:
        body = dict(record)
        body["_key"] = key
        try:
            self._request("POST", self._url(key), body)
        except RuntimeError:
            self._request("POST", self._url(), body)

    def delete(self, key: str) -> None:
        self._request("DELETE", self._url(key))


class KvPersister:
    def __init__(self, splunkd_uri: str, session_key: str, collection: str = "finding_evidence_scores", app: str = "es_finding_evidence"):
        self.col = KvCollection(splunkd_uri, session_key, collection, app)

    def __call__(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            key = str(row.get("finding_id") or "")
            if not key:
                continue
            self.col.put(key, _score_fields(row))


def _score_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    keep = (
        "finding_id",
        "title",
        "urgency",
        "status",
        "owner",
        "disposition",
        "risk_score",
        "user",
        "src",
        "dest",
        "triage_present",
        "triage_disposition",
        "triage_summary",
        "triage_confidence",
        "followup_score",
        "followup_score_ceiling",
        "investigation_required",
        "investigation_label",
        "evidence_net_weight",
        "recommended_search_count",
        "evidence_count",
        "rationale",
        "_time",
        "executed_search_count",
        "override_applied",
        "agent_tasks",
        "judges_json",
        "enrichment_posted",
        "enrichment_error",
        "executed_searches_json",
        "recommended_searches_json",
        "evidence_json",
    )
    return {key: row.get(key) for key in keep if key in row}
