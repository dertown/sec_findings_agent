"""Persist agent results to the app KV store using the Splunk session."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


class KvPersister:
    def __init__(self, splunkd_uri: str, session_key: str, collection: str = "finding_evidence_scores", app: str = "es_finding_evidence"):
        self.base = splunkd_uri.rstrip("/")
        self.session_key = session_key
        self.collection = collection
        self.app = app
        host = urllib.parse.urlparse(self.base).hostname or ""
        if host in {"127.0.0.1", "localhost", "::1"}:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context()

    def __call__(self, rows: list[dict[str, Any]]) -> None:
        for row in rows:
            key = urllib.parse.quote(str(row.get("finding_id") or ""), safe="")
            if not key:
                continue
            payload = _kv_fields(row)
            data = json.dumps(payload).encode("utf-8")
            path = f"/servicesNS/nobody/{self.app}/storage/collections/data/{self.collection}/{key}"
            request = urllib.request.Request(
                self.base + path,
                data=data,
                method="POST",
                headers={
                    "Authorization": f"Splunk {self.session_key}",
                    "Content-Type": "application/json",
                },
            )
            try:
                urllib.request.urlopen(request, timeout=20, context=self.ssl_context).read()
            except urllib.error.HTTPError:
                # Insert if update-by-key is not supported on this collection.
                create = urllib.request.Request(
                    self.base + f"/servicesNS/nobody/{self.app}/storage/collections/data/{self.collection}",
                    data=data,
                    method="POST",
                    headers={
                        "Authorization": f"Splunk {self.session_key}",
                        "Content-Type": "application/json",
                    },
                )
                urllib.request.urlopen(create, timeout=20, context=self.ssl_context).read()


def _kv_fields(row: Mapping[str, Any]) -> dict[str, Any]:
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
    )
    out = {key: row.get(key) for key in keep if key in row}
    out["_key"] = str(row.get("finding_id") or "")
    return out
