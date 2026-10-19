"""Read Splunk Enterprise Security findings and notes using the local session.

Authentication uses the Splunk search-command session key. No passwords or
API tokens are stored in the app.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

FINDINGS_PATH = "/servicesNS/nobody/missioncontrol/public/v2/findings"
FINDING_PATH = "/servicesNS/nobody/missioncontrol/public/v2/findings/{id}"
FINDING_NOTES_PATH = "/servicesNS/nobody/missioncontrol/public/v2/findings/{id}/notes"
INVESTIGATION_NOTES_PATH = "/servicesNS/nobody/missioncontrol/public/v2/investigations/{id}/notes"


class ESClientError(RuntimeError):
    pass


class ESClient:
    def __init__(self, splunkd_uri: str, session_key: str, timeout: int = 30):
        if not session_key:
            raise ESClientError("Missing Splunk session key; cannot call Enterprise Security.")
        self.base = splunkd_uri.rstrip("/")
        self.session_key = session_key
        self.timeout = timeout
        host = urllib.parse.urlparse(self.base).hostname or ""
        # Search-head-local splunkd uses the instance certificate on 8089.
        # Only skip verification for loopback; verify everything else.
        if host in {"127.0.0.1", "localhost", "::1"}:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context()

    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        query = dict(params or {})
        query.setdefault("output_mode", "json")
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Splunk {self.session_key}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise ESClientError(f"ES API {exc.code} for {path}: {body}") from exc
        except urllib.error.URLError as exc:
            raise ESClientError(f"ES API unreachable at {url}: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ESClientError(f"ES API returned non-JSON for {path}") from exc

    def get_findings(
        self,
        *,
        finding_ids: str = "",
        urgency: str = "",
        status: str = "",
        owner: str = "",
        disposition: str = "",
        rule_title: str = "",
        earliest: str = "",
        latest: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        params = {
            "finding_ids": finding_ids,
            "urgency": urgency,
            "status": status,
            "owner": owner,
            "disposition": disposition,
            "rule_title": rule_title,
            "earliest": earliest,
            "latest": latest,
            "limit": limit,
            "offset": offset,
        }
        payload = self._get(FINDINGS_PATH, params)
        return _as_records(payload)

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        payload = self._get(FINDING_PATH.format(id=urllib.parse.quote(finding_id, safe="")))
        records = _as_records(payload)
        return records[0] if records else (payload if isinstance(payload, dict) else {})

    def get_notes(self, finding_id: str) -> list[Any]:
        for path in (FINDING_NOTES_PATH, INVESTIGATION_NOTES_PATH):
            try:
                payload = self._get(path.format(id=urllib.parse.quote(finding_id, safe="")))
            except ESClientError:
                continue
            records = _as_records(payload)
            if records:
                return records
        return []

    def load(
        self,
        *,
        finding_id: str = "",
        include_notes: bool = False,
        **filters: Any,
    ) -> list[dict[str, Any]]:
        if finding_id:
            record = self.get_finding(finding_id)
            records = [record] if record else []
        else:
            records = self.get_findings(**filters)
        if include_notes:
            for record in records:
                ident = str(record.get("id") or record.get("finding_id") or record.get("event_id") or "")
                if ident:
                    record["notes"] = self.get_notes(ident)
        return records

    def post_note(self, finding_id: str, body: str) -> Any:
        """Attach an analyst-visible note. Opt-in from the agent write_notes task."""
        payload = json.dumps({"body": body, "comment": body}).encode("utf-8")
        path = FINDING_NOTES_PATH.format(id=urllib.parse.quote(finding_id, safe=""))
        request = urllib.request.Request(
            self.base + path,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Splunk {self.session_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body_txt = exc.read().decode("utf-8", errors="replace")[:400]
            raise ESClientError(f"ES note API {exc.code}: {body_txt}") from exc
        return json.loads(raw) if raw else {}


def _as_records(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("entry", "results", "data", "findings", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            rows = []
            for item in value:
                if isinstance(item, dict) and isinstance(item.get("content"), dict):
                    row = dict(item["content"])
                    row.setdefault("id", item.get("name") or item.get("id"))
                    rows.append(row)
                elif isinstance(item, dict):
                    rows.append(item)
            return rows
    if "id" in payload or "finding_id" in payload or "rule_title" in payload:
        return [payload]
    return []
