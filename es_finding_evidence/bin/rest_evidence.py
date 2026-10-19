#!/usr/bin/env python3
"""REST endpoint for Finding Evidence Advisor.

  GET  /services/es_finding_evidence/analyze?demo=true
  POST /services/es_finding_evidence/analyze   JSON finding body

Uses the caller's Splunk session. No passwords or tokens are accepted.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.analyze import analyze_records, demo_records

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:  # local unit tests

    class PersistentServerConnectionApplication:  # type: ignore[no-redef]
        def __init__(self, command_line=None, command_arg=None):
            pass


class AnalyzeHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            return _response({"error": "invalid request envelope"}, 400)
        method = str(request.get("method") or "GET").upper()
        query = _query_map(request.get("query") or [])
        payload = _payload(request)
        try:
            if method == "GET" and str(query.get("demo", "")).lower() not in {"1", "true", "yes"}:
                return _response(
                    {
                        "app": "es_finding_evidence",
                        "usage": "POST a finding JSON body, or GET ?demo=true",
                        "expand": ["none", "searches", "evidence"],
                    }
                )
            records = _records(query, payload)
            expand = str(payload.get("expand") or query.get("expand") or "none")
            rows = analyze_records(records, expand=expand)
            return _response({"count": len(rows), "results": rows})
        except Exception as exc:  # noqa: BLE001
            return _response({"error": str(exc)}, 500)


def _query_map(query) -> dict:
    if isinstance(query, dict):
        return {str(k): _first(v) for k, v in query.items()}
    out = {}
    for item in query:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out[str(item[0])] = str(item[1])
    return out


def _first(value):
    if isinstance(value, list) and value:
        return str(value[0])
    return str(value)


def _payload(request) -> dict:
    raw = request.get("payload") or request.get("raw_args") or ""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {"records": parsed}


def _records(query: dict, payload: dict):
    if str(query.get("demo") or payload.get("demo") or "").lower() in {"1", "true", "yes"}:
        records = demo_records()
        finding_id = str(query.get("finding_id") or payload.get("finding_id") or "")
        if finding_id:
            records = [row for row in records if row.get("finding_id") == finding_id]
        return records
    if isinstance(payload.get("records"), list):
        return payload["records"]
    if isinstance(payload.get("finding"), dict):
        return [payload["finding"]]
    if payload:
        return [payload]
    return []


def _response(payload, status=200):
    return {
        "status": status,
        "payload": json.dumps(payload, default=str),
        "headers": {"Content-Type": "application/json"},
    }


if __name__ == "__main__":
    envelope = json.dumps({"method": "GET", "query": [["demo", "true"], ["finding_id", "F-1001"]]})
    print(AnalyzeHandler().handle(envelope)["payload"])
