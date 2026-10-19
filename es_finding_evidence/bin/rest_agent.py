#!/usr/bin/env python3
"""REST for judges, agent runs, and finding enrichment.

  GET/POST/DELETE /services/es_finding_evidence/judges
  POST            /services/es_finding_evidence/agent/run
  GET             /services/es_finding_evidence/enrichment
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.agent import agent_from_options
from lib.judge_store import (
    delete_python_file,
    describe_all,
    record_from_payload,
    write_python_file,
)
from lib.kvstore import KvCollection
from lib.paths import app_home

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:

    class PersistentServerConnectionApplication:  # type: ignore[no-redef]
        def __init__(self, command_line=None, command_arg=None):
            pass


def _query_map(query) -> dict:
    if isinstance(query, dict):
        return {str(k): (v[0] if isinstance(v, list) and v else v) for k, v in query.items()}
    out = {}
    for item in query or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out[str(item[0])] = str(item[1])
    return out


def _payload(request) -> dict:
    raw = request.get("payload") or ""
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
    return parsed if isinstance(parsed, dict) else {}


def _session(request) -> tuple[str, str]:
    session_key = ""
    uri = "https://127.0.0.1:8089"
    info = request.get("session") or {}
    if isinstance(info, dict):
        session_key = str(info.get("key") or info.get("authtoken") or "")
        uri = str(info.get("server_uri") or uri)
    headers = request.get("headers") or []
    for item in headers:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and str(item[0]).lower() == "authorization":
            value = str(item[1])
            if value.lower().startswith("splunk "):
                session_key = session_key or value.split(" ", 1)[1]
    return session_key, uri


def _response(payload, status=200):
    return {
        "status": status,
        "payload": json.dumps(payload, default=str),
        "headers": {"Content-Type": "application/json"},
    }


def _kv_judges(uri: str, session_key: str) -> tuple[KvCollection | None, list[dict]]:
    if not session_key:
        return None, []
    try:
        col = KvCollection(uri, session_key, "fea_custom_judges")
        return col, col.list()
    except Exception:
        return None, []


class JudgesHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            return _response({"error": "invalid request"}, 400)
        method = str(request.get("method") or "GET").upper()
        query = _query_map(request.get("query") or [])
        payload = _payload(request)
        session_key, uri = _session(request)
        col, records = _kv_judges(uri, session_key)
        home = app_home()
        try:
            if method == "GET":
                return _response({"judges": describe_all(home, records)})
            if method in {"POST", "PUT"}:
                if col is None:
                    return _response({"error": "KV store unavailable; sign in to Splunk Web."}, 401)
                existing = next((r for r in records if r.get("name") == payload.get("name")), None)
                record = record_from_payload(payload, existing)
                if record["type"] == "python":
                    write_python_file(record, home)
                col.put(record["name"], record)
                _, records = _kv_judges(uri, session_key)
                return _response({"ok": True, "judge": record, "judges": describe_all(home, records)})
            if method == "DELETE":
                name = str(query.get("name") or payload.get("name") or "")
                if not name:
                    return _response({"error": "name is required"}, 400)
                if col is None:
                    return _response({"error": "KV store unavailable"}, 401)
                col.delete(name)
                delete_python_file(name, home)
                _, records = _kv_judges(uri, session_key)
                return _response({"ok": True, "deleted": name, "judges": describe_all(home, records)})
            return _response({"error": f"unsupported method {method}"}, 405)
        except ValueError as exc:
            return _response({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            return _response({"error": str(exc)}, 500)


class AgentRunHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            return _response({"error": "invalid request"}, 400)
        query = _query_map(request.get("query") or [])
        payload = _payload(request)
        options = {**query, **payload}
        session_key, uri = _session(request)
        try:
            agent = agent_from_options(options, splunkd_uri=uri, session_key=session_key)
            return _response(agent.run())
        except Exception as exc:  # noqa: BLE001
            return _response({"error": str(exc)}, 500)


class EnrichmentHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            return _response({"error": "invalid request"}, 400)
        query = _query_map(request.get("query") or [])
        session_key, uri = _session(request)
        if not session_key:
            return _response({"results": [], "error": "not authenticated"}, 401)
        try:
            rows = KvCollection(uri, session_key, "finding_enrichment").list()
            finding_id = str(query.get("finding_id") or "")
            if finding_id:
                rows = [row for row in rows if str(row.get("finding_id")) == finding_id]
            return _response({"count": len(rows), "results": rows})
        except Exception as exc:  # noqa: BLE001
            return _response({"error": str(exc)}, 500)


if __name__ == "__main__":
    print(JudgesHandler().handle(json.dumps({"method": "GET"}))["payload"][:500])
