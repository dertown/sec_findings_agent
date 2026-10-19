#!/usr/bin/env python3
"""REST: list judges, run the backend agent.

  GET  /services/es_finding_evidence/judges
  POST /services/es_finding_evidence/agent/run
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.agent import agent_from_options
from lib.judges.loader import describe_judges
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


class JudgesHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    def handle(self, in_string):
        try:
            return _response({"judges": describe_judges(app_home()), "home": app_home()})
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
            agent = agent_from_options(
                options,
                splunkd_uri=uri,
                session_key=session_key,
            )
            cycle = agent.run()
            return _response(cycle)
        except Exception as exc:  # noqa: BLE001
            return _response({"error": str(exc)}, 500)


if __name__ == "__main__":
    print(JudgesHandler().handle("{}")["payload"])
    envelope = json.dumps({"method": "POST", "payload": json.dumps({"mode": "demo", "limit": 2, "run_searches": True})})
    print(AgentRunHandler().handle(envelope)["payload"][:400])
