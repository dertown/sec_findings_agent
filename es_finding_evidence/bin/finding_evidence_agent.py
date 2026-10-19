#!/usr/bin/env python3
"""Splunk modular input: backend Finding Evidence Agent.

Enable in Settings → Data inputs → Finding Evidence Agent (disabled by default).
Each interval the agent loads ES findings, optionally runs evidence searches,
applies configured judges, and writes result events.
"""

from __future__ import annotations

import os
import sys
import time
from xml.etree.ElementTree import fromstring

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.agent import FindingEvidenceAgent, agent_from_options
from lib.kvstore import KvPersister
from lib.util import dumps

SCHEME = """<scheme>
  <title>Finding Evidence Agent</title>
  <description>Backend agent that scores ES findings, runs evidence searches, and applies custom judges.</description>
  <use_external_validation>true</use_external_validation>
  <streaming_mode>xml</streaming_mode>
  <endpoint>
    <args>
      <arg name="name">
        <title>Stanza name</title>
        <data_type>string</data_type>
      </arg>
      <arg name="mode">
        <title>Finding source</title>
        <description>demo, rest, or auto</description>
        <data_type>string</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="tasks">
        <title>Tasks</title>
        <description>Comma-separated: gather_evidence,score,enrich,persist,emit,write_notes</description>
        <data_type>string</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="run_searches">
        <title>Run evidence searches</title>
        <data_type>boolean</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="max_searches_per_finding">
        <title>Max searches per finding</title>
        <data_type>number</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="limit">
        <title>Finding limit per cycle</title>
        <data_type>number</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="status">
        <title>Finding status filter</title>
        <data_type>string</data_type>
        <required_on_create>false</required_on_create>
      </arg>
      <arg name="write_notes">
        <title>Write a note back onto the ES finding</title>
        <data_type>boolean</data_type>
        <required_on_create>false</required_on_create>
      </arg>
    </args>
  </endpoint>
</scheme>
"""


def _xml_text(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def parse_input(raw: str) -> dict:
    # Splunk modular-input XML only (no DTD / external entities).
    root = fromstring(raw)
    cfg = {
        "server_uri": (root.findtext("server_uri") or "https://127.0.0.1:8089").strip(),
        "session_key": (root.findtext("session_key") or "").strip(),
        "params": {},
    }
    stanza = root.find("./configuration/stanza")
    if stanza is not None:
        for param in stanza.findall("param"):
            name = param.get("name")
            if name:
                cfg["params"][name] = (param.text or "").strip()
    return cfg


def run_once(raw: str) -> str:
    cfg = parse_input(raw)
    params = cfg["params"]
    kwargs = {
        "splunkd_uri": cfg["server_uri"],
        "session_key": cfg["session_key"],
    }
    if str(params.get("persist") or "true").lower() in {"1", "true", "yes"} and cfg["session_key"]:
        kwargs["persister"] = KvPersister(cfg["server_uri"], cfg["session_key"])
    agent = agent_from_options(params, **kwargs)
    cycle = agent.run()
    chunks = ['<stream>']
    now = int(time.time())
    chunks.append(
        "<event><time>{t}</time><source>fea_agent</source><sourcetype>fea:agent:cycle</sourcetype><data>{d}</data></event>".format(
            t=now,
            d=_xml_text(
                dumps(
                    {
                        "count": cycle["count"],
                        "elapsed": cycle["elapsed"],
                        "mode": cycle["mode"],
                        "tasks": cycle["tasks"],
                        "errors": cycle["errors"],
                        "judges": cycle["judges"],
                    }
                )
            ),
        )
    )
    if "emit" in cycle["tasks"]:
        for row in cycle["results"]:
            chunks.append(
                "<event><time>{t}</time><source>fea_agent</source><sourcetype>fea:agent:result</sourcetype><data>{d}</data></event>".format(
                    t=int(row.get("_time") or now),
                    d=_xml_text(dumps(row)),
                )
            )
    chunks.append("</stream>")
    return "".join(chunks)


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--scheme":
        sys.stdout.write(SCHEME)
        return 0
    if len(argv) > 1 and argv[1] == "--validate-arguments":
        sys.stdin.read()
        return 0
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    sys.stdout.write(run_once(raw))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
