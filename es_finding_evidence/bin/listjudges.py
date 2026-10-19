#!/usr/bin/env python3
"""Generating command: | listjudges  — one row per configured judge."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.chunked import ChunkedCommand
from lib.judge_store import describe_all
from lib.kvstore import KvCollection
from lib.paths import app_home


class ListJudgesCommand(ChunkedCommand):
    generating = True
    streaming = False

    def generate(self):
        records = []
        if self.session_key:
            try:
                records = KvCollection(self.splunkd_uri, self.session_key, "fea_custom_judges").list()
            except Exception:
                records = []
        for row in describe_all(app_home(), records):
            yield {
                "name": row.get("name"),
                "kind": row.get("kind") or row.get("type"),
                "type": row.get("type") or row.get("kind"),
                "enabled": 1 if row.get("enabled") else 0,
                "weight": row.get("weight"),
                "mode": row.get("mode"),
                "source": row.get("source"),
                "editable": 1 if row.get("editable") else 0,
                "rationale": row.get("rationale") or "",
                "decision": row.get("decision") or "",
            }


if __name__ == "__main__":
    ListJudgesCommand("listjudges").run()
