#!/usr/bin/env python3
"""Generating command: | listenrichment  — enrichment posted onto findings."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.chunked import ChunkedCommand, option
from lib.kvstore import KvCollection


class ListEnrichmentCommand(ChunkedCommand):
    generating = True
    streaming = False

    def generate(self):
        if not self.session_key:
            return
        finding_id = option(self.options, "finding_id")
        try:
            rows = KvCollection(self.splunkd_uri, self.session_key, "finding_enrichment").list()
        except Exception:
            return
        for row in rows:
            if finding_id and str(row.get("finding_id")) != finding_id:
                continue
            yield row


if __name__ == "__main__":
    ListEnrichmentCommand("listenrichment").run()
