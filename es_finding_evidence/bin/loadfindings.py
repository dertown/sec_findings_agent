#!/usr/bin/env python3
"""Generating command: load ES findings (or demo samples) onto the search pipeline.

Syntax:
    | loadfindings mode=demo
    | loadfindings mode=rest status=new urgency=high limit=50
    | loadfindings mode=rest finding_id=F-1001 include_notes=true
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.analyze import analyze_records, demo_records
from lib.chunked import ChunkedCommand, option, option_float, option_int
from lib.constants import DEFAULT_WINDOW_MINUTES, INVESTIGATE_THRESHOLD, REVIEW_THRESHOLD
from lib.demo import is_demo_finding_id


class LoadFindingsCommand(ChunkedCommand):
    generating = True
    streaming = False

    def generate(self):
        mode = option(self.options, "mode", "auto").lower()
        finding_id = option(self.options, "finding_id")
        include_notes = option(self.options, "include_notes", "false").lower() in {"1", "true", "yes"}
        window_minutes = option_int(self.options, "window_minutes", DEFAULT_WINDOW_MINUTES)
        investigate_threshold = option_float(
            self.options, "investigate_threshold", INVESTIGATE_THRESHOLD
        )
        review_threshold = option_float(self.options, "review_threshold", REVIEW_THRESHOLD)
        expand = option(self.options, "expand", "none")
        score = option(self.options, "score", "true").lower() in {"1", "true", "yes"}
        limit = option_int(self.options, "limit", 100)

        records = []
        if mode in {"demo", "sample"} or is_demo_finding_id(finding_id):
            records = demo_records()
        else:
            records = self._from_es(finding_id, include_notes, limit)
            if not records and mode == "auto":
                records = demo_records()
        if finding_id:
            records = [
                row
                for row in records
                if str(row.get("finding_id") or row.get("id") or "") == finding_id
            ]
        records = records[:limit]
        if not score:
            for row in records:
                yield row
            return
        for row in analyze_records(
            records,
            window_minutes=window_minutes,
            investigate_threshold=investigate_threshold,
            review_threshold=review_threshold,
            expand=expand,
        ):
            yield row

    def _from_es(self, finding_id: str, include_notes: bool, limit: int):
        from lib.es_client import ESClient, ESClientError

        try:
            client = ESClient(self.splunkd_uri, self.session_key)
            return client.load(
                finding_id=finding_id,
                include_notes=include_notes or bool(finding_id),
                urgency=option(self.options, "urgency"),
                status=option(self.options, "status"),
                owner=option(self.options, "owner"),
                disposition=option(self.options, "disposition"),
                rule_title=option(self.options, "rule_title"),
                earliest=option(self.options, "earliest"),
                latest=option(self.options, "latest"),
                limit=limit,
            )
        except ESClientError:
            if option(self.options, "mode", "auto").lower() == "rest":
                raise
            return []


if __name__ == "__main__":
    LoadFindingsCommand("loadfindings").run()
