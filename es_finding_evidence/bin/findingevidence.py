#!/usr/bin/env python3
"""Streaming command: recommend evidence searches, weight evidence, score follow-up.

Syntax:
    <findings> | findingevidence
    <findings> | findingevidence expand=searches window_minutes=90
    | loadfindings mode=demo | findingevidence expand=evidence
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.analyze import analyze_records
from lib.chunked import ChunkedCommand, option, option_float, option_int
from lib.constants import DEFAULT_WINDOW_MINUTES, INVESTIGATE_THRESHOLD, REVIEW_THRESHOLD


class FindingEvidenceCommand(ChunkedCommand):
    generating = False
    streaming = True

    def stream(self, records):
        window_minutes = option_int(self.options, "window_minutes", DEFAULT_WINDOW_MINUTES)
        investigate_threshold = option_float(
            self.options, "investigate_threshold", INVESTIGATE_THRESHOLD
        )
        review_threshold = option_float(self.options, "review_threshold", REVIEW_THRESHOLD)
        expand = option(self.options, "expand", "none")
        max_searches = option_int(self.options, "max_searches", 12)
        return analyze_records(
            records,
            window_minutes=window_minutes,
            investigate_threshold=investigate_threshold,
            review_threshold=review_threshold,
            expand=expand,
            max_searches=max_searches,
        )


if __name__ == "__main__":
    FindingEvidenceCommand("findingevidence").run()
