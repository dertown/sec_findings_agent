#!/usr/bin/env python3
"""Generating command: run one backend agent cycle on the search pipeline.

    | findingagent mode=demo
    | findingagent mode=demo run_searches=true tasks=gather_evidence,score,emit
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.agent import agent_from_options
from lib.chunked import ChunkedCommand


class FindingAgentCommand(ChunkedCommand):
    generating = True
    streaming = False

    def generate(self):
        agent = agent_from_options(
            self.options,
            splunkd_uri=self.splunkd_uri,
            session_key=self.session_key,
        )
        cycle = agent.run()
        for row in cycle.get("results") or []:
            yield row
        if cycle.get("errors"):
            yield {
                "row_type": "agent_errors",
                "error_count": len(cycle["errors"]),
                "errors_json": str(cycle["errors"]),
            }


if __name__ == "__main__":
    FindingAgentCommand("findingagent").run()
