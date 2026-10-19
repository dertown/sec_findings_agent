#!/usr/bin/env python3
"""Score bundled demo findings without Splunk. Usage: python3 demo_cli.py [finding_id]"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.analyze import demo_records
from lib.scoring import analyze_finding


def main() -> int:
    wanted = sys.argv[1] if len(sys.argv) > 1 else None
    rows = demo_records()
    if wanted:
        rows = [row for row in rows if row["finding_id"] == wanted]
        if not rows:
            print(f"unknown finding_id {wanted}", file=sys.stderr)
            return 1
    print(f"{'ID':7} {'Score':>5} {'Decision':7} {'Triage':16} Title")
    for record in rows:
        result = analyze_finding(record)
        print(
            f"{result['finding']['finding_id']:7} "
            f"{result['followup_score']:5.1f} "
            f"{result['investigation_required']:7} "
            f"{str(result['finding']['triage']['disposition'])[:16]:16} "
            f"{result['finding']['title']}"
        )
        if wanted:
            print("\nRationale:")
            for line in result["rationale"]:
                print(f"  - {line}")
            print("\nEvidence:")
            for item in result["evidence"]:
                print(f"  {item['signed_weight']:+6.1f}  {item['title']}")
            print("\nRecommended searches:")
            for search in result["recommended_searches"]:
                print(f"  [{search['category']}] {search['search_name']}")
                print(f"      {search['search']}")
            print("\nJSON score breakdown:")
            print(json.dumps(result["score_breakdown"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
