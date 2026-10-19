"""Example custom judge: bump the score for after-hours activity.

Enable in local/judges.conf:

    [example_offhours]
    enabled = 1
    type = python
    file = example_offhours.py
    function = judge
    mode = adjust
    weight = 1.0
"""

from datetime import datetime, timezone


def judge(finding, evidence, searches, context):
    created = finding.get("create_time")
    if not created:
        return {"abstain": True}
    hour = datetime.fromtimestamp(float(created), tz=timezone.utc).hour
    if hour < 6 or hour >= 20:
        return {
            "adjustment": 8,
            "rationale": f"Finding created at hour {hour} UTC (off-hours bump).",
            "mode": "adjust",
            "confidence": 0.6,
        }
    return {"abstain": True}
