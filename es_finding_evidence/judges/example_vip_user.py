"""Example custom judge: force investigation for named VIP users.

Copy this file to local/judges/ and enable it in local/judges.conf:

    [example_vip_user]
    enabled = 1
    type = python
    file = example_vip_user.py
    function = judge
    mode = override
    weight = 0.9

Or just drop it in local/judges/ with a judge() function; auto_load_local
picks it up as a vote unless you add a stanza.
"""


def judge(finding, evidence, searches, context):
    user = str(finding.get("user") or "").lower()
    vips = {"c.okonkwo", "ceo", "ciso"}
    if user in vips:
        return {
            "score": 80,
            "decision": "Yes",
            "rationale": f"VIP identity {user} matched the custom VIP judge.",
            "confidence": 0.85,
            "mode": "override",
        }
    return {"abstain": True}
