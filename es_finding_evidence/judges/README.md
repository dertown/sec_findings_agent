# Custom judges

The backend agent runs every enabled judge in `judges.conf` after it gathers
evidence. Add your own without editing app Python.

## 1. Python judge

Create `local/judges/my_judge.py` in this app:

```python
def judge(finding, evidence, searches, context):
    # finding: canonical finding dict (user, urgency, triage, ...)
    # evidence: observed + executed-search evidence items
    # searches: recommended SPL
    # context: analysis, executed search results, thresholds
    if finding.get("user") == "admin":
        return {
            "score": 85,
            "decision": "Yes",          # Yes | Review | No
            "rationale": "Privileged user",
            "confidence": 0.8,
            "mode": "override",        # vote | adjust | override
        }
    return {"abstain": True}
```

Then either:

- Drop the file in `local/judges/` (`auto_load_local = 1` loads `judge()` as a vote), or
- Register it explicitly in `local/judges.conf`:

```
[my_judge]
enabled = 1
type = python
file = my_judge.py
function = judge
mode = override
weight = 0.8
```

`file` must resolve under `local/judges/`, `judges/`, or `bin/judges/` of this
app. Arbitrary paths are rejected.

## 2. Rule judge (no Python)

```
[force_critical]
enabled = 1
type = rule
mode = override
when_urgency = critical
when_triage_disposition = true_positive
decision = Yes
score = 92
rationale = SOC policy
```

Filters: `when_urgency`, `when_status`, `when_disposition`,
`when_triage_disposition`, `when_asset_priority`, `when_identity_priority`,
`when_min_risk`, `when_title_contains`, `when_user_in`.

## Modes

| mode | Effect |
| --- | --- |
| vote | Weighted average of `score` |
| adjust | Add `adjustment` to the running score |
| override | If the judge returns a `decision`, that decision wins |

Judges are trusted admin code. Do not load untrusted files.
