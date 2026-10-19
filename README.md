# Finding Evidence Advisor

A Splunk Enterprise app for **Splunk Enterprise Security (ES) 8.x**. It is a **backend agent**: it loads **findings** and **Triage agent** enrichment, **runs evidence searches**, applies **built-in and custom judge functions** (including judges added in Splunk Web), and scores whether an analyst should **follow up / open an investigation**. **Every cycle posts that full result onto the ES finding as enrichment.**

This is not an official Splunk or Cisco product. It is designed to sit beside Mission Control and the ES 8.6 Triage agent.

## What it does

1. **Load findings** from the ES Mission Control API or from notables already on the pipeline.
2. **Attach Triage agent enrichment** — disposition, summary, justification, tools/connectors, evidence, analysis details.
3. **Recommend and (in backend mode) execute evidence searches** for the entities on the finding.
4. **Run judges** — built-in follow-up score, triage guardrails, critical-asset bump, plus any custom Python or rule judges you register.
5. **Enrich the finding** — post a Mission Control note plus `fea_*` fields with the score, investigation decision, judges, weighted evidence, and searches that were run. The agent does **not** change owner, status, urgency, or disposition.
6. **Persist / emit** scores to KV store and `fea:agent:result` events so the Agent activity dashboard can show what ran.

## Install

1. Package is `dist/es_finding_evidence-1.2.0.spl` (gzip tarball).
2. In Splunk Web: **Manage apps → Install app from file**.
3. Restart the search head if commands do not appear immediately.
4. Open the **Finding Evidence Advisor** app.

Requires Splunk Enterprise 9.x / 10.x (Python 3). Live ES mode needs **Enterprise Security 8.x** and a role that can read findings (`mc_investigation_read` or equivalent). Demo mode needs nothing else.

## Dashboards

| View | Purpose |
| --- | --- |
| **Follow-up queue** | Scored findings, investigation decision, drilldown to the workbench |
| **Finding workbench** | One finding: posted enrichment note, triage, weighted evidence, recommended SPL |
| **Judge manager** | Add/edit/delete rule and Python judges in Splunk Web |
| **Agent activity** | What the agent ran, enrichment posted onto findings, indexed cycles |
| **Scoring model** | How the 0–100 score is built |
| **Evidence search catalog** | Templates and rendered searches |

Switch **Data source** to `Demo findings` to explore without ES, or `ES Mission Control API` for live findings.

## Search commands

```spl
| loadfindings mode=demo
| table finding_id, title, urgency, triage_disposition, followup_score, investigation_required
```

Live ES:

```spl
| loadfindings mode=rest status=new limit=50
| sort - followup_score
```

Already have notables on the pipeline:

```spl
index=notable earliest=-24h
| findingevidence
| where investigation_required="Yes"
```

Workbench (one row per recommended search):

```spl
| loadfindings mode=demo finding_id=F-1001 expand=searches
| table search_name, search_purpose, potential_weight, search_spl
```

Weighted evidence:

```spl
| loadfindings mode=demo finding_id=F-1001 expand=evidence
| table evidence_signed_weight, evidence_direction, evidence_title, evidence_detail
```

Backend agent cycle (gathers evidence, applies judges):

```spl
| findingagent mode=demo run_searches=true limit=12
| table finding_id, followup_score, investigation_required, executed_search_count, override_applied
```

REST (session-authenticated):

```
GET  /services/es_finding_evidence/analyze?demo=true
POST /services/es_finding_evidence/analyze   { finding JSON }
GET/POST/DELETE  /services/es_finding_evidence/judges
POST             /services/es_finding_evidence/agent/run   { "mode":"demo", "run_searches":true }
GET              /services/es_finding_evidence/enrichment
```

List judges and posted enrichment from search:

```spl
| listjudges
| listenrichment finding_id=F-1001
```

## Backend agent

Enable a scheduled worker: **Settings → Data inputs → Finding Evidence Agent** (disabled by default). Each interval it:

1. `gather_evidence` — run the top N recommended SPL jobs via the Splunk session
2. `score` — run the judge pipeline
3. `enrich` — post the full result onto the ES finding (note + `fea_*` fields) and store a copy in `finding_enrichment`
4. `persist` — upsert `finding_evidence_scores` KV collection
5. `emit` — index `fea:agent:cycle` / `fea:agent:result`

The agent never writes owner, status, urgency, or disposition. Optional extra task `write_notes` is redundant with `enrich` (enrich already posts the note).

## Finding enrichment

Every handled finding gets:

- A Mission Control **note** titled `Finding Evidence Agent enrichment` with the score, decision, weighted evidence, searches the agent ran, judges, and a `fea-enrichment` JSON fence (the complete payload).
- Scalar **`fea_*` fields** on the finding (`fea_followup_score`, `fea_investigation_required`, `fea_agent_summary`, …). Large JSON blobs stay in the note so the finding fields stay small.

Demo mode still writes `finding_enrichment` KV so the workbench and Agent activity dashboards show the same payload without live ES.

## Custom judges

Add judges in **Judge manager** (Splunk Web) or without the UI. See `es_finding_evidence/judges/README.md`.

**Python** — `local/judges/my_judge.py`:

```python
def judge(finding, evidence, searches, context):
    if finding.get("user") == "admin":
        return {"score": 85, "decision": "Yes", "mode": "override", "rationale": "admin account"}
    return {"abstain": True}
```

Register in `local/judges.conf`:

```
[my_judge]
enabled = 1
type = python
file = my_judge.py
function = judge
mode = override
weight = 0.8
```

Files must live under `local/judges/`, `judges/`, or `bin/judges/`. Arbitrary paths are rejected.

**Rule** (no Python):

```
[force_critical]
type = rule
mode = override
when_urgency = critical
decision = Yes
score = 90
rationale = SOC policy
```

Judge modes: `vote` (weighted score), `adjust` (add `adjustment` points), `override` (force a decision).

## Follow-up score

Score is **0–100**:

| Band | Decision | Meaning |
| --- | --- | --- |
| 0–29 | **No** | Likely false/benign; do not open an investigation |
| 30–49 | **Review** | Glance at evidence and run a couple of recommended searches |
| 50–100 | **Yes** | Investigation required; higher scores first |

Mix (defaults in `default/es_finding_evidence.conf`):

- 22% urgency
- 18% ES risk score
- 22% observed evidence (50 = none; supporting raises, refuting lowers)
- 18% Triage agent / analyst disposition
- 10% kill-chain / MITRE phase
- 10% corroboration (distinct sources, related findings, connectors)

Guardrails:

- High-confidence **false positive** from the Triage agent with weak supporting evidence → **No** (unless urgency is critical).
- High-confidence **true positive** with supporting evidence → at least **Review**, usually **Yes**.
- Unrun recommended searches only raise `followup_score_ceiling`. They never pad the live score.

Copy `default/es_finding_evidence.conf` to `local/` to change thresholds and mix.

## Evidence weights

Observed items get a **signed weight**:

`signed_weight = base_weight × confidence × source_reliability × direction`

Sources: threat intel (0.92), triage agent (0.85), SOAR connector (0.80), asset/identity (0.75), finding metadata (0.70). See `lookups/evidence_weights.csv`.

## Demo findings

Twelve sample SOC cases covering credential dumping, brute force, sanctioned scanners, encoded PowerShell, allowlisted hashes, C2 beaconing, impossible travel, phishing, newly registered domains, expected PsExec, exfiltration, and a finding with **no** triage-agent output.

## Security notes

- **No passwords, API keys, or tokens are stored in the app.** ES calls use the current Splunk session key on the local management port.
- Evidence IDs are **SHA-256** prefixes of non-secret finding fields.
- The app does not change finding disposition, owner, urgency, or status. Enrichment is a note plus `fea_*` fields.

## Layout

```
es_finding_evidence/
  bin/                 custom commands + REST handler
  bin/lib/             scoring, templates, ES client, judges, enrichment
  appserver/static/    Splunk Web judge manager and agent activity JS/CSS
  default/             conf, dashboards, macros, saved searches
  lookups/             weights, templates, sample ids
  metadata/
```

Run tests from the repo root:

```
python3 -m unittest discover -s tests -v
```
