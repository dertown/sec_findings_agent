# Finding Evidence Advisor

A Splunk Enterprise app for **Splunk Enterprise Security (ES) 8.x**. It reads **findings** and **Triage agent** enrichment, recommends Splunk searches that would prove or disprove the finding, **weights** that evidence, and scores whether an analyst should **follow up / open an investigation**.

This is not an official Splunk or Cisco product. It is designed to sit beside Mission Control and the ES 8.6 Triage agent.

## What it does

1. **Load findings** from the ES Mission Control API (`/servicesNS/nobody/missioncontrol/public/v2/findings`) or from notables already on the pipeline (`index=notable | findingevidence`).
2. **Attach Triage agent enrichment** — disposition, summary, justification, tools/connectors, evidence, analysis details — from finding fields or notes. The ES 8.6 Analysis panel is the source of those values; the agent never auto-dispositions the finding, and neither does this app.
3. **Recommend evidence searches** (CIM-oriented SPL) for the entities on the finding: user, src/dest, hash, domain, URL, process, threat object, risk object.
4. **Weight observed evidence** (finding metadata + agent output + SOAR connector verdicts). Recommended searches that have not been run do **not** inflate the live score.
5. **Score follow-up (0–100)** and decide **Yes / Review / No**.

## Install

1. Package is `dist/es_finding_evidence-1.0.0.spl` (gzip tarball).
2. In Splunk Web: **Manage apps → Install app from file**.
3. Restart the search head if commands do not appear immediately.
4. Open the **Finding Evidence Advisor** app.

Requires Splunk Enterprise 9.x / 10.x (Python 3). Live ES mode needs **Enterprise Security 8.x** and a role that can read findings (`mc_investigation_read` or equivalent). Demo mode needs nothing else.

## Dashboards

| View | Purpose |
| --- | --- |
| **Follow-up queue** | Scored findings, investigation decision, drilldown to the workbench |
| **Finding workbench** | One finding: agent enrichment, weighted evidence, recommended SPL |
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

REST (session-authenticated):

```
GET  /services/es_finding_evidence/analyze?demo=true
POST /services/es_finding_evidence/analyze   { finding JSON }
```

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
- The app does not change finding disposition, owner, or status. It only recommends.

## Layout

```
es_finding_evidence/
  bin/                 custom commands + REST handler
  bin/lib/             scoring, templates, ES client (pure Python)
  default/             conf, dashboards, macros, saved searches
  lookups/             weights, templates, sample ids
  metadata/
```

Run tests from the repo root:

```
python3 -m unittest tests.test_scoring -v
```
