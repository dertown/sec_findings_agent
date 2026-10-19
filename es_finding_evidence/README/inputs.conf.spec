[finding_evidence_agent://<name>]
* Backend Finding Evidence Agent. Disabled by default; enable under
* Settings → Data inputs → Finding Evidence Agent.

interval = <integer>
mode = <demo|rest|auto>
status = <string>
urgency = <string>
limit = <integer>
tasks = <comma-separated-tasks>
* Default: gather_evidence,score,enrich,persist,emit
* enrich posts score, judges, evidence, and searches onto the ES finding.
run_searches = <bool>
max_searches_per_finding = <integer>
search_timeout = <integer>
window_minutes = <integer>
write_notes = <bool>
create_investigation = <bool>
index = <string>
sourcetype = <string>
