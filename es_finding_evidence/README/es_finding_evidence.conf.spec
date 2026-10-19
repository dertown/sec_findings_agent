[scoring]
investigate_threshold = <float>
review_threshold = <float>
urgency_weight = <float>
risk_weight = <float>
evidence_weight = <float>
triage_weight = <float>
killchain_weight = <float>
corroboration_weight = <float>
max_searches = <int>
window_minutes = <int>

[findings]
rest_path = <path>
fallback_index = <index>

[triage]
parse_notes = <bool>
field_prefix = <string>

[agent]
tasks = <comma-separated-tasks>
run_searches = <bool>
max_searches_per_finding = <int>
search_timeout = <int>
write_notes = <bool>
create_investigation = <bool>
