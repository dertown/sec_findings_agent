"""Shared constants, maps, and default scoring policy."""

APP_ID = "es_finding_evidence"
APP_LABEL = "Finding Evidence Advisor"

# Follow-up score is always 0-100.
SCORE_MIN = 0.0
SCORE_MAX = 100.0

# Default decision thresholds. Override from es_finding_evidence.conf.
INVESTIGATE_THRESHOLD = 50.0
REVIEW_THRESHOLD = 30.0

# Mix of independent signals. Must sum to 1.0.
COMPONENT_WEIGHTS = {
    "urgency": 0.22,
    "risk": 0.18,
    "evidence": 0.22,
    "triage": 0.18,
    "killchain": 0.10,
    "corroboration": 0.10,
}

URGENCY_SCORE = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 25.0,
    "informational": 10.0,
    "info": 10.0,
    "unknown": 35.0,
    "": 35.0,
}

# Analyst or triage-agent disposition -> investigation pressure (0-100).
DISPOSITION_SCORE = {
    "true_positive": 92.0,
    "suspicious": 88.0,
    "other": 55.0,
    "undetermined": 50.0,
    "unknown": 50.0,
    "testing": 20.0,
    "benign_positive": 22.0,
    "false_positive": 8.0,
}

SOURCE_RELIABILITY = {
    "threat_intel": 0.92,
    "triage_agent": 0.85,
    "soar_connector": 0.80,
    "finding_metadata": 0.70,
    "asset_identity": 0.75,
    "related_findings": 0.72,
    "recommended_search": 0.0,  # unrun searches never inflate the live score
}

# Later kill-chain phases need human follow-up more often.
KILLCHAIN_SCORE = {
    "reconnaissance": 22.0,
    "resource-development": 28.0,
    "initial-access": 55.0,
    "delivery": 48.0,
    "exploitation": 62.0,
    "installation": 68.0,
    "persistence": 70.0,
    "privilege-escalation": 74.0,
    "defense-evasion": 66.0,
    "credential-access": 80.0,
    "discovery": 50.0,
    "lateral-movement": 84.0,
    "collection": 78.0,
    "command-and-control": 88.0,
    "exfiltration": 94.0,
    "impact": 96.0,
    "actions-on-objectives": 94.0,
}

INVESTIGATION_LABELS = {
    "Yes": "Investigation required",
    "Review": "Analyst review recommended",
    "No": "No investigation required",
}

# Finding field aliases seen in ES notables, Mission Control REST, and CIM.
FIELD_ALIASES = {
    "finding_id": (
        "finding_id",
        "id",
        "event_id",
        "notable_id",
        "incident_id",
        "mc_event_id",
    ),
    "title": ("title", "rule_title", "search_name", "rule_name", "name"),
    "description": ("description", "rule_description", "security_domain", "risk_message"),
    "urgency": ("urgency", "severity", "priority"),
    "severity": ("severity", "orig_severity"),
    "status": ("status", "status_label", "status_group"),
    "owner": ("owner", "assigned_to"),
    "disposition": ("disposition", "rule_disposition", "status_end"),
    "risk_score": ("risk_score", "risk_score_total", "normalized_risk_score"),
    "confidence": ("confidence", "detection_confidence"),
    "impact": ("impact", "detection_impact"),
    "rule_name": ("rule_name", "search_name", "detection_name"),
    "detection_id": ("detection_id", "rule_id", "savedsearch_id"),
    "src": ("src", "src_host", "src_nt_host", "orig_src"),
    "dest": ("dest", "dest_host", "dest_nt_host", "orig_dest"),
    "user": ("user", "src_user", "user_name", "orig_user", "suser"),
    "src_user": ("src_user", "src_user_name"),
    "src_ip": ("src_ip", "src", "id.orig_h"),
    "dest_ip": ("dest_ip", "dest", "id.resp_h"),
    "dvc": ("dvc", "host", "orig_host"),
    "url": ("url", "uri", "http_url"),
    "domain": ("domain", "query", "query_name", "dest_dns", "url_domain"),
    "file_hash": ("file_hash", "sha256", "sha256_hash", "file_hash_sha256", "hash"),
    "file_name": ("file_name", "file", "filename", "file_path"),
    "process": ("process", "process_name", "orig_process", "Image"),
    "parent_process": ("parent_process", "parent_process_name", "ParentImage"),
    "command_line": ("command_line", "process_exec", "CommandLine"),
    "threat_object": ("threat_object", "threat_match_value", "indicator"),
    "threat_object_type": ("threat_object_type", "indicator_type"),
    "risk_object": ("risk_object", "normalized_risk_object", "entity"),
    "risk_object_type": ("risk_object_type", "entity_type"),
    "asset_priority": ("asset_priority", "priority", "dest_priority", "src_priority"),
    "identity_priority": ("identity_priority", "user_priority"),
    "create_time": ("create_time", "create_time_iso", "_time", "timestamp"),
    "update_time": ("update_time", "mod_time"),
    "index": ("index",),
    "orig_sid": ("orig_sid", "sid", "info_search_id"),
}

TRIAGE_FIELD_ALIASES = {
    "disposition": (
        "triage_disposition",
        "ai_analysis_disposition",
        "ai_disposition",
        "agent_disposition",
        "recommended_disposition",
        "analysis_disposition",
    ),
    "summary": (
        "triage_summary",
        "ai_analysis_summary",
        "ai_summary",
        "agent_summary",
        "analysis_summary",
    ),
    "justification": (
        "triage_justification",
        "ai_analysis_justification",
        "ai_justification",
        "agent_justification",
        "analysis_justification",
    ),
    "tools": (
        "triage_tools",
        "ai_analysis_tools",
        "ai_tools",
        "agent_tools",
        "analysis_tools",
    ),
    "evidence": (
        "triage_evidence",
        "ai_analysis_evidence",
        "ai_evidence",
        "agent_evidence",
        "analysis_evidence",
    ),
    "analysis_details": (
        "triage_analysis_details",
        "ai_analysis_details",
        "analysis_details",
        "agent_analysis_details",
    ),
    "confidence": (
        "triage_confidence",
        "ai_analysis_confidence",
        "agent_confidence",
        "analysis_confidence",
    ),
}

DEFAULT_WINDOW_MINUTES = 60
