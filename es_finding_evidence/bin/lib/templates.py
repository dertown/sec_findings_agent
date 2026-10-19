"""Evidence-search templates. Placeholders are $field$ values from the finding."""

from __future__ import annotations

from typing import Any

# requires: entity fields that must be non-empty
# mitre: optional prefixes; empty means always eligible
SEARCH_TEMPLATES: list[dict[str, Any]] = [
    {
        "template_id": "auth_user_window",
        "name": "Authentication activity for the user",
        "purpose": "Show successes and failures around the finding to confirm account takeover or brute force.",
        "evidence_class": "auth_anomaly",
        "direction": "supporting",
        "base_weight": 64,
        "priority": 10,
        "requires": ["user"],
        "mitre": ["T1110", "T1078", "T1021"],
        "category": "Authentication",
        "spl": 'index=* (`cim_authentication_indexes`) sourcetype=* user="$user$" earliest=$earliest$ latest=$latest$ '
        "| eval result=coalesce(action, status, result) "
        "| stats count min(_time) as first_seen max(_time) as last_seen by user, src, dest, result "
        "| sort -count",
    },
    {
        "template_id": "auth_failures_then_success",
        "name": "Failed logons followed by success",
        "purpose": "Classic brute-force / password-spray evidence for the same user or source.",
        "evidence_class": "credential_access",
        "direction": "supporting",
        "base_weight": 78,
        "priority": 12,
        "requires": ["user"],
        "mitre": ["T1110"],
        "category": "Authentication",
        "spl": 'index=* (EventCode=4625 OR EventCode=4624 OR action=failure OR action=success) user="$user$" earliest=$earliest$ latest=$latest$ '
        "| bin _time span=5m "
        "| stats count(eval(EventCode=4625 OR action=failure)) as failures count(eval(EventCode=4624 OR action=success)) as successes by _time, user, src "
        "| where failures>5 AND successes>0",
    },
    {
        "template_id": "network_src_dest",
        "name": "Network traffic between source and destination",
        "purpose": "Confirm the connection, volume, ports, and whether the dest is rare for this src.",
        "evidence_class": "c2_beacon",
        "direction": "supporting",
        "base_weight": 70,
        "priority": 15,
        "requires": ["src_ip", "dest_ip"],
        "mitre": ["T1071", "T1095", "T1048"],
        "category": "Network",
        "spl": 'index=* (`cim_network_traffic_indexes`) src="$src_ip$" dest="$dest_ip$" earliest=$earliest$ latest=$latest$ '
        "| stats count sum(bytes) as bytes sum(bytes_out) as bytes_out dc(dest_port) as ports by src, dest, dest_port, transport "
        "| sort -bytes",
    },
    {
        "template_id": "rare_dest_for_src",
        "name": "Is this destination rare for the source?",
        "purpose": "First-seen / rare destinations increase C2 and exfil confidence.",
        "evidence_class": "c2_beacon",
        "direction": "supporting",
        "base_weight": 66,
        "priority": 18,
        "requires": ["src_ip", "dest_ip"],
        "mitre": ["T1071", "T1568"],
        "category": "Network",
        "spl": 'index=* src="$src_ip$" dest="$dest_ip$" earliest=-30d latest=$latest$ '
        "| stats min(_time) as first_seen max(_time) as last_seen count by src, dest "
        "| eval first_seen_in_window=if(first_seen>=strptime(\"$earliest$\",\"%m/%d/%Y:%H:%M:%S\"),1,0)",
    },
    {
        "template_id": "dns_domain",
        "name": "DNS lookups for the domain",
        "purpose": "See who queried the domain, how often, and whether it is newly seen.",
        "evidence_class": "c2_beacon",
        "direction": "supporting",
        "base_weight": 68,
        "priority": 16,
        "requires": ["domain"],
        "mitre": ["T1071", "T1568", "T1048"],
        "category": "DNS",
        "spl": 'index=* (sourcetype=*dns* OR sourcetype=stream:dns) query="$domain$" earliest=$earliest$ latest=$latest$ '
        "| stats count dc(src) as srcs values(src) as srcs_sample by query, query_type, reply_code "
        "| sort -count",
    },
    {
        "template_id": "web_url",
        "name": "Proxy / web access to the URL or domain",
        "purpose": "User-agent, status, and bytes for the suspected URL.",
        "evidence_class": "c2_beacon",
        "direction": "supporting",
        "base_weight": 62,
        "priority": 20,
        "requires": ["url"],
        "mitre": ["T1071", "T1102", "T1566"],
        "category": "Web",
        "spl": 'index=* (`cim_web_indexes`) url="$url$" earliest=$earliest$ latest=$latest$ '
        "| stats count values(status) as status values(http_user_agent) as ua sum(bytes) as bytes by src, user, url, dest",
    },
    {
        "template_id": "web_domain",
        "name": "Web requests to the domain",
        "purpose": "Broader than the exact URL: every request to the suspected domain.",
        "evidence_class": "c2_beacon",
        "direction": "supporting",
        "base_weight": 58,
        "priority": 22,
        "requires": ["domain"],
        "mitre": ["T1071", "T1102"],
        "category": "Web",
        "spl": 'index=* (`cim_web_indexes`) (url="*$domain$*" OR dest="$domain$") earliest=$earliest$ latest=$latest$ '
        "| stats count dc(url) as urls sum(bytes) as bytes by src, user, dest",
    },
    {
        "template_id": "endpoint_process",
        "name": "Process execution on the host",
        "purpose": "Confirm the process, parent, and command line on the impacted endpoint.",
        "evidence_class": "credential_access",
        "direction": "supporting",
        "base_weight": 74,
        "priority": 11,
        "requires": ["process"],
        "mitre": ["T1059", "T1003", "T1218", "T1053"],
        "category": "Endpoint",
        "spl": 'index=* (`cim_endpoint_indexes`) (host="$src$" OR dest="$dest$" OR src="$src$") process_name="$process$" earliest=$earliest$ latest=$latest$ '
        "| stats count values(parent_process_name) as parents values(user) as users dc(command_line) as cmds by dest, process_name "
        "| sort -count",
    },
    {
        "template_id": "endpoint_commandline",
        "name": "Encoded or suspicious command lines",
        "purpose": "Catch encoded PowerShell, rundll32, and LOLBins around the finding.",
        "evidence_class": "credential_access",
        "direction": "supporting",
        "base_weight": 80,
        "priority": 9,
        "requires": ["src"],
        "mitre": ["T1059", "T1027", "T1218"],
        "category": "Endpoint",
        "spl": '(index=* host="$src$" OR dest="$src$") earliest=$earliest$ latest=$latest$ '
        "(powershell OR cmd.exe OR rundll32 OR mshta OR wscript OR cscript OR pwsh) "
        '(EncodedCommand OR -enc OR -nop OR FromBase64String OR IEX OR Invoke-Expression OR DownloadString) '
        "| table _time, host, user, process_name, parent_process_name, command_line",
    },
    {
        "template_id": "hash_prevalence",
        "name": "File hash prevalence",
        "purpose": "First-seen hashes and low-prevalence files are stronger malware evidence.",
        "evidence_class": "malware_hash",
        "direction": "supporting",
        "base_weight": 88,
        "priority": 8,
        "requires": ["file_hash"],
        "mitre": ["T1204", "T1105", "T1027"],
        "category": "Malware",
        "spl": 'index=* (file_hash="$file_hash$" OR sha256="$file_hash$" OR sha1="$file_hash$" OR md5="$file_hash$") earliest=-30d latest=$latest$ '
        "| stats min(_time) as first_seen max(_time) as last_seen dc(dest) as hosts values(file_name) as names count",
    },
    {
        "template_id": "email_for_user",
        "name": "Email delivery for the user",
        "purpose": "Phishing delivery evidence: sender, subject, attachments, URLs.",
        "evidence_class": "phishing",
        "direction": "supporting",
        "base_weight": 60,
        "priority": 24,
        "requires": ["user"],
        "mitre": ["T1566"],
        "category": "Email",
        "spl": 'index=* (`cim_email_indexes`) (recipient="$user$" OR src_user="$user$" OR user="$user$") earliest=$earliest$ latest=$latest$ '
        "| stats count values(subject) as subjects values(src_user) as senders values(url) as urls by recipient",
    },
    {
        "template_id": "threat_intel_lookup",
        "name": "Threat intelligence match on entities",
        "purpose": "Check ES threat intel / threat activity for IPs, domains, hashes, and URLs.",
        "evidence_class": "threat_intel_match",
        "direction": "supporting",
        "base_weight": 90,
        "priority": 5,
        "requires": [],
        "mitre": [],
        "category": "Threat intel",
        "spl": '| from datamodel:"Threat_Intelligence.Threat_Activity" '
        '| search threat_match_value IN ("$src_ip$","$dest_ip$","$domain$","$url$","$file_hash$","$threat_object$") '
        "| stats count values(threat_collection) as collections values(threat_category) as categories by threat_match_value, threat_match_field",
    },
    {
        "template_id": "related_findings_entity",
        "name": "Related ES findings for the entity",
        "purpose": "Corroborate with other findings / notables on the same user, host, or threat object.",
        "evidence_class": "related_findings",
        "direction": "supporting",
        "base_weight": 72,
        "priority": 6,
        "requires": ["risk_object"],
        "mitre": [],
        "category": "ES findings",
        "spl": 'index=notable (user="$user$" OR src="$src$" OR dest="$dest$" OR risk_object="$risk_object$" OR threat_object="$threat_object$") earliest=-7d latest=$latest$ '
        '| search event_id!="$finding_id$" '
        "| stats count dc(rule_name) as detections values(rule_title) as titles max(urgency) as urgency by user, src, dest "
        "| sort -count",
    },
    {
        "template_id": "intermediate_findings_risk",
        "name": "Intermediate findings (risk events) for the entity",
        "purpose": "RBA context: contributing intermediate findings and risk score trend.",
        "evidence_class": "related_findings",
        "direction": "supporting",
        "base_weight": 68,
        "priority": 7,
        "requires": ["risk_object"],
        "mitre": [],
        "category": "Risk",
        "spl": 'index=risk risk_object="$risk_object$" earliest=-7d latest=$latest$ '
        "| stats sum(risk_score) as risk_score dc(source) as detections values(risk_message) as messages by risk_object, risk_object_type "
        "| sort -risk_score",
    },
    {
        "template_id": "asset_context",
        "name": "Asset lookup for involved hosts",
        "purpose": "Owner, category, priority, and whether the asset is a DC / crown jewel.",
        "evidence_class": "critical_asset",
        "direction": "supporting",
        "base_weight": 55,
        "priority": 30,
        "requires": ["dest"],
        "mitre": [],
        "category": "Asset",
        "spl": '| inputlookup append=t asset_lookup_by_str where ip="$dest$" OR nt_host="$dest$" OR dns="$dest$" '
        "| append [| inputlookup asset_lookup_by_str where ip=\"$src$\" OR nt_host=\"$src$\"] "
        "| table ip, nt_host, dns, owner, priority, category, bunit, lat, long",
    },
    {
        "template_id": "identity_context",
        "name": "Identity lookup for the user",
        "purpose": "Watchlist, privileged, executive, and category flags from ES identities.",
        "evidence_class": "privileged_account",
        "direction": "supporting",
        "base_weight": 58,
        "priority": 28,
        "requires": ["user"],
        "mitre": ["T1078", "T1003"],
        "category": "Identity",
        "spl": '| inputlookup identity_lookup_expanded where identity="$user$" OR nick="$user$" OR email="$user$" '
        "| table identity, first, last, email, category, watchlist, priority, bunit, phone",
    },
    {
        "template_id": "windows_4688_around",
        "name": "Windows process creation (4688 / Sysmon 1)",
        "purpose": "Full process tree on the host during the window.",
        "evidence_class": "credential_access",
        "direction": "supporting",
        "base_weight": 70,
        "priority": 13,
        "requires": ["src"],
        "mitre": ["T1059", "T1003", "T1053", "T1547"],
        "category": "Endpoint",
        "spl": 'index=* (EventCode=4688 OR EventCode=1) (host="$src$" OR dest="$src$" OR Computer="$src$") earliest=$earliest$ latest=$latest$ '
        "| table _time, host, user, process_name, parent_process_name, command_line "
        "| sort _time",
    },
    {
        "template_id": "lateral_4624_type3",
        "name": "Network logons (possible lateral movement)",
        "purpose": "Type 3 / type 10 logons from the source onto other hosts.",
        "evidence_class": "lateral_movement",
        "direction": "supporting",
        "base_weight": 76,
        "priority": 14,
        "requires": ["src_ip"],
        "mitre": ["T1021"],
        "category": "Authentication",
        "spl": 'index=* EventCode=4624 (Logon_Type=3 OR Logon_Type=10 OR LogonType=3 OR LogonType=10) src="$src_ip$" earliest=$earliest$ latest=$latest$ '
        "| stats count dc(dest) as dests values(dest) as dest_sample values(user) as users by src, Logon_Type "
        "| sort -dests",
    },
    {
        "template_id": "large_outbound",
        "name": "Large outbound transfer from the source",
        "purpose": "Exfiltration evidence: unusual bytes out in the window.",
        "evidence_class": "exfiltration",
        "direction": "supporting",
        "base_weight": 74,
        "priority": 17,
        "requires": ["src_ip"],
        "mitre": ["T1048", "T1567", "T1030"],
        "category": "Network",
        "spl": 'index=* (`cim_network_traffic_indexes`) src="$src_ip$" earliest=$earliest$ latest=$latest$ '
        "| stats sum(bytes_out) as bytes_out dc(dest) as dests by src, dest "
        "| where bytes_out>5000000 "
        "| sort -bytes_out",
    },
    {
        "template_id": "impossible_travel",
        "name": "Authentication geography for the user",
        "purpose": "Impossible travel / new country evidence.",
        "evidence_class": "auth_anomaly",
        "direction": "supporting",
        "base_weight": 72,
        "priority": 19,
        "requires": ["user"],
        "mitre": ["T1078", "T1110"],
        "category": "Authentication",
        "spl": 'index=* user="$user$" (action=success OR EventCode=4624 OR sourcetype=*noninteractive*) earliest=-24h latest=$latest$ '
        "| iplocation src "
        "| stats dc(Country) as countries values(Country) as country_list values(City) as cities dc(src) as srcs by user "
        "| where countries>=2",
    },
    {
        "template_id": "crowdstrike_or_endpoint_alert",
        "name": "Endpoint security alerts on the host",
        "purpose": "Corroborate with CrowdStrike / Defender / ES endpoint detections.",
        "evidence_class": "malware_hash",
        "direction": "supporting",
        "base_weight": 80,
        "priority": 12,
        "requires": ["src"],
        "mitre": ["T1204", "T1059"],
        "category": "Endpoint",
        "spl": 'index=* (sourcetype=crowdstrike:* OR sourcetype=ms:defender:* OR sourcetype=*sysmon*) (ComputerName="$src$" OR host="$src$" OR dest="$src$") earliest=$earliest$ latest=$latest$ '
        "| stats count values(event_simpleName) as events values(DetectName) as detects by host, user",
    },
    {
        "template_id": "soar_investigation_note",
        "name": "Triage agent / investigation notes",
        "purpose": "Pull notes attached to the finding, including Triage agent analysis text.",
        "evidence_class": "triage_narrative",
        "direction": "supporting",
        "base_weight": 40,
        "priority": 40,
        "requires": ["finding_id"],
        "mitre": [],
        "category": "Triage",
        "spl": '| rest splunk_server=local "/servicesNS/nobody/missioncontrol/public/v2/findings/$finding_id$/notes?search_format=true" '
        "| table id, created, author, body",
    },
]


def templates_as_rows() -> list[dict[str, str]]:
    rows = []
    for item in SEARCH_TEMPLATES:
        rows.append(
            {
                "template_id": item["template_id"],
                "name": item["name"],
                "purpose": item["purpose"],
                "evidence_class": item["evidence_class"],
                "direction": item["direction"],
                "base_weight": str(item["base_weight"]),
                "priority": str(item["priority"]),
                "requires": ";".join(item["requires"]),
                "mitre": ";".join(item["mitre"]),
                "category": item["category"],
                "spl": item["spl"],
            }
        )
    return rows
