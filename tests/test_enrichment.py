#!/usr/bin/env python3
"""Tests for judge-store UI, finding enrichment, and REST handlers."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "es_finding_evidence", "bin"))
sys.path.insert(0, ROOT)

from lib.agent import FindingEvidenceAgent  # noqa: E402
from lib.enrichment import ENRICHMENT_MARKER, build_enrichment, build_note, compact_fields  # noqa: E402
from lib.demo import is_demo_finding_id  # noqa: E402
from lib.es_client import ESClient, ESClientError  # noqa: E402
from lib.judge_store import (  # noqa: E402
    delete_python_file,
    merge_kv_judges,
    record_from_payload,
    sanitize_name,
    validate_python,
    write_python_file,
)
from lib.judges.loader import load_judges  # noqa: E402
from rest_agent import AgentRunHandler, EnrichmentHandler, JudgesHandler  # noqa: E402

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "es_finding_evidence"))

GOOD_PY = (
    "def judge(finding, evidence, searches, context):\n"
    "    if finding.get('user') == 'admin':\n"
    "        return {'score': 85, 'decision': 'Yes', 'mode': 'override', 'rationale': 'admin'}\n"
    "    return {'abstain': True}\n"
)


class JudgeStoreTests(unittest.TestCase):
    def test_sanitize_name(self):
        self.assertEqual(sanitize_name("VipUser"), "VipUser")
        with self.assertRaises(ValueError):
            sanitize_name("../etc")
        with self.assertRaises(ValueError):
            sanitize_name("1bad")

    def test_validate_python_accepts_judge(self):
        self.assertIn("def judge(", validate_python(GOOD_PY))

    def test_validate_python_rejects_dangerous(self):
        with self.assertRaises(ValueError):
            validate_python("def judge(finding, evidence, searches, context):\n    eval('1')\n")
        with self.assertRaises(ValueError):
            validate_python("import os\ndef judge(finding, evidence, searches, context):\n    return {}\n")
        with self.assertRaises(ValueError):
            validate_python("def judge(finding, evidence, searches, context):\n    open('/etc/passwd')\n")
        with self.assertRaises(ValueError):
            validate_python("def nope(finding, evidence, searches, context):\n    return {}\n")

    def test_record_and_write_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = record_from_payload(
                {
                    "name": "VipCheck",
                    "type": "python",
                    "mode": "override",
                    "weight": 0.9,
                    "python": GOOD_PY,
                }
            )
            path = write_python_file(record, tmp)
            self.assertTrue(path.endswith(os.path.join("local", "judges", "VipCheck.py")))
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as handle:
                self.assertIn("def judge(", handle.read())
            delete_python_file("VipCheck", tmp)
            self.assertFalse(os.path.isfile(path))

    def test_merge_kv_rule_overrides(self):
        records = [
            {
                "name": "force_high",
                "type": "rule",
                "enabled": 1,
                "mode": "override",
                "when_urgency": "high",
                "decision": "Yes",
                "score": 88,
                "weight": 1,
            }
        ]
        merged = merge_kv_judges(load_judges(APP), records, APP)
        names = {item.name for item in merged}
        self.assertIn("force_high", names)


class EnrichmentPayloadTests(unittest.TestCase):
    def test_note_and_fields(self):
        row = {
            "finding_id": "F-1001",
            "title": "Credential dump",
            "followup_score": 81,
            "investigation_required": "Yes",
            "investigation_label": "Investigation required",
            "triage_disposition": "true_positive",
            "rationale": "High urgency with supporting evidence.",
            "evidence_json": json.dumps(
                [{"signed_weight": 12.5, "title": "procdump targeting lsass.exe", "class": "credential_access"}]
            ),
            "executed_searches_json": json.dumps([{"search_name": "process", "count": 3}]),
            "judges_json": json.dumps(
                [{"name": "followup_score", "mode": "vote", "score": 81, "decision": "Yes", "rationale": "mix"}]
            ),
            "executed_search_count": 2,
            "recommended_search_count": 6,
            "evidence_net_weight": 18,
        }
        note = build_note(row)
        self.assertIn(ENRICHMENT_MARKER, note)
        self.assertIn("```fea-enrichment", note)
        self.assertIn("procdump targeting lsass.exe", note)
        self.assertIn("+12.5", note)
        payload = build_enrichment(row)
        self.assertEqual(payload["fea_followup_score"], 81)
        self.assertEqual(payload["fea_investigation_required"], "Yes")
        self.assertIn("fea_judges_json", payload)
        compact = compact_fields(row)
        self.assertTrue(all(not key.endswith("_json") for key in compact))
        self.assertIn("fea_agent_summary", compact)

    def test_update_finding_fields_blocks_workflow(self):
        client = ESClient("https://127.0.0.1:8089", "session")
        posted = []

        def _post(path, payload):
            posted.append((path, dict(payload)))
            return {}

        client._post_json = _post  # type: ignore[method-assign]
        client.update_finding_fields(
            "F-1",
            {"fea_followup_score": 70, "status": "closed", "owner": "soc", "disposition": "true_positive", "urgency": "low"},
        )
        self.assertEqual(len(posted), 1)
        fields = posted[0][1]
        self.assertEqual(fields.get("fea_followup_score"), 70)
        self.assertNotIn("status", fields)
        self.assertNotIn("owner", fields)
        self.assertNotIn("disposition", fields)
        self.assertNotIn("urgency", fields)

    def test_enrich_finding_posts_note_and_fields(self):
        client = ESClient("https://127.0.0.1:8089", "session")
        calls = {"fields": 0, "notes": 0}
        client.update_finding_fields = lambda *_a, **_k: calls.__setitem__("fields", calls["fields"] + 1)  # type: ignore[method-assign]
        client.post_note = lambda *_a, **_k: calls.__setitem__("notes", calls["notes"] + 1)  # type: ignore[method-assign]
        result = client.enrich_finding("F-1", {"fea_followup_score": 40}, "note body")
        self.assertTrue(result["fields"])
        self.assertTrue(result["note"])
        self.assertEqual(calls["fields"], 1)
        self.assertEqual(calls["notes"], 1)


class AgentEnrichTests(unittest.TestCase):
    def test_enrich_task_posts_payload_before_persist(self):
        posted = []
        persisted = []

        def enricher(row):
            row["enrichment_posted"] = 1
            row["enrichment_note"] = build_note(row)
            posted.append(row["finding_id"])

        def persister(rows):
            persisted.extend(int(r.get("enrichment_posted") or 0) for r in rows)

        agent = FindingEvidenceAgent(
            mode="demo",
            tasks=("score", "enrich", "persist", "emit"),
            run_searches=False,
            finding_id="F-1005",
            limit=1,
            home=APP,
            enricher=enricher,
            persister=persister,
        )
        cycle = agent.run()
        self.assertEqual(cycle["count"], 1)
        self.assertEqual(posted, ["F-1005"])
        self.assertEqual(persisted, [1])
        self.assertEqual(cycle["results"][0]["enrichment_posted"], 1)
        self.assertIn(ENRICHMENT_MARKER, cycle["results"][0]["enrichment_note"])


class RestHandlerTests(unittest.TestCase):
    def test_get_judges(self):
        raw = JudgesHandler().handle(json.dumps({"method": "GET"}))
        payload = json.loads(raw["payload"])
        self.assertIn("judges", payload)
        names = {item["name"] for item in payload["judges"]}
        self.assertIn("followup_score", names)

    def test_post_judge_without_session_is_401(self):
        raw = JudgesHandler().handle(
            json.dumps({"method": "POST", "payload": json.dumps({"name": "force_x", "type": "rule"})})
        )
        self.assertEqual(raw["status"], 401)

    def test_post_and_delete_rule_with_memory_kv(self):
        store = {}

        class Mem:
            def list(self):
                return list(store.values())

            def put(self, key, record):
                store[key] = dict(record)
                store[key]["_key"] = key

            def delete(self, key):
                store.pop(key, None)

        import rest_agent as ra

        original = ra._kv_judges

        def fake(_uri, _session):
            col = Mem()
            return col, col.list()

        ra._kv_judges = fake
        try:
            created = JudgesHandler().handle(
                json.dumps(
                    {
                        "method": "POST",
                        "session": {"key": "sess", "server_uri": "https://127.0.0.1:8089"},
                        "payload": json.dumps(
                            {
                                "name": "force_ui",
                                "type": "rule",
                                "mode": "override",
                                "when_urgency": "critical",
                                "decision": "Yes",
                                "score": 91,
                                "rationale": "ui rule",
                            }
                        ),
                    }
                )
            )
            body = json.loads(created["payload"])
            self.assertTrue(body.get("ok"))
            self.assertEqual(body["judge"]["name"], "force_ui")
            self.assertIn("force_ui", store)
            deleted = JudgesHandler().handle(
                json.dumps(
                    {
                        "method": "DELETE",
                        "session": {"key": "sess", "server_uri": "https://127.0.0.1:8089"},
                        "query": [["name", "force_ui"]],
                    }
                )
            )
            self.assertEqual(json.loads(deleted["payload"]).get("deleted"), "force_ui")
            self.assertNotIn("force_ui", store)
        finally:
            ra._kv_judges = original

    def test_python_eval_rejected(self):
        store = {}

        class Mem:
            def list(self):
                return list(store.values())

            def put(self, key, record):
                store[key] = dict(record)

            def delete(self, key):
                store.pop(key, None)

        import rest_agent as ra

        original = ra._kv_judges
        ra._kv_judges = lambda *_a, **_k: (Mem(), [])
        try:
            raw = JudgesHandler().handle(
                json.dumps(
                    {
                        "method": "POST",
                        "session": {"key": "sess"},
                        "payload": json.dumps(
                            {
                                "name": "badEval",
                                "type": "python",
                                "python": "def judge(finding, evidence, searches, context):\n    return eval('1')\n",
                            }
                        ),
                    }
                )
            )
            self.assertEqual(raw["status"], 400)
            self.assertIn("eval", json.loads(raw["payload"])["error"])
        finally:
            ra._kv_judges = original

    def test_agent_run_demo(self):
        raw = AgentRunHandler().handle(
            json.dumps(
                {
                    "method": "POST",
                    "payload": json.dumps(
                        {
                            "mode": "demo",
                            "limit": 1,
                            "finding_id": "F-1005",
                            "run_searches": "false",
                            "tasks": "score,emit",
                        }
                    ),
                }
            )
        )
        body = json.loads(raw["payload"])
        self.assertTrue(body.get("ok"))
        self.assertEqual(body.get("count"), 1)

    def test_enrichment_requires_auth(self):
        raw = EnrichmentHandler().handle(json.dumps({"method": "GET"}))
        self.assertEqual(raw["status"], 401)


class DashboardXmlTests(unittest.TestCase):
    def test_views_parse(self):
        from xml.etree.ElementTree import parse

        views = os.path.join(APP, "default", "data", "ui", "views")
        for name in ("judge_manager.xml", "agent_ops.xml", "finding_workbench.xml", "overview.xml"):
            parse(os.path.join(views, name))
            if name == "overview.xml":
                with open(os.path.join(views, name), encoding="utf-8") as handle:
                    text = handle.read()
                self.assertNotIn('match(investigation_required,"$decision$")', text)
                self.assertIn('"$decision$"="*" OR investigation_required="$decision$"', text)


class DemoFindingLookupTests(unittest.TestCase):
    def test_sample_ids(self):
        self.assertTrue(is_demo_finding_id("F-1001"))
        self.assertTrue(is_demo_finding_id("F-1012"))
        self.assertFalse(is_demo_finding_id(""))
        self.assertFalse(is_demo_finding_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890"))

    def test_loadfindings_rest_does_not_call_es_for_demo_id(self):
        from loadfindings import LoadFindingsCommand

        cmd = LoadFindingsCommand("loadfindings")
        cmd.options = {"mode": "rest", "finding_id": "F-1001", "limit": "1"}

        def boom(*_a, **_k):
            raise AssertionError("ES should not be called for bundled demo finding ids")

        cmd._from_es = boom  # type: ignore[method-assign]
        rows = list(cmd.generate())
        self.assertEqual(rows[0]["finding_id"], "F-1001")
        self.assertIn(rows[0]["investigation_required"], {"Yes", "Review", "No"})

    def test_agent_rest_demo_id_skips_es(self):
        agent = FindingEvidenceAgent(
            mode="rest",
            finding_id="F-1001",
            tasks=("score", "emit"),
            run_searches=False,
            limit=1,
            home=APP,
            session_key="sess",
            splunkd_uri="https://127.0.0.1:8089",
        )
        cycle = agent.run()
        self.assertEqual(cycle["count"], 1)
        self.assertEqual(cycle["results"][0]["finding_id"], "F-1001")

    def test_get_finding_400_is_empty(self):
        client = ESClient("https://127.0.0.1:8089", "session")

        def _get(path, params=None):
            raise ESClientError(f"ES API 400 for {path}", status=400)

        client._get = _get  # type: ignore[method-assign]
        self.assertEqual(client.get_finding("F-1001"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
