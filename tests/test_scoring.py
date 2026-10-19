#!/usr/bin/env python3
"""Unit tests for Finding Evidence Advisor scoring and search recommendations."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "es_finding_evidence", "bin"))
sys.path.insert(0, ROOT)

from lib.analyze import analyze_records, demo_records  # noqa: E402
from lib.chunked import ChunkedCommand  # noqa: E402
from lib.demo import sample_findings  # noqa: E402
from lib.findings import normalize_finding  # noqa: E402
from lib.recommendations import recommend_searches  # noqa: E402
from lib.scoring import analyze_finding  # noqa: E402
from lib.triage import normalize_triage  # noqa: E402
from lib.util import normalize_disposition, sha256_id  # noqa: E402


class DispositionTests(unittest.TestCase):
    def test_true_positive_labels(self):
        self.assertEqual(normalize_disposition("True Positive - Suspicious Activity"), "true_positive")
        self.assertEqual(normalize_disposition("tp"), "true_positive")

    def test_false_and_benign(self):
        self.assertEqual(normalize_disposition("False Positive - Incorrect Analytic Logic"), "false_positive")
        self.assertEqual(normalize_disposition("Benign Positive - Suspicious But Expected"), "benign_positive")

    def test_empty_is_undetermined(self):
        self.assertEqual(normalize_disposition(""), "undetermined")


class FindingNormalizeTests(unittest.TestCase):
    def test_hash_threat_object_fills_file_hash(self):
        finding = normalize_finding(
            {
                "event_id": "n1",
                "rule_title": "hash hit",
                "threat_object": "ab" * 32,
                "threat_object_type": "hash",
                "urgency": "high",
            }
        )
        self.assertEqual(finding["finding_id"], "n1")
        self.assertEqual(finding["file_hash"], "ab" * 32)

    def test_src_ip_from_src(self):
        finding = normalize_finding({"id": "n2", "src": "10.1.2.3", "rule_title": "x"})
        self.assertEqual(finding["src_ip"], "10.1.2.3")


class TriageTests(unittest.TestCase):
    def test_nested_and_flat_fields(self):
        triage = normalize_triage(
            {
                "triage_disposition": "True Positive - Suspicious Activity",
                "triage_summary": "bad",
                "triage_tools": [{"name": "VirusTotal", "result": "malicious"}],
            }
        )
        self.assertTrue(triage["present"])
        self.assertEqual(triage["disposition"], "true_positive")
        self.assertEqual(triage["connectors_used"], ["VirusTotal"])

    def test_notes_json(self):
        triage = normalize_triage(
            {
                "notes": [
                    json.dumps(
                        {
                            "disposition": "False Positive",
                            "summary": "scanner",
                            "evidence": ["Known Qualys scanner"],
                        }
                    )
                ]
            }
        )
        self.assertEqual(triage["disposition"], "false_positive")
        self.assertEqual(triage["evidence"][0]["direction"], "refuting")


class ScoringTests(unittest.TestCase):
    def _by_id(self):
        return {row["finding_id"]: analyze_finding(row) for row in sample_findings()}

    def test_credential_dump_requires_investigation(self):
        result = self._by_id()["F-1001"]
        self.assertEqual(result["investigation_required"], "Yes")
        self.assertGreaterEqual(result["followup_score"], 70)
        self.assertGreater(result["evidence_net_weight"], 0)

    def test_scanner_is_not_an_investigation(self):
        result = self._by_id()["F-1003"]
        self.assertEqual(result["investigation_required"], "No")
        self.assertLess(result["followup_score"], 45)
        classes = {item["class"] for item in result["evidence"]}
        self.assertNotIn("soar_malicious", classes)
        self.assertIn("known_scanner", classes)

    def test_allowlisted_hash_is_false_positive(self):
        result = self._by_id()["F-1005"]
        self.assertEqual(result["investigation_required"], "No")
        self.assertLess(result["followup_score"], 40)

    def test_beaconing_requires_investigation(self):
        result = self._by_id()["F-1006"]
        self.assertEqual(result["investigation_required"], "Yes")
        self.assertGreaterEqual(result["followup_score"], 65)

    def test_exfil_is_highest_priority(self):
        scored = self._by_id()
        self.assertEqual(scored["F-1011"]["investigation_required"], "Yes")
        self.assertGreater(scored["F-1011"]["followup_score"], scored["F-1012"]["followup_score"])

    def test_missing_triage_still_scores(self):
        result = self._by_id()["F-1012"]
        self.assertIn(result["investigation_required"], {"No", "Review"})
        self.assertFalse(result["finding"]["triage"]["present"])

    def test_impossible_travel_is_review_or_yes(self):
        result = self._by_id()["F-1007"]
        self.assertIn(result["investigation_required"], {"Review", "Yes"})

    def test_psexec_change_window_not_forced_yes(self):
        result = self._by_id()["F-1010"]
        self.assertNotEqual(result["investigation_required"], "Yes")

    def test_ceiling_is_at_least_live_score(self):
        for result in self._by_id().values():
            self.assertGreaterEqual(result["followup_score_ceiling"], result["followup_score"])

    def test_sha256_ids_are_stable(self):
        self.assertEqual(sha256_id("a", "b"), sha256_id("a", "b"))
        self.assertNotEqual(sha256_id("a", "b"), sha256_id("a", "c"))


class RecommendationTests(unittest.TestCase):
    def test_user_gets_auth_search(self):
        finding = normalize_finding(sample_findings()[1])
        names = [row["search_name"] for row in recommend_searches(finding)]
        self.assertTrue(any("Authentication" in name or "logon" in name.lower() for name in names))

    def test_hash_gets_prevalence_search(self):
        finding = normalize_finding(sample_findings()[3])
        ids = [row["template_id"] for row in recommend_searches(finding)]
        self.assertIn("hash_prevalence", ids)

    def test_ip_pair_gets_network_search(self):
        finding = normalize_finding(sample_findings()[5])
        ids = [row["template_id"] for row in recommend_searches(finding)]
        self.assertIn("network_src_dest", ids)

    def test_placeholders_are_substituted(self):
        finding = normalize_finding(sample_findings()[1])
        for row in recommend_searches(finding):
            self.assertNotIn("$user$", row["search"])
            self.assertNotIn("$src_ip$", row["search"])

    def test_unrun_searches_do_not_change_signed_weight(self):
        result = analyze_finding(sample_findings()[0])
        for search in result["recommended_searches"]:
            self.assertEqual(search["signed_weight"], 0.0)
            self.assertGreater(search["potential_weight"], 0)


class PipelineTests(unittest.TestCase):
    def test_demo_rows_flatten(self):
        rows = analyze_records(demo_records(), expand="none")
        self.assertEqual(len(rows), len(demo_records()))
        self.assertIn("followup_score", rows[0])
        self.assertIn("investigation_required", rows[0])

    def test_expand_searches(self):
        rows = analyze_records(demo_records()[:1], expand="searches")
        self.assertGreater(len(rows), 1)
        self.assertEqual(rows[0]["row_type"], "search")
        self.assertTrue(rows[0]["search_spl"])

    def test_expand_evidence(self):
        rows = analyze_records(demo_records()[:1], expand="evidence")
        self.assertGreater(len(rows), 1)
        self.assertEqual(rows[0]["row_type"], "evidence")


class ChunkedProtocolTests(unittest.TestCase):
    def test_generating_roundtrip(self):
        class Demo(ChunkedCommand):
            generating = True

            def generate(self):
                return [{"finding_id": "F-1", "followup_score": 80}]

        getinfo = _chunk({"action": "getinfo", "searchinfo": {"raw_args": ["mode=demo"]}}, b"")
        execute = _chunk({"action": "execute", "searchinfo": {"raw_args": ["mode=demo"]}}, b"")
        infile = io.BytesIO(getinfo + execute)
        outfile = io.BytesIO()
        Demo("loadfindings").run(infile, outfile)
        output = outfile.getvalue().decode("utf-8")
        self.assertIn("chunked 1.0", output)
        self.assertIn("F-1", output)
        self.assertIn("followup_score", output)


def _chunk(meta: dict, body: bytes) -> bytes:
    meta_bytes = json.dumps(meta).encode("utf-8")
    header = f"chunked 1.0,{len(meta_bytes)},{len(body)}\n".encode("utf-8")
    return header + meta_bytes + body


if __name__ == "__main__":
    unittest.main(verbosity=2)
