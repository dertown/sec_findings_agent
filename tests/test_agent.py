#!/usr/bin/env python3
"""Tests for the backend agent and custom judges."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "es_finding_evidence", "bin"))
sys.path.insert(0, ROOT)

from lib.agent import FindingEvidenceAgent  # noqa: E402
from lib.demo import sample_findings  # noqa: E402
from lib.findings import normalize_finding  # noqa: E402
from lib.judges.ensemble import run_judges  # noqa: E402
from lib.judges.loader import load_judges  # noqa: E402
from lib.paths import app_home, judge_roots, safe_py_path  # noqa: E402
from lib.search_runner import DemoSearchRunner  # noqa: E402


APP = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "es_finding_evidence"))


class PathSafetyTests(unittest.TestCase):
    def test_rejects_outside_app(self):
        roots = judge_roots(APP)
        with self.assertRaises(ValueError):
            safe_py_path("/etc/passwd", roots)
        with self.assertRaises(ValueError):
            safe_py_path("../../../../etc/hosts.py", roots)

    def test_allows_bundled_example(self):
        path = safe_py_path("example_vip_user.py", judge_roots(APP))
        self.assertTrue(path.endswith("example_vip_user.py"))
        self.assertTrue(os.path.isfile(path))


class JudgeLoaderTests(unittest.TestCase):
    def test_builtin_judges_load(self):
        loaded = load_judges(APP)
        names = {item.name for item in loaded if item.enabled}
        self.assertIn("followup_score", names)
        self.assertIn("triage_guardrail", names)
        self.assertIn("critical_asset", names)
        disabled = {item.name for item in loaded if not item.enabled}
        self.assertIn("example_vip_user", disabled)

    def test_rule_judge_override(self):
        conf = """
[followup_score]
type = builtin
class = FollowupScoreJudge
weight = 1
mode = vote
enabled = 1

[force_medium]
type = rule
enabled = 1
mode = override
when_urgency = medium
decision = Yes
score = 77
rationale = test rule
"""
        judges = load_judges(APP, conf_text=conf)
        finding = normalize_finding(sample_findings()[6])  # F-1007 medium
        overlay = run_judges(finding, judges=judges, home=APP)
        self.assertEqual(overlay["investigation_required"], "Yes")
        self.assertEqual(overlay["followup_score"], 77)
        self.assertEqual(overlay["override_applied"], "force_medium")

    def test_python_vip_judge(self):
        conf = """
[default]
auto_load_local = 0

[example_vip_user]
enabled = 1
type = python
file = example_vip_user.py
function = judge
mode = override
weight = 1
"""
        judges = load_judges(APP, conf_text=conf)
        finding = normalize_finding(sample_findings()[6])  # c.okonkwo
        overlay = run_judges(finding, judges=judges, home=APP)
        self.assertEqual(overlay["investigation_required"], "Yes")
        self.assertEqual(overlay["override_applied"], "example_vip_user")

    def test_local_auto_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = os.path.join(tmp, "local", "judges")
            os.makedirs(local)
            with open(os.path.join(local, "always_review.py"), "w", encoding="utf-8") as handle:
                handle.write(
                    "def judge(finding, evidence, searches, context):\n"
                    "    return {'decision': 'Review', 'score': 40, 'mode': 'override', 'rationale': 'auto'}\n"
                )
            open(os.path.join(tmp, "judges.conf"), "w", encoding="utf-8").close()
            os.makedirs(os.path.join(tmp, "default"), exist_ok=True)
            with open(os.path.join(tmp, "default", "judges.conf"), "w", encoding="utf-8") as handle:
                handle.write("[default]\nauto_load_local = 1\n")
            judges = load_judges(tmp)
            names = {item.name for item in judges}
            self.assertIn("always_review", names)


class AgentTests(unittest.TestCase):
    def test_demo_cycle_runs_searches_and_judges(self):
        agent = FindingEvidenceAgent(
            mode="demo",
            tasks=("gather_evidence", "score", "emit"),
            run_searches=True,
            max_searches_per_finding=3,
            limit=3,
            home=APP,
            search_runner=DemoSearchRunner({"finding_id": "F-1001"}),
        )
        cycle = agent.run()
        self.assertGreaterEqual(cycle["count"], 3)
        self.assertFalse(cycle["errors"])
        first = cycle["results"][0]
        self.assertIn(first["investigation_required"], {"Yes", "Review", "No"})
        self.assertGreaterEqual(int(first.get("executed_search_count") or 0), 1)
        self.assertIn("judges_json", first)

    def test_score_only_skips_searches(self):
        agent = FindingEvidenceAgent(
            mode="demo",
            tasks=("score", "emit"),
            run_searches=False,
            finding_id="F-1005",
            limit=1,
            home=APP,
        )
        cycle = agent.run()
        self.assertEqual(cycle["count"], 1)
        self.assertEqual(int(cycle["results"][0].get("executed_search_count") or 0), 0)
        self.assertEqual(cycle["results"][0]["investigation_required"], "No")


class ModularInputTests(unittest.TestCase):
    def test_scheme(self):
        from finding_evidence_agent import SCHEME, parse_input, run_once

        self.assertIn("Finding Evidence Agent", SCHEME)
        xml = """
        <input>
          <server_uri>https://127.0.0.1:8089</server_uri>
          <session_key></session_key>
          <configuration>
            <stanza name="finding_evidence_agent://default">
              <param name="mode">demo</param>
              <param name="limit">1</param>
              <param name="run_searches">true</param>
              <param name="tasks">gather_evidence,score,emit</param>
            </stanza>
          </configuration>
        </input>
        """
        cfg = parse_input(xml)
        self.assertEqual(cfg["params"]["mode"], "demo")
        out = run_once(xml)
        self.assertIn("fea:agent:cycle", out)
        self.assertIn("fea:agent:result", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
