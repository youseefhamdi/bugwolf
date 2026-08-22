#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.chain_orchestrator import orchestrate, refresh_target, _persist


class TestChainOrchestrator(unittest.TestCase):
    def _finding(self, finding_id, bug_class, endpoint, severity="medium", status="confirmed"):
        return {
            "finding_id": finding_id,
            "bug_class": bug_class,
            "title": bug_class,
            "endpoint": endpoint,
            "method": "GET",
            "severity": severity,
            "status": status,
            "evidence": "redacted controlled observation",
        }

    def test_missing_links_become_continuation_tasks(self):
        result = orchestrate([
            self._finding("F1", "idor", "/api/users/1", "low"),
        ], [], max_hops=4)
        self.assertTrue(result["chains"])
        chain = next(item for item in result["chains"]
                     if item["path"][-1] == "account-takeover")
        self.assertEqual(chain["state"], "blocked_missing_link")
        self.assertIn("mass-assignment", chain["missing_links"])
        self.assertTrue(chain["validation_queue"])
        self.assertEqual(chain["validation_queue"][0]["status"], "blocked_missing_link")
        self.assertEqual(result["resume"]["chain_id"],
                         result["chains"][0]["chain_id"])
        self.assertTrue(chain["gates"]["explicit_scope_required"])
        self.assertFalse(chain["gates"]["automatic_execution"])

    def test_full_chain_is_resolved_but_never_auto_executed(self):
        findings = [
            self._finding("F1", "idor", "/api/users/1", "low"),
            self._finding("F2", "mass-assignment", "/api/users/1", "medium"),
            self._finding("F3", "privilege-escalation-web", "/api/users/1", "high"),
            self._finding("F4", "account-takeover", "/api/users/1", "critical"),
        ]
        result = orchestrate(findings, [], max_hops=4)
        chain = next(item for item in result["chains"]
                     if item["path"] == [
                         "idor", "mass-assignment", "privilege-escalation-web",
                         "account-takeover",
                     ])
        self.assertEqual(chain["state"], "ready_for_gated_validation")
        self.assertEqual(chain["missing_links"], [])
        self.assertEqual(chain["evidence_gaps"], [])
        self.assertEqual(chain["impact"], "account takeover / impersonation")
        self.assertEqual(
            [item["status"] for item in chain["validation_queue"]],
            ["pending_gated_validation"] * 3,
        )
        self.assertFalse(chain["gates"]["automatic_execution"])
        self.assertTrue(chain["gates"]["human_review_required"])

    def test_leads_and_findings_deduplicate_nodes_and_chains_are_bounded(self):
        result = orchestrate([
            self._finding("F1", "open_redirect", "/login/redirect", "medium"),
            self._finding("F2", "oauth-bypass", "/oauth/callback", "high"),
        ], [
            {"lead_id": "L1", "title": "Open redirect follow-up", "bug_class": "open_redirect",
             "state": "PARKED", "trigger_half": "proven", "impact_half": "untraced"},
        ], max_hops=4, max_chains=2)
        self.assertLessEqual(len(result["chains"]), 2)
        self.assertEqual(len({node["node_id"] for node in result["nodes"]}), len(result["nodes"]))
        self.assertGreaterEqual(result["stats"]["blocked_chains"], 0)

    def test_refresh_target_uses_the_hunt_state_store_and_persists_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "state" / "sessions" / "example.test"
            session.mkdir(parents=True)
            (session / "findings.jsonl").write_text(json.dumps(
                self._finding("F1", "idor", "/api/users/1", "low")) + "\n")
            result = refresh_target(root, "example.test")
            self.assertEqual(result["stats"]["nodes"], 1)
            self.assertTrue(result["persistence"]["orchestration"].endswith(
                "state/chains/example.test/orchestration.json"))
            saved = json.loads(Path(result["persistence"]["orchestration"]).read_text())
            self.assertEqual(saved["target"], "example.test")
            self.assertTrue(saved["chains"])

    def test_persistence_is_target_local_and_hash_linked(self):
        result = orchestrate([
            self._finding("F1", "ssrf", "/api/fetch", "high"),
        ], [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = _persist(root, "example.test", result)
            second = _persist(root, "example.test", result)
            output = Path(first["orchestration"])
            history = Path(second["history"])
            self.assertTrue(output.is_file())
            self.assertTrue(history.is_file())
            self.assertEqual(len(history.read_text().splitlines()), 2)
            records = [json.loads(line) for line in history.read_text().splitlines()]
            self.assertEqual(records[1]["previous_hash"], records[0]["record_hash"])
            self.assertNotIn("payload", output.read_text())


if __name__ == "__main__":
    unittest.main()
