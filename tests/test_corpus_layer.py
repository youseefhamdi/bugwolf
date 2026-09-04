#!/usr/bin/env python3
"""Corpus-v3 layer tests: canonical checklists, coverage ledger gates,
new specialist agents, checklist dispatch slices, dork-plan lanes."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core import checklists  # noqa: E402
from tools.core.agent_registry import AgentRegistry, AgentRegistryError  # noqa: E402
from tools.core.coverage_ledger import CoverageLedger, CoverageError  # noqa: E402


class TestChecklistRegistry(unittest.TestCase):
    def test_inventory_shape(self):
        inv = checklists.inventory()
        self.assertEqual(inv["schema"], "bugwolf.checklists/1.0")
        self.assertGreaterEqual(inv["total"], 120)
        self.assertGreaterEqual(len(inv["lanes"]), 10)
        self.assertGreater(inv["attest_count"], 0)

    def test_ids_unique_and_canonical(self):
        ids = checklists.all_ids()
        self.assertEqual(len(ids), len(set(ids)))
        for item_id in ids:
            prefix = item_id.split("-", 1)[0]
            # lane prefix == the lane constant for every canonical item
            lane_by_prefix = {"AUTH": "auth", "ACC": "access",
                              "INF": "infra", "API": "api",
                              "LOG": "logic", "RCE": "rce",
                              "XML": "xml", "RCN": "recon",
                              "CLD": "cloud", "CLI": "client",
                              "PLT": "platform"}
            self.assertEqual(checklists.get(item_id).lane,
                             lane_by_prefix[prefix], item_id)

    def test_every_item_has_source(self):
        for item_id in checklists.all_ids():
            item = checklists.get(item_id)
            # item.source is the SOURCES key; expansion happens in inventory
            self.assertIn(item.source, checklists.SOURCES,
                          f"{item_id} source {item.source!r} unmapped")

    def test_slice_deterministic_and_deduped(self):
        a = checklists.slice_for_bug_classes(["idor", "mfa_bypass"])
        b = checklists.slice_for_bug_classes(["mfa_bypass", "idor"])
        self.assertEqual(a, b)  # order comes from the registry, not input
        self.assertEqual(len(a), len(set(a)))

    def test_attest_gate_membership(self):
        attest = set(checklists.attest_ids())
        self.assertIn("AUTH-14", attest)   # social MFA ladder
        self.assertIn("XML-07", attest)    # billion laughs
        self.assertIn("PLT-06", attest)    # PII census
        self.assertNotIn("AUTH-01", attest)

    def test_unknown_class_slice_empty_never_raises(self):
        self.assertEqual(checklists.slice_for_bug_class("nope"), [])
        self.assertEqual(checklists.slice_for_bug_classes(["nope"]), [])


class TestCoverageLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ledger = CoverageLedger(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_verdict_requires_evidence(self):
        with self.assertRaises(CoverageError):
            self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-01",
                                    "confirmed")
        rec = self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-01",
                                      "confirmed", ["EVID-0001"])
        self.assertEqual(rec["verdict"], "confirmed")

    def test_na_requires_reason(self):
        with self.assertRaises(CoverageError):
            self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-05",
                                    "n-a")
        self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-05",
                                "n-a", reason="no export feature")
        self.assertEqual(self.ledger.get_verdict(
            "https://t/a", "GET", "A", "ACC-05")["verdict"], "n-a")

    def test_attest_items_never_confirm_without_operator(self):
        with self.assertRaises(CoverageError):
            self.ledger.set_verdict("https://t/a", "GET", "A", "AUTH-14",
                                    "confirmed", ["E1"])
        # operator clearance path: n-a with an explicit reason
        self.ledger.set_verdict("https://t/a", "GET", "A", "AUTH-14",
                                "n-a", reason="operator cleared on call")

    def test_holes_skip_attest_and_flag_inconsistent(self):
        self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-01",
                                "confirmed", ["E1"])
        self.ledger.set_verdict("https://t/a", "GET", "A", "ACC-05",
                                "n-a", reason="r")
        # ACC-02 untested => hole; AUTH-14 attest => not closeable
        holes = self.ledger.holes(
            ["ACC-01", "ACC-02", "ACC-05", "AUTH-14"], "https://t/a",
            "GET", "A")
        self.assertEqual(holes, ["ACC-02"])
        # inconsistent: confirmed with no evidence (hand-crafted state)
        self.ledger._entry(self.ledger.key(
            "https://t/a", "GET", "A"))["ACC-03"] = {
            "verdict": "confirmed", "evidence": [], "reason": ""}
        self.assertIn("ACC-03", self.ledger.holes(
            ["ACC-03"], "https://t/a", "GET", "A"))

    def test_persistence_atomic_and_digest_stable(self):
        self.ledger.set_verdict("https://t/b", "POST", "A", "ACC-04",
                                "not-vuln", ["E2"])
        self.ledger.save()
        again = CoverageLedger(self.dir)
        self.assertEqual(again.digest(), self.ledger.digest())
        self.assertEqual(again.get_verdict(
            "https://t/b", "POST", "A", "ACC-04")["verdict"], "not-vuln")

    def test_summary_counts_open_closeable(self):
        self.ledger.set_verdict("https://t/c", "GET", "anon", "ACC-01",
                                "confirmed", ["E1"])
        s = self.ledger.summary(["idor"], keys=[
            self.ledger.key("https://t/c", "GET", "anon")])
        # ACC-01 confirmed; the rest of the idor slice (10 more IDs) were
        # never recorded on this endpoint and count as open/untested
        self.assertGreater(s["open_closeable"], 0)
        self.assertEqual(s["items"]["ACC-01"]["confirmed"], 1)


class TestCorpusAgents(unittest.TestCase):
    def setUp(self):
        self.reg = AgentRegistry()

    NEW_ROLES = ("mfa-bypass", "host-header", "rce-chain", "xml-xxe",
                 "shadow-surface", "platform-misconfig", "webhook-logic")

    def test_all_new_agents_registered_with_playbooks(self):
        for role in self.NEW_ROLES:
            spec = self.reg.get(role)
            self.assertTrue(spec.playbook, role)

    def test_playbook_files_exist(self):
        for role in self.NEW_ROLES:
            spec = self.reg.get(role)
            path = ROOT / "references" / "hacking-agents" / spec.playbook
            self.assertTrue(path.exists(), str(path))
            self.assertGreater(path.stat().st_size, 2000)

    def test_selection_for_new_bug_classes(self):
        routing = {
            "mfa_bypass": "mfa-bypass",
            "host_header": "host-header",
            "file_upload": "rce-chain",
            "xxe": "xml-xxe",
            "surface_expansion": "shadow-surface",
            "platform_misconfig": "platform-misconfig",
            "webhook_abuse": "webhook-logic",
        }
        for bug, role in routing.items():
            self.assertEqual(
                self.reg.select(bug_class=bug).role, role,
                f"{bug} should route to {role}")

    def test_new_agents_do_not_break_existing_routing(self):
        # pre-existing corpus pins must survive the expansion (matches
        # tests/test_multi_agent.py's own expectations)
        self.assertEqual(self.reg.select(bug_class="idor").role,
                         "access-control")
        self.assertEqual(self.reg.select(bug_class="race_condition").role,
                         "business-logic")
        self.assertEqual(self.reg.select(bug_class="jwt_attack").role,
                         "crypto-math")
        self.assertEqual(self.reg.select(domain="auth").role,
                         "access-control")

    def test_inventory_count_grew(self):
        inv = self.reg.inventory()
        self.assertGreaterEqual(inv["count"], 39)


class TestDispatchSlices(unittest.TestCase):
    """Checklist + intel slices ride the real dispatch payload."""

    def _engine(self, tmp):
        from tools.runtime.contracts import MissionSpec
        from tools.runtime.team import TeamEngine
        mission = MissionSpec(
            mission_id="m-corpus", target="https://t",
            objective="corpus wiring check",
            domains=["web"], budget={"max_agents": 12})
        engine = TeamEngine(mission, worker=None, project_root=tmp)
        engine.plan(bug_classes=["mfa_bypass", "webhook_abuse"])
        return engine

    def test_plan_records_checklist_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            sl = engine.state.get("checklist_slice") or []
            self.assertIn("AUTH-01", sl)
            self.assertIn("LOG-06", sl)
            self.assertTrue(set(sl) & set(checklists.attest_ids()))

    def test_member_payload_carries_member_and_attest_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            member = next(m for m in engine.members.values()
                          if m.role == "mfa-bypass")
            intel = engine._build_research_context(
                member.role, ("mfa_bypass",))
            ck = intel.get("checklist") or {}
            self.assertIn("AUTH-01", ck.get("member_ids", []))
            self.assertIn("AUTH-14", ck.get("attest_pending", []))
            self.assertIn("AUTH-01", ck.get("mission_ids", []))

    def test_coverage_gate_reports_open_honestly(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            gate = engine._coverage_gate()
            self.assertTrue(gate["applicable"])
            self.assertFalse(gate["ledger"])  # nothing written yet
            self.assertEqual(gate["open"], gate["slice"])
            # now close one endpoint partially and re-gate
            mdir = Path(tmp) / "state" / "orchestrator" / "m-corpus"
            led = CoverageLedger(mdir)
            led.set_verdict("https://t/x", "GET", "A", "AUTH-01",
                            "confirmed", ["E1"])
            led.save()
            gate2 = engine._coverage_gate()
            self.assertTrue(gate2["ledger"])
            self.assertIn("AUTH-01", [i for i in gate2["slice"]
                                      if i not in gate2["open"]])
            self.assertIn("AUTH-03", gate2["open"])


class TestDorkPlanCorpus(unittest.TestCase):
    def test_corpus_lanes_present(self):
        from tools.intel.research_engine import ResearchEngine
        plans = ResearchEngine().build_query_plans(
            techs=["nginx"], bug_classes=["idor"])
        queries = " || ".join(p["query"] for p in plans)
        for marker in ("org:", "http.favicon.hash", "site:crt.sh",
                       "inurl:webhook", "infosecwriteups"):
            self.assertIn(marker, queries, marker)

    def test_plans_are_honest_query_strings(self):
        from tools.intel.research_engine import ResearchEngine
        plans = ResearchEngine().build_query_plans(
            techs=["next.js"], bug_classes=["account_takeover"])
        for p in plans:
            self.assertIn("query", p)
            self.assertIn("execute_with", p)
            self.assertIn("paste_back", p)  # ledger loop is mandatory


if __name__ == "__main__":
    unittest.main()
