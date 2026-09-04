#!/usr/bin/env python3
"""Finding-driven roster recomposition tests.

A mission starts with a planned roster; hunt members that report
finding-backed agent recommendations grow the roster mid-mission:

  * ``recommended_bug_classes`` result field (strings or dicts)
  * ``kind: "agent_recommendation"`` handoff messages

Every addition is budget-capped, deduped, workflow-safe, and recorded in
``state["recompositions"]`` (and the runs ledger) -- recomposition is
observable, never silent, and never fabricates members that were skipped.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.agent_registry import AgentRegistry  # noqa: E402
from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.team import (  # noqa: E402
    TeamEngine, MEMBER_DONE, MEMBER_FAILED)


def _mission(tmp: str, **kw) -> MissionSpec:
    defaults = dict(mission_id="m-recomp", target="stub.local",
                    domains=["web_api"],
                    budget={"max_agents": 12, "max_parallel_tasks": 4})
    defaults.update(kw)
    return MissionSpec(**defaults)


def _ok_worker(payload):
    return {"status": MEMBER_DONE}


class RecompositionTests(unittest.TestCase):
    """Roster growth from hunt-wave recommendations."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_recommended_bug_class_grows_hunt_wave(self):
        def worker(payload):
            if payload["role"] == "web-api":
                return {"status": MEMBER_DONE,
                        "recommended_bug_classes": ["race_condition"]}
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        # race_condition resolves to the business-logic specialist
        roles = [m.role for m in engine.members.values()]
        self.assertIn("business-logic", roles)
        added = [r for r in out["recompositions"]
                 if r.get("outcome") == "added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["role"], "business-logic")
        self.assertEqual(added[0]["bug_class"], "race_condition")
        # the added member ran: run ledger records started+finished for it
        runs = (Path(self.root) / "state/orchestrator/m-recomp/team/"
                "runs.jsonl").read_text()
        self.assertIn("recomposed", runs)
        self.assertIn("business-logic", runs)
        member = next(m for m in engine.members.values()
                      if m.role == "business-logic")
        self.assertEqual(member.status, MEMBER_DONE)
        self.assertEqual(member.wave, "hunt")

    def test_agent_recommendation_message_grows_roster(self):
        def worker(payload):
            if payload["role"] == "web-api":
                return {"status": MEMBER_DONE,
                        "messages": [{"to_role": "",
                                      "kind": "agent_recommendation",
                                      "body": {"bug_class": "waf_bypass",
                                               "reason": "WAF 403s on all probes"}}]}
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        roles = [m.role for m in engine.members.values()]
        self.assertIn("waf-bypass", roles)
        added = [r for r in engine.state["recompositions"]
                 if r.get("outcome") == "added"]
        self.assertEqual(added[0]["reason"], "WAF 403s on all probes")

    def test_skips_are_recorded_not_silent(self):
        def worker(payload):
            if payload["role"] == "web-api":
                # already staffed (web-api owns ssrf) + unknown class
                return {"status": MEMBER_DONE,
                        "recommended_bug_classes": ["ssrf",
                                                    "nonexistent_class_xyz"]}
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        recs = engine.state["recompositions"]
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["outcome"], "skipped")
        self.assertIn("already staffed", recs[0]["detail"])
        self.assertEqual(recs[1]["outcome"], "skipped")
        self.assertIn("no specialist owns", recs[1]["detail"])
        # no fabricated member: nothing was added to the roster
        self.assertFalse([r for r in recs if r.get("outcome") == "added"])

    def test_budget_cap_bounds_growth(self):
        def worker(payload):
            # recommend many distinct bug classes from every hunt member
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": [
                        "race_condition", "waf_bypass", "xss", "sqli",
                        "idor", "bola", "ssrf", "cors", "jwt_attack"]}

        engine = TeamEngine(
            _mission(self.root,
                     budget={"max_agents": 5, "max_parallel_tasks": 2}),
            worker=worker, project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        self.assertLessEqual(len(engine.members), 5)
        skips = [r for r in out["recompositions"]
                 if r.get("outcome") == "skipped"
                 and "max_agents" in str(r.get("detail"))]
        self.assertTrue(skips)

    def test_no_recompose_pins_roster(self):
        def worker(payload):
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": ["race_condition"]}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine._recompose = False
        engine.run(bug_classes=["ssrf"])
        self.assertEqual(engine.state["recompositions"], [])
        self.assertNotIn("business-logic",
                         [m.role for m in engine.members.values()])
        self.assertFalse(engine.state.get("recompose", False)
                         or engine._recompose)

    def test_resume_honors_recompose_preference(self):
        # plan with the flag pinned, resume from disk state
        def worker(payload):
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": ["race_condition"]}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine._recompose = False
        engine.plan(bug_classes=["ssrf"])
        engine2 = TeamEngine.load("m-recomp", project_root=self.root,
                                  worker=worker)
        self.assertFalse(engine2._recompose)
        engine2.run()
        self.assertNotIn("business-logic",
                         [m.role for m in engine2.members.values()])

    def test_extract_recommendations_shapes(self):
        recs = TeamEngine._recommendations_from_results([
            {"status": MEMBER_DONE,
             "recommended_bug_classes": ["race_condition",
                                         {"bug_class": "waf_bypass",
                                          "reason": "filtered"},
                                         "", 7, None]},
            {"status": MEMBER_DONE,
             "messages": [{"kind": "agent_recommendation",
                           "body": {"bug_class": "xxe",
                                    "reason": "SAML seen"}},
                          {"kind": "lead", "body": {"x": 1}},
                          "not-a-dict"]},
            "not-a-dict-result",
            None,
        ])
        pairs = {(r["bug_class"], r["reason"]) for r in recs}
        self.assertEqual(pairs, {
            ("race_condition", "member result recommendation"),
            ("waf_bypass", "filtered"),
            ("xxe", "SAML seen"),
        })

    def test_failed_member_recommendations_ignored(self):
        def worker(payload):
            if payload["role"] == "web-api":
                raise RuntimeError("exploded")
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        self.assertEqual(engine.state["recompositions"], [])
        failed = [m for m in engine.members.values()
                  if m.status == MEMBER_FAILED]
        self.assertEqual(failed[0].role, "web-api")

    def test_registry_resolution_matches_plan(self):
        # the added specialist is the same agent a planned mission would
        # have composed for the recommended bug class
        reg = AgentRegistry()
        expected = reg.select(bug_class="jwt_attack").role

        def worker(payload):
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": ["jwt_attack"]}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        self.assertIn(expected, [m.role for m in engine.members.values()])
        added = [r for r in engine.state["recompositions"]
                 if r.get("outcome") == "added"]
        self.assertEqual(added[0]["role"], expected)

    def test_recon_recommendation_grows_hunt_roster(self):
        # The feedback loop now starts at recon: a recon-wave finding
        # staffs a specialist BEFORE the hunt wave runs.
        seen = []

        def worker(payload):
            seen.append(payload["role"])
            if payload["role"] == "recon":
                return {"status": MEMBER_DONE,
                        "recommended_bug_classes": [
                            {"bug_class": "race_condition",
                             "reason": "checkout state machine found"}]}
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        added = [r for r in out["recompositions"]
                 if r.get("outcome") == "added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["role"], "business-logic")
        member = next(m for m in engine.members.values()
                      if m.role == "business-logic")
        self.assertEqual(member.wave, "hunt")
        self.assertEqual(member.status, MEMBER_DONE)
        # the added specialist ran in the hunt wave, after recon
        self.assertLess(seen.index("recon"), seen.index("business-logic"))

    def test_idempotent_ledger_across_reentry_rounds(self):
        # A member that re-recommends the same class every round is
        # re-evaluated but never re-recorded: exactly one ledger entry.
        def worker(payload):
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": ["race_condition"]}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        recs = [r for r in out["recompositions"]
                if r.get("bug_class") == "race_condition"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"], "added")
        self.assertEqual(
            len([m for m in engine.members.values()
                 if m.role == "business-logic"]), 1)

    def test_recompose_round_cap_bounds_reentry(self):
        # Each round recommends a NEW class; re-entry stops after
        # max_recompose_rounds ROUNDS (a round may add several members)
        # and the cap is recorded, not silent.
        fresh = iter(["waf_bypass", "jwt_attack", "prompt_injection",
                      "reentrancy", "xxe"])

        def worker(payload):
            bug = next(fresh, None)
            out = {"status": MEMBER_DONE}
            if bug:
                out["recommended_bug_classes"] = [bug]
            return out

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        # The cap bounds RE-ENTRY ROUNDS (a round may add several
        # specialists in parallel); max_agents bounds the roster.
        self.assertTrue(out["recompose_capped"])
        self.assertEqual(engine.state["recompose_rounds"],
                         engine.max_recompose_rounds)
        self.assertLessEqual(len(engine.members), engine.max_agents)
        added = [r for r in out["recompositions"]
                 if r.get("outcome") == "added"]
        # every recommended class got exactly one specialist, no more
        self.assertEqual({r["bug_class"] for r in added},
                         {"waf_bypass", "jwt_attack", "prompt_injection",
                          "reentrancy", "xxe"})
        # and every added specialist actually ran before verify
        for rec in added:
            member = next(m for m in engine.members.values()
                          if m.role == rec["role"])
            self.assertEqual(member.status, MEMBER_DONE, rec)
        # verify still ran after the capped growth (report wave closed)
        report = next(m for m in engine.members.values()
                      if m.wave == "report")
        self.assertEqual(report.status, MEMBER_DONE)

    def test_resume_does_not_re_record_decisions(self):
        def worker(payload):
            return {"status": MEMBER_DONE,
                    "recommended_bug_classes": ["race_condition"]}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        before = len(engine.state["recompositions"])
        engine2 = TeamEngine.load("m-recomp", project_root=self.root,
                                  worker=worker)
        engine2.resume()
        self.assertEqual(engine2.state["status"], "complete")
        self.assertEqual(len(engine2.state["recompositions"]), before)
        self.assertEqual(
            len([m for m in engine2.members.values()
                 if m.role == "business-logic"]), 1)

    def test_preflight_report(self):
        # Fresh mission: honest degraded facts (no worker, nothing run).
        engine = TeamEngine(_mission(self.root), worker=None,
                            project_root=self.root)
        report = engine.preflight()
        self.assertEqual(report["status"], "created")
        self.assertEqual(report["members"], 0)
        self.assertIn("BLOCKED", report["worker_binding"])
        self.assertEqual(report["recompose"]["max_rounds"],
                         engine.max_recompose_rounds)
        # After a run, the loaded engine reports the real state.
        engine.worker = _ok_worker
        engine.run(bug_classes=["ssrf"])
        loaded = TeamEngine.load("m-recomp", project_root=self.root,
                                 worker=_ok_worker)
        report = loaded.preflight()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["worker_binding"], "bound")
        self.assertGreater(report["members"], 0)
        self.assertEqual(report["recompose"]["recorded"],
                         len(loaded.state["recompositions"]))


if __name__ == "__main__":
    unittest.main()
