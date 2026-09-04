#!/usr/bin/env python3
"""Recon depth ladder tests: D0-D3 anti-satisficing ledger and engine
dispatch wiring (every recon member carries its depth contract)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.recon.depth_ladder import (  # noqa: E402
    ReconDepthLedger, DEPTH_TECHNIQUES, DEPTHS, SCHEMA)  # noqa: E402
from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.team import TeamEngine, MEMBER_DONE  # noqa: E402


def _mission(tmp: str, **kw) -> MissionSpec:
    defaults = dict(mission_id="m-depth", target="stub.local",
                    domains=["web_api"],
                    budget={"max_agents": 12, "max_parallel_tasks": 4})
    defaults.update(kw)
    return MissionSpec(**defaults)


class DepthLedgerTests(unittest.TestCase):
    """Append-only D0-D3 journal: honest coverage, waivers, blockers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def _ledger(self) -> ReconDepthLedger:
        return ReconDepthLedger("m-depth", project_root=self.root)

    def test_record_and_rehydrate(self):
        led = self._ledger()
        led.record("D1", "resolve-all", outcome="done", detail="412 hosts")
        led.record("D0", "ct-log-mining", outcome="empty")
        led2 = self._ledger().load()
        self.assertEqual(len(led2._events), 2)
        self.assertEqual(led2.record_outcome("resolve-all"), "done")
        self.assertEqual(led2.record_outcome("ct-log-mining"), "empty")

    def test_untried_excludes_terminal_and_includes_partial(self):
        led = self._ledger().load()
        for depth, techs in DEPTH_TECHNIQUES.items():
            for t in techs:
                led.record(depth, t, outcome="done")
        self.assertEqual(led.untried(), [])
        # a partial attempt is NOT terminal: the technique stays required
        led2 = self._ledger().load()
        led2.record("D0", "hist-churn", outcome="partial")
        self.assertIn("hist-churn", led2.untried())

    def test_waiver_is_explicit_and_removes_from_untried(self):
        led = self._ledger().load()
        led.waive("cloud-buckets", reason="no cloud surface declared")
        self.assertNotIn("cloud-buckets", led.untried())
        cov = led.coverage()
        self.assertIn("cloud-buckets", cov["depths"]["D3"]["waived"])
        waiver = [e for e in led._events if e.get("event") == "waiver"]
        self.assertEqual(waiver[0]["reason"], "no cloud surface declared")

    def test_close_blockers_are_honest(self):
        led = self._ledger().load()
        blockers = led.close_blockers(list(DEPTHS))
        self.assertTrue(any("untried" in b for b in blockers))
        unclosed = [b for b in blockers if b[:2] in DEPTHS]
        self.assertEqual(len(unclosed), 4)  # D0..D3 none closed yet
        # cover everything: every technique terminal + every level closed
        for depth, techs in DEPTH_TECHNIQUES.items():
            for t in techs:
                led.record(depth, t, outcome="done")
            led.close(depth)
        self.assertEqual(led.close_blockers(list(DEPTHS)), [])

    def test_invalid_inputs_raise(self):
        led = self._ledger().load()
        with self.assertRaises(ValueError):
            led.record("D9", "x")
        with self.assertRaises(ValueError):
            led.record("D0", "x", outcome="fabricated")
        with self.assertRaises(ValueError):
            led.close("D7")

    def test_torn_tail_write_survives(self):
        led = self._ledger()
        led.record("D0", "ct-log-mining", outcome="done")
        with led.journal_path().open("a", encoding="utf-8") as fh:
            fh.write('{"schema": "%s", "torn' % SCHEMA)  # simulated crash
        led2 = self._ledger().load()
        self.assertEqual(len(led2._events), 1)

    def test_signal_rules_recommend_specialists(self):
        led = self._ledger().load()
        led.record("D3", "cloud-buckets", outcome="done",
                   detail="found target.s3.amazonaws.com with listing")
        led.record("D2", "header-fingerprint", outcome="done",
                   detail="cloudflare WAF present on all hosts")
        led.record("D3", "mobile-endpoints", outcome="done",
                   asset="deep link handler on app target")
        led.record("D2", "js-mining", outcome="done",
                   detail="aws_access_key in main.bundle.js")
        recs = {r["bug_class"] for r in led.recommendations()}
        self.assertEqual(recs, {"s3_misconfig", "waf_bypass",
                                "shadow_api", "js_secrets"})
        for rec in led.recommendations():
            self.assertTrue(rec["reason"].startswith("recon D-evidence:"))

    def test_clean_census_recommends_nothing(self):
        # Evidence-based: a census that ran clean recommends nothing --
        # silence must never staff a specialist.
        led = self._ledger().load()
        led.record("D3", "cloud-buckets", outcome="empty",
                   detail="no buckets found")
        led.record("D2", "header-fingerprint", outcome="done",
                   detail="nginx 1.24, no shield detected")
        led.record("D3", "param-surface", outcome="done",
                   detail="412 hosts resolved")
        self.assertEqual(led.recommendations(), [])

    def test_blocked_attempts_produce_no_recommendations(self):
        # A blocked census produced no evidence: its text is not signal.
        led = self._ledger().load()
        led.record("D3", "cloud-buckets", outcome="blocked",
                   detail="s3.amazonaws.com unreachable from sandbox")
        self.assertEqual(led.recommendations(), [])

    def test_recommendations_deduped_and_technique_scoped(self):
        led = self._ledger().load()
        led.record("D3", "cloud-buckets", outcome="done",
                   detail="bucket s3.amazonaws.com/acme")
        led.record("D3", "cloud-buckets", outcome="done",
                   detail="bucket s3.amazonaws.com/acme-backup")
        led.record("D3", "js-route-map", outcome="done",
                   detail="mentions bucket in a comment")  # wrong technique
        recs = led.recommendations()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["bug_class"], "s3_misconfig")

    def test_offline_by_construction(self):
        # The ledger only ever writes mission state: its source imports
        # stdlib + runtime_paths only, never network or spawn modules.
        import tools.recon.depth_ladder as mod
        src = Path(mod.__file__).read_text()
        for banned in ("urllib", "requests", "socket", "http.client",
                       "subprocess"):
            self.assertNotIn(f"import {banned}", src)


class EngineDepthWiringTests(unittest.TestCase):
    """Every recon-lane dispatch carries the D0-D3 depth contract."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_recon_dispatch_carries_depth_contract(self):
        seen = {}

        def worker(payload):
            seen[payload["role"]] = payload
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        payload = seen["recon"]
        self.assertIn("recon_depth", payload["intel"])
        self.assertEqual(payload["intel"]["recon_depth"]["slice"],
                         list(DEPTHS))
        self.assertIn("coverage", payload["intel"]["recon_depth"])
        self.assertIn("close_blockers", payload["intel"]["recon_depth"])
        # non-recon members carry no depth contract
        self.assertNotIn("recon_depth", seen["web-api"]["intel"])

    def test_depth_records_persist_across_engine_reload(self):
        # ledger activity between runs is visible to a reloaded engine
        ReconDepthLedger("m-depth", project_root=self.root).load().record(
            "D0", "ct-log-mining", outcome="done")
        payloads = []

        def worker(payload):
            payloads.append(payload)
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.plan(bug_classes=["ssrf"])
        engine2 = TeamEngine.load("m-depth", project_root=self.root,
                                  worker=worker)
        engine2.resume()
        recon = next(p for p in payloads if p["role"] == "recon")
        covered = recon["intel"]["recon_depth"]["coverage"]["depths"]["D0"][
            "covered"]
        self.assertIn("ct-log-mining", covered)

    def test_d3_evidence_auto_staffs_specialist(self):
        # End-to-end: recorded D3 census evidence staffs a specialist
        # through the recomposition hook -- no agent handoff required.
        ReconDepthLedger("m-depth", project_root=self.root).load().record(
            "D3", "cloud-buckets", outcome="done",
            detail="target.s3.amazonaws.com responds with listing")

        def worker(payload):
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        roles = [m.role for m in engine.members.values()]
        self.assertIn("cloud-cicd", roles)  # s3_misconfig -> cloud-cicd
        member = next(m for m in engine.members.values()
                      if m.role == "cloud-cicd")
        self.assertEqual(member.wave, "hunt")
        self.assertEqual(member.status, MEMBER_DONE)
        recs = [r for r in out["recompositions"]
                if r.get("bug_class") == "s3_misconfig"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"], "added")
        self.assertIn("recon D-evidence", recs[0]["reason"])

    def test_d3_evidence_idempotent_across_resume(self):
        ReconDepthLedger("m-depth", project_root=self.root).load().record(
            "D3", "cloud-buckets", outcome="done",
            detail="target.s3.amazonaws.com responds with listing")

        def worker(payload):
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        before = len(engine.state["recompositions"])
        engine2 = TeamEngine.load("m-depth", project_root=self.root,
                                  worker=worker)
        engine2.resume()
        self.assertEqual(len(engine2.state["recompositions"]), before)
        self.assertEqual(
            len([m for m in engine2.members.values()
                 if m.role == "cloud-cicd"]), 1)

    def test_status_and_preflight_surface_depth(self):
        # Record evidence, run, then verify both operator reports carry
        # depth coverage and staffed evidence recommendations.
        ReconDepthLedger("m-depth", project_root=self.root).load().record(
            "D3", "cloud-buckets", outcome="done",
            detail="target.s3.amazonaws.com responds with listing")

        def worker(payload):
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])

        status = engine.status()
        depth = status["recon_depth"]
        self.assertTrue(depth["journal"])
        self.assertGreater(depth["events"], 0)
        self.assertEqual(depth["depths"]["D3"], {
            "covered": 1, "total": 5,
            "untried": ["param-surface", "js-route-map",
                        "mobile-endpoints", "historical-crossref"],
            "waived": []})
        recs = depth["recommendations"]
        self.assertEqual([r["bug_class"] for r in recs], ["s3_misconfig"])
        # the recommended specialist was auto-staffed by the run
        self.assertTrue(recs[0]["staffed"])
        self.assertEqual(recs[0]["role"], "cloud-cicd")

        # preflight carries the same section (loaded from disk)
        loaded = TeamEngine.load("m-depth", project_root=self.root,
                                 worker=worker)
        pre = loaded.preflight()
        self.assertTrue(pre["recon_depth"]["journal"])
        self.assertEqual(pre["recon_depth"]["depths"]["D3"]["covered"], 1)
        self.assertTrue(pre["recon_depth"]["recommendations"][0]["staffed"])

    def test_unstaffed_recommendation_reports_honestly(self):
        # Evidence for a class whose specialist is NOT on the roster:
        # reported with staffed=false, never silently omitted.
        ReconDepthLedger("m-depth", project_root=self.root).load().record(
            "D2", "header-fingerprint", outcome="done",
            detail="imperva WAF detected on edge")

        def worker(payload):
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine._recompose = False   # pin roster: evidence stays unstaffed
        engine.run(bug_classes=["ssrf"])
        depth = engine.status()["recon_depth"]
        recs = depth["recommendations"]
        self.assertEqual([r["bug_class"] for r in recs], ["waf_bypass"])
        self.assertFalse(recs[0]["staffed"])
        self.assertEqual(recs[0]["role"], "waf-bypass")

    def test_reports_degrade_without_journal(self):
        # No recon-depth activity at all: section reports journal=false
        # with honest zeros -- reporting never fabricates depth intel.
        def worker(payload):
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf"])
        depth = engine.status()["recon_depth"]
        self.assertFalse(depth["journal"])
        self.assertEqual(depth["events"], 0)
        self.assertEqual(depth["recommendations"], [])
        pre = engine.preflight()["recon_depth"]
        self.assertFalse(pre["journal"])
        self.assertEqual(pre["close_blockers"], [])

    def test_shadow_surface_also_gets_depth_contract(self):
        # shadow-surface declares lanes ("recon", "hunt") -- it must
        # receive the depth contract too, not just the recon workflow agent.
        seen = {}

        def worker(payload):
            seen[payload["role"]] = payload
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run(bug_classes=["ssrf", "takeover_candidate"])
        self.assertIn("recon_depth", seen["shadow-surface"]["intel"])


if __name__ == "__main__":
    unittest.main()
