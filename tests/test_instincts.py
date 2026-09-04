#!/usr/bin/env python3
"""Instinct distillation tests (INTEGRATION_PLAN Phase A, v1.24).

Locked contract:

  * mining: deterministic over existing ledgers (leads, reporting,
    u_regression, benchmark, evidence); snapshot-journal dedupe;
    fail-open on malformed state;
  * store: bugwolf-instinct/v1 schema; idempotent distill (re-mining
    REPLACES occurrences — the ledger is the source of truth); instinct
    is ACTIVE only at >= 2 occurrences; contradiction HALVES confidence;
    TTL prune drops expired entries;
  * consumers: cockpit section (confidence desc, cap 5); dispatch
    modifier bounded to +/-0.25; technique ordering is reorder-only
    (nothing added/removed); promote is operator-gated to global.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from tools import instincts as I

from tools.runtime.lead_protocol import LeadStore


def _seed_race(tmp: str, *, missions=("m-12", "m-13")) -> None:
    """Two missions with the same un-won technique on voucher-race."""
    for mission in missions:
        store = LeadStore(mission, project_root=tmp)
        lead = store.open_lead(
            title=f"race on {mission}", mission_id=mission,
            target="http://t.example", bug_class="voucher-race",
            surface="/api/voucher/redeem", evidence_refs=[],
            signal="voucher-reuse")
        store.record_technique(lead.lead_id, "race-single-redeem", "tried",
                               detail="no double spend")


class TestMining(unittest.TestCase):
    def test_technique_mining_from_lead_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            candidates = I.mine_techniques(tmp)
            self.assertEqual(len(candidates), 1)
            cand = candidates[0]
            self.assertEqual(cand["kind"], "technique")
            self.assertEqual(cand["occurrences"], 2)
            self.assertEqual(cand["trigger"]["bug_class"], "voucher-race")
            self.assertEqual(cand["evidence"][0]["lead"],
                             "LEAD-0001-race-on-m-12")

    def test_snapshot_journal_dedupe(self):
        """Append-only full snapshots must not multi-count techniques."""
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            # Rewriting the same journal via a fresh store mutates the same
            # lead -> more snapshots, same final state.
            store = LeadStore("m-12", project_root=tmp).load()
            lead = store.get("LEAD-0001-race-on-m-12")
            store.record_technique(lead.lead_id, "another-tech", "tried")
            candidates = I.mine_techniques(tmp)
            race = next(c for c in candidates
                        if c["trigger"]["technique"] == "race-single-redeem")
            self.assertEqual(race["occurrences"], 2)  # not 3+

    def test_success_outcomes_are_not_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LeadStore("m-1", project_root=tmp)
            lead = store.open_lead(title="win", mission_id="m-1",
                                   target="http://t.example",
                                   bug_class="idor", surface="/u/1",
                                   evidence_refs=[], signal="bola")
            store.record_technique(lead.lead_id, "direct-object-reference",
                                   "success")
            self.assertEqual(I.mine_techniques(tmp), [])

    def test_fail_open_on_missing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            for miner in I.MINERS:
                self.assertEqual(miner(tmp), [])


class TestStore(unittest.TestCase):
    def test_distill_is_idempotent_and_active_at_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            first = I.distill(tmp)
            self.assertEqual(first["total"], 1)
            self.assertEqual(first["active"], 1)      # 2 occurrences
            second = I.distill(tmp)
            self.assertEqual(second["total"], 1)      # no growth on re-run
            self.assertEqual(second["candidates_created"], 0)

    def test_single_occurrence_is_stored_but_inactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = LeadStore("m-1", project_root=tmp)
            lead = store.open_lead(title="one", mission_id="m-1",
                                   target="http://t.example",
                                   bug_class="voucher-race", surface="/v",
                                   evidence_refs=[], signal="voucher-reuse")
            store.record_technique(lead.lead_id, "race-single-redeem",
                                   "tried")
            report = I.distill(tmp)
            self.assertEqual(report["total"], 1)
            self.assertEqual(report["active"], 0)     # threshold not met
            self.assertEqual(I.load_instincts(tmp), [])

    def test_schema_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            I.distill(tmp)
            rec = I.load_instincts(tmp)[0]
            self.assertEqual(rec["schema"], "bugwolf-instinct/v1")
            self.assertEqual(rec["scope"], "project")
            self.assertTrue(rec["evidence"])
            self.assertIn("mission", rec["evidence"][0])
            for key in ("statement", "action", "confidence", "occurrences",
                        "created_at", "updated_at", "ttl_days"):
                self.assertIn(key, rec)

    def test_contradiction_halves_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            # A success for the SAME (technique, class) shape contradicts.
            store = LeadStore("m-14", project_root=tmp)
            lead = store.open_lead(title="later win", mission_id="m-14",
                                   target="http://t.example",
                                   bug_class="voucher-race", surface="/v",
                                   evidence_refs=[], signal="voucher-reuse")
            store.record_technique(lead.lead_id, "race-single-redeem",
                                   "success")
            rec = I.load_instincts(tmp)[0] if I.load_instincts(tmp) else None
            if rec is None:
                I.distill(tmp)
                rec = I.load_instincts(tmp)[0]
            base = I._confidence(2, 0)
            self.assertEqual(rec["confidence"], base / 2)

    def test_ttl_prune_drops_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            I.distill(tmp)
            path = tmp + "/state/instincts/instincts.jsonl"
            records = [json.loads(line) for line in
                       Path(path).read_text().splitlines() if line]
            # Force every record past its TTL.
            old = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                time.gmtime(time.time() - 400 * 86400))
            for rec in records:
                rec["updated_at"] = old
            Path(path).write_text(
                "".join(json.dumps(r, sort_keys=True) + "\n"
                        for r in records))
            self.assertEqual(I.prune(tmp), len(records))
            self.assertEqual(I.load_instincts(tmp), [])

    def test_promote_is_operator_gated_to_global(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            I.distill(tmp)
            rec = I.load_instincts(tmp)[0]
            self.assertTrue(I.promote(rec["id"], tmp))
            gpath = Path(tmp) / "state" / "instincts" / "global.jsonl"
            self.assertTrue(gpath.is_file())
            exported = json.loads(gpath.read_text().splitlines()[0])
            self.assertEqual(exported["scope"], "global")
            self.assertFalse(I.promote("nonexistent-id", tmp))


class TestConsumers(unittest.TestCase):
    def test_cockpit_section_sorted_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            I.distill(tmp)
            section = I.cockpit_section(tmp, cap=5)
            self.assertEqual(len(section), 1)
            self.assertIn("statement", section[0])
            self.assertNotIn("evidence", section[0])  # bounded payload

    def test_dispatch_modifier_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            _seed_race(tmp)
            I.distill(tmp)
            # technique-kind instincts carry no modifier (only signal/noise)
            self.assertEqual(
                I.dispatch_modifier("voucher-race", project_root=tmp), 0.0)
            self.assertEqual(
                I.dispatch_modifier("idor", project_root=tmp), 0.0)
            # Direct bounded check with synthetic instincts.
            noisy = [{"kind": "signal",
                      "trigger": {"bug_class": "idor"}},
                     {"kind": "signal",
                      "trigger": {"bug_class": "idor"}},
                     {"kind": "signal",
                      "trigger": {"bug_class": "idor"}}]
            self.assertEqual(I.dispatch_modifier("idor", instincts=noisy),
                             0.25)
            sinks = [{"kind": "noise",
                      "trigger": {"bug_class": "xss-dom"}},
                     {"kind": "noise",
                      "trigger": {"bug_class": "xss-dom"}}]
            self.assertEqual(I.dispatch_modifier("xss-dom", instincts=sinks),
                             -0.25)

    def test_order_techniques_is_reorder_only(self):
        required = ["a-tech", "race-single-redeem", "c-tech"]
        instincts = [{"kind": "technique",
                      "trigger": {"technique": "race-single-redeem",
                                  "bug_class": "voucher-race"}}]
        ordered = I.order_techniques(required, instincts, "voucher-race")
        self.assertEqual(sorted(ordered), sorted(required))  # same set
        self.assertEqual(ordered[-1], "race-single-redeem")  # demoted last
        # Unrelated class: untouched order.
        self.assertEqual(I.order_techniques(required, instincts, "idor"),
                         required)


if __name__ == "__main__":
    unittest.main()
