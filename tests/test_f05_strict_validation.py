#!/usr/bin/env python3
"""F0.5 precision-first validation tests (U3).

Covers:
  * refutation.confidence_score — deterministic evidence-derived scoring
  * RefutationEngine strict (default) — CONFIRMED vs DEMOTED + quarantine
  * RefutationEngine --no-strict — legacy UNCENSORED auto-confirm preserved
  * refute_chain strict — joined-chain scoring
  * CandidateTriage strict bands — sub-threshold candidates quarantined
  * CandidateTriage legacy mode — unscored behavior unchanged
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.refutation import (  # noqa: E402
    RefutationEngine, confidence_score, has_reproducible_evidence,
    recorded_evidence_block, FindingVerdict, GateResult,
    STRICT_CONFIDENCE_THRESHOLD,
)
from tools.triage import (  # noqa: E402
    CandidateTriage, STRICT_CONFIDENCE_THRESHOLD as TRIAGE_THRESHOLD,
)
from tools.research_model import (  # noqa: E402
    ResearchCandidate, CandidateStatus, NoveltyLabel, Surface, EvidenceRef,
)


def _rich_finding():
    """A finding that carries full reproducible evidence (high confidence)."""
    return {
        "finding_id": "f-rich",
        "title": "IDOR on user profile",
        "bug_class": "idor",
        "severity": "high",
        "endpoint": "https://api.acme.com/v1/users/1",
        "trigger_trace": "Sent GET /v1/users/2 with account B session",
        "impact_trace": "Read account B's full profile and PII",
        "evidence": ["ev-1", "ev-2"],
        "confirmed_behavior": "Cross-account read confirmed on two sessions",
    }


def _bare_finding():
    """A hypothesis with no reproducible evidence (low confidence)."""
    return {
        "finding_id": "f-bare",
        "title": "possible IDOR",
        "bug_class": "idor",
    }


class TestConfidenceScore(unittest.TestCase):
    def test_rich_finding_scores_high(self):
        self.assertGreaterEqual(confidence_score(_rich_finding()),
                                STRICT_CONFIDENCE_THRESHOLD)

    def test_bare_finding_scores_low(self):
        self.assertLess(confidence_score(_bare_finding()),
                        STRICT_CONFIDENCE_THRESHOLD)

    def test_deterministic(self):
        a = confidence_score(_rich_finding())
        b = confidence_score(_rich_finding())
        self.assertEqual(a, b)

    def test_evidence_weight(self):
        with_evidence = confidence_score({"evidence": ["e1"]})
        without = confidence_score({})
        self.assertGreater(with_evidence, without)

    def test_trigger_and_impact_add_up(self):
        score = confidence_score({
            "trigger_trace": "payload sent",
            "impact_trace": "data read",
        })
        self.assertGreaterEqual(score, 0.45)
        self.assertLessEqual(score, 1.0)


class TestRefutationStrict(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = str(Path(self._tmp.name))

    def _learning_store(self, target="acme"):
        path = Path(self.root) / "state" / "learning" / f"{target}.jsonl"
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()
                if line.strip()]

    def test_strict_default_demotes_and_quarantines_low_confidence(self):
        engine = RefutationEngine("acme", project_root=self.root)
        record = engine.refute(_bare_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.DEMOTED)
        self.assertFalse(record.eligible_for_report)
        self.assertTrue(record.quarantined)
        self.assertLess(record.confidence, STRICT_CONFIDENCE_THRESHOLD)
        self.assertEqual(record.killed_passes, 1)
        self.assertEqual(record.survived_passes, 0)
        records = self._learning_store()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "low-confidence-finding")
        self.assertEqual(records[0]["status"], "candidate")

    def test_strict_confirms_rich_finding_without_quarantine(self):
        engine = RefutationEngine("acme", project_root=self.root)
        record = engine.refute(_rich_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.CONFIRMED)
        self.assertTrue(record.eligible_for_report)
        self.assertFalse(record.quarantined)
        self.assertEqual(self._learning_store(), [])

    def test_strict_gate_results_are_evidence_derived(self):
        engine = RefutationEngine("acme", project_root=self.root)
        record = engine.refute(_bare_finding())
        gates = record.passes[0].gate_results
        by_gate = {g.gate: g for g in gates}
        self.assertEqual(by_gate["refutation"].result, GateResult.DEMOTED)
        self.assertEqual(by_gate["reachability"].result, GateResult.UNCERTAIN)
        self.assertEqual(by_gate["trigger"].result, GateResult.UNCERTAIN)
        rich = engine.refute(_rich_finding())
        rich_gates = {g.gate: g for g in rich.passes[0].gate_results}
        self.assertEqual(rich_gates["refutation"].result, GateResult.CLEARED)
        self.assertEqual(rich_gates["impact"].result, GateResult.CLEARED)

    def test_no_strict_preserves_auto_confirm(self):
        engine = RefutationEngine("acme", strict=False, project_root=self.root)
        record = engine.refute(_bare_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.CONFIRMED)
        self.assertTrue(record.eligible_for_report)
        self.assertFalse(record.quarantined)
        self.assertEqual(record.confidence, 1.0)
        self.assertEqual(self._learning_store(), [])

    def test_refute_overrides_engine_default(self):
        engine = RefutationEngine("acme", strict=False, project_root=self.root)
        record = engine.refute(_bare_finding(), strict=True)
        self.assertEqual(record.final_verdict, FindingVerdict.DEMOTED)
        engine_strict = RefutationEngine("acme", strict=True,
                                         project_root=self.root)
        legacy = engine_strict.refute(_bare_finding(), strict=False)
        self.assertEqual(legacy.final_verdict, FindingVerdict.CONFIRMED)

    def test_chain_strict_joins_evidence(self):
        engine = RefutationEngine("acme", project_root=self.root)
        record = engine.refute_chain([
            {"finding_id": "c1", "title": "link A",
             "trigger_trace": "probe sent", "impact_trace": "read data",
             "evidence": ["ev-a"], "severity": "high"},
            {"finding_id": "c2", "title": "link B"},
        ])
        self.assertEqual(record.final_verdict, FindingVerdict.CONFIRMED)
        self.assertTrue(record.eligible_for_report)
        chain_legacy = RefutationEngine("acme", strict=False,
                                        project_root=self.root)
        legacy = chain_legacy.refute_chain([])
        self.assertEqual(legacy.final_verdict, FindingVerdict.CONFIRMED)


class TestTriageStrict(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = str(Path(self._tmp.name))

    def _candidate(self, *, base_confidence=0.0, evidence=True,
                   trigger=True, impact=True):
        return ResearchCandidate(
            target="acme",
            surface=Surface.WEB_API,
            bug_class="idor",
            title="candidate",
            hypothesis="object-level auth bypass",
            trigger_trace="probe sent" if trigger else "",
            impact_trace="read other user data" if impact else "",
            severity="high",
            confidence=base_confidence,
            status=CandidateStatus.NOVELTY_PENDING,
            novelty=NoveltyLabel.UNKNOWN,
            evidence=([EvidenceRef(evidence_id="ev-1", kind="http", sha256="a"*64)]
                      if evidence else []),
        )

    def test_strict_quarantines_subthreshold_candidate(self):
        triage = CandidateTriage(strict=True, project_root=self.root)
        candidate = self._candidate(base_confidence=0.0)
        decision = triage.evaluate(candidate)
        self.assertFalse(decision.eligible_for_human_review)
        self.assertLess(decision.confidence, TRIAGE_THRESHOLD)
        self.assertTrue(any("F0.5" in reason for reason in decision.reasons))
        with self.assertRaises(ValueError):
            triage.enter_review(candidate)
        path = Path(self.root) / "state" / "learning" / "acme.jsonl"
        self.assertTrue(path.is_file())
        records = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(records[0]["kind"], "low-confidence-candidate")
        self.assertEqual(records[0]["status"], "candidate")

    def test_strict_admits_high_confidence_candidate(self):
        triage = CandidateTriage(strict=True, project_root=self.root)
        candidate = self._candidate(base_confidence=0.5)
        decision = triage.evaluate(candidate)
        self.assertTrue(decision.eligible_for_human_review)
        self.assertGreaterEqual(decision.confidence, TRIAGE_THRESHOLD)

    def test_legacy_mode_admits_candidate_strict_would_quarantine(self):
        candidate = self._candidate(base_confidence=0.0)
        legacy = CandidateTriage(strict=False, project_root=self.root)
        decision = legacy.evaluate(candidate)
        # Evidence checks pass; legacy mode has no confidence band.
        self.assertTrue(decision.eligible_for_human_review)
        path = Path(self.root) / "state" / "learning" / "acme.jsonl"
        self.assertFalse(path.exists())

    def test_confidence_bands_deterministic(self):
        triage = CandidateTriage(strict=True, project_root=self.root)
        a = triage.evaluate(self._candidate(base_confidence=0.4))
        b = triage.evaluate(self._candidate(base_confidence=0.4))
        self.assertEqual(a.confidence, b.confidence)
        self.assertEqual(a.eligible_for_human_review,
                         b.eligible_for_human_review)


def _recorded_finding():
    """A finding carrying a live-executor recorded request/response block."""
    return {
        "finding_id": "f-live",
        "title": "IDOR reproduced live",
        "bug_class": "idor",
        "severity": "high",
        "endpoint": "https://api.acme.com/v1/users/2",
        "trigger_trace": "Sent GET /v1/users/2 with account B session",
        "impact_trace": "Read account B's full profile and PII",
        "evidence": {
            "schema": "bugwolf/probe-evidence/v1",
            "request": {"method": "GET", "url": "https://api.acme.com/v1/users/2",
                         "headers": {}, "body": None,
                         "technique": "id", "bug_class": "idor"},
            "response": {"status": 200, "headers": {"Server": "nginx"},
                          "body": "{\"id\":2,\"username\":\"bob\"}",
                          "elapsed_ms": 5.0},
            "replay_key": "abc123",
            "recorded_at": "2026-08-26T00:00:00+00:00",
            "waf": "",
            "signals": [],
        },
        "confirmed_behavior": "Cross-account read confirmed with recorded replay",
    }


class TestReproducibleEvidenceGate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = str(Path(self._tmp.name))

    def test_recorded_block_detected(self):
        self.assertTrue(has_reproducible_evidence(_recorded_finding()))
        self.assertIsNotNone(recorded_evidence_block(_recorded_finding()))

    def test_legacy_evidence_list_has_no_recorded_block(self):
        self.assertFalse(has_reproducible_evidence(_rich_finding()))
        self.assertIsNone(recorded_evidence_block(_rich_finding()))

    def test_recorded_block_boosts_confidence(self):
        recorded = confidence_score(_recorded_finding())
        legacy = confidence_score(_rich_finding())
        self.assertGreaterEqual(recorded, 1.0)
        self.assertGreaterEqual(recorded, legacy)

    def test_require_reproducible_demotes_unrecorded_finding(self):
        # Live-execution gate ON: a rich-but-unrecorded finding is DEMOTED
        # even though its confidence clears the threshold.
        engine = RefutationEngine("acme", project_root=self.root,
                                  require_reproducible=True)
        record = engine.refute(_rich_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.DEMOTED)
        self.assertFalse(record.eligible_for_report)
        self.assertTrue(record.quarantined)
        # The reproducible gate is UNCERTAIN, not cleared.
        gate = next(g for g in record.passes[0].gate_results
                    if g.gate == "reproducible")
        self.assertEqual(gate.result, GateResult.UNCERTAIN)

    def test_require_reproducible_confirms_recorded_finding(self):
        engine = RefutationEngine("acme", project_root=self.root,
                                  require_reproducible=True)
        record = engine.refute(_recorded_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.CONFIRMED)
        self.assertTrue(record.eligible_for_report)
        self.assertFalse(record.quarantined)
        gate = next(g for g in record.passes[0].gate_results
                    if g.gate == "reproducible")
        self.assertEqual(gate.result, GateResult.CLEARED)

    def test_default_engine_keeps_legacy_behavior(self):
        # require_reproducible defaults to False: legacy findings (evidence
        # ids, no recorded block) still pass the confidence gate.
        engine = RefutationEngine("acme", project_root=self.root)
        record = engine.refute(_rich_finding())
        self.assertEqual(record.final_verdict, FindingVerdict.CONFIRMED)
        self.assertTrue(record.eligible_for_report)

    def test_verify_reproducibility_false_without_recorded_block(self):
        engine = RefutationEngine("acme", project_root=self.root)
        self.assertFalse(engine.verify_reproducibility(_rich_finding(),
                                                       "https://acme"))

    def test_verify_reproducibility_delegates_to_live_executor(self):
        # Delegates to live_executor.verify_reproducibility, which replays
        # the recorded request through the (fake) transport.
        def transport(spec):
            return 200, {"Server": "nginx"}, "{\"id\":2}", 5.0

        engine = RefutationEngine("acme", project_root=self.root)
        # Recorded response says 200 and the replay returns 200 -> True.
        self.assertTrue(engine.verify_reproducibility(_recorded_finding(),
                                                      "https://acme",
                                                      transport=transport))
        # No recorded evidence block -> nothing to replay -> False.
        self.assertFalse(engine.verify_reproducibility(_rich_finding(),
                                                       "https://acme",
                                                       transport=transport))


if __name__ == "__main__":
    unittest.main()
