#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.candidate_lifecycle import (
    CandidateStore,
    CandidateStatus,
    ResearchCandidate,
    candidate_signature,
    export_candidate,
    migrate_candidate,
)


class TestCandidateSchema(unittest.TestCase):
    def test_defaults_and_round_trip(self):
        candidate = ResearchCandidate(domain="web_api", title="Unexpected delta")
        data = candidate.to_dict()
        restored = ResearchCandidate.from_dict(data)
        self.assertEqual(restored.candidate_id, candidate.candidate_id)
        self.assertEqual(restored.status, CandidateStatus.DISCOVERED)
        self.assertEqual(restored.domain, "web_api")

    def test_invalid_domain_and_transition_are_rejected(self):
        with self.assertRaises(ValueError):
            ResearchCandidate(domain="unknown")
        candidate = ResearchCandidate(domain="web3")
        with self.assertRaises(ValueError):
            candidate.transition(CandidateStatus.CONFIRMED)

    def test_valid_lifecycle_transition(self):
        candidate = ResearchCandidate(domain="ai", title="Tool trace anomaly")
        for status in (
            CandidateStatus.NORMALIZED,
            CandidateStatus.DEDUPLICATED,
            CandidateStatus.TRIAGED,
            CandidateStatus.REPRODUCTION_PENDING,
            CandidateStatus.REPRODUCED,
            CandidateStatus.NOVELTY_PENDING,
            CandidateStatus.IMPACT_VALIDATION,
            CandidateStatus.CONFIRMED,
        ):
            candidate.transition(status)
        self.assertEqual(candidate.status, CandidateStatus.CONFIRMED)

    def test_signature_is_stable_and_ignores_volatile_fields(self):
        first = ResearchCandidate(domain="web_api", title="x", behavior={"status": 500})
        second = ResearchCandidate(domain="web_api", title="x", behavior={"status": 500})
        self.assertEqual(candidate_signature(first), candidate_signature(second))


class TestCandidateStore(unittest.TestCase):
    def test_deduplicates_candidates_by_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CandidateStore(Path(tmp) / "candidates.jsonl")
            first = ResearchCandidate(domain="web3", title="Invariant", behavior={"delta": "loss"})
            second = ResearchCandidate(domain="web3", title="Invariant", behavior={"delta": "loss"})
            self.assertTrue(store.add(first))
            self.assertFalse(store.add(second))
            self.assertEqual(len(store.load()), 1)

    def test_migrates_legacy_finding(self):
        candidate = migrate_candidate({
            "finding_id": "legacy-1",
            "bug_class": "idor",
            "endpoint": "/users/1",
            "confirmed_behavior": "cross-account data returned",
        })
        self.assertEqual(candidate.candidate_id, "legacy-1")
        self.assertEqual(candidate.domain, "web_api")
        self.assertEqual(candidate.status, CandidateStatus.DISCOVERED)
        self.assertEqual(candidate.behavior["confirmed_behavior"], "cross-account data returned")

    def test_import_legacy_findings_and_export_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CandidateStore(Path(tmp) / "candidates.jsonl")
            self.assertEqual(store.migrate_legacy([{
                "finding_id": "legacy-2", "bug_class": "oracle_manipulation",
                "title": "Price deviation", "impact": "accounting loss",
            }]), 1)
            candidate = store.load()[0]
            paths = export_candidate(candidate, Path(tmp) / "reports")
            self.assertEqual(json.loads(paths["json"].read_text())["candidate_id"], "legacy-2")
            self.assertIn("Price deviation", paths["markdown"].read_text())


if __name__ == "__main__":
    unittest.main()
