#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.candidate_lifecycle import ResearchCandidate
from tools.novelty_pipeline import (
    AdvisoryCatalog,
    AdvisoryRecord,
    classify_novelty,
    rank_candidates,
    build_reproducibility_manifest,
)


def _candidate(domain="web_api", *, bug_class="x", title="x", behavior=None,
               endpoint="/x", severity="medium", confidence=0.5):
    return ResearchCandidate(
        domain=domain, bug_class=bug_class, title=title,
        endpoint=endpoint, behavior=behavior or {}, severity=severity,
        confidence=confidence,
    )


class TestAdvisoryCatalog(unittest.TestCase):
    def test_matches_known_advisory(self):
        catalog = AdvisoryCatalog([{
            "cve_id": "CVE-2026-0001",
            "keywords": ["reentrancy", "vault"],
            "description": "Reentrancy in vault contract",
            "severity": "high",
        }])
        candidate = _candidate("web3", bug_class="reentrancy", endpoint="vault")
        result = classify_novelty(candidate, catalog)
        self.assertTrue(result["known"])
        self.assertEqual(result["label"], "known")
        self.assertEqual(result["matches"][0]["cve_id"], "CVE-2026-0001")

    def test_no_match_is_potentially_novel(self):
        catalog = AdvisoryCatalog([])
        candidate = _candidate(bug_class="unusual_behavior", endpoint="/api/x")
        result = classify_novelty(candidate, catalog)
        self.assertEqual(result["label"], "potentially_novel")

    def test_catalog_round_trips_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "advisories.json"
            catalog = AdvisoryCatalog([{
                "cve_id": "CVE-2026-0002", "keywords": ["graphql"],
                "description": "GraphQL batching", "severity": "medium",
            }])
            catalog.write(path)
            loaded = AdvisoryCatalog.load(path)
            self.assertEqual(len(loaded.records), 1)
            self.assertEqual(loaded.records[0].cve_id, "CVE-2026-0002")


class TestNoveltyRanking(unittest.TestCase):
    def test_ranks_novel_high_above_known_low(self):
        novel = _candidate("web3", bug_class="novel_invariant", severity="critical", confidence=0.9)
        known = _candidate("web_api", bug_class="known_issue", severity="low", confidence=0.9)
        novel.novelty = "potentially_novel"
        known.novelty = "known"
        ranked = rank_candidates([known, novel])
        self.assertEqual(ranked[0].candidate_id, novel.candidate_id)


class TestReproducibilityManifest(unittest.TestCase):
    def test_manifest_records_fixture_and_sequence(self):
        manifest = build_reproducibility_manifest(
            target="lab", candidate_id="cand-1",
            fixture_digest="sha256:abc", tool_versions={"foundry": "1.0"},
            action_sequence=["deposit", "withdraw"],
            initial_state={"assets": 100},
        )
        self.assertEqual(manifest["candidate_id"], "cand-1")
        self.assertEqual(manifest["fixture_digest"], "sha256:abc")
        self.assertEqual(manifest["action_sequence"], ["deposit", "withdraw"])


if __name__ == "__main__":
    unittest.main()