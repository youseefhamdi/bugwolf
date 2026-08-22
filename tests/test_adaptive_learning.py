#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.adaptive_learning import AdaptiveMemory, learn_from_journey
from tools.research_loop import ResearchExecutor, ResearchLoop


class TestAdaptiveLearning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_journey_learning_is_quarantined_and_redacted(self):
        journey = {
            "research": [{
                "checkpoint": "bypass",
                "records": [{
                    "task_type": "search",
                    "query": "Cloudflare WAF bypass",
                    "results": [{
                        "title": "Header variation technique",
                        "url": "https://example.test/report",
                        "snippet": "Authorization: Bearer secret-value",
                    }],
                }],
            }],
            "results": [{
                "notes": "[medium] idor: cross-tenant difference",
                "observation_state": "signal",
                "observation_id": "obs-1",
            }],
        }
        result = learn_from_journey(
            "example.com", journey, journey_type="hunt", root=self.root)
        self.assertEqual(result["status"], "candidates_quarantined")
        self.assertGreaterEqual(result["candidate_count"], 2)
        records = AdaptiveMemory("example.com", root=self.root).all()
        self.assertTrue(records)
        self.assertTrue(all(record["status"] == "candidate" for record in records))
        raw = (self.root / "state" / "learning" / "example.com.jsonl").read_text()
        self.assertNotIn("secret-value", raw)
        self.assertIn("https://example.test/report", raw)

    def test_duplicate_ingestion_merges_without_duplicate_current_records(self):
        memory = AdaptiveMemory("example.com", root=self.root)
        first = memory.ingest(
            kind="researched-technique", title="Encoding variation",
            summary="bypass technique", source_refs=["https://example.test/a"],
            journey="hunt")
        second = memory.ingest(
            kind="researched-technique", title="Encoding variation",
            summary="bypass technique", source_refs=["https://example.test/a"],
            journey="recon")
        self.assertEqual(first["technique_id"], second["technique_id"])
        current = memory.all()
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["seen_count"], 2)
        self.assertEqual(set(current[0]["journeys"]), {"hunt", "recon"})

    def test_only_explicit_review_allows_reuse(self):
        memory = AdaptiveMemory("example.com", root=self.root)
        candidate = memory.ingest(
            kind="researched-technique", title="Known safe term",
            summary="review me", terms=["known-safe"], journey="hunt")
        self.assertEqual(memory.approved(), [])
        with self.assertRaises(ValueError):
            memory.review(candidate["technique_id"], "approve", "", "")
        approved = memory.review(
            candidate["technique_id"], "approve", "operator",
            "Confirmed against an authorized disposable fixture")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(memory.approved()[0]["technique_id"], candidate["technique_id"])

    def test_approved_terms_are_reused_in_future_wordlists(self):
        memory = AdaptiveMemory("example.com", root=self.root)
        candidate = memory.ingest(
            kind="observed-pattern", title="Learned path term",
            summary="validated", terms=["learned-path"], journey="hunt")
        memory.review(candidate["technique_id"], "approve", "operator", "Validated")

        executor = ResearchExecutor(
            target="example.com", base_dir=str(self.root / "research"),
            run_search=False)
        loop = ResearchLoop(target="example.com")
        with mock.patch("tools.wordlist_gen.generate", return_value=["baseline"]):
            result = executor.execute(loop, "post-maps", ["web"])
        records = [record for record in result["records"]
                   if record["task_type"] == "wordlist"]
        self.assertTrue(records)
        self.assertTrue(all(candidate["technique_id"] in record["applied_learning"]
                            for record in records))
        wordlist = (self.root / "research" / "example.com" /
                    "post-maps" / "wordlists" / "vhosts.txt")
        self.assertIn("learned-path", wordlist.read_text())
        self.assertEqual(memory.approved()[0]["used_count"], 4)


if __name__ == "__main__":
    unittest.main()
