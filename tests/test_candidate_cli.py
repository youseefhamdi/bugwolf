#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.candidate_cli import query_candidates


class TestCandidateCli(unittest.TestCase):
    def test_query_filters_by_domain_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "candidates.jsonl"
            store_path.write_text(
                json.dumps({"domain": "web_api", "title": "a", "status": "discovered",
                            "behavior": {}, "evidence_refs": [], "payload_lineage": [],
                            "operation_ids": [], "parent_candidate_ids": [], "notes": [],
                            "schema": "bugwolf/research-candidate/v1",
                            "candidate_id": "c1", "created_at": "2026-01-01T00:00:00+00:00",
                            "updated_at": "2026-01-01T00:00:00+00:00", "signature": "s1",
                            "confidence": 0.5, "target": "lab", "bug_class": "x",
                            "severity": "high", "endpoint": "/x"}) + "\n" +
                json.dumps({"domain": "ai", "title": "b", "status": "confirmed",
                            "behavior": "y", "evidence_refs": [], "payload_lineage": [],
                            "operation_ids": [], "parent_candidate_ids": [], "notes": [],
                            "schema": "bugwolf/research-candidate/v1",
                            "candidate_id": "c2", "created_at": "2026-01-02T00:00:00+00:00",
                            "updated_at": "2026-01-02T00:00:00+00:00", "signature": "s2",
                            "confidence": 0.9, "target": "", "bug_class": "AI",
                            "endpoint": "/y"}) + "\n"
            )
            result = query_candidates(store_path, domain="web_api")
            self.assertEqual(len(result["candidates"]), 1)
            self.assertEqual(result["candidates"][0]["candidate_id"], "c1")
            result = query_candidates(store_path, status="confirmed")
            self.assertEqual(len(result["candidates"]), 1)
            self.assertEqual(result["candidates"][0]["candidate_id"], "c2")


if __name__ == "__main__":
    unittest.main()