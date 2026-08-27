#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dependency_map import build  # noqa: E402
import tools.evidence as evidence_module  # noqa: E402
from tools.evidence import EvidenceStore  # noqa: E402


class TestUnifiedEvidence(unittest.TestCase):
    def test_evidence_is_redacted_and_verifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore.__new__(EvidenceStore)
            store.target = "fixture"
            evidence_module.ROOT = root
            store.root = root / "evidence"
            store.root.mkdir()
            store.manifest = store.root / "manifest.jsonl"
            record = store.add_replay_fixture(
                {"url": "https://fixture.test", "headers": {"Authorization": "secret"}},
                {"status": 200, "body": {"id": "user-1"}},
            )
            payload = json.loads((root / "evidence" / f"{record.evidence_id}.json").read_text())
            self.assertEqual(payload["request"]["headers"]["Authorization"], "[REDACTED]")
            self.assertTrue(store.verify()["valid"])

    def test_tampered_evidence_fails_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore.__new__(EvidenceStore)
            store.target = "fixture"
            evidence_module.ROOT = root
            store.root = root / "evidence"
            store.root.mkdir()
            store.manifest = store.root / "manifest.jsonl"
            record = store.add("response", {"body": "original"})
            (root / "evidence" / f"{record.evidence_id}.json").write_text("tampered")
            self.assertFalse(store.verify()["valid"])


class TestDependencyMap(unittest.TestCase):
    def test_map_contains_modules_and_internal_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tools"
            root.mkdir()
            (root / "a.py").write_text("from tools.b import value\n")
            (root / "b.py").write_text("value = 1\n")
            result = build(root)
            self.assertEqual(result["schema"], "bugwolf-dependency-map/v1")
            self.assertEqual([item["module"] for item in result["modules"]], ["a", "b"])
            self.assertEqual(result["edges"], [{"from": "a", "to": "tools.b"}])


if __name__ == "__main__":
    unittest.main()
