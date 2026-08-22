#!/usr/bin/env python3
import json
import shutil
import unittest
import uuid
from pathlib import Path

from tools.ledger import LedgerVerifier
from tools.post_finding_trigger import trigger_after_finding
from tools.state import _state_dir, mark_tested


class TestTriggerLedgerIntegrity(unittest.TestCase):
    def setUp(self):
        self.target = "trigger-ledger-" + uuid.uuid4().hex[:10]
        self.state_dir = _state_dir(self.target)
        shutil.rmtree(self.state_dir, ignore_errors=True)
        shutil.rmtree(Path("state/chains") / self.target, ignore_errors=True)
        mark_tested(self.target, "https://example.test/api/users/1")
        trigger_after_finding(self.target, {
            "finding_id": "finding-1",
            "title": "Synthetic authorization signal",
            "endpoint": "https://example.test/api/users/1",
            "method": "GET",
            "bug_class": "idor",
            "severity": "high",
            "description": "redacted controlled observation",
        })

    def tearDown(self):
        shutil.rmtree(self.state_dir, ignore_errors=True)
        shutil.rmtree(Path("state/chains") / self.target, ignore_errors=True)
        shutil.rmtree(Path("state/ledger") / self.target, ignore_errors=True)

    def _check(self):
        return LedgerVerifier(self.target).check_integrity()

    def test_clean_trigger_streams_are_valid(self):
        integrity = self._check()
        self.assertIsNotNone(integrity)
        self.assertTrue(integrity.is_valid)
        self.assertIsNotNone(integrity.trigger_receipts)
        self.assertIsNotNone(integrity.trigger_queue)
        self.assertTrue(integrity.trigger_receipts.is_valid)
        self.assertTrue(integrity.trigger_queue.is_valid)
        self.assertEqual(integrity.trigger_receipts.total_records, 1)
        self.assertGreaterEqual(integrity.trigger_queue.total_records, 1)

    def test_receipt_tampering_is_reported_separately(self):
        path = self.state_dir / "post-finding-triggers.jsonl"
        record = json.loads(path.read_text().splitlines()[0])
        record["status"] = "finding" if record["status"] != "finding" else "error"
        path.write_text(json.dumps(record) + "\n")

        integrity = self._check()
        self.assertFalse(integrity.is_valid)
        self.assertFalse(integrity.trigger_receipts.is_valid)
        self.assertTrue(integrity.trigger_queue.is_valid)
        self.assertGreaterEqual(integrity.trigger_receipts.tampered_records, 1)
        self.assertTrue(any("trigger receipts" in error
                            for error in integrity.errors))

    def test_queue_tampering_is_reported_separately(self):
        path = self.state_dir / "post-finding-queue.jsonl"
        lines = path.read_text().splitlines()
        record = json.loads(lines[0])
        record["status"] = "complete"
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n")

        integrity = self._check()
        self.assertFalse(integrity.is_valid)
        self.assertTrue(integrity.trigger_receipts.is_valid)
        self.assertFalse(integrity.trigger_queue.is_valid)
        self.assertGreaterEqual(integrity.trigger_queue.tampered_records, 1)
        self.assertTrue(any("trigger queue" in error
                            for error in integrity.errors))


if __name__ == "__main__":
    unittest.main()
