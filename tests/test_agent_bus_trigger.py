#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.agent_bus import AgentBus, Signal
from tools.state import get_findings


class TestAgentBusHardTrigger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = "signals.example"
        self.patches = patch.multiple(
            "tools.agent_bus",
            ROOT=self.root,
            SIGNALS_ROOT=self.root / "state" / "signals",
        )
        self.patches.start()
        self.state_patches = patch.multiple(
            "tools.state",
            ROOT=self.root,
            STATE_ROOT=self.root / "state",
        )
        self.state_patches.start()

    def tearDown(self):
        self.state_patches.stop()
        self.patches.stop()
        self.tmp.cleanup()

    def _signal(self, **overrides):
        value = {
            "signal_type": "discovery",
            "from_agent": "web-api-agent",
            "to_agents": ["access-control-agent", "business-logic-agent"],
            "priority": "high",
            "finding_ref": "lead-123",
            "signal_data": {
                "endpoint": "/api/users/42",
                "pattern": "cross-account object boundary",
            },
            "timestamp": "2026-08-22T00:00:00+00:00",
            "signal_id": "signal-123",
        }
        value.update(overrides)
        return Signal(**value)

    def _latest(self):
        return json.loads((self.root / "state" / "sessions" / self.target /
                           "post-signal-latest.json").read_text())

    def test_send_creates_one_receipt_for_broadcast_and_shared_review_queue(self):
        bus = AgentBus(self.target)
        signal = self._signal()
        bus.send(signal)

        latest = self._latest()
        receipt_log = (self.root / "state" / "sessions" / self.target /
                       "post-finding-triggers.jsonl")
        queue_log = (self.root / "state" / "sessions" / self.target /
                     "post-finding-queue.jsonl")
        self.assertEqual(latest["event_kind"], "signal")
        self.assertEqual(latest["signal_id"], signal.signal_id)
        self.assertEqual(latest["status"], "signal")
        self.assertTrue(latest["queue"])
        self.assertEqual(len(receipt_log.read_text().splitlines()), 1)
        self.assertEqual(len(queue_log.read_text().splitlines()), len(latest["queue"]))
        self.assertTrue(all(item["event_kind"] == "signal"
                            for item in latest["queue"]))
        self.assertTrue(all(item["automatic_execution"] is False
                            for item in latest["queue"]))
        self.assertTrue(all("human_review" in item["requires"]
                            for item in latest["queue"]))

        # The signal remains deliverable to each addressed agent independently.
        self.assertEqual([s.signal_id for s in bus.receive("access-control-agent")],
                         [signal.signal_id])
        self.assertEqual([s.signal_id for s in bus.receive("business-logic-agent")],
                         [signal.signal_id])

    def test_signal_without_evidence_is_blocked_not_promoted_to_finding(self):
        bus = AgentBus(self.target)
        bus.send(self._signal(finding_ref=None, signal_data={}))

        latest = self._latest()
        self.assertEqual(latest["status"], "blocked")
        self.assertIn("signal_data_or_finding_ref", latest["evidence"]["missing"])
        self.assertTrue(all(item["status"] == "blocked_missing_evidence"
                            for item in latest["queue"]))
        self.assertFalse((self.root / "state" / "sessions" / self.target /
                          "findings.jsonl").exists())
        self.assertEqual(get_findings(self.target), [])

    def test_trigger_failure_writes_signal_repair_receipt(self):
        bus = AgentBus(self.target)
        signal = self._signal()
        with patch("tools.agent_bus.trigger_after_signal",
                   side_effect=RuntimeError("synthetic signal trigger failure")):
            bus.send(signal)

        latest = self._latest()
        self.assertEqual(latest["event_kind"], "signal")
        self.assertEqual(latest["status"], "error")
        self.assertIn("synthetic signal trigger failure", latest["error"])
        self.assertEqual(latest["queue"][0]["status"], "blocked_trigger_error")
        self.assertFalse(latest["queue"][0]["automatic_execution"])


if __name__ == "__main__":
    unittest.main()
