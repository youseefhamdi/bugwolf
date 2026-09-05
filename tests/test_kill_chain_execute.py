#!/usr/bin/env python3
"""Tests for the kill_chain.execute_chain() v1.24.1+ live execution path."""
import json
import sys
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.kill_chain import (
    KillChainBuilder, ChainCandidate, CHAIN_PATTERNS,
)


def _candidate(chain_id: str = "CHAIN-001") -> ChainCandidate:
    pat = next(p for p in CHAIN_PATTERNS if p.chain_id == chain_id)
    return ChainCandidate(
        pattern=pat,
        matched_findings=[{"endpoint": "/api/v1/users/1", "id": "f-1"}],
        match_score=1.0,
        combined_severity="high",
        trigger_sequence=[],
        auto_testable=True,
        estimated_bounty=pat.bounty_range,
    )


class KillChainExecuteChain(unittest.TestCase):

    def test_execute_chain_uses_replay(self):
        builder = KillChainBuilder("test.example.com")
        result = builder.execute_chain(_candidate("CHAIN-001"))
        # Result is one of EXECUTED, REFUSED, ERROR — never PLAN_GENERATED
        self.assertIn(result["status"], ("EXECUTED", "REFUSED", "ERROR"))
        self.assertEqual(result["chain_id"], "CHAIN-001")
        self.assertEqual(result["target"], "test.example.com")
        # Plan was still generated (auto_test_chain still works as planner)
        self.assertIn("test_count", result)

    def test_auto_test_chain_remains_planner(self):
        """Legacy planner must NOT change behavior — just no longer lies."""
        builder = KillChainBuilder("test.example.com")
        result = builder.auto_test_chain(_candidate("CHAIN-001"))
        self.assertIn("results", result)
        # Note: still says PLAN_GENERATED but with the new honest note
        self.assertEqual(result["results"][0]["status"], "PLAN_GENERATED")
        self.assertIn("execute_chain", result["results"][0]["note"])

    def test_non_auto_testable_refused(self):
        # Build a non-auto-testable pattern
        candidate = ChainCandidate(
            pattern=type("P", (), {
                "chain_id": "X", "name": "x", "required_classes": [],
                "endpoint_patterns": [], "severity": "high",
                "bounty_range": "$0",
            })(),
            matched_findings=[],
            match_score=0.5,
            combined_severity="low",
            trigger_sequence=[],
            auto_testable=False,
            estimated_bounty="$0",
        )
        builder = KillChainBuilder("test.example.com")
        result = builder.execute_chain(candidate)
        self.assertEqual(result["status"], "REFUSED")
        self.assertIn("reason", result)


if __name__ == "__main__":
    unittest.main()
