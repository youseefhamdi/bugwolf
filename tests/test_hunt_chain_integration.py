#!/usr/bin/env python3
import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.hunt import HuntResult, _format_structured_json, refresh_chain_state


class TestHuntChainIntegration(unittest.TestCase):
    def test_refresh_chain_state_is_explicit_when_orchestrator_fails(self):
        with patch("tools.hunt.refresh_chain_target", side_effect=RuntimeError("broken graph")):
            result = refresh_chain_state("example.test")
        self.assertEqual(result["status"], "error")
        self.assertTrue(result["offline"])
        self.assertEqual(result["stats"]["chains"], 0)

    def test_structured_handoff_contains_authoritative_chain_graph(self):
        args = argparse.Namespace(active=False, idor_only=False)
        chain = {
            "schema": "bugwolf-chain-orchestration/v1",
            "offline": True,
            "chains": [{"chain_id": "chain-1", "state": "blocked_missing_link"}],
            "stats": {"nodes": 1, "edges": 0, "chains": 1,
                      "complete_chains": 0, "blocked_chains": 1},
        }
        output = _format_structured_json(
            "example.test", [HuntResult(endpoint="/api/users/1")], args,
            chain_orchestration=chain,
            chain_refreshes=[{"finding_id": "F1", "stats": chain["stats"]}],
        )
        self.assertEqual(output["chain_orchestration"], chain)
        self.assertEqual(output["chain_refreshes"][0]["finding_id"], "F1")
        self.assertTrue(output["chain_orchestration"]["offline"])


if __name__ == "__main__":
    unittest.main()
