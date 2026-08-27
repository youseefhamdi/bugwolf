#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.web3_research import Web3ResearchAdapter


class TestWeb3ResearchAdapter(unittest.TestCase):
    def test_emits_candidate_for_invariant_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Web3ResearchAdapter("vault", project_root=tmp)
            candidates = adapter.analyze_observations([{
                "sequence": ["deposit", "withdraw"],
                "caller": "attacker",
                "state_before": {"assets": 100},
                "state_after": {"assets": 90},
                "invariants": {"assets_conserved": False},
                "trace": [{"function": "withdraw", "value": 110}],
            }])
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].domain, "web3")
            self.assertEqual(candidates[0].bug_class, "invariant_violation")
            self.assertIn("assets_conserved", candidates[0].behavior["violated"])

    def test_emits_candidate_for_cross_environment_trace_delta(self):
        adapter = Web3ResearchAdapter("bridge")
        candidates = adapter.analyze_trace_pairs([{
            "name": "withdraw",
            "chain_a": {"status": "reverted", "events": []},
            "chain_b": {"status": "success", "events": [{"name": "Withdrawn"}]},
        }])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "execution_trace_differential")

    def test_registers_deduplicated_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Web3ResearchAdapter("vault", project_root=tmp)
            candidates = adapter.analyze_observations([{
                "sequence": ["withdraw"], "caller": "attacker",
                "state_after": {"assets": 0},
                "invariants": {"solvent": False},
            }])
            self.assertTrue(adapter.register(candidates))
            self.assertFalse(adapter.register(candidates))


if __name__ == "__main__":
    unittest.main()
