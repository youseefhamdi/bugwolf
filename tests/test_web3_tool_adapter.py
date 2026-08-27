#!/usr/bin/env python3
import tempfile
import unittest

from tools.web3_tool_adapter import Web3ToolResultAdapter


class TestWeb3ToolResultAdapter(unittest.TestCase):
    def test_normalizes_slither_detector_output(self):
        adapter = Web3ToolResultAdapter("vault")
        candidates = adapter.from_slither({
            "results": {"detectors": [{
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "High",
                "description": "External call before state update",
                "elements": [{"source_mapping": {"filename_relative": "src/Vault.sol", "lines": [42]}}],
            }]}
        })
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "web3")
        self.assertEqual(candidates[0].bug_class, "reentrancy-eth")
        self.assertIn("Vault.sol", str(candidates[0].behavior["source"]))

    def test_normalizes_property_failure_output(self):
        adapter = Web3ToolResultAdapter("vault")
        candidates = adapter.from_property_runner({
            "tool": "foundry",
            "failures": [{"test": "invariant_solvency", "reason": "assets < liabilities", "trace": ["deposit", "withdraw"]}],
        })
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "invariant_solvency")
        self.assertEqual(candidates[0].behavior["sequence"], ["deposit", "withdraw"])

    def test_register_deduplicates_tool_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Web3ToolResultAdapter("vault", project_root=tmp)
            raw = {"results": {"detectors": [{"check": "x", "impact": "Medium", "confidence": "High", "description": "same"}]}}
            candidates = adapter.from_slither(raw)
            self.assertTrue(adapter.register(candidates))
            self.assertFalse(adapter.register(candidates))


if __name__ == "__main__":
    unittest.main()
