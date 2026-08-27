#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.candidate_lifecycle import ResearchCandidate
from tools.sarif_export import export_candidates_sarif


class TestSarifExport(unittest.TestCase):
    def test_export_produces_valid_sarif(self):
        candidate = ResearchCandidate(
            domain="web3", bug_class="reentrancy", title="Reentrancy",
            endpoint="/vault/withdraw", severity="high",
            behavior={"sequence": ["withdraw"]},
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "results.sarif"
            export_candidates_sarif([candidate], path)
            data = json.loads(path.read_text())
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
            self.assertEqual(len(data["runs"][0]["results"]), 1)
            result = data["runs"][0]["results"][0]
            self.assertEqual(result["ruleId"], "reentrancy")
            self.assertEqual(result["level"], "error")


if __name__ == "__main__":
    unittest.main()