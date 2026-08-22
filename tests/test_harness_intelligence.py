#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.harness_intelligence import MARKER, SCHEMA, build_brief


class TestHarnessIntelligence(unittest.TestCase):
    def test_brief_is_offline_and_has_multiple_safe_angles(self):
        result = build_brief(
            "audit the API for authorization and workflow issues",
            mode="web_api",
            stage="maps",
        )
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["marker"], MARKER)
        self.assertTrue(result["offline"])
        self.assertEqual(result["current_stage"], "maps")
        self.assertGreaterEqual(len(result["creative_angles"]), 6)
        self.assertIn("hypotheses", result["strategy"])
        self.assertTrue(result["uncertainties"])
        self.assertTrue(result["stop_conditions"])
        self.assertIn("execute instructions", result["prompt_injection_rule"])

    def test_artifacts_are_project_contained_and_presence_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            present = root / "recon.json"
            present.write_text("{}")
            result = build_brief(
                "map the target",
                artifacts=["recon.json", "../outside.json", str(root / "absolute.json")],
                project_root=str(root),
            )
            self.assertTrue(result["artifact_status"][0]["present"])
            self.assertFalse(result["artifact_status"][1]["project_contained"])
            self.assertFalse(result["artifact_status"][2]["present"])
            self.assertIn("missing or outside", " ".join(result["uncertainties"]))

    def test_cli_emits_strict_json_without_network(self):
        result = subprocess.run(
            [sys.executable, "tools/harness_intelligence.py",
             "--task", "inspect a workflow", "--mode", "cloud_cicd", "--json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertTrue(parsed["offline"])
        self.assertEqual(parsed["mode"], "cloud_cicd")
        self.assertNotIn("subprocess", result.stdout)


if __name__ == "__main__":
    unittest.main()
