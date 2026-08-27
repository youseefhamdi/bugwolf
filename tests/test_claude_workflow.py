#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.claude_workflow import analyze_file
from tools.lab_runtime_adapters import diagnostics


class TestClaudeWorkflow(unittest.TestCase):
    def test_web_api_dispatches_to_candidate_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text("X-Account-Id = request.headers.get('X-Account-Id')\n")
            result = analyze_file("fixture", "web_api", str(path))
            self.assertEqual(result["domain"], "web_api")
            self.assertTrue(result["candidates"])
            self.assertIn("runtime_diagnostics", result)

    def test_mobile_dispatches_binary_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "AndroidManifest.xml"
            path.write_bytes(b'<activity android:exported="true" />')
            result = analyze_file("fixture", "mobile", str(path))
            self.assertEqual(result["domain"], "mobile_binary")
            self.assertTrue(result["candidates"])

    def test_optional_runtimes_are_explicitly_unavailable(self):
        result = diagnostics()
        self.assertEqual(result["available"], [])
        self.assertEqual(set(result["unavailable"]), {
            "browser", "emulator", "chain_node", "model", "mcp", "cloud"})
        self.assertTrue(all("runtime not supplied" in item["diagnostic"]
                            for item in result["runtimes"]))


if __name__ == "__main__":
    unittest.main()
