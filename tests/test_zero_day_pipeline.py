#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.zero_day_pipeline import run_pipeline


class TestZeroDayPipeline(unittest.TestCase):
    def test_pipeline_emits_candidates_chains_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            observations = root / "observations.json"
            observations.write_text(json.dumps({
                "target": "lab",
                "observations": [
                    {"domain": "web_api", "kind": "behavior_differential",
                     "endpoint": "/api/transfer", "status": 500,
                     "body": "error", "baseline_status": 200, "baseline_body": "ok"},
                    {"domain": "ai", "kind": "tool_misuse",
                     "tool_call": {"tool": "fetch", "arguments": {"url": "https://lab/api/transfer"}},
                     "context_source": "web_content"},
                ],
            }))
            result = run_pipeline(str(observations), project_root=tmp)
            self.assertGreaterEqual(result["candidates"], 1)
            self.assertTrue(result["report_json"].is_file())
            self.assertTrue(result["report_markdown"].is_file())
            self.assertTrue(result["report_sarif"].is_file())
            # Cross-domain chain links the AI tool call to the Web/API endpoint.
            self.assertGreaterEqual(result["chains"], 1)

    def test_pipeline_rejects_unknown_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            observations = root / "observations.json"
            observations.write_text(json.dumps({
                "target": "lab",
                "observations": [{"domain": "unknown", "kind": "x"}],
            }))
            with self.assertRaises(ValueError):
                run_pipeline(str(observations), project_root=str(root))


if __name__ == "__main__":
    unittest.main()