#!/usr/bin/env python3
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.harness_command import MARKER, SCHEMA, parse_invocation


class TestHarnessCommand(unittest.TestCase):
    def test_full_command_extracts_target_without_granting_permission(self):
        result = parse_invocation(
            "bugwolf --full attack this target https://example.test"
        )
        self.assertTrue(result["recognized"])
        self.assertTrue(result["full"])
        self.assertEqual(result["target"], "https://example.test")
        self.assertEqual(result["modes"], ["all_applicable"])
        self.assertTrue(result["requires"]["explicit_scope"])
        self.assertTrue(result["requires"]["active_confirmation"])
        self.assertFalse(result["controls_requested"]["active_requested"])
        self.assertEqual(result["intent"], "authorized_security_assessment")

    def test_mode_and_target_flag_are_supported(self):
        result = parse_invocation("bugwolf --web --target api.example.test audit")
        self.assertEqual(result["modes"], ["web"])
        self.assertEqual(result["target"], "api.example.test")
        self.assertFalse(result["needs_clarification"])

    def test_missing_target_is_clarification_not_execution(self):
        result = parse_invocation("bugwolf --full attack this target")
        self.assertTrue(result["recognized"])
        self.assertTrue(result["needs_clarification"])
        self.assertIsNone(result["target"])
        self.assertIn("target is missing", result["errors"])

    def test_non_bugwolf_text_is_not_reinterpreted(self):
        result = parse_invocation("please audit https://example.test")
        self.assertFalse(result["recognized"])
        self.assertFalse(result["needs_clarification"])

    def test_cli_is_strict_json_and_offline(self):
        result = subprocess.run(
            [sys.executable, "tools/harness_command.py", "--json",
             "--text", "bugwolf --full attack this target example.test"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["marker"], MARKER)
        self.assertTrue(payload["offline"])
        self.assertNotIn("subprocess", result.stdout)


if __name__ == "__main__":
    unittest.main()
