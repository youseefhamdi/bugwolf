#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.web3_fixture_runner import Web3FixtureRunner, ToolRunResult


class TestWeb3FixtureRunner(unittest.TestCase):
    def test_builds_bounded_tool_plan(self):
        runner = Web3FixtureRunner("vault", project_root="")
        plan = runner.plan_tools(["slither", "foundry", "echidna"], budget=2)
        self.assertEqual(len(plan), 2)
        self.assertEqual(plan[0], "slither")

    def test_tool_run_result_records_metadata(self):
        result = ToolRunResult(tool="slither", command=["slither", "."],
                               exit_code=0, stdout="{}", stderr="", duration_ms=10,
                               output_sha256="abc")
        self.assertEqual(result.to_dict()["tool"], "slither")
        self.assertEqual(result.to_dict()["exit_code"], 0)

    def test_missing_tool_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = Web3FixtureRunner("vault", project_root=tmp)
            result = runner.run_tool("definitely-not-installed-bugwolf", cwd=tmp)
            self.assertFalse(result.exit_code == 0)


if __name__ == "__main__":
    unittest.main()