#!/usr/bin/env python3
import unittest

from tools.red_team_runner import RedTeamRunner


class TestRedTeamRunner(unittest.TestCase):
    def test_plans_commands_for_available_tools(self):
        runner = RedTeamRunner("agent-lab")
        plan = runner.plan_commands("garak", target="agent-lab")
        self.assertTrue(plan)
        self.assertEqual(plan[0]["tool"], "garak")

    def test_missing_tool_is_reported_not_raised(self):
        runner = RedTeamRunner("agent-lab")
        result = runner.run_command("definitely-not-installed-bugwolf", ["--help"])
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_normalizes_garak_output_through_adapter(self):
        runner = RedTeamRunner("agent-lab")
        candidates = runner.normalize("garak", {"probes": [
            {"probe": "jailbreak", "outputs": [{"output": "Sure"}],
             "detectors": {"jailbreak": {"score": 0.9}}}]})
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "ai")
        self.assertEqual(candidates[0].bug_class, "jailbreak")


if __name__ == "__main__":
    unittest.main()