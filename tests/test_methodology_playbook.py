#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.methodology_playbook import (
    build_tool_plans,
    build_validation_tasks,
    build_workflow_plans,
)


class TestMethodologyPlaybook(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "authorized": True,
            "in_scope": ["example.com"],
            "in_scope_wildcards": ["*.example.com"],
        }

    def test_workflow_plans_cover_article_logic_categories_and_keep_all_uncensored(self):
        urls = [
            "https://example.com/api/order?id=123&coupon=10OFF",
            "https://example.com/reset?token=test-token",
            "https://outside.example.net/admin/export",
        ]
        plans = build_workflow_plans("example.com", urls, scope=self.scope)
        categories = {plan.category for plan in plans}
        self.assertIn("payment_state", categories)
        self.assertIn("ownership_boundary", categories)
        self.assertIn("token_reuse", categories)
        self.assertTrue(plans)
        self.assertTrue(any("outside.example.net" in plan.location for plan in plans))  # uncensored: kept
        self.assertTrue(all(plan.status == "hypothesis_only" for plan in plans))
        self.assertTrue(all("Stop" in plan.stop_conditions[0] for plan in plans))

    def test_scanner_signals_become_trigger_impact_tasks_not_findings(self):
        signals = [
            {"source": "nuclei", "template-id": "generic-sqli", "matched-at": "https://example.com/api"},
            {"source": "manual", "type": "idor", "location": "https://example.com/api/user?id=1"},
            {"source": "ffuf", "type": "discovery", "url": "https://example.com/admin"},
        ]
        tasks = build_validation_tasks("example.com", signals)
        self.assertEqual(len(tasks), 3)
        by_type = {task.signal_type: task for task in tasks}
        self.assertIn("sql_injection_signal", by_type)
        self.assertIn("idor_signal", by_type)
        self.assertIn("surface_discovery_signal", by_type)
        self.assertTrue(all(task.status == "pending_human_validation" for task in tasks))
        self.assertIn("no --dbs", by_type["sql_injection_signal"].recommended_next_step)

    def test_tool_plans_are_non_executing_and_exclude_extraction(self):
        signals = [
            {"source": "nuclei", "template-id": "sqli", "matched-at": "https://example.com/api"},
            {"source": "manual", "type": "xss", "location": "https://example.com/search?q=x"},
            {"source": "ffuf", "type": "discovery", "url": "https://example.com/admin"},
        ]
        tasks = build_validation_tasks("example.com", signals)
        tool_plans = build_tool_plans("example.com", tasks)
        self.assertEqual({plan.tool for plan in tool_plans}, {"sqlmap", "xsstrike", "ffuf"})
        serialized = " ".join(" ".join(plan.argv) for plan in tool_plans)
        self.assertNotIn("--dbs", serialized)
        self.assertNotIn("--dump", serialized)
        self.assertNotIn("--tables", serialized)
        self.assertTrue(all(plan.status == "not_executed_offline_plan" for plan in tool_plans))
        self.assertTrue(all("explicit active confirmation" in " ".join(plan.safety_requirements)
                            or plan.tool == "ffuf" for plan in tool_plans))

    def test_cli_inputs_can_be_written_without_network_execution(self):
        # Smoke-test the output contract's required path names without invoking
        # any external tool or network source.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plans = build_workflow_plans(
                "example.com", ["https://example.com/checkout?coupon=x"], scope=self.scope
            )
            output = root / "workflow-plans.jsonl"
            output.write_text("\n".join(plan.title for plan in plans), encoding="utf-8")
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
