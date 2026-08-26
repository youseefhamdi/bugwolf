#!/usr/bin/env python3
"""Tests for the Phase 1 engagement-context recorder (accountability, no gates)."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.engagement_context import (
    default_context,
    load_audit,
    load_context,
    record_context,
    stamp_operation,
    validate_context,
)
from tools.runtime_paths import workspace_root


class TestEngagementContext(unittest.TestCase):
    def test_default_context_records_macquire_and_is_advisory(self):
        context = default_context(target="https://example.test")
        self.assertEqual(context["operator"], "unknown")
        self.assertEqual(context["authorization"], "operator_declared")
        report = validate_context(context)
        # Missing engagement id is an error in validation, but the recorder
        # never blocks execution — it only warns.
        self.assertFalse(report["valid"])
        self.assertTrue(any("engagement_id" in e for e in report["errors"]))

    def test_record_and_load_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = {
                "operator": "Example Research Org",
                "authorization": "operator_declared",
                "engagement_id": "ENG-001",
                "target": "example.test",
                "environment": "authorized_production",
            }
            recorded = record_context(context, project_root=tmp)
            self.assertEqual(recorded["operator"], "Example Research Org")
            loaded = load_context(project_root=tmp)
            self.assertEqual(loaded["engagement_id"], "ENG-001")
            report = validate_context(loaded)
            self.assertTrue(report["valid"])
            self.assertTrue((Path(tmp) / "state" / "context" / "engagement.json").is_file())

    def test_stamp_operation_appends_audit_without_gating(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp_operation("live_probe", target="https://example.test/api",
                            project_root=tmp,
                            metadata={"probe_id": "p1"})
            stamp_operation("exploit_replay", target="https://example.test/api",
                            project_root=tmp)
            audit = load_audit(tmp)
            self.assertEqual(len(audit), 2)
            self.assertEqual(audit[0]["action"], "live_probe")
            self.assertEqual(audit[0]["operator"], "unknown")
            self.assertIn("example.test", audit[0]["target_slug"])

    def test_stamp_never_raises_on_unwritable_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocked = Path(tmp) / "state" / "context" / "audit.jsonl"
            blocked.parent.mkdir(parents=True, exist_ok=True)
            blocked.write_text("", encoding="utf-8")
            os.chmod(blocked, 0o444)
            try:
                record = stamp_operation("fuzz_probe", target="https://example.test",
                                         project_root=tmp)
                self.assertEqual(record["action"], "fuzz_probe")
                self.assertIn("persist_error", record)
            finally:
                os.chmod(blocked, 0o644)

    def test_simulate_records_dry_run_not_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp_operation("state_change", target="https://example.test",
                            project_root=tmp, simulate=True)
            self.assertEqual(load_audit(tmp), [])
            dry = load_audit(tmp, simulate=True)
            self.assertEqual(len(dry), 1)
            self.assertTrue(dry[0]["simulate"])


class TestLiveExecutorAttribution(unittest.TestCase):
    def test_execute_probe_stamps_operation_audit(self):
        from tools.core.live_executor import execute_probe

        with tempfile.TemporaryDirectory() as tmp:
            unit = {"endpoint": "https://example.test/api", "bug_class": "web"}

            def transport(spec):
                return (200, {}, "ok", 1.0)

            result = execute_probe(unit, "https://example.test",
                                   transport=transport, project_root=tmp,
                                   include_baseline=False)
            self.assertEqual(result.status, 200)
            audit = load_audit(tmp)
            self.assertTrue(any(
                r["action"] == "live_probe" and r["target"] == "https://example.test/api"
                for r in audit), audit)


if __name__ == "__main__":
    unittest.main()
