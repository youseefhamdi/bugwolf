#!/usr/bin/env python3
"""Tests for tools/runtime/orphan_orchestrator.py (v1.24.1+)."""
import json
import sys
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime import orphan_orchestrator
from tools.runtime.orphan_orchestrator import (
    dispatch_phase, coverage_report, PHASE_HANDLERS,
)


class OrphanOrchestratorPhases(unittest.TestCase):

    def test_all_5_phases_have_handlers(self):
        self.assertIn("pre-recon", PHASE_HANDLERS)
        self.assertIn("recon", PHASE_HANDLERS)
        self.assertIn("hunt", PHASE_HANDLERS)
        self.assertIn("post-hunt", PHASE_HANDLERS)
        self.assertIn("report", PHASE_HANDLERS)

    def test_unknown_phase_returns_error(self):
        result = dispatch_phase("bogus-phase", "acme.com", "m-1")
        self.assertEqual(result["status"], "error")
        self.assertIn("unknown phase", result["error"])

    def test_pre_recon_no_manifest(self):
        result = dispatch_phase("pre-recon", "acme.com", "m-1")
        self.assertEqual(result["phase"], "pre-recon")
        # Either ok (if module loads) or skipped (if not)
        self.assertIn(result["status"], ("ok", "skipped", "error"))

    def test_recon_no_endpoints(self):
        result = dispatch_phase("recon", "acme.com", "m-1")
        self.assertEqual(result["phase"], "recon")
        self.assertIn(result["status"], ("ok", "skipped", "error"))

    def test_hunt_no_profile(self):
        result = dispatch_phase("hunt", "acme.com", "m-1")
        self.assertEqual(result["phase"], "hunt")
        self.assertIn(result["status"], ("ok", "skipped", "error"))

    def test_post_hunt_no_findings(self):
        result = dispatch_phase("post-hunt", "acme.com", "m-1",
                               findings=[])
        self.assertEqual(result["phase"], "post-hunt")
        self.assertIn("modules", result)

    def test_report_no_findings(self):
        result = dispatch_phase("report", "acme.com", "m-1",
                                findings=[])
        self.assertEqual(result["phase"], "report")
        self.assertIn("modules", result)

    def test_coverage_report_dict(self):
        report = coverage_report()
        self.assertIsInstance(report, dict)
        for mod in ("kill_chain", "trust_map", "capability_registry",
                    "adversary_emulation", "patch_gap", "threat_intel",
                    "program_fit", "formal_verify", "replay_cli"):
            self.assertIn(mod, report)


class OrphanOrchestratorPersistence(unittest.TestCase):

    def test_dispatch_persists_to_jsonl(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path.cwd()
            try:
                import os
                os.chdir(tmp)
                result = dispatch_phase("hunt", "test.example.com", "m-test")
                # Find the state/sessions/.../orchestrator/m-test-hunt.jsonl
                p = Path("state") / "sessions" / "test.example.com" / "orchestrator" / "m-test-hunt.jsonl"
                self.assertTrue(p.exists(),
                                f"expected {p} to exist after dispatch")
                lines = p.read_text().strip().splitlines()
                self.assertEqual(len(lines), 1)
                rec = json.loads(lines[0])
                self.assertEqual(rec["phase"], "hunt")
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
