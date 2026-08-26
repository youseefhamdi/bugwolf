#!/usr/bin/env python3
"""F0.5 quarantine-store integrity tests.

Covers:
  * state/learning/<target>.jsonl is recorded as a hashed triage-stage
    supplementary artifact (append-only digest: lines:N:sha256)
  * later quarantine appends never trip the integrity gate
  * tampering with the recorded prefix fails verification
  * truncating the ledger fails verification
  * an absent quarantine store never blocks triage
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.harness_guard import initialize as initialize_contract
from tools.stage_controller import WorkflowController, WorkflowError

RESEARCH_SEQUENCE = [
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
]


class TestQuarantineStoreIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name)
        self.target = "example.com"
        initialize_contract(str(self.project))
        (self.project / "BUGWOLF.md").write_text(
            "# BugWolf\n`BUGWOLF-HARNESS-CONTRACT-V2`\n")
        self.controller = WorkflowController(
            self.target, project_root=str(self.project), mode="web")
        self.controller.initialize()
        self.addCleanup(self.tmp.cleanup)

    # -- helpers -----------------------------------------------------------

    @property
    def learning_store(self) -> Path:
        return self.project / "state" / "learning" / f"{self.target}.jsonl"

    def _write_quarantine(self, count=2):
        store = self.learning_store
        store.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps({"kind": "low-confidence-finding",
                             "technique_id": f"q{i}",
                             "status": "candidate",
                             "confidence": 0.2}) + "\n"
                 for i in range(count)]
        store.write_text("".join(lines), encoding="utf-8")

    def _complete_to_triage(self, *, with_quarantine=True, with_findings=False):
        if with_quarantine:
            self._write_quarantine()
        if with_findings:
            ledger = self.project / "state" / "sessions" \
                / self.target / "findings.jsonl"
            ledger.parent.mkdir(parents=True, exist_ok=True)
            ledger.write_text(json.dumps({
                "finding_id": "f1", "state": "FINDING",
                "bug_class": "idor", "severity": "high",
                "refutation": {"final_verdict": "confirmed"},
            }) + "\n", encoding="utf-8")
        c = self.controller
        c.complete("setup")
        env = self.project / "state" / "environment.json"
        env.parent.mkdir(parents=True, exist_ok=True)
        env.write_text(json.dumps({"location": "unknown"}))
        c.complete("environment-preflight")
        scope = self.project / "scope.json"
        scope.write_text(json.dumps({"authorized": True,
                                     "in_scope_domains": [self.target]}))
        c.complete("authorization", scope_file=str(scope))
        recon = self.project / "recon" / self.target
        recon.mkdir(parents=True)
        (recon / "recon-complete.json").write_text(json.dumps({"complete": True}))
        c.complete("passive-recon")
        asset = recon / "asset-intel"
        asset.mkdir()
        (asset / "asset-inventory.json").write_text("{}")
        c.complete("asset-intelligence")
        (recon / "tech-fingerprint.json").write_text("{}")
        c.complete("technology-fingerprint")
        maps = self.project / "state" / "sessions" / self.target / "maps"
        maps.mkdir(parents=True)
        for name in ("asset.md", "trust.md", "authz.md", "state.md",
                     "capability.md"):
            (maps / name).write_text(f"# {name}\n")
        c.complete("maps")
        seq = self.project / "research" / self.target / "sequence.json"
        seq.parent.mkdir(parents=True)
        seq.write_text(json.dumps({
            "executions": [{
                "sequence": list(RESEARCH_SEQUENCE),
                "runs": [],
                "latest_ready": True,
            }],
            "latest_ready": True,
        }))
        c.complete("research")
        discovery = recon / "discovery"
        discovery.mkdir()
        (discovery / "plan.jsonl").write_text("{}\n")
        c.complete("coverage-plan")
        artifact = str(env)
        c.complete("validation", artifacts=[artifact])
        c.complete("triage", artifacts=[artifact])
        return c

    def _triage_stage(self):
        data = json.loads(
            (self.project / ".bugwolf" / "workflows"
             / f"{self.target}.json").read_text(encoding="utf-8"))
        return next(s for s in data["stages"] if s["name"] == "triage")

    # -- tests -------------------------------------------------------------

    def test_quarantine_store_recorded_and_hash_chained(self):
        self._complete_to_triage(with_quarantine=True)
        stage = self._triage_stage()
        rel = f"state/learning/{self.target}.jsonl"
        self.assertIn(rel, stage["artifacts"])
        recorded = stage["artifact_hashes"][rel]
        # Append-only digest format: lines:N:<sha256>.
        parts = recorded.split(":")
        self.assertEqual(parts[0], "lines")
        self.assertEqual(int(parts[1]), 2)
        self.assertEqual(len(parts[2]), 64)

    def test_append_after_completion_never_breaks_integrity(self):
        self._complete_to_triage(with_quarantine=True)
        # More findings get quarantined after triage recorded the store.
        with self.learning_store.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": "low-confidence-candidate",
                                     "technique_id": "q3",
                                     "status": "candidate"}) + "\n")
        # Advancing to report re-verifies all completed stages.
        self.controller.require_stage("report")

    def test_tampering_with_recorded_prefix_fails(self):
        self._complete_to_triage(with_quarantine=True)
        lines = self.learning_store.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"status": "candidate"',
                                     '"status": "approved"')
        self.learning_store.write_text("\n".join(lines) + "\n",
                                       encoding="utf-8")
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("report")

    def test_truncating_the_ledger_fails(self):
        self._complete_to_triage(with_quarantine=True)
        lines = self.learning_store.read_text(encoding="utf-8").splitlines()
        self.learning_store.write_text("\n".join(lines[:1]) + "\n",
                                       encoding="utf-8")
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("report")

    def test_absent_quarantine_store_never_blocks_triage(self):
        self._complete_to_triage(with_quarantine=False)
        stage = self._triage_stage()
        rel = f"state/learning/{self.target}.jsonl"
        self.assertNotIn(rel, stage["artifacts"])
        self.controller.require_stage("report")

    def test_findings_ledger_recorded_and_append_safe(self):
        self._complete_to_triage(with_quarantine=False, with_findings=True)
        stage = self._triage_stage()
        rel = f"state/sessions/{self.target}/findings.jsonl"
        self.assertIn(rel, stage["artifacts"])
        recorded = stage["artifact_hashes"][rel]
        self.assertTrue(recorded.startswith("lines:1:"))
        # A later gated finding appends without breaking the gate.
        with (self.project / rel).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"finding_id": "f2",
                                     "state": "FINDING"}) + "\n")
        self.controller.require_stage("report")
        # Tampering with the recorded first line still fails.
        path = self.project / rel
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"severity": "high"', '"severity": "low"')
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(WorkflowError):
            self.controller.require_stage("report")


if __name__ == "__main__":
    unittest.main()
