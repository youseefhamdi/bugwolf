#!/usr/bin/env python3
"""Tests for the CI bundle check (scripts/ci_bundle_check.sh logic).

The check guarantees the release bundles ship the self-eval harness AND pass
the eval.  These tests exercise the two verification layers directly:

  1. content check — the built .skill / .freebuff.zip bundles must contain the
     self-eval harness + core domain tools, carry the matching VERSION, and
     contain no __pycache__ / bytecode,
  2. eval-pass check — the self-eval harness, run from inside the extracted
     Freebuff bundle against a deterministic synthetic campaign, must score
     100% (6/6 tasks).

The full shell script additionally runs the 12-stage workflow and the bundle
rebuild; the unit tests below assert the same invariants without the slow
rebuild by reading the current dist bundles (built by the CI workflow before
this job's test step) — and, when bundles are absent, build them once.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text().strip()
SKILL = ROOT / "dist" / f"bugwolf-v{VERSION}.skill"
FREEBUFF = ROOT / "dist" / f"bugwolf-v{VERSION}.freebuff.zip"

REQUIRED_IN_BUNDLE = [
    "tools/validation/self_eval_harness.py",
    "tools/core/stage_controller.py",
    "tools/core/research_loop.py",
    "tools/core/signal_bus.py",
    "tools/core/campaign_orchestrator.py",
    "tools/domains/web/http_smuggling_detector.py",
    "tools/domains/web/parser_differential.py",
    "tools/domains/auth/jwt_forgery.py",
    "tools/domains/api/bopla_matrix.py",
    "tools/domains/cloud/iam_privesc_graph.py",
    "tools/recon/historical_asset_delta.py",
    "tools/intelligence/chain_graph_ai.py",
]

MANDATORY_SEQUENCE = ["pre-hunt", "post-recon", "post-maps", "bypass",
                      "post-findings", "escalation", "pre-report"]


def _build_bundles() -> None:
    """Rebuild the release bundles if they are missing."""
    if SKILL.is_file() and FREEBUFF.is_file():
        return
    subprocess.run(["bash", str(ROOT / "scripts" / "build_skill.sh")],
                   cwd=ROOT, check=True, capture_output=True)


def _bundle_rel_names(path: Path) -> set:
    """Relative names inside a bundle (prefix stripped for the freebuff zip)."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
    prefix = "" if path == SKILL else ".agents/skills/bugwolf/"
    return {n[len(prefix):] for n in names if n.startswith(prefix)}


def _check_bundle(path: Path, errors: list) -> None:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        rel = _bundle_rel_names(path)
        for req in REQUIRED_IN_BUNDLE:
            if req not in rel:
                errors.append(f"[{path.name}] missing {req}")
        version_entry = "" if path == SKILL else ".agents/skills/bugwolf/"
        version_entry += "VERSION"
        if version_entry in names:
            got = z.read(version_entry).decode().strip()
            if got != VERSION:
                errors.append(f"[{path.name}] VERSION mismatch: {got} != {VERSION}")
        else:
            errors.append(f"[{path.name}] missing VERSION")
        for n in names:
            if n.endswith(".pyc") or "__pycache__" in n or n.endswith(".tmp"):
                errors.append(f"[{path.name}] build artifact leaked: {n}")


def _write_synthetic_campaign(ws: Path, target: str) -> None:
    """Deterministic synthetic campaign the eval can score 100% on."""
    recon = ws / "recon" / target
    (recon / "asset-intel").mkdir(parents=True, exist_ok=True)
    (recon / "discovery").mkdir(parents=True, exist_ok=True)
    research = ws / "research" / target
    for sub in ("bypass", "auth", "contracts", "llm", "advisor", "learning",
                "chains", "verification"):
        (research / sub).mkdir(parents=True, exist_ok=True)
    maps = ws / "state" / "sessions" / target / "maps"
    maps.mkdir(parents=True, exist_ok=True)
    (ws / "state" / "capability").mkdir(parents=True, exist_ok=True)
    (ws / "state" / "chains" / target).mkdir(parents=True, exist_ok=True)

    (recon / "urls.txt").write_text(f"https://api.{target}\n")
    (recon / "tech-fingerprint.json").write_text(
        json.dumps({"stack": ["nginx", "node"], "waf": True}))
    (recon / "asset-intel" / "history.jsonl").write_text("snapshot1\n")
    (recon / "asset-intel" / "delta.json").write_text("{}")
    (recon / "recon-complete.json").write_text(json.dumps({"complete": True}))
    for m in ("asset.md", "trust.md", "authz.md", "state.md", "capability.md"):
        (maps / m).write_text(f"# {m}\n")
    (ws / "state" / "environment.json").write_text(json.dumps({"location": "local"}))
    (ws / "scope.json").write_text(json.dumps({"targets": [target]}))

    (research / "sequence.json").write_text(json.dumps({
        "schema": "research_execution/sequential-v1",
        "target": target,
        "executions": [{
            "sequence": MANDATORY_SEQUENCE,
            "runs": [{"checkpoint": ck, "pending_searches": 0,
                      "latest_ready": True} for ck in MANDATORY_SEQUENCE],
            "latest_required": True,
            "latest_ready": True,
        }],
        "latest_ready": True,
    }))

    deep_evidence = [
        (recon / "discovery" / "smuggling-plan.jsonl", [{"kind": "CL.TE"}]),
        (recon / "discovery" / "graphql-plans.json", {"plans": [{"category": "batching"}]}),
        (recon / "discovery" / "bopla-matrix.json", {"findings": [{"kind": "over-post"}]}),
        (recon / "discovery" / "ato-chain-plans.json", {"plans": [{"chain_id": "email-ato"}]}),
        (research / "auth" / "jwt-forgery-plans.json", {"plans": [{"name": "alg=none"}]}),
        (research / "auth" / "oauth-flow-plans.json", {"plans": [{"name": "code-theft"}]}),
        (ws / "state" / "capability" / f"iam-privesc-{target}.json",
         {"methods": [{"method": "iam:CreatePolicyVersion"}]}),
        (recon / "discovery" / "deep-link-plans.json", {"plans": [{"kind": "link_hijack"}]}),
        (recon / "discovery" / "mobile-policy-check.json", {"findings": [{"check": "allowBackup"}]}),
        (research / "contracts" / "triage-verdicts.json", {"verdicts": [{"score": 9.3}]}),
        (research / "contracts" / "price-manipulation-plans.json", {"plans": [{"dependency": "amm_spot"}]}),
        (research / "llm" / "agentic-tool-auth-plans.json", {"plans": [{"asi": "ASI02"}]}),
        (research / "llm" / "rag-poisoning-plans.json", {"plans": [{"vector": "write_back"}]}),
        (research / "advisor" / "seed-proposals.json", {"proposals": [{"mode": "web"}]}),
        (research / "learning" / "failure-bypass-candidates.json", {"candidates": [{"blocker": "403"}]}),
        (research / "chains" / "graph-ai-proposals.json", {"proposals": [{"kind": "terminal-gap"}]}),
        (research / "verification" / "lab-plans.json", {"plans": [{"family": "web"}]}),
    ]
    for path, obj in deep_evidence:
        path.write_text(json.dumps(obj))

    events = ws / "state" / "signals" / "events" / f"{target}.jsonl"
    events.parent.mkdir(parents=True, exist_ok=True)
    with events.open("a") as f:
        for event_type in ("FINDING_DISCOVERED", "AUTH_CANDIDATE"):
            f.write(json.dumps({"event_type": event_type, "payload": {}}) + "\n")
    (ws / "state" / "chains" / target / "orchestration.json").write_text(
        json.dumps({"graph": {"nodes": [], "edges": []}}))


class TestBundleContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _build_bundles()

    def test_bundles_exist(self):
        self.assertTrue(SKILL.is_file(), f"missing {SKILL}")
        self.assertTrue(FREEBUFF.is_file(), f"missing {FREEBUFF}")

    def test_both_bundles_ship_self_eval_harness_and_core(self):
        for bundle in (SKILL, FREEBUFF):
            rel = _bundle_rel_names(bundle)
            for req in REQUIRED_IN_BUNDLE:
                self.assertIn(req, rel,
                              f"[{bundle.name}] missing {req}")

    def test_version_matches_and_no_bytecode(self):
        errors = []
        for bundle in (SKILL, FREEBUFF):
            _check_bundle(bundle, errors)
        self.assertEqual(errors, [])


class TestCheckScriptFailsOnTamperedBundle(unittest.TestCase):
    """The ci_bundle_check.sh script itself must fail on a tampered bundle.

    Uses the CI_BUNDLE_* overrides so the script checks a deliberately
    corrupted copy (self-eval harness removed) instead of rebuilding fresh.
    """

    @classmethod
    def setUpClass(cls):
        _build_bundles()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bad = Path(cls.tmp.name) / "bugwolf-tampered.skill"
        with zipfile.ZipFile(SKILL) as zin, \
                zipfile.ZipFile(cls.bad, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename.endswith("self_eval_harness.py"):
                    continue  # remove the harness from the copy
                zout.writestr(item, zin.read(item.filename))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _run_script(self, extra_env=None):
        env = dict(os.environ)
        env.update({
            "CI_BUNDLE_NO_BUILD": "1",
            "CI_BUNDLE_SKILL": str(self.bad),
            "CI_BUNDLE_FREEBUFF": str(FREEBUFF),
        })
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / "ci_bundle_check.sh")],
            capture_output=True, text=True, cwd=ROOT, env=env)

    def test_script_exits_nonzero_and_reports_missing_harness(self):
        result = self._run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing tools/validation/self_eval_harness.py",
                      result.stdout + result.stderr)
        self.assertIn("bundle content check failed",
                      result.stdout + result.stderr)

    def test_script_passes_when_pointed_at_the_real_bundle(self):
        # Control: with the pristine bundle the same override path must pass,
        # proving the failure above is caused by the tampering, not the
        # override plumbing.
        result = self._run_script({"CI_BUNDLE_SKILL": str(SKILL)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CI bundle check PASSED", result.stdout)

    def test_script_fails_when_violating_each_required_tool(self):
        # Removing any single required tool must be caught, not just the
        # harness — spot-check a second core file.
        with zipfile.ZipFile(SKILL) as zin, \
                zipfile.ZipFile(self.bad, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename.endswith("core/stage_controller.py"):
                    continue
                zout.writestr(item, zin.read(item.filename))
        result = self._run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing tools/core/stage_controller.py",
                      result.stdout + result.stderr)

    def test_script_fails_when_version_mismatches(self):
        # A stale/incorrect VERSION inside the bundle must be detected.
        with zipfile.ZipFile(SKILL) as zin, \
                zipfile.ZipFile(self.bad, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "VERSION":
                    zout.writestr(item, "0.0.0-tampered")
                else:
                    zout.writestr(item, zin.read(item.filename))
        result = self._run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VERSION mismatch", result.stdout + result.stderr)


class TestEvalPassFromBundle(unittest.TestCase):
    """The self-eval harness must score 100% when run from inside the bundle."""

    @classmethod
    def setUpClass(cls):
        _build_bundles()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = Path(cls.tmp.name)
        cls.extract = cls.work / "bundle"
        cls.extract.mkdir()
        with zipfile.ZipFile(FREEBUFF) as z:
            z.extractall(cls.extract)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_eval_scores_six_of_six_from_bundle(self):
        target = "synth.ci"
        ws = self.work / "campaign"
        ws.mkdir()
        _write_synthetic_campaign(ws, target)
        bundle_tools = self.extract / ".agents/skills/bugwolf" / "tools"
        harness = bundle_tools / "validation" / "self_eval_harness.py"
        self.assertTrue(harness.is_file(), "harness missing from extraction")

        # Complete all 12 stages with the BUNDLE's stage controller so the
        # workflow task scores from the shipped code, exactly like the shell
        # CI check does.
        (ws / "BUGWOLF.md").write_text("# BugWolf harness contract\n")
        subprocess.run([sys.executable, str(bundle_tools / "harness_guard.py"),
                        "--init", "--project-root", str(ws), "--json"],
                       check=True, capture_output=True, cwd=ROOT)
        sc = [sys.executable, str(bundle_tools / "core" / "stage_controller.py"),
              "--target", target, "--project-root", str(ws)]
        subprocess.run(sc + ["--start", "--json"], check=True,
                       capture_output=True, cwd=ROOT)
        for stage in ("setup", "environment-preflight", "authorization",
                      "passive-recon", "asset-intelligence",
                      "technology-fingerprint", "maps", "research",
                      "coverage-plan", "validation", "triage", "report"):
            cmd = sc + ["--complete", stage]
            if stage == "authorization":
                cmd += ["--scope-file", str(ws / "scope.json")]
            if stage in ("validation", "triage", "report"):
                cmd += ["--artifact",
                        str(ws / "recon" / target / "recon-complete.json")]
            subprocess.run(cmd + ["--json"], check=True,
                           capture_output=True, cwd=ROOT)

        result = subprocess.run(
            [sys.executable, str(harness), "--target", target,
             "--base-dir", str(ws), "--json"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["task_count"], 6)
        self.assertEqual(data["tasks_passed"], 6)
        self.assertEqual(data["score_pct"], 100.0)
        self.assertEqual(data["milestone_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
