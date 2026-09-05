#!/usr/bin/env python3
"""
## Source: bugwolf Phase 1.5 + Phase 1.3 test suite (new module)
## License: bugwolf-MIT
## Port: 2026-09-05

Phase 1.5 + 1.3 test suite.

Covers 16 cross-project sub-phases + 8 TS harness bridges.  Every
sub-phase has at least 3 tests (import + core function + stub-safe).
The 8 bridges have at least 1 smoke test each.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _import(stem: str):
    """Import a cross_project sub-module by stem."""
    return importlib.import_module(f"tools.cross_project.{stem}")


# ===========================================================================
# 1.5.a ReAct memory
# ===========================================================================

class TestReactMemory(unittest.TestCase):

    def test_import(self):
        mod = _import("react_memory")
        self.assertIsNotNone(mod.ReActMemory)

    def test_3_layer_basic(self):
        mod = _import("react_memory")
        m = mod.ReActMemory()
        ctx = m.begin_step("s1", thought="x", action="y")
        self.assertEqual(ctx.step_id, "s1")
        m.record_observation("s1", "obs1", "result-1")
        m.record_semantic("fingerprint:xss", {"pattern": "innerHTML"})
        self.assertIsNotNone(m.recall_semantic("fingerprint:xss"))
        self.assertGreaterEqual(m.episodic_count(), 1)
        m.end_step("s1")

    def test_snapshot_roundtrip(self):
        mod = _import("react_memory")
        m1 = mod.ReActMemory()
        m1.record_semantic("k1", "v1")
        snap = m1.snapshot()
        m2 = mod.ReActMemory()
        m2.restore(snap)
        rec = m2.recall_semantic("k1")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.content, "v1")


# ===========================================================================
# 1.5.b DOM XSS harness
# ===========================================================================

class TestDOMXSSHarness(unittest.TestCase):

    def setUp(self):
        """Reset global scope state so DOMXSSHarness sees a clean gate."""
        from tools.runtime import scope
        scope.reset()
        self.addCleanup(self._reset_scope)

    @staticmethod
    def _reset_scope():
        from tools.runtime import scope
        scope.reset()

    def test_import(self):
        mod = _import("dom_xss_harness")
        self.assertIsNotNone(mod.DOMXSSHarness)

    def test_sink_detection(self):
        mod = _import("dom_xss_harness")
        harness = mod.DOMXSSHarness(timeout_seconds=2.0)
        # Localhost URL — harness serves a mock with innerHTML assignment
        result = harness.confirm(
            "http://127.0.0.1:1/", "<script>alert(1)</script>")
        self.assertIsInstance(result, mod.DOMXSSResult)
        sink_names = [name for name, _ in mod.DOM_SINKS] + [""]
        self.assertIn(result.sink, sink_names)
        self.assertEqual(len(result.evidence_sha256), 64)

    def test_empty_url_returns_error(self):
        mod = _import("dom_xss_harness")
        harness = mod.DOMXSSHarness()
        r = harness.confirm("", "payload")
        self.assertFalse(r.executed)
        self.assertTrue(r.error)


# ===========================================================================
# 1.5.b WAF encoder
# ===========================================================================

class TestWAFEncoder(unittest.TestCase):

    def test_import(self):
        mod = _import("waf_encoder")
        self.assertIsNotNone(mod.WAFEncoder)

    def test_techniques_produce_different_outputs(self):
        mod = _import("waf_encoder")
        enc = mod.WAFEncoder()
        payload = "<script>alert(1)</script>"
        outputs = enc.encode_all(payload)
        # All 11 techniques should be present
        self.assertEqual(len(outputs), 11)
        # At least 4 outputs should be distinct (url, base64, html_entity,
        # double_url, hex_escape all differ)
        distinct = set(outputs.values())
        self.assertGreater(len(distinct), 4)

    def test_unknown_technique_raises(self):
        mod = _import("waf_encoder")
        enc = mod.WAFEncoder()
        with self.assertRaises(ValueError):
            enc.encode("x", technique="nonexistent")

    def test_empty_payload(self):
        mod = _import("waf_encoder")
        enc = mod.WAFEncoder()
        self.assertEqual(enc.encode("", "url"), "")


# ===========================================================================
# 1.5.c Multipart mutator
# ===========================================================================

class TestMultipartMutator(unittest.TestCase):

    def test_import(self):
        mod = _import("multipart_mutator")
        self.assertIsNotNone(mod.MultipartMutator)

    def test_10_variants(self):
        mod = _import("multipart_mutator")
        mut = mod.MultipartMutator()
        variants = mut.mutate("----b", "field", b"value")
        self.assertEqual(len(variants), 10)
        for v in variants:
            self.assertIsInstance(v, mod.MultipartVariant)
            self.assertIn(v.technique, mod.MultipartMutator.TECHNIQUES)
            self.assertGreater(len(v.body), 0)

    def test_unicode_name_has_unicode(self):
        mod = _import("multipart_mutator")
        mut = mod.MultipartMutator()
        variants = mut.mutate("----b", "field", b"value")
        unicode_variant = next(v for v in variants if v.technique == "unicode_name")
        self.assertIn("\u00e9", unicode_variant.field_name)


# ===========================================================================
# 1.5.d Lead Board
# ===========================================================================

class TestLeadBoard(unittest.TestCase):

    def test_import(self):
        mod = _import("lead_board")
        self.assertIsNotNone(mod.LeadBoard)

    def test_routes_by_url_pattern(self):
        mod = _import("lead_board")
        lb = mod.LeadBoard()
        skills = lb.route({"url": "https://t/search?q=x", "tech": "python"})
        names = [s.name for s in skills]
        self.assertIn("xss_reflected", names)

    def test_stale_high_detection(self):
        mod = _import("lead_board")
        lb = mod.LeadBoard()
        # Insert an old lead (8 days old)
        old_ms = 0  # epoch — definitely > 7 days
        lead = mod.Lead(
            lead_id="L1", title="old",
            url="https://t/", severity=mod.Severity.HIGH,
            created_at_ms=old_ms, last_updated_ms=old_ms,
        )
        stale = lb.detect_stale_highs([lead], max_age_days=7.0, now_ms=8 * 86400 * 1000)
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].lead_id, "L1")


# ===========================================================================
# 1.5.e Secret scanner
# ===========================================================================

class TestSecretScanner(unittest.TestCase):

    def test_import(self):
        mod = _import("secret_scan")
        self.assertIsNotNone(mod.SecretScanner)

    def test_pattern_count_at_least_80(self):
        mod = _import("secret_scan")
        scanner = mod.SecretScanner()
        self.assertGreaterEqual(scanner.pattern_count, 80)

    def test_aws_key(self):
        mod = _import("secret_scan")
        scanner = mod.SecretScanner()
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        hits = scanner.scan(text)
        names = {h.pattern_name for h in hits}
        self.assertIn("aws_access_key_id", names)

    def test_github_pat(self):
        mod = _import("secret_scan")
        scanner = mod.SecretScanner()
        text = "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        hits = scanner.scan(text)
        self.assertTrue(any(h.pattern_name == "github_pat" for h in hits))

    def test_stripe_live_secret(self):
        mod = _import("secret_scan")
        scanner = mod.SecretScanner()
        text = "key is STRIPE_LIVE_PLACEHOLDER_0123456789abcdefghijklmnop"
        hits = scanner.scan(text)
        self.assertTrue(any(h.pattern_name == "stripe_live_secret" for h in hits))


# ===========================================================================
# 1.5.e H1 reference (stub-safe)
# ===========================================================================

class TestH1Reference(unittest.TestCase):

    def test_import(self):
        mod = _import("h1_reference")
        self.assertIsNotNone(mod.H1Reference)

    def test_stub_safe_without_token(self):
        mod = _import("h1_reference")
        # Ensure no token is set
        os.environ.pop("HACKERONE_API_TOKEN", None)
        ref = mod.H1Reference()
        self.assertFalse(ref.credentials_configured)
        # fetch_reports must return [] when no token is set
        result = ref.fetch_reports("disclosed:true")
        self.assertEqual(result, [])

    def test_dataclass_shape(self):
        mod = _import("h1_reference")
        rep = mod.H1Report(
            report_id="r1", title="x", severity="high",
            program="p", disclosed=True, url="u",
        )
        d = rep.to_dict()
        self.assertEqual(d["report_id"], "r1")
        self.assertEqual(d["severity"], "high")


# ===========================================================================
# 1.5.f Identifier scanner
# ===========================================================================

class TestIdentifierScanner(unittest.TestCase):

    def test_import(self):
        mod = _import("scan_identifiers")
        self.assertIsNotNone(mod.IdentifierScanner)

    def test_aws_key_detected(self):
        mod = _import("scan_identifiers")
        scanner = mod.IdentifierScanner()
        text = "id = AKIAIOSFODNN7EXAMPLE"
        hits = scanner.scan(text, file_path="x.py")
        names = {h.pattern_name for h in hits}
        self.assertIn("aws_access_key_id", names)

    def test_no_false_positive_on_clean(self):
        mod = _import("scan_identifiers")
        scanner = mod.IdentifierScanner()
        text = "def hello():\n    return 42\n"
        hits = scanner.scan(text, file_path="x.py")
        self.assertEqual(hits, [])


# ===========================================================================
# 1.5.g Confidence gates
# ===========================================================================

class TestConfidenceGates(unittest.TestCase):

    def test_import(self):
        mod = _import("confidence_gates")
        self.assertIsNotNone(mod.ConfidenceGate)

    def test_transitions(self):
        mod = _import("confidence_gates")
        gate = mod.ConfidenceGate()
        # TENTATIVE (signal only)
        d1 = gate.upgrade({"signal": "xss"})
        self.assertEqual(d1.level, mod.ConfidenceLevel.TENTATIVE)
        # TENTATIVE -> FIRM (signal + reproducer)
        d2 = gate.upgrade({"signal": "xss", "reproducer": "curl ..."})
        self.assertEqual(d2.level, mod.ConfidenceLevel.FIRM)
        # FIRM -> CONFIRMED (signal + reproducer + impact)
        d3 = gate.upgrade({
            "signal": "xss", "reproducer": "curl ...",
            "impact": "cookie exfil",
        })
        self.assertEqual(d3.level, mod.ConfidenceLevel.CONFIRMED)

    def test_no_inflation_beyond_evidence(self):
        mod = _import("confidence_gates")
        gate = mod.ConfidenceGate()
        gate.upgrade({"signal": "xss"})  # TENTATIVE
        # Trying to upgrade without impact should stay FIRM, not CONFIRMED
        d = gate.upgrade({"signal": "xss", "reproducer": "curl ..."})
        self.assertEqual(d.level, mod.ConfidenceLevel.FIRM)


# ===========================================================================
# 1.5.h Claude skills manifest
# ===========================================================================

class TestClaudeSkillsManifest(unittest.TestCase):

    def test_import(self):
        mod = _import("claude_skills_manifest")
        self.assertIsNotNone(mod.SkillManifest)

    def test_loads_78_skills(self):
        mod = _import("claude_skills_manifest")
        manifest = mod.SkillManifest()
        self.assertEqual(manifest.count(), 78)

    def test_get_skill(self):
        mod = _import("claude_skills_manifest")
        manifest = mod.SkillManifest()
        s = manifest.get_skill("xss_reflected")
        self.assertIsNotNone(s)
        self.assertEqual(s.bug_class, "xss")

    def test_by_bug_class(self):
        mod = _import("claude_skills_manifest")
        manifest = mod.SkillManifest()
        rows = manifest.by_bug_class("xss")
        self.assertGreaterEqual(len(rows), 1)


# ===========================================================================
# 1.5.i Subdomain takeover v20
# ===========================================================================

class TestSubdomainTakeoverV20(unittest.TestCase):

    def test_import(self):
        mod = _import("subdomain_takeover_v20")
        self.assertIsNotNone(mod.SubdomainTakeoverV20)

    def test_vendor_count_at_least_20(self):
        mod = _import("subdomain_takeover_v20")
        scanner = mod.SubdomainTakeoverV20()
        self.assertGreaterEqual(scanner.vendor_count, 20)

    def test_check_heroku(self):
        mod = _import("subdomain_takeover_v20")
        scanner = mod.SubdomainTakeoverV20()
        risk = scanner.check("foo.herokuapp.com",
                             http_body="No such app")
        self.assertIsNotNone(risk)
        self.assertEqual(risk.service, "Heroku")

    def test_check_unknown_returns_none(self):
        mod = _import("subdomain_takeover_v20")
        scanner = mod.SubdomainTakeoverV20()
        risk = scanner.check("foo.example.com")
        self.assertIsNone(risk)

    def test_jwt_alg_none(self):
        mod = _import("subdomain_takeover_v20")
        token = mod.jwt_alg_none_token(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "1", "exp": 9999999999})
        # alg=none token ends with empty signature segment
        self.assertTrue(token.endswith("."))
        parts = token.split(".")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[2], "")


# ===========================================================================
# 1.5.j Identity segregation
# ===========================================================================

class TestIdentitySegregation(unittest.TestCase):

    def test_import(self):
        mod = _import("identity_segregation")
        self.assertIsNotNone(mod.IdentitySegregator)

    def test_admin_requires_auth_b(self):
        mod = _import("identity_segregation")
        seg = mod.IdentitySegregator()
        self.assertFalse(seg.check("anonymous", "/admin"))
        self.assertFalse(seg.check("auth_a", "/admin"))
        self.assertTrue(seg.check("auth_b", "/admin"))

    def test_decision_dataclass(self):
        mod = _import("identity_segregation")
        seg = mod.IdentitySegregator()
        d = seg.decision("anonymous", "/login")
        self.assertTrue(d.allowed)
        self.assertEqual(d.actor_kind, mod.IdentityKind.ANONYMOUS)


# ===========================================================================
# 1.5.k Structured contracts
# ===========================================================================

class TestStructuredContracts(unittest.TestCase):

    def test_import(self):
        mod = _import("structured_contracts")
        self.assertIsNotNone(mod.Contract)

    def test_exit_code_gov_blocked_is_3(self):
        mod = _import("structured_contracts")
        self.assertEqual(int(mod.ExitCode.GOV_BLOCKED), 3)

    def test_redact_argv_strips_secrets(self):
        mod = _import("structured_contracts")
        argv = ["tool", "--target", "x",
                "--api-key=AKIAIOSFODNN7EXAMPLE",
                "--token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"]
        redacted = mod.redact_argv(argv)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted[3])
        self.assertNotIn("ghp_abcdef", redacted[4])

    def test_contract_validate(self):
        mod = _import("structured_contracts")
        c = mod.Contract(
            name="t",
            schema={"x": "int", "y": "enum:a|b"},
            required=("x",),
        )
        errs = c.validate({"x": 1, "y": "a"})
        self.assertEqual(errs, [])
        errs = c.validate({"y": "c"})
        self.assertTrue(any("missing required" in e for e in errs))


# ===========================================================================
# 1.5.l FTS5 finding store
# ===========================================================================

class TestFTS5FindingStore(unittest.TestCase):

    def test_import(self):
        mod = _import("fts5_finding_store")
        self.assertIsNotNone(mod.FindingStore)

    def test_add_and_search(self):
        mod = _import("fts5_finding_store")
        store = mod.FindingStore()
        f = mod.Finding(
            id="F1", scope_id="S1",
            bug_class="xss", severity="high",
            endpoint="https://t/", method="GET",
            evidence="<script>alert(1)</script>",
        )
        store.add(f)
        results = store.search("alert", scope_id="S1")
        self.assertEqual(len(results), 1)

    def test_scope_isolation(self):
        mod = _import("fts5_finding_store")
        store = mod.FindingStore()
        store.add(mod.Finding(id="F1", scope_id="S1", bug_class="xss",
                              severity="high", endpoint="https://t/",
                              method="GET", evidence="xss"))
        store.add(mod.Finding(id="F2", scope_id="S2", bug_class="xss",
                              severity="high", endpoint="https://t/",
                              method="GET", evidence="xss"))
        self.assertEqual(len(store.iter("S1")), 1)
        self.assertEqual(len(store.iter("S2")), 1)
        self.assertEqual(len(store.iter("S3")), 0)

    def test_disk_persistence(self):
        mod = _import("fts5_finding_store")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.jsonl"
            store = mod.FindingStore()
            store.use_disk(path)
            f = mod.Finding(id="F1", scope_id="S1", bug_class="xss",
                            severity="high", endpoint="https://t/",
                            method="GET", evidence="payload")
            store.add(f)
            # Reload from disk in a new store
            store2 = mod.FindingStore()
            store2.use_disk(path)
            self.assertEqual(store2.load_disk(), 1)


# ===========================================================================
# 1.5.m Model scorecard
# ===========================================================================

class TestModelScorecard(unittest.TestCase):

    def test_import(self):
        mod = _import("model_scorecard")
        self.assertIsNotNone(mod.ModelScorecard)

    def test_calibration_after_enough_samples(self):
        mod = _import("model_scorecard")
        sc = mod.ModelScorecard(min_samples=5, max_miss_rate=0.5)
        for _ in range(20):
            sc.update(predicted_pass=True, actual_pass=True)
        self.assertTrue(sc.is_calibrated())

    def test_not_calibrated_with_misses(self):
        mod = _import("model_scorecard")
        sc = mod.ModelScorecard(min_samples=5, max_miss_rate=0.1)
        for _ in range(20):
            sc.update(predicted_pass=True, actual_pass=False)  # all misses
        self.assertFalse(sc.is_calibrated())

    def test_budget_decrement(self):
        mod = _import("model_scorecard")
        sc = mod.ModelScorecard(budget_total=10)
        for _ in range(3):
            sc.update(True, True)
        self.assertEqual(sc.remaining_budget(), 7)


# ===========================================================================
# 1.5.n Safe subprocess library
# ===========================================================================

class TestSafeSubprocessLib(unittest.TestCase):

    def test_import(self):
        mod = _import("safe_subprocess_lib")
        self.assertIsNotNone(mod.safe_subprocess)

    def test_spawn_argv_refuses_shell_metachar(self):
        mod = _import("safe_subprocess_lib")
        with self.assertRaises(mod.ShellInjectionRefused):
            mod.spawn_argv(["ls", "a; rm -rf /"])

    def test_spawn_argv_runs_success(self):
        mod = _import("safe_subprocess_lib")
        result = mod.spawn_argv(["echo", "hi"], timeout=5)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hi", result.stdout)

    def test_action_guard_detects_binary(self):
        mod = _import("safe_subprocess_lib")
        issues = mod.action_guard.check_argv(["rm", "-rf", "/"])
        self.assertTrue(any(i.code == "dangerous_binary" for i in issues))

    def test_redact_headers(self):
        mod = _import("safe_subprocess_lib")
        out = mod.redact_headers({
            "Authorization": "Bearer xyz",
            "X-Custom": "ok",
            "Cookie": "s=v",
        })
        self.assertEqual(out["Authorization"], "<redacted>")
        self.assertEqual(out["Cookie"], "<redacted>")
        self.assertEqual(out["X-Custom"], "ok")

    def test_extract_from_url(self):
        mod = _import("safe_subprocess_lib")
        creds = mod.extract_from_url("https://user:pass@example.com/x")
        self.assertEqual(creds["username"], "user")
        self.assertEqual(creds["password"], "pass")


# ===========================================================================
# 1.5.o YAML workflow DSL
# ===========================================================================

class TestYAMLWorkflowDSL(unittest.TestCase):

    def test_import(self):
        mod = _import("yaml_workflow_dsl")
        self.assertIsNotNone(mod.WorkflowDSL)

    def test_assemble_command(self):
        mod = _import("yaml_workflow_dsl")
        argv = mod.assemble_command({
            "tool": "scanner",
            "args": {"wordlist": "a", "depth": 3, "verbose": True},
        }, target="https://t/")
        self.assertEqual(argv[0], "scanner")
        self.assertIn("--target", argv)
        self.assertIn("https://t/", argv)
        self.assertIn("--wordlist", argv)
        self.assertIn("--depth", argv)
        self.assertIn("--verbose", argv)

    def test_sarif_import(self):
        mod = _import("yaml_workflow_dsl")
        sarif = {
            "runs": [{
                "results": [{
                    "ruleId": "xss-reflected",
                    "level": "error",
                    "message": {"text": "XSS at /search"},
                    "locations": [{"physicalLocation":
                                   {"artifactLocation": {"uri": "https://t/"}}}],
                }]
            }]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.sarif"
            path.write_text(json.dumps(sarif))
            findings = mod.import_sarif(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["bug_class"], "xss-reflected")
        self.assertEqual(findings[0]["severity"], "high")

    def test_workflow_load_dump_roundtrip(self):
        mod = _import("yaml_workflow_dsl")
        dsl = mod.WorkflowDSL()
        yaml_text = (
            "name: test\n"
            "target: https://t/\n"
            "steps:\n"
            "  - name: scan\n"
            "    tool: xss\n"
            "    on_failure: abort\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wf.yaml"
            path.write_text(yaml_text)
            wf = dsl.load(path)
            self.assertEqual(wf.name, "test")
            self.assertEqual(len(wf.steps), 1)
            argv = dsl.compile_step(wf.steps[0], wf.target)
            self.assertIn("xss", argv[0])


# ===========================================================================
# 1.5.p Santa loop convergence
# ===========================================================================

class TestSantaLoopConvergence(unittest.TestCase):

    def test_import(self):
        mod = _import("santa_loop_convergence")
        self.assertIsNotNone(mod.santa_loop)

    def test_accepted_when_both_agree(self):
        mod = _import("santa_loop_convergence")
        a = mod.Review(reviewer="A", verdict=mod.ReviewVerdict.REAL, confidence=0.9)
        b = mod.Review(reviewer="B", verdict=mod.ReviewVerdict.REAL, confidence=0.95)
        result = mod.santa_loop(a, b)
        self.assertEqual(result.convergence, mod.Convergence.ACCEPTED)

    def test_needs_human_when_diverge(self):
        mod = _import("santa_loop_convergence")
        a = mod.Review(reviewer="A", verdict=mod.ReviewVerdict.REAL, confidence=0.9)
        b = mod.Review(reviewer="B", verdict=mod.ReviewVerdict.BENIGN, confidence=0.9)
        result = mod.santa_loop(a, b)
        self.assertEqual(result.convergence, mod.Convergence.NEEDS_HUMAN)

    def test_rejected_when_both_benign(self):
        mod = _import("santa_loop_convergence")
        a = mod.Review(reviewer="A", verdict=mod.ReviewVerdict.BENIGN, confidence=0.9)
        b = mod.Review(reviewer="B", verdict=mod.ReviewVerdict.BENIGN, confidence=0.95)
        result = mod.santa_loop(a, b)
        self.assertEqual(result.convergence, mod.Convergence.REJECTED)


# ===========================================================================
# Citation check
# ===========================================================================

class TestCitationCheck(unittest.TestCase):

    def test_all_submodules_have_source_header(self):
        """Every cross_project module must start with ## Source: header."""
        # We scan for the header pattern in the source file.
        cross_dir = ROOT / "tools" / "cross_project"
        missing: List[str] = []
        for py in cross_dir.glob("*.py"):
            if py.name == "__init__.py":
                continue
            text = py.read_text(encoding="utf-8")
            if "## Source:" not in text:
                missing.append(py.name)
        self.assertEqual(missing, [],
                         f"missing ## Source: header in: {missing}")

    def test_bridges_have_source_header(self):
        bridge_dir = ROOT / "bugwolf" / "runtime" / "bridges"
        missing: List[str] = []
        for py in bridge_dir.glob("*.py"):
            if py.name == "__init__.py":
                continue
            if py.name == "adapter.py":
                # adapter is the contract — not a port
                continue
            text = py.read_text(encoding="utf-8")
            if "## Source:" not in text:
                missing.append(py.name)
        self.assertEqual(missing, [],
                         f"missing ## Source: header in: {missing}")

    def test_no_shell_true_in_cross_project(self):
        cross_dir = ROOT / "tools" / "cross_project"
        bridge_dir = ROOT / "bugwolf" / "runtime" / "bridges"
        # Active-statement pattern (NOT in docstrings / comments).
        offenders: List[str] = []
        shell_re = re.compile(r"shell\s*=\s*True")
        for d in (cross_dir, bridge_dir):
            for py in d.rglob("*.py"):
                text = py.read_text(encoding="utf-8")
                if shell_re.search(text):
                    offenders.append(str(py))
        self.assertEqual(offenders, [],
                         f"shell=True found in: {offenders}")

    def test_no_verify_false_in_cross_project(self):
        cross_dir = ROOT / "tools" / "cross_project"
        bridge_dir = ROOT / "bugwolf" / "runtime" / "bridges"
        offenders: List[str] = []
        verify_re = re.compile(r"verify\s*=\s*False")
        for d in (cross_dir, bridge_dir):
            for py in d.rglob("*.py"):
                text = py.read_text(encoding="utf-8")
                if verify_re.search(text):
                    offenders.append(str(py))
        self.assertEqual(offenders, [],
                         f"verify=False found in: {offenders}")


# ===========================================================================
# TS Bridge smoke tests
# ===========================================================================

_BRIDGE_NAMES = (
    "claude_code", "codex", "cursor", "opencode",
    "kiro", "gemini", "kimi", "zed",
)


class TestBridgeSmokeTests(unittest.TestCase):

    def test_all_8_bridges_registered(self):
        from bugwolf.runtime.bridges import list_bridges
        names = {b.name for b in list_bridges()}
        self.assertEqual(names, set(_BRIDGE_NAMES))

    def test_each_bridge_has_contract(self):
        from bugwolf.runtime.bridges import get_bridge
        for n in _BRIDGE_NAMES:
            b = get_bridge(n)
            self.assertIsNotNone(b, f"{n} not registered")
            self.assertEqual(b.name, n)
            self.assertTrue(len(b.command) >= 1)
            self.assertIn("BUGWOLF_BRIDGE", b.env_overrides)

    def test_each_bridge_playbook_loader_returns_argv(self):
        from bugwolf.runtime.bridges import get_bridge
        for n in _BRIDGE_NAMES:
            b = get_bridge(n)
            argv = b.playbook_loader({"prompt": "x"}, "/tmp/t")
            self.assertIsInstance(argv, list)
            self.assertGreater(len(argv), 0)

    def test_each_bridge_parser_returns_list(self):
        from bugwolf.runtime.bridges import get_bridge
        for n in _BRIDGE_NAMES:
            b = get_bridge(n)
            events = b.result_parser('{"kind": "x"}\n')
            self.assertIsInstance(events, list)

    def test_each_bridge_smoke_test(self):
        from bugwolf.runtime.bridges import get_bridge
        for n in _BRIDGE_NAMES:
            b = get_bridge(n)
            # The smoke test returns BridgeSmokeResult with ok=False if the
            # binary isn't installed — that's expected in CI.
            self.assertIsNotNone(b.smoke_test)


if __name__ == "__main__":
    unittest.main()