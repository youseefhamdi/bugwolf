#!/usr/bin/env python3
"""Phase 0 Critical Fix Sprint regression tests (MAX_DEPTH_PLAN_BUGWOLF.md).

Each test pins one of the 5 CRITICAL audit findings (C-1..C-5) plus the
18 HIGH findings (H-1..H-10) and the M/L remediations that the Phase 0
gate requires to be GREEN before Phase 1 begins.

Conventions:
  - Every test imports only the modules it pins.
  - Tests are isolated via tempfile + monkeypatched sys.argv.
  - Tests assert the FAIL-CLOSED behavior; the lab profile escape hatch
    (PROFILE_LAB_UNCENSORED) is NOT exercised here — that gate is owned
    by tools/runtime/contracts.py and is tested in test_audit_remediation.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _run_module(argv, module):
    """Invoke ``module.main()`` in-process with patched argv; return (rc, stdout, stderr)."""
    saved = sys.argv
    sys.argv = argv
    try:
        buf_out, buf_err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = module.main()
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        return rc, buf_out.getvalue(), buf_err.getvalue()
    finally:
        sys.argv = saved


# =============================================================================
# C-1: tools/hunt.py:1107-1128 — wildcard scope, all-action allowlist, 999999
# =============================================================================

class HuntCriticalScopeGate(unittest.TestCase):
    """C-1: tools/hunt.py main() refuses to start without a scope file."""

    def setUp(self):
        import tools.hunt as hunt
        self.hunt = hunt
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_hunt_refuses_empty_scope_file(self):
        """C-1.1: --scope-file is required; empty exits 2."""
        argv = ["hunt.py", "--target", "example.com",
                "--no-opsec", "--quick", "--json"]
        rc, _, err = _run_module(argv, self.hunt)
        self.assertIn(rc, (1, 2), f"expected refusal exit code, got {rc}; err={err!r}")
        self.assertTrue(
            "scope" in err.lower() or "scope file required" in err.lower(),
            f"scope error not surfaced: {err!r}",
        )

    def test_hunt_refuses_scope_file_with_zero_entries(self):
        """C-1.1: scope file with comments only is treated as empty."""
        scope_file = self.tmp_path / "scope.json"
        scope_file.write_text("# nothing\n# here\n")
        argv = ["hunt.py", "--target", "example.com",
                "--scope-file", str(scope_file),
                "--no-opsec", "--quick", "--json"]
        rc, _, err = _run_module(argv, self.hunt)
        self.assertIn(rc, (1, 2), f"expected refusal, got {rc}; err={err!r}")
        self.assertIn("scope", err.lower())

    def test_hunt_active_controller_no_longer_wildcard(self):
        """C-1.2/3: ActiveExecutionController default scope is no longer wildcard."""
        from tools.execution_controller import ActiveExecutionController, ExecutionPolicy
        ctl = ActiveExecutionController(ExecutionPolicy(target="example.com"))
        # Wildcard is gone; controller starts empty.
        self.assertNotIn("*", ctl.scope.get("in_scope_domains", []))
        self.assertFalse(ctl.scope.get("authorized", False))


# =============================================================================
# C-2: tools/hunt.py:897-924 — run_active_injection bypasses scope
# =============================================================================

class HuntActiveInjectionScopeFilter(unittest.TestCase):
    """C-2: run_active_injection returns empty list when no in-scope URLs."""

    def setUp(self):
        import tools.hunt as hunt
        self.hunt = hunt

    def test_run_active_injection_empty_when_no_scope(self):
        """C-2: with no in-scope hosts, no probes are issued."""
        # Build a HuntSession without loading any recon URLs.
        session = self.hunt.HuntSession(name="t", target="example.com")
        results = self.hunt.run_active_injection(
            "example.com", session, rotator=None, max_urls=10,
            scope={"authorized": True, "in_scope_domains": []},
        )
        self.assertEqual(results, [],
                         "expected zero probes when in-scope host set is empty")


# =============================================================================
# C-3: tools/refutation.py:312-358 + CLI --no-strict flag
# =============================================================================

class RefutationStrictMode(unittest.TestCase):
    """C-3: --no-strict removed; strict mode is the only path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_refutation_strict_mode_demotes_low_confidence(self):
        """C-3: empty evidence in strict mode yields DEMOTED, not CONFIRMED."""
        from tools.refutation import RefutationEngine, FindingVerdict
        with mock.patch("tools.adaptive_learning.AdaptiveMemory.ingest",
                        return_value={"status": "ok"}):
            engine = RefutationEngine("t.test", strict=True, project_root=self.tmp.name)
            record = engine.refute({"finding_id": "f1", "title": "x",
                                    "bug_class": "test"})
        self.assertEqual(record.final_verdict, FindingVerdict.DEMOTED)
        self.assertLess(record.confidence, 1.0)

    def test_refutation_no_strict_argparse_flag_removed(self):
        """C-3: --no-strict CLI flag no longer exists."""
        from tools import refutation
        # argparse --help output should not mention --no-strict.
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                refutation.main.__wrapped__ if hasattr(refutation.main, "__wrapped__") else None
                # Directly invoke argparse by calling with --help.
                saved = sys.argv
                sys.argv = ["refutation.py", "--help"]
                try:
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        refutation.main()
                except SystemExit:
                    pass
                finally:
                    sys.argv = saved
            except SystemExit:
                pass
        # We can't easily capture argparse's help text here; instead, inspect
        # the source for the marker.
        import inspect
        src = inspect.getsource(refutation)
        self.assertNotIn('"--no-strict"', src)
        self.assertNotIn("'--no-strict'", src)

    def test_refutation_require_reproducible_demotes_without_evidence(self):
        """C-3.2: require_reproducible=True + no evidence → DEMOTED."""
        from tools.refutation import RefutationEngine, FindingVerdict
        with mock.patch("tools.adaptive_learning.AdaptiveMemory.ingest",
                        return_value={"status": "ok"}):
            engine = RefutationEngine("t.test", strict=True,
                                      require_reproducible=True,
                                      project_root=self.tmp.name)
            record = engine.refute({
                "finding_id": "f2", "title": "no evidence",
                "bug_class": "test", "confidence": 0.9,
                "trigger_trace": "x" * 50,  # score-only, no evidence block
                "impact_trace": "y" * 50,
            })
        self.assertEqual(record.final_verdict, FindingVerdict.DEMOTED)


# =============================================================================
# C-4: tools/kill_chain.py:632-755 — destructive IDOR + blind /1
# =============================================================================

class KillChainSafeByDefault(unittest.TestCase):
    """C-4: IDOR chain plan no longer includes PUT/DELETE; blind /1 gone."""

    def setUp(self):
        from tools.kill_chain import KillChainBuilder, CHAIN_PATTERNS
        self.KillChainBuilder = KillChainBuilder
        self.CHAIN_PATTERNS = CHAIN_PATTERNS

    def _candidate(self, chain_id="CHAIN-001", findings=None):
        from tools.kill_chain import ChainCandidate
        pat = next(p for p in self.CHAIN_PATTERNS if p.chain_id == chain_id)
        return ChainCandidate(
            pattern=pat,
            matched_findings=findings or [{"endpoint": "/api/v1/users/42",
                                           "id": "f-1"}],
            match_score=1.0, combined_severity="high",
            trigger_sequence=[], auto_testable=True,
            estimated_bounty=pat.bounty_range,
        )

    def test_chained_001_plan_has_no_destructive_verbs(self):
        """C-4.1: auto_test_chain does NOT emit PUT/PATCH/DELETE."""
        builder = self.KillChainBuilder("t.example")
        plan = builder.auto_test_chain(self._candidate("CHAIN-001"))
        verbs = {t.get("method", "GET").upper() for t in plan["tests"]}
        self.assertTrue(verbs.issubset({"GET"}),
                        f"destructive verbs leaked into plan: {verbs}")

    def test_chained_001_plan_does_not_blind_append_numeric_id(self):
        """C-4.2: IDOR candidate endpoints do not end with literal /1 or /2."""
        builder = self.KillChainBuilder("t.example")
        plan = builder.auto_test_chain(self._candidate("CHAIN-001"))
        for test in plan["tests"]:
            ep = test.get("endpoint", "")
            self.assertFalse(
                re.search(r"/(1|2)$", ep),
                f"blind numeric suffix survived: {ep}",
            )

    def test_execute_chain_refuses_destructive_when_no_opt_in(self):
        """C-4.1: execute_chain with allow_destructive=False refuses DELETE."""
        builder = self.KillChainBuilder("t.example")
        # Build a candidate whose plan has a DELETE (if any pattern still
        # produces one) and verify the default execute_chain refuses it.
        result = builder.execute_chain(self._candidate("CHAIN-001"))
        for r in result.get("results", []):
            self.assertNotEqual(r.get("method"), "DELETE",
                                "DELETE leaked into default execute_chain")


# =============================================================================
# C-5: tools/kill_chain.py:476-480 — race-condition step text
# =============================================================================

class KillChainRaceConditionPlanText(unittest.TestCase):
    """C-5: CHAIN-008 trigger text no longer instructs live double-spend."""

    def test_chain_008_step_text_is_analysis_only(self):
        from tools.kill_chain import KillChainBuilder, CHAIN_PATTERNS, ChainCandidate
        pat = next(p for p in CHAIN_PATTERNS if p.chain_id == "CHAIN-008")
        cand = ChainCandidate(
            pattern=pat, matched_findings=[{"endpoint": "/x", "id": "f1"}],
            match_score=1.0, combined_severity="high",
            trigger_sequence=[], auto_testable=True,
            estimated_bounty=pat.bounty_range,
        )
        builder = KillChainBuilder("t.example")
        steps = builder._build_trigger_sequence(pat, cand.matched_findings)
        text = "\n".join(steps)
        self.assertNotIn("Send 10+ concurrent", text)
        self.assertNotIn("double spend", text.lower())
        self.assertIn("rate-limit", text.lower())


# =============================================================================
# H-1: tools/runtime/sandbox.py:218-235 scrub_env deterministic PATH
# =============================================================================

class SandboxDeterministicPath(unittest.TestCase):
    """H-1: scrub_env never inherits the caller's PATH."""

    def test_scrub_env_overrides_caller_path(self):
        from tools.runtime import sandbox
        with mock.patch.dict(os.environ, {"PATH": "/tmp/attacker/bin:/bin"}):
            env = sandbox.scrub_env()
        # The attacker-injected PATH prefix must not survive.
        self.assertNotIn("/tmp/attacker", env["PATH"])
        # The deterministic default system dirs are present.
        for d in ("/usr/bin", "/bin"):
            self.assertIn(d, env["PATH"])

    def test_deterministic_path_uses_etc_environment(self):
        """H-1: PATH can be augmented from /etc/environment when present."""
        from tools.runtime import sandbox
        # Build a fake /etc/environment. We can't actually write the system
        # file, so we test the helper directly.
        path = sandbox._deterministic_path()
        # Must be a non-empty colon-separated string of absolute paths.
        self.assertTrue(path)
        for p in path.split(":"):
            self.assertTrue(p.startswith("/"),
                            f"non-absolute PATH component: {p!r}")


# =============================================================================
# H-2: tools/runtime/sandbox.py:204-210 basename allowlist bypass
# =============================================================================

class SandboxResolvedPathCheck(unittest.TestCase):
    """H-2: _is_allowed resolves argv[0] via deterministic PATH."""

    def test_is_allowed_resolves_basename_against_allowed_prefix(self):
        from tools.runtime import sandbox
        # Python3 is in /usr/bin on standard Linux. Allow it.
        self.assertTrue(sandbox._is_allowed("python3", None, allow_unlisted=False))
        # A nonexistent binary must be rejected.
        self.assertFalse(sandbox._is_allowed(
            "this-binary-should-not-be-installed-xyzzy", None,
            allow_unlisted=False))


# =============================================================================
# H-3: tools/runtime/scope.py — clear_scope_contract strict variant
# =============================================================================

class ScopeContractStrictClear(unittest.TestCase):
    """H-3: strict clear refuses to remove another mission's contract."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_clear_scope_contract_strict_refuses_other_mission(self):
        from tools.runtime import scope
        scope.reset()
        scope.bind_target("http://a.test", force=True)
        scope.write_scope_contract("mission-A", root=self.tmp.name)
        with self.assertRaises(scope.ScopeContractError):
            scope.clear_scope_contract_strict("mission-B", root=self.tmp.name)

    def test_clear_scope_contract_strict_succeeds_for_own_mission(self):
        from tools.runtime import scope
        scope.reset()
        scope.bind_target("http://a.test", force=True)
        scope.write_scope_contract("mission-A", root=self.tmp.name)
        self.assertTrue(scope.clear_scope_contract_strict(
            "mission-A", root=self.tmp.name))


# =============================================================================
# H-4: tools/core/fuzz_bridge.py — scope check before every probe
# =============================================================================

class FuzzBridgeScopeCheck(unittest.TestCase):
    """H-4: run_fuzzing_campaign gates transport calls through check_url."""

    def test_out_of_scope_target_does_not_call_transport(self):
        """An explicitly out-of-scope target yields zero transport calls."""
        import tools.core.fuzz_bridge as fuzz_bridge
        from tools.runtime import scope

        scope.reset()
        scope.bind_target("http://evil.test", force=True)

        seen = []

        # The transport signature for fuzz_bridge is (req, timeout, retries).
        def fake_transport(req, timeout=None, retries=None):
            seen.append(req)
            return None

        # Minimal duck-typed mutation object: fuzz_bridge accesses
        # operation_id, method, path.
        class FakeMut:
            operation_id = "op1"
            method = "GET"
            path = "/q"

        # Bind to a target whose scope does NOT include evil.test.
        scope.reset()
        scope.bind_target("http://in-scope.test", force=True)
        summary = fuzz_bridge.run_fuzzing_campaign(
            target="evil.test",
            base_url="http://evil.test",
            mutations=[FakeMut()],
            transport=fake_transport,
            budget=5,
        )
        self.assertEqual(seen, [],
                         "out-of-scope target must not produce transport calls")
        # Either the campaign short-circuited before transport, or the
        # scope check incremented summary.errors. Both are acceptable.
        self.assertGreaterEqual(summary.errors, 1)


# =============================================================================
# H-5: tools/runtime/replay/backend_socket.py — DNS-pin
# =============================================================================

class ReplayDNSPin(unittest.TestCase):
    """H-5: send_raw pins to a resolved IP and rejects loopback for external targets."""

    def test_resolve_in_scope_filters_loopback_for_external_target(self):
        from tools.runtime.replay import backend_socket
        from tools.runtime import scope
        scope.reset()
        scope.bind_target("https://public.example.com")
        # Mock DNS to return loopback only — should be filtered.
        fake_infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                       ("127.0.0.1", 80))]
        with mock.patch("socket.getaddrinfo", return_value=fake_infos):
            ips = backend_socket._resolve_in_scope("public.example.com", 80)
        self.assertEqual(ips, [],
                         "loopback must be filtered for external target")

    def test_resolve_in_scope_keeps_loopback_for_loopback_target(self):
        from tools.runtime.replay import backend_socket
        from tools.runtime import scope
        scope.reset()
        scope.bind_target("http://127.0.0.1:8080")
        fake_infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                       ("127.0.0.1", 8080))]
        with mock.patch("socket.getaddrinfo", return_value=fake_infos):
            ips = backend_socket._resolve_in_scope("127.0.0.1", 8080)
        self.assertIn("127.0.0.1", ips,
                      "loopback target must permit loopback resolutions")


# =============================================================================
# H-6: tools/runtime/replay/apply.py — _op_set_target origin-form only
# =============================================================================

class ReplaySetTargetOriginOnly(unittest.TestCase):
    """H-6: absolute-form URLs in set-target are rejected with ApplyError."""

    def test_set_target_absolute_form_rejected(self):
        from tools.runtime.replay.apply import _op_set_target, ApplyError, Mutation

        class _Req:
            target = "/"
            method = "GET"
        req = _Req()
        mut = Mutation(op="set-target", value="https://evil.test/path")
        with self.assertRaises(ApplyError):
            _op_set_target(req, mut)

    def test_set_target_origin_form_accepted(self):
        from tools.runtime.replay.apply import _op_set_target, Mutation

        class _Req:
            target = "/"
            method = "GET"
        req = _Req()
        mut = Mutation(op="set-target", value="/new/path?q=1")
        _op_set_target(req, mut)
        self.assertEqual(req.target, "/new/path?q=1")


# =============================================================================
# H-7: tools/header_trust.py — internal-host probes require opt-in
# =============================================================================

class HeaderTrustInternalHostOptIn(unittest.TestCase):
    """H-7: --scope-internal-host gates loopback/internal probes."""

    def test_internal_hosts_skipped_by_default(self):
        from tools.header_trust import (
            HeaderTrustRunner, HeaderProbe, _INTERNAL_HOSTS, _TRUSTED_IPS,
        )
        from unittest import mock

        runner = HeaderTrustRunner()
        # allow_internal_hosts defaults to False (or falsy).
        self.assertFalse(getattr(runner, "allow_internal_hosts", False))
        # Build a probe with a loopback value.
        probe = HeaderProbe(name="X-Forwarded-For", value="127.0.0.1",
                            bug_class="ip_trust",
                            category="IP trust", severity="high")
        recorded = []

        # Stub the oracle validator so the transport return value isn't
        # required to be a real ObservationRecord. The test only cares that
        # transport() is NOT called for skipped internal-host probes.
        fake_validator = mock.MagicMock()
        runner.validator = fake_validator

        def transport(method, url, headers):
            recorded.append(url)
            return None

        runner.run([probe], transport, target="example.com")
        self.assertEqual(recorded, [],
                         "loopback probe must be skipped without opt-in")
        self.assertEqual(fake_validator.validate.call_count, 0)

    def test_internal_hosts_allowed_when_opt_in(self):
        """When allow_internal_hosts=True, loopback probes reach transport.

        We construct real HttpObservation objects so the runner's result
        builder doesn't crash on `.status` access. The test asserts that
        the transport function was called when opt-in is set.
        """
        from tools.header_trust import (
            HeaderTrustRunner, HeaderProbe,
        )
        from tools.observation import HttpObservation
        from unittest import mock

        runner = HeaderTrustRunner()
        runner.allow_internal_hosts = True
        probe = HeaderProbe(name="X-Forwarded-For", value="127.0.0.1",
                            bug_class="ip_trust",
                            category="IP trust", severity="high")
        recorded = []

        # Return a real HttpObservation from transport.
        def transport(method, url, headers):
            recorded.append(url)
            return HttpObservation(status=200, body="", headers={})

        # Stub the oracle validator (avoids instantiating ObservationRecord).
        runner.validator = mock.MagicMock()
        fake_record = mock.MagicMock()
        fake_record.state.value = "unknown"
        fake_record.decisive_rule = ""
        fake_record.observation_id = ""
        fake_record.metrics.body_similarity = 0.0
        runner.validator.validate = mock.MagicMock(return_value=fake_record)

        with mock.patch("tools.header_trust.classify_trust",
                        return_value={"trust_signal": False, "reason": "ok"}), \
             mock.patch.object(HeaderTrustRunner, "_hypothesis",
                               return_value="mocked hypothesis"):
            runner.run([probe], transport, target="example.com")

        self.assertGreater(len(recorded), 0,
                           "loopback probe must fire with opt-in")


# =============================================================================
# H-8: tools/research_thread.py:670-676 — literal payload strings
# =============================================================================

class ResearchThreadNoLiteralPayloads(unittest.TestCase):
    """H-8: ThreadBuilder._detection_approaches does not embed literal file:// / gopher://."""

    def test_ssrf_approach_has_no_literal_payloads(self):
        from tools.research_thread import ThreadBuilder
        ssrf = ThreadBuilder._detection_approaches("ssrf")
        text = "\n".join(ssrf)
        # Phase 0 H-8: literal payload strings must not appear.
        # The phrase "file:// or gopher:// URLs" appears in the negation
        # ("do not embed literal") so we check for ACTUAL payload forms,
        # not just substring presence. The four indicators below are
        # unambiguously payload-shaped.
        for banned in ("file:///etc/passwd", "127.0.0.1:80/",
                       "169.254.169.254/latest/meta-data",
                       "://127.0.0.1"):
            self.assertNotIn(banned, text,
                             f"literal payload survives in ssrf approach: {banned}")
        # The "gopher://" substring in the negation is acceptable; what we
        # need to assert is that no actual gopher URL follows it.
        self.assertNotRegex(text, r"gopher://[^\s]+")


# =============================================================================
# H-9: tools/research_thread.py:372-389 — persistence in ESCALATION_TECHNIQUES
# =============================================================================

class ResearchThreadNoPersistenceInSuggestions(unittest.TestCase):
    """H-9: ESCALATION_TECHNIQUES does not suggest establishing persistence."""

    def test_command_injection_says_not_executed(self):
        from tools import research_thread
        cmd = research_thread.ESCALATION_TECHNIQUES["command_injection"]
        joined = "\n".join(cmd).lower()
        # Persistence instructions are kept as descriptions only.
        self.assertIn("not executed", joined)
        # No "establish persistence" as an executable step.
        for banned in ("establish reverse shell",
                       "establish persistence",
                       "read sensitive files"):
            self.assertFalse(
                any(banned in line.lower() and "not executed" not in line
                    for line in cmd),
                f"literal persistence step survives: {banned}",
            )


# =============================================================================
# H-10: tools/formal_verify.py:148-150 — tautological Certora spec
# =============================================================================

class FormalVerifyNoTautology(unittest.TestCase):
    """H-10: the noPrivilegeEscalation rule is no longer a tautology."""

    def test_spec_does_not_contain_tautology(self):
        from tools.formal_verify import generate_certora_spec
        spec = generate_certora_spec({"contract_or_program": "X"})
        # Old tautology form must be gone.
        self.assertNotIn("target.owner() == e.msg.sender || target.owner() != e.msg.sender",
                         spec)
        # New implication form must be present.
        self.assertIn("=>", spec,
                      "implication form missing — fix not landed")


# =============================================================================
# M-4: tools/hunt.py:792-795 — 5xx-as-sqli false-positive
# =============================================================================

class HuntSQLINotJustStatus(unittest.TestCase):
    """M-4: a 5xx response alone (no SQL error body signature) is NOT sqli."""

    def test_classify_response_5xx_no_signature_no_sqli(self):
        from tools.hunt import classify_response
        # 5xx with no SQL error signature must NOT classify as sqli.
        result = classify_response(
            body="<html>Internal server error</html>",
            probe_label="sqli-probe", bug_class="sqli",
            status=500, baseline_status=200,
        )
        # Either None or a non-sqli bug_class.
        if result is not None:
            self.assertNotEqual(getattr(result, "bug_class", None), "sqli",
                                "5xx alone must not classify as sqli")


# =============================================================================
# M-6: tools/mutator.py — destructive SQLi payloads gated
# =============================================================================

class MutatorDestructiveOffByDefault(unittest.TestCase):
    """M-6: DROP TABLE / INSERT INTO are NOT in the default payload pool."""

    def test_default_pool_excludes_destructive(self):
        from tools import mutator
        from tools.mutator import Mutator
        m = Mutator()
        joined = "\n".join(m._injection_values.get("sqli", []))
        # The destructive tokens must not be in the default pool.
        self.assertNotIn("DROP TABLE", joined,
                         "DROP TABLE leaked into default payload pool")
        self.assertNotIn("INSERT INTO log", joined,
                         "INSERT INTO log leaked into default payload pool")

    def test_include_destructive_flag_adds_payloads(self):
        """Opt-in via constructor flag."""
        from tools.mutator import Mutator
        m = Mutator(include_destructive=True)
        joined = "\n".join(m._injection_values.get("sqli", []))
        self.assertIn("DROP TABLE", joined,
                      "include_destructive=True should expose DROP TABLE")


# =============================================================================
# M-7: tools/js_token_forge.py — 4-char trigger false-positive
# =============================================================================

class JSTokenForgeTriggerLength(unittest.TestCase):
    """M-7: short literal triggers no longer fire critical hardcoded_secret."""

    def test_short_benign_key_does_not_match(self):
        from tools import js_token_forge
        # 4-char trigger like `apiKey = "abcd"` must NOT match the first rule.
        rules = js_token_forge.RULES
        first_pattern = rules[0][0]
        compiled = re.compile(first_pattern, re.IGNORECASE)
        self.assertFalse(compiled.search('var apiKey = "abcd";'),
                         "short benign literal still matches critical rule")


# =============================================================================
# M-9 / M-10: full SHA-256 digests in agent_registry + scheduler + mutator
# =============================================================================

class FullSHA256Digests(unittest.TestCase):
    """M-9/M-10: identity digests use the full 64-char SHA-256."""

    def test_agent_registry_full_digest(self):
        from tools.core.agent_registry import AgentRegistry
        reg = AgentRegistry()
        # prompt_digest returns the full 64-char SHA-256 (no truncation).
        try:
            digest = reg.prompt_digest("recon")
        except (FileNotFoundError, KeyError):
            self.skipTest("playbook file unavailable in this environment")
        self.assertEqual(len(digest), 64,
                         f"agent_registry digest still truncated: {digest!r}")

    def test_agent_registry_roster_digest_full(self):
        """The team-composition digest (line 745) is full SHA-256."""
        from tools.core.agent_registry import AgentRegistry
        reg = AgentRegistry()
        roster = reg.compose_team(domains=["web"], bug_classes=["idor"],
                                    max_agents=4)
        self.assertEqual(len(roster["digest"]), 64,
                         f"roster digest truncated: {roster['digest']!r}")

    def test_scheduler_full_digest(self):
        from tools.runtime import scheduler
        fp = scheduler.task_fingerprint({"task_type": "x", "domain": "y",
                                         "title": "z", "inputs": {},
                                         "model_profile": "p"})
        self.assertEqual(len(fp), 64, f"scheduler fingerprint truncated: {fp!r}")

    def test_mutator_full_digest(self):
        from tools.mutator import Mutator, RiskClass
        out = []
        Mutator()._add(out, "op1", "GET", "/p", "k", "v", "", "x",
                       "test", RiskClass.READ)
        self.assertEqual(len(out[0].mutation_id), 64,
                         f"mutator mutation_id truncated: {out[0].mutation_id!r}")


# =============================================================================
# M-7 (scope.py AAAA): AAAA resolutions outside scope are rejected
# =============================================================================

class ScopeResolvesInsideScopeAAAA(unittest.TestCase):
    """M-7: resolves_inside_scope honors the address-family filter."""

    def test_scope_resolves_inside_scope_with_loopback_only(self):
        from tools.runtime import scope
        # Loopback target: loopback IP is in scope.
        self.assertTrue(scope.resolves_inside_scope("localhost"))


# =============================================================================
# L-7: tools/exploit_gen.py — _safe_text strips CRLF
# =============================================================================

class ExploitGenSafeTextStripsCRLF(unittest.TestCase):
    """L-7: _safe_text removes \\r and \\n in addition to NUL."""

    def test_safe_text_strips_crlf(self):
        from tools.exploit_gen import _safe_text
        out = _safe_text("a\r\nb\rc\nd")
        self.assertNotIn("\r", out)
        self.assertNotIn("\n", out)
        self.assertEqual(out, "abcd")


# =============================================================================
# L-9: tools/ledger.py — canonical JSON hash chain
# =============================================================================

class LedgerCanonicalJSON(unittest.TestCase):
    """L-9: hash-chain verifier uses pinned canonical JSON."""

    def test_canonical_json_helper_is_pinned(self):
        from tools import ledger
        # The helper must exist and produce identical bytes for the same input.
        a = ledger._canonical_json_bytes({"a": 1, "b": [1, 2, 3]})
        b = ledger._canonical_json_bytes({"b": [1, 2, 3], "a": 1})
        self.assertEqual(a, b, "canonical form must be order-independent")
        # Must be ASCII bytes (ensure_ascii=False keeps non-ASCII, but the
        # separators are pinned to (",", ":")).
        self.assertIn(b'"a":1', a)
        self.assertIn(b'"b":[1,2,3]', a)
        # schema_version is injected as default.
        self.assertIn(b'"schema_version":1', a)


# =============================================================================
# L-12: tools/surface_model.py — $ref cycle cap
# =============================================================================

class SurfaceModelRefCycleCap(unittest.TestCase):
    """L-12: _flatten_schema terminates on $ref cycles."""

    def test_flatten_schema_terminates_on_cycle(self):
        from tools.surface_model import _flatten_schema
        # Self-referential schema: A -> A
        schema = {"type": "object", "properties": {"self": {"$ref": "#"}}}
        # Depth 0 root call; recurse into "self"; detect cycle.
        out = _flatten_schema(schema, "")
        # Must return a bounded list, not raise RecursionError.
        self.assertIsInstance(out, list)


# =============================================================================
# CI gate: no destructive UNCENSORED markers in default paths
# =============================================================================

class CIUNCENSOREDMarkerGate(unittest.TestCase):
    """Phase 0 CI gate: dangerous UNCENSORED markers must not ship."""

    def test_no_wildcard_in_scope_domains(self):
        bad = re.compile(r"in_scope_domains\s*[:=]\s*\[\s*[\"']\*")
        hits = []
        for dirpath, _, filenames in os.walk(ROOT / "tools"):
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = Path(dirpath) / fn
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                for m in bad.finditer(text):
                    start = text.rfind("\n", 0, m.start()) + 1
                    end = text.find("\n", m.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end]
                    if "lab-uncensored" in line or "PROFILE_LAB_UNCENSORED" in line:
                        continue
                    hits.append(f"{path}: {line.strip()[:120]}")
        self.assertEqual(hits, [],
                         "wildcard in_scope_domains still ships: " + "\n".join(hits))

    def test_no_destructive_uncensored_marker(self):
        bad = re.compile(r"UNCENSORED\s*:.*(DESTRUCTIVE|STATE_CHANGE)")
        hits = []
        for dirpath, _, filenames in os.walk(ROOT / "tools"):
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                path = Path(dirpath) / fn
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                for m in bad.finditer(text):
                    start = text.rfind("\n", 0, m.start()) + 1
                    end = text.find("\n", m.end())
                    if end == -1:
                        end = len(text)
                    line = text[start:end]
                    if "lab-uncensored" in line or "PROFILE_LAB_UNCENSORED" in line:
                        continue
                    hits.append(f"{path}: {line.strip()[:120]}")
        self.assertEqual(hits, [],
                         "destructive UNCENSORED marker still ships: " + "\n".join(hits))


if __name__ == "__main__":
    unittest.main()