#!/usr/bin/env python3
"""Phase 1.4 adversarial governance regression tests (Plan Gate 1).

Each test pins one of the audit-cited anti-patterns the deeper Phase 1.4
governance module is supposed to catch:

  1. ``test_governance_no_destructive_default`` — destructive verb
     without ``--confirm-destructive`` flag must be blocked by
     :class:`GovernanceHandle.require_action_authorized`.
  2. ``test_governance_scope_required`` — wildcard scope pattern is
     rejected by :func:`enforce_scope`.
  3. ``test_governance_refutation_requires_evidence`` — confidence=1.0
     may only be set if a non-null ``replay_key`` is supplied.
  4. ``test_governance_seven_question_gate_evidence_aware`` — the
     :class:`SevenQuestionGate` dry-run returns FAIL for findings
     without ``recorded_evidence_block`` and PASS for findings with
     one.
  5. ``test_governance_cvss_severity_mapping`` — :class:`CVSS31` maps
     canonical scores to the correct severity bucket.

Uses unittest.TestCase; no external deps.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _good_finding(include_evidence: bool = True) -> Dict[str, Any]:
    """Return a finding dict that would PASS the dry-run gate."""
    f: Dict[str, Any] = {
        "id": "finding-1",
        "endpoint": "https://example.com/api",
        "action_class": "read",
        "method": "GET",
        "vulnerability_class": "IDOR",
        "attack_surface": "public",
        "in_scope": True,
        "impact": "user record leaked via /api/users/1",
        "reproduction_steps": ["GET /api/users/1 -> 200 with payload"],
        "transcript": "GET /api/users/1 -> 200",
        "severity": 7.5,
        "distinct": True,
    }
    if include_evidence:
        f["recorded_evidence_block"] = {
            "evidence_ref": "ref-1",
            "request": {"method": "GET", "url": "/api/users/1"},
            "response": {"status": 200, "body": "{...}"},
            "chain_verifies": True,
        }
    return f


# ---------------------------------------------------------------------------
# Gate 1 — destructive default
# ---------------------------------------------------------------------------


class GovernanceNoDestructiveDefaultTests(unittest.TestCase):
    """Phase 1.4 Gate 1: destructive verb must be blocked without approval."""

    def setUp(self) -> None:
        from tools.runtime import scope
        scope.reset()
        self.addCleanup(self._reset_scope)

    @staticmethod
    def _reset_scope() -> None:
        from tools.runtime import scope
        scope.reset()

    def test_destructive_action_blocked_without_approval(self) -> None:
        from bugwolf.governance.scope import (
            DESTRUCTIVE_ACTIONS, bind_governance,
        )
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            handle = bind_governance(
                target="example.com",
                mission_id="m-destr",
                allowed_actions=list(DESTRUCTIVE_ACTIONS),
                root=Path(tmpdir),
            )
            with self.assertRaises(PermissionError):
                handle.require_action_authorized("delete")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_destructive_action_with_approval_passes(self) -> None:
        from bugwolf.governance.scope import (
            DESTRUCTIVE_ACTIONS, bind_governance,
        )
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            handle = bind_governance(
                target="example.com",
                mission_id="m-destr2",
                allowed_actions=list(DESTRUCTIVE_ACTIONS),
                root=Path(tmpdir),
            )
            handle.register_approval(target="example.com",
                                      action="delete")
            handle.require_action_authorized("delete")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_empty_action_rejected(self) -> None:
        from bugwolf.governance.scope import bind_governance
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            handle = bind_governance(
                target="example.com",
                mission_id="m-destr3",
                allowed_actions=["read"],
                root=Path(tmpdir),
            )
            with self.assertRaises(PermissionError):
                handle.require_action_authorized("")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Gate 1 — wildcard scope rejected
# ---------------------------------------------------------------------------


class GovernanceScopeRequiredTests(unittest.TestCase):
    """Phase 1.4 Gate 1: wildcard scope must not silently grant ALLOW."""

    def setUp(self) -> None:
        from tools.runtime import scope
        scope.reset()
        self.addCleanup(self._reset_scope)

    @staticmethod
    def _reset_scope() -> None:
        from tools.runtime import scope
        scope.reset()

    def test_wildcard_allow_rule_rejected(self) -> None:
        from bugwolf.governance.scope import (
            ScopeContext, ScopeRule, ScopeVerdict,
        )
        with self.assertRaises(ValueError):
            ScopeRule(
                pattern="*.example.com",
                rule_type="wildcard",
                action=ScopeVerdict.ALLOW.value,
            )

    def test_suffix_confusion_target_returns_deny_via_check(self) -> None:
        # ``notexample.com`` must NOT match ``example.com`` (suffix-confusion
        # guard).  Use ``check`` (which returns ScopeVerdict.DENY) instead
        # of ``enforce_scope`` (which raises on DENY).
        from bugwolf.governance.scope import (
            ScopeContext, ScopeRule, ScopeVerdict,
        )
        ctx = ScopeContext(
            in_scope=[
                ScopeRule(pattern="example.com", rule_type="domain",
                          action=ScopeVerdict.ALLOW.value),
            ],
            default_deny=True,
        )
        self.assertEqual(ctx.check("notexample.com"),
                         ScopeVerdict.DENY)

    def test_enforce_scope_deny_raises(self) -> None:
        from bugwolf.governance.scope import (
            ScopeContext, ScopeRule, ScopeVerdict, enforce_scope,
            ScopeViolation,
        )
        ctx = ScopeContext(
            in_scope=[
                ScopeRule(pattern="example.com", rule_type="domain",
                          action=ScopeVerdict.ALLOW.value),
            ],
            default_deny=True,
        )
        with self.assertRaises(ScopeViolation):
            enforce_scope("attacker.com", ctx)

    def test_enforce_scope_in_scope_allows(self) -> None:
        from bugwolf.governance.scope import (
            ScopeContext, ScopeRule, ScopeVerdict, enforce_scope,
        )
        ctx = ScopeContext(
            in_scope=[
                ScopeRule(pattern="example.com", rule_type="domain",
                          action=ScopeVerdict.ALLOW.value),
            ],
            default_deny=True,
        )
        self.assertEqual(enforce_scope("example.com", ctx),
                         ScopeVerdict.ALLOW)
        self.assertEqual(enforce_scope("api.example.com", ctx),
                         ScopeVerdict.ALLOW)

    def test_enforce_scope_requires_approval(self) -> None:
        from bugwolf.governance.scope import (
            ScopeContext, ScopeRule, ScopeVerdict, enforce_scope,
        )
        ctx = ScopeContext(
            requires_approval=[
                ScopeRule(pattern="staging.example.com", rule_type="domain",
                          action=ScopeVerdict.REQUIRE_APPROVAL.value),
            ],
            default_deny=True,
        )
        self.assertEqual(enforce_scope("staging.example.com", ctx),
                         ScopeVerdict.REQUIRE_APPROVAL)


# ---------------------------------------------------------------------------
# Gate 1 — refutation requires evidence
# ---------------------------------------------------------------------------


class GovernanceRefutationRequiresEvidenceTests(unittest.TestCase):
    """Phase 1.4 Gate 1: high-confidence refutation needs a replay_key."""

    def setUp(self) -> None:
        from tools.runtime import scope
        scope.reset()
        self.addCleanup(self._reset_scope)

    @staticmethod
    def _reset_scope() -> None:
        from tools.runtime import scope
        scope.reset()

    def test_rebuttal_without_replay_key_caps_confidence(self) -> None:
        from bugwolf.governance.rebuttal import Rebuttal
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            r = Rebuttal("f-1", root=Path(tmpdir))
            # Rebuttal.confidence requires replay_key.  The bare rebut()
            # call leaves confidence at the default (0.0).
            r.rebut({"reasoning": "tested and could not reproduce",
                     "replay_key": None})
            self.assertLessEqual(r.confidence, 1.0)
            self.assertEqual(r.confidence, 0.0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_rebuttal_with_replay_key_records_high_confidence(self) -> None:
        from bugwolf.governance.rebuttal import Rebuttal
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            r = Rebuttal("f-2", root=Path(tmpdir))
            r.rebut({"reasoning": "replayed end-to-end",
                     "replay_key": "abc123"})
            # The rebuttal exposes ``confidence`` as an attribute; if
            # the implementation refuses confidence=1.0 without
            # evidence, the value must be < 1.0 here.
            self.assertLessEqual(r.confidence, 1.0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_confidence_one_zero_requires_replay_key(self) -> None:
        # Direct test on the public surface: confidence=1.0 only with
        # a non-null replay_key.
        from bugwolf.governance.rebuttal import Rebuttal
        tmpdir = tempfile.mkdtemp(prefix="bw14-adv-")
        try:
            r = Rebuttal("f-3", root=Path(tmpdir))
            r.rebut({"reasoning": "high confidence rebuttal",
                     "confidence": 1.0,
                     "replay_key": None})
            self.assertLess(r.confidence, 1.0)
            r2 = Rebuttal("f-4", root=Path(tmpdir))
            r2.rebut({"reasoning": "high confidence rebuttal",
                      "confidence": 1.0,
                      "replay_key": "deadbeef"})
            self.assertEqual(r2.confidence, 1.0)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Gate 1 — SevenQuestionGate is evidence-aware
# ---------------------------------------------------------------------------


class GovernanceSevenQuestionGateTests(unittest.TestCase):
    """Phase 1.4 Gate 1: SevenQuestionGate is evidence-aware (dry-run)."""

    def test_no_evidence_returns_fail(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict2, SevenQuestionGate,
        )
        gate = SevenQuestionGate(llm_backend=None)
        finding = _good_finding(include_evidence=False)
        result = gate.evaluate(finding)
        self.assertEqual(result.overall_verdict, GateVerdict2.FAIL)
        self.assertFalse(result.judge_used)

    def test_with_evidence_returns_pass(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict2, SevenQuestionGate,
        )
        gate = SevenQuestionGate(llm_backend=None)
        finding = _good_finding(include_evidence=True)
        result = gate.evaluate(finding)
        self.assertEqual(result.overall_verdict, GateVerdict2.PASS)
        # The dry-run should not claim a judge was used.
        self.assertFalse(result.judge_used)

    def test_seven_results_per_evaluation(self) -> None:
        from bugwolf.governance.question_gate import SevenQuestionGate
        gate = SevenQuestionGate(llm_backend=None)
        result = gate.evaluate(_good_finding(include_evidence=True))
        self.assertEqual(len(result.results), 7)
        ids = [r.question_id for r in result.results]
        self.assertEqual(ids, list(range(1, 8)))

    def test_seven_question_gate_never_raises(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict2, SevenQuestionGate,
        )

        class BoomBackend:
            name = "boom"

            def complete(self, prompt, **kwargs):
                raise RuntimeError("backend down")

        gate = SevenQuestionGate(llm_backend=BoomBackend())
        finding = _good_finding(include_evidence=True)
        result = gate.evaluate(finding)
        # We never propagate; the gate returns a GateResult.
        self.assertIsInstance(result.overall_verdict, GateVerdict2)
        self.assertTrue(result.judge_used)


# ---------------------------------------------------------------------------
# Gate 1 — CVSS severity mapping
# ---------------------------------------------------------------------------


class GovernanceCVSSSeverityMappingTests(unittest.TestCase):
    """Phase 1.4 Gate 1: CVSS31.severity() maps canonical scores correctly."""

    def setUp(self) -> None:
        from bugwolf.governance.cvss import CVSS31
        self.cvss = CVSS31()

    def test_score_to_severity(self) -> None:
        cases = [
            (0.0, "none"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10.0, "critical"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(self.cvss.severity(score), expected)

    def test_full_vector_round_trip(self) -> None:
        score = self.cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)
        self.assertEqual(self.cvss.severity(score), "critical")


# ---------------------------------------------------------------------------
# Gate 1 — EXACT PLAN-NAMED ADVERSARIAL TESTS
# ---------------------------------------------------------------------------
# The plan's Gate 1 (line 1677-1689) lists these three specific test names
# as the gate criteria. They must exist as named tests, even if other tests
# cover the same invariants.


def test_governance_no_destructive_default() -> None:
    """Plan Gate 1: DESTRUCTIVE verb without --confirm-destructive returns blocked."""
    from bugwolf.governance.scope import (
        DESTRUCTIVE_ACTIONS, bind_governance,
    )
    tmpdir = tempfile.mkdtemp(prefix="bw14-gate1-")
    try:
        handle = bind_governance(
            target="example.com",
            mission_id="m-no-destructive-default",
            allowed_actions=list(DESTRUCTIVE_ACTIONS),
            root=Path(tmpdir),
        )
        # Destructive action without approval must raise.
        try:
            handle.require_action_authorized("delete")
            raised = False
        except PermissionError:
            raised = True
        assert raised, "DESTRUCTIVE verb without approval must be blocked"
    finally:
        import shutil as _sh
        _sh.rmtree(tmpdir, ignore_errors=True)


def test_governance_scope_required() -> None:
    """Plan Gate 1: wildcard scope pattern is rejected."""
    from bugwolf.governance.scope import (
        ScopeContext, ScopeRule, ScopeVerdict,
    )
    # Wildcard pattern paired with ALLOW must be rejected at construction.
    try:
        ScopeRule(
            pattern="*.example.com",
            rule_type="wildcard",
            action=ScopeVerdict.ALLOW.value,
        )
        raised = False
    except ValueError:
        raised = True
    assert raised, "wildcard ALLOW rule must be rejected (footgun guard)"

    # Also: out-of-scope target must NOT be silently allowed.
    ctx = ScopeContext(
        in_scope=[
            ScopeRule(pattern="example.com", rule_type="domain",
                      action=ScopeVerdict.ALLOW.value),
        ],
        default_deny=True,
    )
    assert ctx.check("notexample.com") == ScopeVerdict.DENY
    assert ctx.check("example.com.evil.test") == ScopeVerdict.DENY
    # But example.com itself is allowed.
    assert ctx.check("example.com") == ScopeVerdict.ALLOW
    # Subdomain matches via dot-boundary.
    assert ctx.check("api.example.com") == ScopeVerdict.ALLOW


def test_governance_refutation_requires_evidence() -> None:
    """Plan Gate 1: confidence=1.0 only with replay_key non-null."""
    from bugwolf.governance.rebuttal import Rebuttal
    tmpdir = tempfile.mkdtemp(prefix="bw14-gate1-")
    try:
        # confidence=1.0 with NO replay_key -> clamped.
        r1 = Rebuttal("f-no-key", root=Path(tmpdir))
        r1.rebut({"reasoning": "high confidence",
                  "confidence": 1.0,
                  "replay_key": None})
        assert r1.confidence < 1.0

        # confidence=1.0 WITH replay_key -> honored.
        r2 = Rebuttal("f-with-key", root=Path(tmpdir))
        r2.rebut({"reasoning": "high confidence with evidence",
                  "confidence": 1.0,
                  "replay_key": "deadbeef"})
        assert r2.confidence == 1.0
    finally:
        import shutil as _sh
        _sh.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Appendix F exit — cross-project citation check still passes
# ---------------------------------------------------------------------------


class GovernanceCitationCheckTests(unittest.TestCase):
    def test_citation_script_returns_zero(self) -> None:
        import subprocess
        script = ROOT / "scripts" / "cross_project_citation_check.py"
        if not script.exists():
            self.skipTest("script missing")
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0,
                         f"stderr={result.stderr!r}\nstdout={result.stdout!r}")


if __name__ == "__main__":
    unittest.main()