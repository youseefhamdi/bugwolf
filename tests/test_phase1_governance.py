#!/usr/bin/env python3
"""Phase 1.4 Governance Core regression tests.

Covers:
  * MissionStateMachine valid + invalid transitions
  * BudgetGuard consume() and reached_min_steps()
  * LoopDetector window-based detection; thread-safety
  * EvidenceVerifier.verify_chain() accepts a 3-entry chain;
    rejects a tampered entry
  * QuestionGate structural pass + reject
  * QuestionGate with mocked judge_backend accept/reject
  * QuestionGate.NEEDS_HUMAN_REVIEW when no judge_backend and structural
    checks inconclusive
  * Approval 7-day TTL expiry; SHA-256 of approval record
  * Tracer append-only + hash-chain link
  * audit_log.scan_text detects BugWolf/1.0 + proxies-cache.json
  * audit_log.scan_headers detects framework UA leaks
  * audit_log.scan_path recursive walk
  * gpg_signer.sign_with_gpg returns deterministic placeholder when
    gpg missing
  * web.app rejects requests missing X-Outrider-Control-Token with 401
  * web.app sets CSP default-src 'self' header on responses
  * contract.SkillRequest is frozen (frozen=True)
  * Shims import correctly without circular imports

Uses unittest.TestCase; no external deps.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _approx_equal(a: float, b: float, *, eps: float = 0.05) -> bool:
    return abs(a - b) < eps


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="bw14-")
        self._env_backup = dict(os.environ)
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._tmpdir

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env_backup)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _root(self) -> Path:
        return Path(self._tmpdir)


# ---------------------------------------------------------------------------
# MissionStateMachine
# ---------------------------------------------------------------------------


class MissionStateMachineTests(_Base):
    def test_valid_linear_transitions(self) -> None:
        from bugwolf.governance.state import (
            MissionState, MissionStateMachine, MissionStateError,
        )
        m = MissionStateMachine(target="example.com", mission_id="m1",
                                 root=self._root())
        self.assertEqual(m.state, MissionState.INIT)
        for target in (MissionState.SCOPED, MissionState.COLLECTING,
                       MissionState.ANALYZING, MissionState.REPORTING,
                       MissionState.DONE):
            m.transition(target)
            self.assertEqual(m.state, target)
        self.assertEqual(len(m.history()), 5)

    def test_invalid_transition_raises(self) -> None:
        from bugwolf.governance.state import (
            MissionState, MissionStateMachine, MissionStateError,
        )
        m = MissionStateMachine(target="example.com", mission_id="m2",
                                 root=self._root())
        with self.assertRaises(MissionStateError):
            m.transition(MissionState.COLLECTING)  # skip SCOPED

    def test_terminal_state_blocks_forward(self) -> None:
        from bugwolf.governance.state import (
            MissionState, MissionStateMachine, MissionStateError,
        )
        m = MissionStateMachine(target="example.com", mission_id="m3",
                                 root=self._root())
        m.transition(MissionState.SCOPED)
        m.transition(MissionState.COLLECTING)
        m.transition(MissionState.ANALYZING)
        m.transition(MissionState.REPORTING)
        m.transition(MissionState.DONE)
        with self.assertRaises(MissionStateError):
            m.transition(MissionState.INIT)

    def test_halt_reachable_from_any_state(self) -> None:
        from bugwolf.governance.state import (
            MissionState, MissionStateMachine,
        )
        m = MissionStateMachine(target="example.com", mission_id="m4",
                                 root=self._root())
        m.transition(MissionState.SCOPED)
        m.transition(MissionState.COLLECTING)
        m.halt(reason="kill-switch")
        self.assertEqual(m.state, MissionState.HALTED)


# ---------------------------------------------------------------------------
# BudgetGuard
# ---------------------------------------------------------------------------


class BudgetGuardTests(_Base):
    def test_consume_within_budget(self) -> None:
        from bugwolf.governance.budget import BudgetGuard
        budget = BudgetGuard(max_steps=3, max_wall_clock=60, min_steps=1)
        self.assertTrue(budget.consume())
        self.assertTrue(budget.consume())
        self.assertTrue(budget.consume())
        self.assertFalse(budget.consume())  # exhausted
        self.assertFalse(budget.consume())

    def test_reached_min_steps(self) -> None:
        from bugwolf.governance.budget import BudgetGuard
        budget = BudgetGuard(max_steps=10, max_wall_clock=60, min_steps=3)
        self.assertFalse(budget.reached_min_steps())
        budget.consume()
        self.assertFalse(budget.reached_min_steps())
        budget.consume()
        self.assertFalse(budget.reached_min_steps())
        budget.consume()
        self.assertTrue(budget.reached_min_steps())

    def test_wall_clock_exhaustion(self) -> None:
        from bugwolf.governance.budget import BudgetGuard
        clock = iter([0.0, 0.0, 5.0, 11.0])
        budget = BudgetGuard(max_steps=10, max_wall_clock=10, min_steps=0,
                             clock=lambda: next(clock))
        self.assertTrue(budget.consume())  # elapsed 0s
        self.assertTrue(budget.consume())  # elapsed 5s
        self.assertFalse(budget.consume())  # elapsed 11s > max=10

    def test_snapshot(self) -> None:
        from bugwolf.governance.budget import BudgetGuard
        budget = BudgetGuard(max_steps=5, max_wall_clock=10, min_steps=2)
        budget.consume()
        snap = budget.snapshot()
        self.assertEqual(snap.max_steps, 5)
        self.assertEqual(snap.steps_consumed, 1)
        self.assertEqual(snap.min_steps, 2)


# ---------------------------------------------------------------------------
# LoopDetector
# ---------------------------------------------------------------------------


class LoopDetectorTests(_Base):
    def test_window_detection(self) -> None:
        from bugwolf.governance.loop_detector import LoopDetector
        now = [1000.0]

        def clock() -> float:
            return now[0]

        detector = LoopDetector(window_seconds=60, max_repeats=3, clock=clock)
        self.assertFalse(detector.record("act"))
        self.assertFalse(detector.record("act"))
        self.assertTrue(detector.record("act"))
        self.assertTrue(detector.record("act"))
        now[0] = 1200.0  # way past window
        self.assertFalse(detector.record("act"))  # window reset

    def test_thread_safety(self) -> None:
        from bugwolf.governance.loop_detector import LoopDetector
        detector = LoopDetector(window_seconds=60, max_repeats=10)
        hits = []

        def worker() -> None:
            for _ in range(5):
                if detector.record("act"):
                    hits.append(True)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(detector.total("act"), 20)

    def test_total_counter(self) -> None:
        from bugwolf.governance.loop_detector import LoopDetector
        detector = LoopDetector(window_seconds=60, max_repeats=3)
        for _ in range(2):
            detector.record("act")
        self.assertEqual(detector.total("act"), 2)


# ---------------------------------------------------------------------------
# EvidenceVerifier
# ---------------------------------------------------------------------------


class EvidenceVerifierTests(_Base):
    def test_verify_chain_accepts_three_entries(self) -> None:
        from bugwolf.governance.verifier import EvidenceVerifier
        v = EvidenceVerifier(expected_first_sequence=0)
        body_a = {"event": "a"}
        body_b = {"event": "b"}
        body_c = {"event": "c"}
        first = v.build_entry(body_a, previous_hash="", sequence=0)
        second = v.build_entry(body_b,
                               previous_hash=first["entry_hash"], sequence=1)
        third = v.build_entry(body_c,
                              previous_hash=second["entry_hash"], sequence=2)
        report = v.verify_chain([first, second, third])
        self.assertTrue(report.is_valid)
        self.assertEqual(report.verified_entries, 3)
        self.assertEqual(report.tampered_entries, 0)
        self.assertEqual(report.sequence_gaps, 0)
        self.assertTrue(report.hash_chain_intact)

    def test_verify_chain_rejects_tampered_entry(self) -> None:
        from bugwolf.governance.verifier import EvidenceVerifier
        v = EvidenceVerifier()
        first = v.build_entry({"event": "a"}, previous_hash="", sequence=0)
        second = v.build_entry({"event": "b"},
                               previous_hash=first["entry_hash"], sequence=1)
        tampered = copy.deepcopy(second)
        tampered["event"] = "B-tampered"
        report = v.verify_chain([first, tampered])
        self.assertFalse(report.is_valid)
        self.assertEqual(report.tampered_entries, 1)
        self.assertGreater(len(report.errors), 0)

    def test_compute_chain_digest_deterministic(self) -> None:
        from bugwolf.governance.verifier import EvidenceVerifier
        v = EvidenceVerifier()
        entry = {"event": "x", "previous_hash": "abc"}
        h1 = v.compute_chain_digest(entry)
        h2 = v.compute_chain_digest(entry)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)


# ---------------------------------------------------------------------------
# QuestionGate
# ---------------------------------------------------------------------------


def _structural_evidence() -> dict:
    return {
        "request": {"method": "GET", "url": "https://example.com/api"},
        "response": {"status": 200, "body": "{}"},
        "transcript": "GET /api -> 200",
        "chain_verifies": True,
        "chain_hash": "deadbeef",
        "evidence_ref": "ref-1",
    }


def _good_finding() -> dict:
    return {
        "endpoint": "https://example.com/api",
        "action_class": "read",
        "method": "GET",
        "signal": "GET /api -> 200 with leaky header",
        "impact": "PII exposure in response",
        "reasoning": "x" * 60,
    }


class QuestionGateTests(_Base):
    def test_structural_pass_returns_needs_human_review(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )
        gate = QuestionGate()
        verdict = gate.evaluate(
            _good_finding(),
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com",
                             "allowed_actions": ["read", "write"]},
        )
        # No judge_backend → NEEDS_HUMAN_REVIEW after structural pass
        self.assertEqual(verdict.verdict, GateVerdict.NEEDS_HUMAN_REVIEW)

    def test_structural_reject_returns_rejected(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )
        gate = QuestionGate()
        bad_finding = {"endpoint": "https://example.com/api",
                        "method": "GET"}  # missing signal + impact
        verdict = gate.evaluate(
            bad_finding,
            evidence_block={"request": {}, "response": {}},
            scope_contract={"target": "example.com"},
        )
        self.assertEqual(verdict.verdict, GateVerdict.REJECTED)
        self.assertGreater(len(verdict.reasons), 0)

    def test_judge_backend_accepts(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )

        def backend(index, payload):
            return True, "judge OK", {"index": index}

        gate = QuestionGate(judge_backend=backend, min_reasoning_chars=10)
        verdict = gate.evaluate(
            _good_finding(),
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com"},
        )
        self.assertEqual(verdict.verdict, GateVerdict.ACCEPTED)
        self.assertTrue(verdict.judge_used)

    def test_judge_backend_rejects(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )

        def backend(index, payload):
            return False, "judge says no", {}

        gate = QuestionGate(judge_backend=backend)
        verdict = gate.evaluate(
            _good_finding(),
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com"},
        )
        self.assertEqual(verdict.verdict, GateVerdict.REJECTED)

    def test_judge_backend_raises_never_propagates(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )

        def backend(index, payload):
            raise RuntimeError("boom")

        gate = QuestionGate(judge_backend=backend)
        verdict = gate.evaluate(
            _good_finding(),
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com"},
        )
        # Even with judge error, structural pass + (failed) judge => REJECTED
        self.assertEqual(verdict.verdict, GateVerdict.REJECTED)
        self.assertTrue(verdict.judge_used)

    def test_destructive_action_requires_opt_in(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )
        gate = QuestionGate()
        finding = {
            "endpoint": "https://example.com/users/1",
            "action_class": "delete",
            "method": "DELETE",
            "signal": "DELETE -> 204",
            "impact": "user removed",
            "reasoning": "x" * 40,
        }
        verdict = gate.evaluate(
            finding,
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com",
                             "allowed_actions": ["delete", "read"]},
        )
        self.assertEqual(verdict.verdict, GateVerdict.REJECTED)

    def test_destructive_with_opt_in_pass(self) -> None:
        from bugwolf.governance.question_gate import (
            GateVerdict, QuestionGate,
        )
        gate = QuestionGate()
        finding = _good_finding()
        finding["action_class"] = "delete"
        finding["method"] = "DELETE"
        finding["operator_opt_in"] = True
        finding["reasoning"] = "x" * 60
        verdict = gate.evaluate(
            finding,
            evidence_block=_structural_evidence(),
            scope_contract={"target": "example.com",
                             "allowed_actions": ["delete", "read"]},
        )
        self.assertEqual(verdict.verdict, GateVerdict.NEEDS_HUMAN_REVIEW)


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class ApprovalTests(_Base):
    def test_request_and_grant_is_approved(self) -> None:
        from bugwolf.governance.approval import (
            Approval, ApprovalStatus, APPROVAL_TTL,
        )
        store = Approval(root=self._root())
        pending = store.request(
            target="example.com", action="delete",
            method="DELETE", endpoint="/users/1",
            scope_file_sha256="abc")
        self.assertEqual(pending.status, ApprovalStatus.PENDING.value)
        granted = store.grant(pending.approval_id, target="example.com")
        self.assertEqual(granted.status, ApprovalStatus.GRANTED.value)
        self.assertTrue(store.is_approved({
            "target": "example.com",
            "action": "delete",
            "method": "DELETE",
            "endpoint": "/users/1",
            "scope_file_sha256": "abc",
        }))

    def test_approval_ttl_7_days(self) -> None:
        from bugwolf.governance.approval import APPROVAL_TTL
        self.assertEqual(APPROVAL_TTL, 7 * 24 * 3600)

    def test_approval_expires(self) -> None:
        from bugwolf.governance.approval import Approval
        # The approval clock returns unix-time seconds (time.time()-like).
        clock = [1_000_000_000.0]

        def now() -> float:
            return clock[0]

        store = Approval(root=self._root(), clock=now, ttl_seconds=10)
        pending = store.request(target="example.com", action="delete")
        store.grant(pending.approval_id, target="example.com")
        clock[0] += 11
        self.assertFalse(store.is_approved({
            "target": "example.com", "action": "delete",
        }))

    def test_approval_sha256_present(self) -> None:
        from bugwolf.governance.approval import Approval
        store = Approval(root=self._root())
        pending = store.request(
            target="example.com", action="delete")
        self.assertEqual(len(pending.record_sha256), 64)
        report = store.verify_chain("example.com")
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["verified"], 1)

    def test_revoked_approval_is_not_approved(self) -> None:
        from bugwolf.governance.approval import Approval, ApprovalError
        store = Approval(root=self._root())
        pending = store.request(
            target="example.com", action="delete")
        store.grant(pending.approval_id, target="example.com")
        store.revoke(pending.approval_id, target="example.com")
        self.assertFalse(store.is_approved({
            "target": "example.com", "action": "delete",
        }))


# ---------------------------------------------------------------------------
# Tracer
# ---------------------------------------------------------------------------


class TracerTests(_Base):
    def test_append_only_and_chain_link(self) -> None:
        from bugwolf.governance.tracer import Tracer
        tracer = Tracer("mission-1", root=self._root())
        plan_hash = _sha256("plan-1")
        a = tracer.record(plan_hash=plan_hash, event="step.start",
                          actor="runner", detail={"step": 1})
        b = tracer.record(plan_hash=plan_hash, event="step.end",
                          actor="runner", detail={"step": 1})
        self.assertEqual(a["prev_sha256"], "")
        self.assertEqual(b["prev_sha256"], a["entry_sha256"])
        self.assertNotEqual(a["entry_sha256"], b["entry_sha256"])
        report = tracer.verify_chain()
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["verified"], 2)

    def test_hash_chain_detects_tamper(self) -> None:
        from bugwolf.governance.tracer import Tracer
        tracer = Tracer("mission-2", root=self._root())
        plan_hash = _sha256("plan-2")
        tracer.record(plan_hash=plan_hash, event="a", actor="r", detail={})
        tracer.record(plan_hash=plan_hash, event="b", actor="r", detail={})
        # Tamper: rewrite the file
        path = tracer.path
        lines = path.read_text(encoding="utf-8").splitlines()
        payload = json.loads(lines[0])
        payload["event"] = "tampered"
        lines[0] = json.dumps(payload, sort_keys=True,
                              separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = tracer.verify_chain()
        self.assertFalse(report["is_valid"])
        self.assertGreater(len(report["errors"]), 0)


# ---------------------------------------------------------------------------
# audit_log scanner
# ---------------------------------------------------------------------------


class AuditLogTests(_Base):
    def test_scan_text_detects_bugwolf_ua(self) -> None:
        from bugwolf.governance.audit_log import scan_text
        hits = scan_text("User-Agent: BugWolf/1.0")
        self.assertIn("BugWolf/1.0", hits)

    def test_scan_text_detects_proxies_cache(self) -> None:
        from bugwolf.governance.audit_log import scan_text
        hits = scan_text("loading proxies-cache.json from /opt")
        self.assertIn("proxies-cache.json", hits)

    def test_scan_text_clean_text_no_hits(self) -> None:
        from bugwolf.governance.audit_log import scan_text
        hits = scan_text("nothing dangerous here")
        self.assertEqual(hits, [])

    def test_scan_headers_detects_framework_ua(self) -> None:
        from bugwolf.governance.audit_log import scan_headers
        headers = {"User-Agent": "BugWolf/2.1"}
        hits = scan_headers(headers)
        self.assertTrue(any("bugwolf" in h.lower() for h in hits))

    def test_scan_path_recursive(self) -> None:
        from bugwolf.governance.audit_log import scan_path
        root = self._root()
        (root / "subdir" / "deep").mkdir(parents=True, exist_ok=True)
        (root / "clean.txt").write_text("nothing dangerous", encoding="utf-8")
        (root / "subdir" / "ua.log").write_text(
            "client was BugWolf/1.0", encoding="utf-8")
        (root / "subdir" / "deep" / "x.json").write_text(
            'reference to proxies-cache.json file', encoding="utf-8")
        hits = scan_path(root)
        joined = "\n".join(hits)
        self.assertIn("ua.log", joined)
        self.assertTrue(any("deep" in h for h in hits))


# ---------------------------------------------------------------------------
# gpg_signer
# ---------------------------------------------------------------------------


class GpgSignerTests(_Base):
    def test_placeholder_when_gpg_missing(self) -> None:
        from bugwolf.governance import gpg_signer
        with mock.patch.object(gpg_signer.shutil, "which",
                                return_value=None):
            sig = gpg_signer.sign_with_gpg("a" * 64, "b" * 64)
        self.assertTrue(sig.startswith("sha256:"))
        self.assertEqual(len(sig), len("sha256:") + 64)

    def test_placeholder_is_deterministic(self) -> None:
        from bugwolf.governance import gpg_signer
        with mock.patch.object(gpg_signer.shutil, "which",
                                return_value=None):
            s1 = gpg_signer.sign_with_gpg("a" * 64, "b" * 64)
            s2 = gpg_signer.sign_with_gpg("a" * 64, "b" * 64)
        self.assertEqual(s1, s2)

    def test_gpg_present_succeeds(self) -> None:
        from bugwolf.governance import gpg_signer

        # Simulate gpg producing an armored signature.
        def fake_gpg(*args, **kwargs):
            class R:
                returncode = 0
                stdout = b""
                stderr = b""
            # Find the --output path arg.
            argv = args[0]
            output = None
            for i, a in enumerate(argv):
                if a == "--output":
                    output = argv[i + 1]
                    break
            if output:
                Path(output).write_text(
                    "-----BEGIN PGP SIGNATURE-----\nABCD\n"
                    "-----END PGP SIGNATURE-----\n",
                    encoding="utf-8")
            return R()

        with mock.patch.object(gpg_signer.shutil, "which",
                                return_value="/usr/bin/gpg"), \
             mock.patch.object(gpg_signer.subprocess, "run",
                                side_effect=fake_gpg):
            sig = gpg_signer.sign_with_gpg("a" * 64, "b" * 64)
        self.assertIn("BEGIN PGP", sig)


# ---------------------------------------------------------------------------
# web control plane
# ---------------------------------------------------------------------------


class WebControlPlaneTests(_Base):
    def setUp(self) -> None:
        super().setUp()
        os.environ["OUTRIDER_CONTROL_TOKEN"] = "secret-token"

    def test_missing_token_returns_401(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle("GET", "/healthz", headers={})
        self.assertEqual(response.status_code, 401)

    def test_wrong_token_returns_401(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle(
            "GET", "/healthz",
            headers={"X-Outrider-Control-Token": "nope"})
        self.assertEqual(response.status_code, 401)

    def test_correct_token_returns_200(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle(
            "GET", "/healthz",
            headers={"X-Outrider-Control-Token": "secret-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.payload["status"], "ok")

    def test_csp_header_on_response(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle(
            "GET", "/healthz",
            headers={"X-Outrider-Control-Token": "secret-token"})
        self.assertEqual(
            response.headers.get("Content-Security-Policy"),
            "default-src 'self'")

    def test_csp_header_on_401(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle("GET", "/healthz", headers={})
        self.assertEqual(
            response.headers.get("Content-Security-Policy"),
            "default-src 'self'")

    def test_state_route(self) -> None:
        from bugwolf.governance import web
        response = web.app.handle(
            "GET", "/state/m1",
            headers={"X-Outrider-Control-Token": "secret-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.payload["mission_id"], "m1")

    def test_approval_route(self) -> None:
        from bugwolf.governance import web
        body = {"target": "example.com", "action": "delete",
                "method": "DELETE", "endpoint": "/x"}
        response = web.app.handle(
            "POST", "/approvals",
            headers={"X-Outrider-Control-Token": "secret-token"},
            json_body=body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.payload["status"], "GRANTED")
        self.assertIn("approval_id", response.payload)

    def test_decisions_recent_route(self) -> None:
        from bugwolf.governance import web
        web.record_decision({"ts": "t1", "model": "x"})
        web.record_decision({"ts": "t2", "model": "y"})
        response = web.app.handle(
            "GET", "/decisions/recent",
            headers={"X-Outrider-Control-Token": "secret-token"})
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.payload["decisions"]), 2)


# ---------------------------------------------------------------------------
# contract dataclasses
# ---------------------------------------------------------------------------


class ContractTests(_Base):
    def test_skill_request_is_frozen(self) -> None:
        from bugwolf.governance.contract import SkillRequest
        req = SkillRequest.create(
            request_id="r1", target="example.com",
            action_class="read", scope_ref="scope.json",
            payload_ref="payload.json")
        with self.assertRaises(Exception):
            req.target = "attacker.com"  # type: ignore[misc]

    def test_skill_result_is_frozen(self) -> None:
        from bugwolf.governance.contract import SkillResult
        res = SkillResult.create(
            request_id="r1", status="ok",
            evidence_ref="ref-1", findings_count=3)
        with self.assertRaises(Exception):
            res.status = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Shim imports
# ---------------------------------------------------------------------------


class ShimTests(_Base):
    def test_scope_shim_imports(self) -> None:
        from tools.runtime.scope import bind_governance
        self.assertTrue(callable(bind_governance))

    def test_refutation_shim_imports(self) -> None:
        from tools.refutation import with_question_gate
        from bugwolf.governance.question_gate import FindingVerdict
        out = with_question_gate({"x": 1})
        self.assertIsInstance(out, FindingVerdict)

    def test_chain_of_custody_shim_imports(self) -> None:
        from tools.chain_of_custody import sign_with_gpg
        sig = sign_with_gpg("a" * 64, "b" * 64)
        self.assertIsInstance(sig, str)
        self.assertGreater(len(sig), 0)

    def test_hunt_shim_imports(self) -> None:
        from tools.hunt import apply_question_gate
        from bugwolf.governance.question_gate import GateEvaluation
        out = apply_question_gate([{"x": 1}, {"y": 2}])
        self.assertEqual(len(out), 2)
        for item in out:
            self.assertIsInstance(item, GateEvaluation)

    def test_kill_chain_shim_imports(self) -> None:
        from tools.kill_chain import approve_destructive
        self.assertFalse(approve_destructive({"target": "x",
                                               "action": "delete"}))

    def test_no_circular_imports(self) -> None:
        # Re-import every shim and module — must not error.
        import bugwolf.governance  # noqa: F401
        import bugwolf.governance.scope  # noqa: F401
        import bugwolf.governance.verifier  # noqa: F401
        import bugwolf.governance.approval  # noqa: F401
        import bugwolf.governance.contract  # noqa: F401
        import bugwolf.governance.state  # noqa: F401
        import bugwolf.governance.web  # noqa: F401
        import bugwolf.governance.question_gate  # noqa: F401
        import bugwolf.governance.rebuttal  # noqa: F401
        import bugwolf.governance.budget  # noqa: F401
        import bugwolf.governance.loop_detector  # noqa: F401
        import bugwolf.governance.tracer  # noqa: F401
        import bugwolf.governance.audit_log  # noqa: F401
        import bugwolf.governance.gpg_signer  # noqa: F401
        import tools.runtime.scope  # noqa: F401
        import tools.refutation  # noqa: F401
        import tools.chain_of_custody  # noqa: F401
        import tools.hunt  # noqa: F401
        import tools.kill_chain  # noqa: F401


# ---------------------------------------------------------------------------
# Rebuttal
# ---------------------------------------------------------------------------


class RebuttalTests(_Base):
    def test_active_to_accepted(self) -> None:
        from bugwolf.governance.rebuttal import (
            Rebuttal, RebuttalState, RebuttalError,
        )
        r = Rebuttal("finding-1", root=self._root())
        self.assertEqual(r.state, RebuttalState.ACTIVE)
        r.rebut({"reasoning": "x"})
        r.accept(reason="operator decision")
        self.assertEqual(r.state, RebuttalState.ACCEPTED)
        report = r.verify_chain()
        self.assertTrue(report["is_valid"])

    def test_active_to_stalled_to_active(self) -> None:
        from bugwolf.governance.rebuttal import (
            Rebuttal, RebuttalState, RebuttalError,
        )
        r = Rebuttal("finding-2", root=self._root())
        r.mark_stalled(reason="waiting")
        self.assertEqual(r.state, RebuttalState.STALLED)
        r.rebut({"reasoning": "y"})
        self.assertEqual(r.state, RebuttalState.ACTIVE)

    def test_active_to_exhausted_terminal(self) -> None:
        from bugwolf.governance.rebuttal import (
            Rebuttal, RebuttalState, RebuttalError,
        )
        r = Rebuttal("finding-3", root=self._root())
        r.mark_exhausted(reason="no path forward")
        self.assertEqual(r.state, RebuttalState.EXHAUSTED)
        with self.assertRaises(RebuttalError):
            r.accept()


# ---------------------------------------------------------------------------
# Canonical helper
# ---------------------------------------------------------------------------


class CanonicalTests(_Base):
    def test_canonical_bytes_deterministic(self) -> None:
        from bugwolf.governance._canonical import canonical_bytes
        b1 = canonical_bytes({"b": 1, "a": 2})
        b2 = canonical_bytes({"a": 2, "b": 1})
        self.assertEqual(b1, b2)

    def test_canonical_bytes_utf8(self) -> None:
        from bugwolf.governance._canonical import canonical_bytes
        b = canonical_bytes({"name": "café"})
        self.assertIn("café".encode("utf-8"), b)


if __name__ == "__main__":
    unittest.main()