#!/usr/bin/env python3
"""Tests for Phase 3.3 — Semantic Bug Detector (bugwolf/semantic/).

Covers:
  * Import + core-function smoke test per module (8 modules).
  * ``IDORDetector.check_resource()`` emits a finding when the
    attacker can read the owner's resource.
  * ``JWTLogicAnalyzer.analyze()`` flags ``alg=none`` tokens.
  * ``JWTLogicAnalyzer.analyze()`` flags weak HMAC secrets.
  * ``JWTLogicAnalyzer.analyze()`` flags expired tokens.
  * ``BusinessLogicDetector.detect_race()`` returns findings.
  * ``BusinessLogicDetector.detect_workflow_bypass()`` returns findings.
  * ``BusinessLogicDetector.detect_toctou()`` returns findings.
  * ``AuthFlowChecker.check_endpoint()`` finds missing auth.
  * ``LLMJudge.judge_finding()`` returns a JudgeResult.
  * ``LLMJudge`` never raises on backend error.
  * ``DiffAnalyzer.diff()`` returns a DiffResult.
  * ``StatefulWorkflowAnalyzer.analyze()`` returns findings.
  * ``SemanticSearch.find_similar()`` returns ranked results.
  * No module uses ``shell=True``, ``verify=False``, hardcoded UA.
  * Every file has ``## Source:`` + ``## License:`` comments.

STUB-SAFE: every test relies on a mock transport; nothing here
performs network IO.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import re
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SEMANTIC_DIR = ROOT / "bugwolf" / "semantic"


# ---------------------------------------------------------------------------
# Module loader
# ---------------------------------------------------------------------------


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Canned transports
# ---------------------------------------------------------------------------


def make_echo_transport(responses: Dict[str, Dict[str, Any]]):
    """Mock transport that returns a canned response per URL."""
    sent: List[Dict[str, Any]] = []

    def transport(method, url, headers=None, body=None):
        sent.append({"method": method, "url": url,
                     "headers": headers or {}, "body": body})
        for key, resp in responses.items():
            if key in (url or ""):
                return resp
        return {"status": 200, "headers": {}, "body": ""}

    transport.sent = sent
    return transport


def make_always_success_transport(body: str = "ok"):
    def transport(method, url, headers=None, body=None):
        return {"status": 200, "headers": {}, "body": body}
    return transport


def make_always_401_transport():
    def transport(method, url, headers=None, body=None):
        return {"status": 401, "headers": {}, "body": ""}
    return transport


def make_bypass_transport(allowed_header: str = "X-Forwarded-For"):
    """Returns 200 if the bypass header is set, 401 otherwise."""
    def transport(method, url, headers=None, body=None):
        h = headers or {}
        if h.get(allowed_header):
            return {"status": 200, "headers": {}, "body": "welcome admin"}
        return {"status": 401, "headers": {}, "body": "unauthorized"}
    return transport


def make_race_transport():
    """Returns a payment-confirmed body for 3 of 5 calls."""
    count = {"n": 0}

    def transport(method, url, headers=None, body=None):
        count["n"] += 1
        if count["n"] <= 3:
            return {
                "status": 200,
                "headers": {},
                "body": json.dumps({
                    "status": "paid",
                    "balance": -10 * count["n"],
                    "amount": 10,
                }),
            }
        return {"status": 409, "headers": {}, "body": "conflict"}
    return transport


# ---------------------------------------------------------------------------
# Test source-level audit
# ---------------------------------------------------------------------------


class TestSourceAudit(unittest.TestCase):
    """Static checks over every file in ``bugwolf/semantic/``."""

    FILES: Tuple[Path, ...] = (
        SEMANTIC_DIR / "__init__.py",
        SEMANTIC_DIR / "idor_detector.py",
        SEMANTIC_DIR / "jwt_logic.py",
        SEMANTIC_DIR / "business_logic.py",
        SEMANTIC_DIR / "auth_flow.py",
        SEMANTIC_DIR / "llm_judge.py",
        SEMANTIC_DIR / "diff_analyzer.py",
        SEMANTIC_DIR / "stateful_workflow.py",
        SEMANTIC_DIR / "semantic_search.py",
    )

    def test_files_exist(self):
        for f in self.FILES:
            self.assertTrue(f.exists(), f"missing file: {f}")

    def test_no_shell_true(self):
        offenders: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            if re.search(r"shell\s*=\s*True", txt):
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"shell=True found in: {offenders}")

    def test_no_verify_false(self):
        offenders: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            if re.search(r"verify\s*=\s*False", txt):
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"verify=False found in: {offenders}")

    def test_no_hardcoded_user_agent(self):
        offenders: List[str] = []
        ua_re = re.compile(r"User-Agent['\"]?\s*[:=]\s*['\"][^'\"]+['\"]")
        for f in self.FILES:
            txt = f.read_text()
            if ua_re.search(txt):
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"hardcoded UA in: {offenders}")

    def test_source_and_license_comments(self):
        missing: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            if "## Source:" not in txt:
                missing.append(f"{f} (no ## Source:)")
            if "## License:" not in txt:
                missing.append(f"{f} (no ## License:)")
        self.assertEqual(missing, [],
                         f"missing header comments: {missing}")

    def test_schema_constant_present(self):
        offenders: List[str] = []
        for f in self.FILES:
            if f.name == "__init__.py":
                continue
            txt = f.read_text()
            if 'SCHEMA = "bugwolf-semantic-v1"' not in txt:
                offenders.append(str(f))
        self.assertEqual(offenders, [],
                         f"missing SCHEMA constant in: {offenders}")

    def test_no_file_or_gopher_payloads(self):
        offenders: List[str] = []
        for f in self.FILES:
            txt = f.read_text()
            for pat in (r"file://", r"gopher://"):
                if re.search(pat, txt):
                    offenders.append(f"{f}: {pat}")
        self.assertEqual(offenders, [],
                         f"forbidden scheme literal in: {offenders}")


# ---------------------------------------------------------------------------
# Module import + smoke tests
# ---------------------------------------------------------------------------


class TestModuleImports(unittest.TestCase):

    def test_import_idor_detector(self):
        mod = _load_module("sm_idor_detector", SEMANTIC_DIR / "idor_detector.py")
        self.assertTrue(hasattr(mod, "IDORDetector"))
        self.assertTrue(hasattr(mod, "IDORFinding"))
        self.assertTrue(hasattr(mod, "Session"))
        self.assertTrue(callable(mod.IDORDetector))

    def test_import_jwt_logic(self):
        mod = _load_module("sm_jwt_logic", SEMANTIC_DIR / "jwt_logic.py")
        self.assertTrue(hasattr(mod, "JWTLogicAnalyzer"))
        self.assertTrue(hasattr(mod, "JWTIssue"))

    def test_import_business_logic(self):
        mod = _load_module("sm_business_logic",
                           SEMANTIC_DIR / "business_logic.py")
        self.assertTrue(hasattr(mod, "BusinessLogicDetector"))
        self.assertTrue(hasattr(mod, "RaceFinding"))
        self.assertTrue(hasattr(mod, "WorkflowBypassFinding"))
        self.assertTrue(hasattr(mod, "TOCTOUFinding"))

    def test_import_auth_flow(self):
        mod = _load_module("sm_auth_flow", SEMANTIC_DIR / "auth_flow.py")
        self.assertTrue(hasattr(mod, "AuthFlowChecker"))
        self.assertTrue(hasattr(mod, "AuthFinding"))

    def test_import_llm_judge(self):
        mod = _load_module("sm_llm_judge", SEMANTIC_DIR / "llm_judge.py")
        self.assertTrue(hasattr(mod, "LLMJudge"))
        self.assertTrue(hasattr(mod, "JudgeResult"))

    def test_import_diff_analyzer(self):
        mod = _load_module("sm_diff_analyzer",
                           SEMANTIC_DIR / "diff_analyzer.py")
        self.assertTrue(hasattr(mod, "DiffAnalyzer"))
        self.assertTrue(hasattr(mod, "DiffResult"))
        self.assertTrue(hasattr(mod, "HttpObservation"))

    def test_import_stateful_workflow(self):
        mod = _load_module("sm_stateful_workflow",
                           SEMANTIC_DIR / "stateful_workflow.py")
        self.assertTrue(hasattr(mod, "StatefulWorkflowAnalyzer"))
        self.assertTrue(hasattr(mod, "WorkflowFinding"))

    def test_import_semantic_search(self):
        mod = _load_module("sm_semantic_search",
                           SEMANTIC_DIR / "semantic_search.py")
        self.assertTrue(hasattr(mod, "SemanticSearch"))
        self.assertTrue(hasattr(mod, "SemanticMatch"))

    def test_package_init_reexports(self):
        pkg = _load_module("bugwolf_semantic_test", SEMANTIC_DIR / "__init__.py")
        for name in (
            "IDORDetector", "JWTLogicAnalyzer", "BusinessLogicDetector",
            "AuthFlowChecker", "LLMJudge", "DiffAnalyzer",
            "StatefulWorkflowAnalyzer", "SemanticSearch",
        ):
            self.assertTrue(hasattr(pkg, name), f"missing re-export: {name}")


# ---------------------------------------------------------------------------
# IDORDetector
# ---------------------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(header: Dict[str, Any], payload: Dict[str, Any],
              sig: bytes = b"") -> str:
    h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    s = _b64u(sig)
    return f"{h}.{p}.{s}"


class TestIDORDetector(unittest.TestCase):

    def _build(self):
        from bugwolf.semantic.idor_detector import IDORDetector, Session
        owner = Session(
            name="owner",
            headers={"Authorization": "Bearer owner-token"},
            user_id="owner-1",
            role="user",
        )
        attacker = Session(
            name="attacker",
            headers={"Authorization": "Bearer attacker-token"},
            user_id="attacker-1",
            role="user",
        )
        return IDORDetector([owner, attacker])

    def test_check_resource_finds_idor(self):
        det = self._build()
        owner_body = json.dumps({
            "id": 42, "owner": "owner-1", "email": "owner@example.com",
            "balance": 100,
        })
        responses = {
            "https://t/api/users/me": {
                "status": 200, "headers": {}, "body": owner_body,
            }
        }
        det._transport = make_echo_transport(responses)
        det.transport = det._transport  # type: ignore[attr-defined]
        findings = det.check_resource("https://t/api/users/me")
        self.assertGreater(len(findings), 0)
        kinds = {f.kind for f in findings}
        self.assertIn("idor", kinds)
        first = findings[0]
        self.assertIn(first.severity, ("high", "critical"))
        self.assertIn("attacker", first.evidence.lower())

    def test_check_resource_returns_empty_when_attacker_blocked(self):
        det = self._build()

        def transport(method, url, headers=None, body=None):
            auth = (headers or {}).get("Authorization", "")
            if "attacker" in auth:
                return {"status": 403, "headers": {}, "body": ""}
            return {"status": 200, "headers": {},
                    "body": json.dumps({"id": 1, "owner": "owner-1"})}
        det._transport = transport
        det.transport = transport  # type: ignore[attr-defined]
        findings = det.check_resource("https://t/api/users/me")
        self.assertEqual(findings, [])

    def test_check_resource_handles_transport_failure(self):
        det = self._build()

        def transport(method, url, headers=None, body=None):
            raise RuntimeError("boom")
        det._transport = transport
        det.transport = transport  # type: ignore[attr-defined]
        self.assertEqual(det.check_resource("https://t/api/x"), [])


# ---------------------------------------------------------------------------
# JWTLogicAnalyzer
# ---------------------------------------------------------------------------


class TestJWTLogicAnalyzer(unittest.TestCase):

    def test_flags_alg_none(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer, JWTIssue
        a = JWTLogicAnalyzer()
        token = _make_jwt({"alg": "none", "typ": "JWT"},
                          {"sub": "victim", "role": "admin"})
        out = a.analyze(token)
        kinds = {i.kind for i in out}
        self.assertIn("alg-none", kinds)
        # alg=none implies missing signature -- we already flag
        # the alg=none case with critical severity, so we don't
        # double-emit "missing-signature".  Just make sure the
        # critical-severity alg-none finding is present.
        self.assertTrue(any(i.kind == "alg-none" and i.severity == "critical"
                            for i in out))

    def test_flags_weak_hmac(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "victim"}
        signing_input = (f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}"
                         f".{_b64u(json.dumps(payload, separators=(',', ':')).encode())}")
        sig = hmac.new(b"secret", signing_input.encode("ascii"),
                       hashlib.sha256).digest()
        token = f"{signing_input}.{_b64u(sig)}"
        out = a.analyze(token)
        kinds = {i.kind for i in out}
        self.assertIn("weak-hmac", kinds)

    def test_flags_expired_token(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        past = int(time.time()) - 3600
        token = _make_jwt({"alg": "HS256", "typ": "JWT"},
                          {"sub": "victim", "exp": past})
        # Sign with a non-weak key.
        signing_input = token.rsplit(".", 1)[0]
        sig = hmac.new(b"a-much-longer-and-non-trivial-key",
                       signing_input.encode("ascii"),
                       hashlib.sha256).digest()
        token = f"{signing_input}.{_b64u(sig)}"
        out = a.analyze(token)
        kinds = {i.kind for i in out}
        self.assertIn("expired-token", kinds)

    def test_flags_missing_exp(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "victim"})
        signing_input = token.rsplit(".", 1)[0]
        sig = hmac.new(b"another-non-trivial-key-1234567890",
                       signing_input.encode("ascii"),
                       hashlib.sha256).digest()
        token = f"{signing_input}.{_b64u(sig)}"
        out = a.analyze(token)
        kinds = {i.kind for i in out}
        self.assertIn("missing-exp", kinds)

    def test_flags_kid_injection(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        token = _make_jwt(
            {"alg": "RS256", "typ": "JWT",
             "kid": "../../../etc/passwd"},
            {"sub": "victim"},
        )
        out = a.analyze(token)
        kinds = {i.kind for i in out}
        self.assertIn("kid-injection", kinds)

    def test_malformed_token_returns_finding(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        out = a.analyze("not.a.jwt")
        # The analyzer must not raise; for a token that decodes as
        # base64, it should still produce a (possibly empty) list.
        self.assertIsInstance(out, list)


# ---------------------------------------------------------------------------
# BusinessLogicDetector
# ---------------------------------------------------------------------------


class TestBusinessLogicDetector(unittest.TestCase):

    def test_detect_race_returns_findings(self):
        from bugwolf.semantic.business_logic import (
            BusinessLogicDetector, RaceFinding,
        )
        det = BusinessLogicDetector()
        transport = make_race_transport()
        out = det.detect_race("https://t/api/pay",
                              concurrency=5, transport=transport)
        self.assertIsInstance(out, list)
        self.assertGreater(len(out), 0)
        for f in out:
            self.assertIsInstance(f, RaceFinding)
            self.assertEqual(f.kind, "race-condition")

    def test_detect_workflow_bypass_returns_findings(self):
        from bugwolf.semantic.business_logic import (
            BusinessLogicDetector, WorkflowBypassFinding, WorkflowStep,
        )
        det = BusinessLogicDetector()
        steps = [
            WorkflowStep(name="cart", method="GET",
                         url="https://t/api/cart"),
            WorkflowStep(name="payment", method="POST",
                         url="https://t/api/payment",
                         body="amount=10"),
            WorkflowStep(name="confirm", method="GET",
                         url="https://t/api/confirm"),
        ]

        def transport(method, url, headers=None, body=None):
            if "confirm" in (url or ""):
                return {"status": 200, "headers": {}, "body": "ok"}
            return {"status": 200, "headers": {}, "body": ""}
        out = det.detect_workflow_bypass(steps, transport)
        self.assertIsInstance(out, list)
        self.assertGreater(len(out), 0)
        for f in out:
            self.assertIsInstance(f, WorkflowBypassFinding)
            self.assertEqual(f.kind, "workflow-bypass")

    def test_detect_toctou_returns_findings(self):
        from bugwolf.semantic.business_logic import (
            BusinessLogicDetector, TOCTOUFinding,
        )
        det = BusinessLogicDetector()
        out = det.detect_toctou(
            state_before={"balance": 100, "is_active": True},
            state_after={"balance": -50, "is_active": False},
            operation="withdraw",
        )
        self.assertIsInstance(out, list)
        self.assertGreater(len(out), 0)
        for f in out:
            self.assertIsInstance(f, TOCTOUFinding)
            self.assertEqual(f.kind, "toctou")


# ---------------------------------------------------------------------------
# AuthFlowChecker
# ---------------------------------------------------------------------------


class TestAuthFlowChecker(unittest.TestCase):

    def test_finds_missing_auth(self):
        from bugwolf.semantic.auth_flow import (
            AuthFlowChecker, AuthFinding,
        )
        checker = AuthFlowChecker()
        transport = make_always_success_transport("welcome admin")
        out = checker.check_endpoint(
            "https://t/api/admin", "GET",
            transport=transport, auth_required=True,
        )
        kinds = {f.kind for f in out}
        self.assertIn("missing-auth", kinds)
        # AuthFinding shape
        first = next(f for f in out if f.kind == "missing-auth")
        self.assertIsInstance(first, AuthFinding)
        self.assertEqual(first.severity, "critical")

    def test_finds_header_bypass(self):
        from bugwolf.semantic.auth_flow import AuthFlowChecker
        checker = AuthFlowChecker()
        transport = make_bypass_transport("X-Forwarded-For")
        out = checker.check_endpoint(
            "https://t/api/admin", "GET",
            transport=transport, auth_required=True,
        )
        kinds = {f.kind for f in out}
        self.assertIn("header-bypass", kinds)

    def test_no_finding_when_endpoint_already_denies(self):
        from bugwolf.semantic.auth_flow import AuthFlowChecker
        checker = AuthFlowChecker()
        transport = make_always_401_transport()
        out = checker.check_endpoint(
            "https://t/api/admin", "GET",
            transport=transport, auth_required=True,
        )
        # The checker should NOT emit a missing-auth finding because
        # the endpoint denied the unauthenticated call.
        kinds = {f.kind for f in out}
        self.assertNotIn("missing-auth", kinds)


# ---------------------------------------------------------------------------
# LLMJudge
# ---------------------------------------------------------------------------


class _StubBackend:
    name = "stub"

    def __init__(self, *a, **kw) -> None:
        pass

    def available(self) -> bool:
        return True

    def complete(self, prompt, **kw):
        from bugwolf.runtime.backends.base import CompletionResult
        return CompletionResult(
            text="VERDICT: PASS\nCONFIDENCE: 0.9\nLooks solid.",
            model="stub", dry_run=True, backend="stub",
        )

    def judge(self, prompt, *, rubric=None, model=None, **kw):
        from bugwolf.runtime.backends.base import JudgeResult
        return JudgeResult(
            score=0.9, rationale="passing", passed=True,
            model="stub", dry_run=True, backend="stub", rubric=rubric,
        )


class _RaisingBackend:
    name = "raising"

    def __init__(self, *a, **kw) -> None:
        pass

    def available(self) -> bool:
        return True

    def complete(self, *a, **kw):
        raise RuntimeError("upstream is down")

    def judge(self, *a, **kw):
        raise RuntimeError("upstream is down")


class TestLLMJudge(unittest.TestCase):

    def test_judge_finding_returns_judgeresult_with_backend(self):
        from bugwolf.semantic.llm_judge import LLMJudge, JudgeResult
        j = LLMJudge(backend=_StubBackend())
        result = j.judge_finding({
            "title": "JWT alg=none accepted",
            "endpoint": "https://t/api",
            "severity": "critical",
            "evidence": "GET /api returned 200 with alg=none token",
        })
        self.assertIsInstance(result, JudgeResult)
        self.assertIsInstance(result.passed, bool)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        self.assertTrue(result.reasoning)

    def test_judge_finding_uses_structural_fallback_without_backend(self):
        from bugwolf.semantic.llm_judge import LLMJudge, JudgeResult
        j = LLMJudge()
        result = j.judge_finding({
            "title": "Some finding",
            "endpoint": "https://t/api",
            "severity": "high",
            "evidence": "POST /api returned 200 with bearer token ABCDEFGHIJ",
            "fix": "Rotate the secret.",
        })
        self.assertIsInstance(result, JudgeResult)
        self.assertEqual(result.backend, "structural")
        self.assertGreater(result.confidence, 0.0)

    def test_judge_never_raises_on_backend_error(self):
        from bugwolf.semantic.llm_judge import LLMJudge
        j = LLMJudge(backend=_RaisingBackend())
        # Must NOT raise.
        result = j.judge_finding({
            "title": "x", "evidence": "y", "endpoint": "z",
            "severity": "high",
        })
        self.assertIsNotNone(result)
        self.assertFalse(result.passed)
        self.assertEqual(result.confidence, 0.0)
        self.assertIn("judge-error", result.reasoning)


# ---------------------------------------------------------------------------
# DiffAnalyzer
# ---------------------------------------------------------------------------


class TestDiffAnalyzer(unittest.TestCase):

    def test_diff_returns_diftresult(self):
        from bugwolf.semantic.diff_analyzer import (
            DiffAnalyzer, DiffResult, HttpObservation,
        )
        a = HttpObservation(method="GET", url="https://t/api",
                            status=200,
                            body="<html><head><title>App</title></head>"
                                 "<body>welcome user</body></html>")
        b = HttpObservation(method="GET", url="https://t/api",
                            status=403,
                            body="<html><head><title>App</title></head>"
                                 "<body>welcome user</body></html>")
        diff = DiffAnalyzer().diff(a, b)
        self.assertIsInstance(diff, DiffResult)
        self.assertEqual(diff.status_a, 200)
        self.assertEqual(diff.status_b, 403)
        self.assertEqual(diff.status_delta, 200 - 403)
        # Identical body, different status -> 1.0 similarity.
        self.assertGreaterEqual(diff.body_similarity, 0.95)
        # Signature matches: the title bar is identical.
        self.assertGreater(len(diff.signature_matches), 0)
        # interesting_diffs should call out the status-bucket change.
        self.assertTrue(any("status-bucket" in s
                            for s in diff.interesting_diffs))

    def test_diff_handles_empty_observations(self):
        from bugwolf.semantic.diff_analyzer import (
            DiffAnalyzer, HttpObservation,
        )
        diff = DiffAnalyzer().diff(HttpObservation(), HttpObservation())
        self.assertEqual(diff.status_a, 0)
        self.assertEqual(diff.status_b, 0)
        self.assertEqual(diff.status_delta, 0)
        self.assertEqual(diff.body_similarity, 1.0)


# ---------------------------------------------------------------------------
# StatefulWorkflowAnalyzer
# ---------------------------------------------------------------------------


class TestStatefulWorkflowAnalyzer(unittest.TestCase):

    def test_analyze_returns_findings(self):
        from bugwolf.semantic.stateful_workflow import (
            StatefulWorkflowAnalyzer, WorkflowFinding, WorkflowStep,
        )
        a = StatefulWorkflowAnalyzer()
        steps = [
            WorkflowStep(name="login", method="POST",
                         url="https://t/api/login",
                         headers={"Cookie": "sessionid=abc123",
                                  "X-CSRF-Token": "tok-1"},
                         body="user=victim"),
            WorkflowStep(name="payment", method="POST",
                         url="https://t/api/payment",
                         headers={"Cookie": "sessionid=abc123"},
                         body="amount=10"),
            WorkflowStep(name="confirm", method="GET",
                         url="https://t/api/confirm"),
        ]

        def transport(method, url, headers=None, body=None):
            if "payment" in (url or ""):
                return {
                    "status": 200, "headers": {}, "body": "ok",
                }
            return {"status": 200, "headers": {}, "body": "ok"}
        out = a.analyze(steps, transport)
        self.assertIsInstance(out, list)
        # The "payment" step is missing CSRF and is state-changing
        # -> must surface a finding.
        kinds = {f.kind for f in out}
        self.assertIn("missing-csrf", kinds)
        for f in out:
            self.assertIsInstance(f, WorkflowFinding)


# ---------------------------------------------------------------------------
# SemanticSearch
# ---------------------------------------------------------------------------


class TestSemanticSearch(unittest.TestCase):

    def test_find_similar_returns_ranked_results(self):
        import tempfile
        from bugwolf.semantic.semantic_search import (
            SemanticSearch, SemanticMatch,
        )
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "idor1.json").write_text(json.dumps({
                "pattern_id": "idor-1",
                "title": "IDOR via path parameter",
                "description": (
                    "Attacker can read other users' resources by "
                    "changing the path parameter. Bearer token is "
                    "not bound to the user id."
                ),
                "h100_reference": "H1:123",
                "chain_id": "chain-a",
            }))
            (tmp / "ssrf1.json").write_text(json.dumps({
                "pattern_id": "ssrf-1",
                "title": "SSRF via URL parameter",
                "description": (
                    "Server fetches attacker-supplied URLs. Internal "
                    "metadata endpoints are reachable."
                ),
                "h100_reference": "H1:456",
                "chain_id": "chain-b",
            }))
            search = SemanticSearch(tmp)
            results = search.find_similar({
                "title": "IDOR via path",
                "description": (
                    "Bearer token is not bound to the user id; "
                    "attacker can read other users' resources."
                ),
            })
            self.assertIsInstance(results, list)
            self.assertGreater(len(results), 0)
            top = results[0]
            self.assertIsInstance(top, SemanticMatch)
            self.assertEqual(top.pattern_id, "idor-1")
            # Ranking: idor-1 should beat ssrf-1.
            self.assertGreater(top.similarity, 0.0)
            self.assertLessEqual(top.similarity, 1.0)
            self.assertEqual(results[0].pattern_id, "idor-1")

    def test_find_similar_empty_corpus_returns_empty(self):
        import tempfile
        from bugwolf.semantic.semantic_search import SemanticSearch
        with tempfile.TemporaryDirectory() as td:
            search = SemanticSearch(Path(td))
            results = search.find_similar({"title": "anything"})
            self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# Cross-cutting: STUB-SAFE on broken transport
# ---------------------------------------------------------------------------


class TestSTUBSafe(unittest.TestCase):
    """No detector may raise when the transport raises."""

    def test_idor_with_raising_transport(self):
        from bugwolf.semantic.idor_detector import IDORDetector, Session
        det = IDORDetector([
            Session(name="o", headers={"Authorization": "Bearer o"}),
            Session(name="a", headers={"Authorization": "Bearer a"}),
        ])
        det.transport = lambda *a, **kw: (_ for _ in ()).throw(
            RuntimeError("boom"))
        det._transport = det.transport
        self.assertEqual(det.check_resource("https://t/api/x"), [])

    def test_business_logic_with_none_transport(self):
        from bugwolf.semantic.business_logic import BusinessLogicDetector
        det = BusinessLogicDetector()
        self.assertEqual(det.detect_race("https://t/api/x", transport=None), [])

    def test_auth_flow_with_none_transport(self):
        from bugwolf.semantic.auth_flow import AuthFlowChecker
        checker = AuthFlowChecker()
        self.assertEqual(
            checker.check_endpoint("https://t/api", "GET", transport=None),
            [],
        )

    def test_stateful_workflow_with_none_transport(self):
        from bugwolf.semantic.stateful_workflow import (
            StatefulWorkflowAnalyzer, WorkflowStep,
        )
        a = StatefulWorkflowAnalyzer()
        self.assertEqual(
            a.analyze(
                [WorkflowStep(name="x", method="GET", url="https://t/api")],
                transport=None,
            ),
            [],
        )

    def test_jwt_logic_with_empty_token(self):
        from bugwolf.semantic.jwt_logic import JWTLogicAnalyzer
        a = JWTLogicAnalyzer()
        self.assertEqual(a.analyze(""), [])
        self.assertEqual(a.analyze(None), [])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
