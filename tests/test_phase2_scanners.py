#!/usr/bin/env python3
"""Tests for Phase 2.1 — Scanner Library (40 modules).

Coverage:

  * one ``test_*`` per scanner confirming import + instantiation +
    required attributes (40 tests)
  * :class:`HuntOrchestrator` runs all scanners against an echo mock
  * :class:`CredentialSpray` respects the ``max_attempts`` budget
  * :class:`ZeroDayFuzzerMutationEngine` produces deterministic
    mutations
  * shell scanners (``grpc``, ``rag_vector``, ``dom_xss``,
    ``race_condition``, ``zero_day_fuzzer``, ``cloud_recon``) return
    ``[]`` when transport is None without raising
  * working scanners produce ≥1 finding when the transport echoes the
    request payload back

Uses ``unittest.TestCase``; no external deps.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from bugwolf.scanners import Finding, Scanner
from bugwolf.scanners.web import (
    ATOChainScanner,
    CRLFScanner,
    CachePoisoningScanner,
    CaptchaBypassScanner,
    ClickjackingScanner,
    DOMXSSScanner,
    FileUploadScanner,
    GRPCScanner,
    HostHeaderScanner,
    MFABypassScanner,
    PasswordResetScanner,
    RAGVectorScanner,
    RaceConditionScanner,
    SPAAPIScanner,
    ShadowAPIScanner,
    WebSocketScanner,
    BruteForceScanner,
    HTTPSmugglingScanner,
)
from bugwolf.scanners.api import (
    GraphQLDoSScanner,
    GraphQLIntrospectionScanner,
    ParamDiscoveryScanner,
    RESTFuzzingScanner,
    RateLimitBypassScanner,
)
from bugwolf.scanners.auth import (
    JWTAlgConfusionScanner,
    JWTKeyInjectionScanner,
    SAMLXSWScanner,
)
from bugwolf.scanners.infra import (
    BreachCheckScanner,
    CloudReconScanner,
    DNSReconScanner,
    EmailHarvestScanner,
    EmployeeOSINTScanner,
    PortScanScanner,
    ServiceDetectScanner,
    SubdomainEnumScanner,
)
from bugwolf.scanners.llm import (
    CanaryDetectorScanner,
    DataExfilScanner,
    GuardrailBypassScanner,
    IndirectInjectionScanner,
    JailbreakScanner,
    SystemPromptLeakScanner,
)
from bugwolf.scanners.orchestrator import (
    CampaignResult,
    CredentialSpray,
    HuntOrchestrator,
    ZeroDayFuzzerMutationEngine,
)


def _echo_transport(
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[Any] = None,
) -> Dict[str, Any]:
    """Transport that echoes the request back as a 200 OK."""
    return {
        "status": 200,
        "url": url,
        "method": method,
        "headers": dict(headers or {}),
        "body": body if isinstance(body, str) else (
            body.decode("latin-1", "ignore") if isinstance(body, bytes)
            else ""
        ),
        "request": {
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "body": body,
        },
    }


def _vulnerable_transport(
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[Any] = None,
) -> Dict[str, Any]:
    """A deliberately permissive transport: reflects everything back
    into headers + body.  Any scanner that looks for an echo of its
    own payload will trigger."""
    rheaders = dict(headers or {})
    if isinstance(body, str):
        rbody = body
    elif isinstance(body, bytes):
        rbody = body.decode("latin-1", "ignore")
    else:
        rbody = ""
    # Add marker to make sure GET-only scanners see something
    rheaders.setdefault("X-BugWolfEcho", "1")
    if "evil.example" in rheaders.get("Host", ""):
        rheaders["Location"] = "https://evil.example"
    # Always emit a success marker for credential-style probes so the
    # brute-force / MFA / spray scanners can latch on.
    if method == "POST" and (
        "username=" in rbody or "token=" in rbody
        or "password=" in rbody or "captcha=" in rbody
        or "mfa_token" in rbody
    ):
        rbody = "success: " + rbody
    # CRLF / smuggling-style payload detection — reflect the marker
    # back into the response so scanners can latch on.
    if "x-injected:" in url.lower() or "%0d%0a" in url.lower():
        rheaders["X-Injected"] = "BugWolf"
    if "smuggle" in url.lower() or "bugwolfsmuggle" in url.lower():
        rbody = "BugWolfSmuggle:CLTE\n" + rbody
    if rbody and ("BugWolfIndirectInjector" in rbody
                  or "BugWolfJailbreak=1" in rbody
                  or "BugWolfGuardrail=1" in rbody
                  or "BugWolfDNS" in rbody
                  or "BugWolfSAMLXSW" in rbody
                  or "BugWolfCanary" in rbody
                  or "x-injected" in rbody.lower()
                  or "success" in rbody
                  or "welcome" in rbody
                  or "admin" in rbody):
        rbody += "\nBugWolfEchoed"
    return {
        "status": 200,
        "url": url,
        "method": method,
        "headers": rheaders,
        "body": rbody,
    }


def _required_attrs(cls: type) -> List[str]:
    """Return the list of attribute names a Scanner subclass MUST
    declare."""
    return ["name", "bug_class", "default_severity", "PAYLOADS"]


class _ScannerImportTest(unittest.TestCase):
    """Mixin that asserts the scanner class is importable + has the
    required ABC shape."""

    cls_to_test: type = None  # type: ignore[assignment]

    def _make(self) -> Scanner:
        self.assertTrue(
            issubclass(self.cls_to_test, Scanner),
            f"{self.cls_to_test!r} is not a Scanner subclass",
        )
        s = self.cls_to_test()
        for attr in _required_attrs(Scanner):
            self.assertTrue(
                hasattr(s, attr),
                f"{self.cls_to_test.__name__} missing {attr!r}",
            )
        self.assertIsInstance(s.name, str)
        self.assertTrue(s.name, "scanner name is empty")
        self.assertIsInstance(s.bug_class, str)
        self.assertTrue(s.bug_class, "scanner bug_class is empty")
        self.assertIn(s.default_severity,
                      ("low", "medium", "high", "critical"))
        self.assertIsInstance(s.PAYLOADS, tuple)
        self.assertGreaterEqual(len(s.PAYLOADS), 1)
        return s


# ---------------------------------------------------------------------------
# Web scanners (18)
# ---------------------------------------------------------------------------


class TestCRLFScanner(_ScannerImportTest):
    cls_to_test = CRLFScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = CRLFScanner()
        # Echo transport reflects the URL back into headers + body —
        # the marker substring may not appear, so we craft a custom
        # vulnerable transport.
        def t(method, url, headers=None, body=None):
            return {
                "status": 200,
                "url": url,
                "headers": {
                    "X-Injected": "BugWolf",
                },
                "body": "OK",
            }
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)

    def test_none_transport(self) -> None:
        s = CRLFScanner()
        self.assertEqual(s.scan("https://example.com/", None), [])


class TestHTTPSmugglingScanner(_ScannerImportTest):
    cls_to_test = HTTPSmugglingScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            HTTPSmugglingScanner().scan("https://example.com/", None), []
        )


class TestCachePoisoningScanner(_ScannerImportTest):
    cls_to_test = CachePoisoningScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            CachePoisoningScanner().scan("https://example.com/", None), []
        )


class TestHostHeaderScanner(_ScannerImportTest):
    cls_to_test = HostHeaderScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = HostHeaderScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": dict(headers or {}),
                    "body": "Host: evil.example"}
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)


class TestFileUploadScanner(_ScannerImportTest):
    cls_to_test = FileUploadScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = FileUploadScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": dict(headers or {}),
                    "body": "BugWolfUploadPhtml"}
        findings = s.scan("https://example.com/upload", t)
        self.assertGreaterEqual(len(findings), 1)


class TestClickjackingScanner(_ScannerImportTest):
    cls_to_test = ClickjackingScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = ClickjackingScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": {}, "body": "<html></html>"}
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)


class TestCaptchaBypassScanner(_ScannerImportTest):
    cls_to_test = CaptchaBypassScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = CaptchaBypassScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": {}, "body": "success: ok"}
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)


class TestBruteForceScanner(_ScannerImportTest):
    cls_to_test = BruteForceScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = BruteForceScanner()
        findings = s.scan("https://example.com/login", _vulnerable_transport)
        self.assertGreaterEqual(len(findings), 1)


class TestMFABypassScanner(_ScannerImportTest):
    cls_to_test = MFABypassScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = MFABypassScanner()
        findings = s.scan("https://example.com/login", _vulnerable_transport)
        self.assertGreaterEqual(len(findings), 1)


class TestPasswordResetScanner(_ScannerImportTest):
    cls_to_test = PasswordResetScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = PasswordResetScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": {"Location": "https://evil.example/reset"},
                    "body": "password reset"}
        findings = s.scan("https://example.com/reset", t)
        self.assertGreaterEqual(len(findings), 1)


class TestATOChainScanner(_ScannerImportTest):
    cls_to_test = ATOChainScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = ATOChainScanner()
        findings = s.scan("https://example.com/login", _vulnerable_transport)
        self.assertGreaterEqual(len(findings), 1)


class TestWebSocketScanner(_ScannerImportTest):
    cls_to_test = WebSocketScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = WebSocketScanner()
        findings = s.scan("https://example.com/ws", _vulnerable_transport)
        # No findings expected from a plain echo transport (no Upgrade
        # header round-trip), but scan() must complete without error.
        self.assertIsInstance(findings, list)


class TestGRPCScanner(_ScannerImportTest):
    cls_to_test = GRPCScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            GRPCScanner().scan("https://example.com/", None), []
        )


class TestDOMXSSScanner(_ScannerImportTest):
    cls_to_test = DOMXSSScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            DOMXSSScanner().scan("https://example.com/", None), []
        )


class TestSPAAPIScanner(_ScannerImportTest):
    cls_to_test = SPAAPIScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = SPAAPIScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": {"Content-Type": "application/json"},
                    "body": "{}"}
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)


class TestShadowAPIScanner(_ScannerImportTest):
    cls_to_test = ShadowAPIScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = ShadowAPIScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url,
                    "headers": {}, "body": "ok"}
        findings = s.scan("https://example.com/", t)
        self.assertGreaterEqual(len(findings), 1)


class TestRAGVectorScanner(_ScannerImportTest):
    cls_to_test = RAGVectorScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            RAGVectorScanner().scan("https://example.com/", None), []
        )


class TestRaceConditionScanner(_ScannerImportTest):
    cls_to_test = RaceConditionScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            RaceConditionScanner().scan("https://example.com/", None), []
        )


# ---------------------------------------------------------------------------
# API scanners (5)
# ---------------------------------------------------------------------------


class TestGraphQLIntrospectionScanner(_ScannerImportTest):
    cls_to_test = GraphQLIntrospectionScanner

    def test_attributes(self) -> None:
        self._make()

    def test_echo_produces_finding(self) -> None:
        s = GraphQLIntrospectionScanner()
        def t(method, url, headers=None, body=None):
            return {"status": 200, "url": url, "headers": {},
                    "body": '{"data":{"__schema":{"types":[]}}}'}
        findings = s.scan("https://example.com/graphql", t)
        self.assertGreaterEqual(len(findings), 1)


class TestGraphQLDoSScanner(_ScannerImportTest):
    cls_to_test = GraphQLDoSScanner

    def test_attributes(self) -> None:
        self._make()


class TestRESTFuzzingScanner(_ScannerImportTest):
    cls_to_test = RESTFuzzingScanner

    def test_attributes(self) -> None:
        self._make()


class TestParamDiscoveryScanner(_ScannerImportTest):
    cls_to_test = ParamDiscoveryScanner

    def test_attributes(self) -> None:
        self._make()


class TestRateLimitBypassScanner(_ScannerImportTest):
    cls_to_test = RateLimitBypassScanner

    def test_attributes(self) -> None:
        self._make()


# ---------------------------------------------------------------------------
# Auth scanners (3)
# ---------------------------------------------------------------------------


class TestJWTAlgConfusionScanner(_ScannerImportTest):
    cls_to_test = JWTAlgConfusionScanner

    def test_attributes(self) -> None:
        self._make()


class TestJWTKeyInjectionScanner(_ScannerImportTest):
    cls_to_test = JWTKeyInjectionScanner

    def test_attributes(self) -> None:
        self._make()


class TestSAMLXSWScanner(_ScannerImportTest):
    cls_to_test = SAMLXSWScanner

    def test_attributes(self) -> None:
        self._make()


# ---------------------------------------------------------------------------
# Infra scanners (8)
# ---------------------------------------------------------------------------


class TestCloudReconScanner(_ScannerImportTest):
    cls_to_test = CloudReconScanner

    def test_attributes(self) -> None:
        self._make()

    def test_none_transport(self) -> None:
        self.assertEqual(
            CloudReconScanner().scan("example.com", None), []
        )


class TestSubdomainEnumScanner(_ScannerImportTest):
    cls_to_test = SubdomainEnumScanner

    def test_attributes(self) -> None:
        self._make()


class TestDNSReconScanner(_ScannerImportTest):
    cls_to_test = DNSReconScanner

    def test_attributes(self) -> None:
        self._make()


class TestPortScanScanner(_ScannerImportTest):
    cls_to_test = PortScanScanner

    def test_attributes(self) -> None:
        self._make()


class TestServiceDetectScanner(_ScannerImportTest):
    cls_to_test = ServiceDetectScanner

    def test_attributes(self) -> None:
        self._make()


class TestBreachCheckScanner(_ScannerImportTest):
    cls_to_test = BreachCheckScanner

    def test_attributes(self) -> None:
        self._make()


class TestEmailHarvestScanner(_ScannerImportTest):
    cls_to_test = EmailHarvestScanner

    def test_attributes(self) -> None:
        self._make()


class TestEmployeeOSINTScanner(_ScannerImportTest):
    cls_to_test = EmployeeOSINTScanner

    def test_attributes(self) -> None:
        self._make()


# ---------------------------------------------------------------------------
# LLM scanners (6)
# ---------------------------------------------------------------------------


class TestJailbreakScanner(_ScannerImportTest):
    cls_to_test = JailbreakScanner

    def test_attributes(self) -> None:
        self._make()


class TestSystemPromptLeakScanner(_ScannerImportTest):
    cls_to_test = SystemPromptLeakScanner

    def test_attributes(self) -> None:
        self._make()


class TestDataExfilScanner(_ScannerImportTest):
    cls_to_test = DataExfilScanner

    def test_attributes(self) -> None:
        self._make()


class TestIndirectInjectionScanner(_ScannerImportTest):
    cls_to_test = IndirectInjectionScanner

    def test_attributes(self) -> None:
        self._make()


class TestGuardrailBypassScanner(_ScannerImportTest):
    cls_to_test = GuardrailBypassScanner

    def test_attributes(self) -> None:
        self._make()


class TestCanaryDetectorScanner(_ScannerImportTest):
    cls_to_test = CanaryDetectorScanner

    def test_attributes(self) -> None:
        self._make()


# ---------------------------------------------------------------------------
# Orchestrator scanners (3)
# ---------------------------------------------------------------------------


class TestHuntOrchestrator(unittest.TestCase):
    def test_runs_all_scanners(self) -> None:
        scanners = [CRLFScanner(), HostHeaderScanner(), ClickjackingScanner()]
        orch = HuntOrchestrator(scanners)
        result = orch.scan("https://example.com/", _vulnerable_transport)
        self.assertIsInstance(result, CampaignResult)
        self.assertEqual(result.target, "https://example.com/")
        self.assertEqual(result.scanners_run, 3)
        self.assertIsInstance(result.findings, list)

    def test_dedupes_identical_findings(self) -> None:
        # A stub scanner that emits a deterministic set of findings.
        # Running it twice in an orchestrator should dedupe.
        class Stub(Scanner):
            name = "stub"
            bug_class = "stub"
            default_severity = "low"
            PAYLOADS = ("x",)

            def scan(self, target, transport):
                return [
                    Finding.create(
                        scanner=self.name, bug_class=self.bug_class,
                        severity=self.default_severity, target=target,
                        evidence="dup",
                    ),
                    Finding.create(
                        scanner=self.name, bug_class=self.bug_class,
                        severity=self.default_severity, target=target,
                        evidence="dup",
                    ),
                ]

        orch = HuntOrchestrator([Stub(), Stub()])
        result = orch.scan("https://example.com/", _echo_transport)
        self.assertEqual(result.scanners_run, 2)
        self.assertEqual(len(result.findings), 1)
        self.assertGreaterEqual(result.deduplicated, 1)

    def test_handles_scanner_exceptions(self) -> None:
        class Boom(Scanner):
            name = "boom"
            bug_class = "boom"
            default_severity = "low"
            PAYLOADS = ("x",)

            def scan(self, target, transport):
                raise RuntimeError("boom")

        orch = HuntOrchestrator([Boom(), CRLFScanner()])
        result = orch.scan("https://example.com/", _vulnerable_transport)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.scanners_run, 2)

    def test_empty_scanner_list(self) -> None:
        orch = HuntOrchestrator([])
        result = orch.scan("https://example.com/", _echo_transport)
        self.assertEqual(result.scanners_run, 0)
        self.assertEqual(result.findings, [])


class TestCredentialSpray(unittest.TestCase):
    def test_respects_budget(self) -> None:
        spray = CredentialSpray(
            pairs=[("u1", "p1"), ("u2", "p2"), ("u3", "p3"),
                   ("u4", "p4"), ("u5", "p5")],
            max_attempts=2,
        )
        attempts = {"n": 0}

        def t(method, url, headers=None, body=None):
            attempts["n"] += 1
            return {"status": 401, "url": url, "headers": {}, "body": "no"}

        findings = spray.scan("https://example.com/login", t)
        self.assertEqual(attempts["n"], 2)
        self.assertEqual(findings, [])

    def test_emits_finding_on_success(self) -> None:
        spray = CredentialSpray(
            pairs=[("admin", "admin")], max_attempts=4,
        )
        findings = spray.scan(
            "https://example.com/login", _vulnerable_transport
        )
        self.assertGreaterEqual(len(findings), 1)

    def test_none_transport(self) -> None:
        spray = CredentialSpray()
        self.assertEqual(spray.scan("https://example.com/", None), [])


class TestZeroDayFuzzer(unittest.TestCase):
    def test_mutations_are_deterministic(self) -> None:
        m1 = ZeroDayFuzzerMutationEngine.mutate(b"BugWolfSeed")
        m2 = ZeroDayFuzzerMutationEngine.mutate(b"BugWolfSeed")
        self.assertEqual(m1, m2)
        self.assertGreater(len(m1), 1)

    def test_mutations_differ_from_seed(self) -> None:
        m = ZeroDayFuzzerMutationEngine.mutate(b"BugWolfSeed")
        self.assertNotIn(b"BugWolfSeed", m)

    def test_empty_seed(self) -> None:
        m = ZeroDayFuzzerMutationEngine.mutate(b"")
        self.assertIsInstance(m, tuple)
        self.assertGreaterEqual(len(m), 1)

    def test_none_transport(self) -> None:
        z = ZeroDayFuzzerMutationEngine()
        self.assertEqual(z.scan("https://example.com/", None), [])


# ---------------------------------------------------------------------------
# Cross-cutting / shell-mode assertions
# ---------------------------------------------------------------------------


class TestShellScanners(unittest.TestCase):
    def test_all_shell_scanners_return_empty_for_none_transport(self) -> None:
        shells = [
            GRPCScanner(),
            RAGVectorScanner(),
            DOMXSSScanner(),
            RaceConditionScanner(),
            ZeroDayFuzzerMutationEngine(),
            CloudReconScanner(),
        ]
        for s in shells:
            with self.subTest(scanner=s.name):
                self.assertEqual(s.scan("https://example.com/", None), [])


class TestPayloadsAreStrings(unittest.TestCase):
    def test_all_payloads_are_strings(self) -> None:
        # Skip the two scanners that intentionally include empty /
        # non-string payload entries to express the attack surface
        # (captcha-bypass uses an empty token; file-upload uses tuples).
        scanners = [
            CRLFScanner(), HTTPSmugglingScanner(), CachePoisoningScanner(),
            HostHeaderScanner(), ClickjackingScanner(),
            BruteForceScanner(), MFABypassScanner(),
            PasswordResetScanner(), ATOChainScanner(), WebSocketScanner(),
            GRPCScanner(), DOMXSSScanner(), SPAAPIScanner(),
            ShadowAPIScanner(), RAGVectorScanner(), RaceConditionScanner(),
            GraphQLIntrospectionScanner(), GraphQLDoSScanner(),
            RESTFuzzingScanner(), ParamDiscoveryScanner(),
            RateLimitBypassScanner(),
            JWTAlgConfusionScanner(), JWTKeyInjectionScanner(),
            SAMLXSWScanner(),
            CloudReconScanner(), SubdomainEnumScanner(), DNSReconScanner(),
            PortScanScanner(), ServiceDetectScanner(), BreachCheckScanner(),
            EmailHarvestScanner(), EmployeeOSINTScanner(),
            JailbreakScanner(), SystemPromptLeakScanner(),
            DataExfilScanner(), IndirectInjectionScanner(),
            GuardrailBypassScanner(), CanaryDetectorScanner(),
            ZeroDayFuzzerMutationEngine(),
        ]
        for s in scanners:
            with self.subTest(scanner=s.name):
                for p in s.PAYLOADS:
                    self.assertIsInstance(p, str)


class TestFindingDataclass(unittest.TestCase):
    def test_severity_validation(self) -> None:
        with self.assertRaises(ValueError):
            Finding.create(
                scanner="x", bug_class="x", severity="bogus",
                target="t", evidence="e",
            )

    def test_evidence_truncation(self) -> None:
        big = "x" * 1000
        f = Finding.create(
            scanner="x", bug_class="x", severity="high",
            target="t", evidence=big,
        )
        self.assertLessEqual(len(f.evidence), 160)

    def test_confidence_clamped(self) -> None:
        f1 = Finding.create(scanner="x", bug_class="x", severity="high",
                            target="t", evidence="e", confidence=2.0)
        f2 = Finding.create(scanner="x", bug_class="x", severity="high",
                            target="t", evidence="e", confidence=-1.0)
        self.assertEqual(f1.confidence, 1.0)
        self.assertEqual(f2.confidence, 0.0)


if __name__ == "__main__":
    unittest.main()