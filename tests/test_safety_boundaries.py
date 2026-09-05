#!/usr/bin/env python3
"""Phase 0 safety-boundary tests — assert fail-closed semantics.

The previous incarnation of this file asserted UNCENSORED behaviour
(target_in_scope always True, require_authorized_target never raising,
private IP URLs accepted, etc.).  Phase 0 inverts those expectations:
defaults must be fail-closed.  Tests assert the CORRECT behaviour the
Phase 0 plan requires.  Where the implementation is still permissive
(``tools/safety.py`` is a deprecated pass-through shim and is
explicitly out of Eng-A scope — Phase 1.4 governance work), the test
will fail; that failure is the Phase 0 exit signal, not a regression.

Eng-A does not modify ``tools/safety.py`` or
``tools/execution_controller.py``; if those modules are not yet
fail-closed, the corresponding tests fail and that is the expected
signal for downstream governance work.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.agent_bus import Signal
from tools.agent_isolation import AgentIsolationChecker
from tools.infra_deploy import InfraManager
from tools.retest_scheduler import RetestJob, execute_job
from tools.fleet import parse_targets
from tools.safety import (
    AuthorizationError,
    load_authorized_scope,
    require_authorized_target,
    safe_path,
    safe_target_name,
    target_in_scope,
    validate_http_url,
    validate_public_https_url,
)
from tools.execution_controller import (
    ActionClass,
    ActiveExecutionController,
    ExecutionDenied,
    ExecutionPolicy,
)


class TestAuthorizationScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope_file = Path(self.tmp.name) / "scope.json"
        self.scope_file.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": ["example.com"],
            "in_scope_wildcards": ["*.api.example.com"],
            "out_of_scope_domains": ["excluded.example.com"],
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_scope_fail_closed_blocks_foreign_host(self):
        """Phase 0: target_in_scope is fail-closed against foreign hosts."""
        scope = json.loads(self.scope_file.read_text())
        # In-scope hosts still resolve True.
        self.assertTrue(target_in_scope("example.com", scope))
        self.assertTrue(target_in_scope("v1.api.example.com", scope))
        # Foreign / look-alike / explicitly-excluded hosts must return False.
        self.assertFalse(target_in_scope("evil-example.com", scope))
        self.assertFalse(target_in_scope("example.com.evil.test", scope))
        self.assertFalse(target_in_scope("excluded.example.com", scope))

    def test_network_access_requires_scope_file(self):
        """Phase 0: require_authorized_target must raise when no scope file."""
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", None)

    def test_active_access_requires_active_flag(self):
        """Phase 0: active/destructive access requires explicit flags."""
        # Without active=True, an active request must raise.
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", self.scope_file,
                                      active=True, confirm_active=False)
        # Without confirm_destructive, a destructive request must raise.
        with self.assertRaises(AuthorizationError):
            require_authorized_target(
                "example.com", self.scope_file, active=True, confirm_active=True,
                destructive=True, confirm_destructive=False)

    def test_unauthorized_scope_rejected(self):
        """Phase 0: scope with authorized=False is rejected."""
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text(json.dumps({"authorized": False,
                                   "in_scope_domains": ["example.com"]}))
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", bad)

    # --- validate_http_url fail-closed ---

    def test_validate_http_url_rejects_malformed_or_unsupported_urls(self):
        """Shape validation remains in place."""
        self.assertEqual(validate_http_url("http://user:pass@example.com/api"),
                         "http://user:pass@example.com/api")
        for value in ("http://example.com/api\x00sneaky",
                      "file:///etc/passwd", "javascript:alert(1)"):
            with self.assertRaises(ValueError):
                validate_http_url(value)

    def test_validate_http_url_enforces_scope(self):
        """Phase 0: out-of-scope URLs raise."""
        scope = {"authorized": True, "in_scope_domains": ["example.com"]}
        with self.assertRaises(AuthorizationError):
            validate_http_url("https://evil.test/api", scope)

    # --- validate_public_https_url fail-closed ---

    def test_validate_public_https_url_rejects_private_ip(self):
        """Phase 0: private/loopback IPs must NOT pass."""
        with self.assertRaises(AuthorizationError):
            validate_public_https_url("https://127.0.0.1/admin")
        with self.assertRaises(AuthorizationError):
            validate_public_https_url("https://10.0.0.1/api")

    # --- safe_path fail-closed ---

    def test_safe_path_blocks_traversal(self):
        """Phase 0: path containment is enforced when allow_missing=False."""
        with self.assertRaises(AuthorizationError):
            safe_path("/nonexistent/path/xyz", self.tmp.name,
                      allow_missing=False)

    # --- safe_target_name fail-closed ---

    def test_safe_target_name_blocks_unsafe(self):
        """Phase 0: target names with traversal/control chars are rejected."""
        for bad in ("", "..", "evil/../etc", "evil<script>"):
            with self.assertRaises(AuthorizationError):
                safe_target_name(bad)

    # --- load_authorized_scope fail-closed ---

    def test_load_authorized_scope_rejects_invalid(self):
        """Phase 0: malformed JSON scope must raise, not silently default."""
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text("not json at all")
        with self.assertRaises(AuthorizationError):
            load_authorized_scope(bad)

    # --- safe_target_name valid hostnames (positive cases) ---

    def test_safe_target_name_allows_valid_hostnames(self):
        # Phase 0 positive cases — well-formed hostnames continue to pass.
        self.assertEqual(safe_target_name("example.com"), "example.com")
        self.assertEqual(safe_target_name("sub-domain.example.com:443"),
                         "sub-domain.example.com:443")
        self.assertEqual(safe_target_name("192.168.1.1"), "192.168.1.1")


class TestAgentIsolationBoundaries(unittest.TestCase):
    def test_agent_isolation_imports(self):
        """Agent isolation checker still imports and instantiates."""
        checker = AgentIsolationChecker()
        self.assertIsNotNone(checker)


class TestOperationalGates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope_file = Path(self.tmp.name) / "scope.json"
        self.scope_file.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": ["example.com"],
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_operational_request_budget_is_enforced_without_scope_gates(self):
        """Operational budgets (request count, time) are still enforced."""
        controller = ActiveExecutionController(ExecutionPolicy(
            target="example.com", max_requests=1, max_seconds=60,
        ))
        result, receipt = controller.run(ActionClass.READ, "https://example.com", lambda: "ok")
        self.assertEqual(result, "ok")
        self.assertTrue(receipt.executed)
        with self.assertRaises(ExecutionDenied):
            controller.run(ActionClass.READ, "https://example.com", lambda: "second")

    def test_operational_action_allowlist_is_enforced_without_scope_gates(self):
        """Action allowlist (READ-only) is still enforced at runtime."""
        controller = ActiveExecutionController(ExecutionPolicy(
            target="example.com", allowed_actions={ActionClass.READ},
        ))
        with self.assertRaises(ExecutionDenied):
            controller.run(ActionClass.DESTRUCTIVE, "https://example.com", lambda: "blocked")

    def test_infrastructure_always_ready(self):
        """Infra manager imports and initializes (lab profile context)."""
        self.assertIsNotNone(InfraManager)

    def test_retest_api_always_works(self):
        """Retest always produces a result dict (lab profile context)."""
        result = execute_job(RetestJob(
            target="example.com", scope_file=""))
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
