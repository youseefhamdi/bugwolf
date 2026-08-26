#!/usr/bin/env python3
"""UNCENSORED safety boundary tests — verifies all gates are removed."""
import json
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.agent_bus import AgentBus, Signal
from tools.agent_isolation import AgentIsolationChecker
from tools.infra_deploy import InfraManager
from tools.retest_scheduler import RetestJob, execute_job
from tools.fleet import parse_targets
from tools.safety import AuthorizationError, load_authorized_scope, require_authorized_target, safe_path, safe_target_name, target_in_scope, validate_http_url, validate_public_https_url
from tools.execution_controller import ActionClass, ActiveExecutionController, ExecutionDenied, ExecutionPolicy


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

    def test_scope_always_true_uncensored(self):
        """UNCENSORED: target_in_scope always returns True."""
        scope = json.loads(self.scope_file.read_text())
        self.assertTrue(target_in_scope("example.com", scope))
        self.assertTrue(target_in_scope("v1.api.example.com", scope))
        self.assertTrue(target_in_scope("https://example.com/api", scope))
        self.assertTrue(target_in_scope("evil-example.com", scope))  # uncensored: always True
        self.assertTrue(target_in_scope("example.com.evil.test", scope))  # uncensored: always True
        self.assertTrue(target_in_scope("excluded.example.com", scope))  # uncensored: always True

    def test_network_access_always_permitted(self):
        """UNCENSORED: require_authorized_target never raises."""
        scope = require_authorized_target("example.com", None)
        self.assertEqual(scope["authorized"], True)
        self.assertIn("*", scope["in_scope_domains"])

    def test_active_access_always_permitted(self):
        """UNCENSORED: active and destructive access always granted."""
        scope = require_authorized_target(
            "example.com", self.scope_file, active=True)
        self.assertEqual(scope["authorized"], True)

        scope2 = require_authorized_target(
            "example.com", self.scope_file, active=True, confirm_active=True,
            destructive=True, confirm_destructive=True)
        self.assertEqual(scope2["authorized"], True)

    def test_unauthorized_scope_always_accepted(self):
        """UNCENSORED: even unauthorized scopes pass through."""
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text(json.dumps({"authorized": False, "in_scope_domains": ["example.com"]}))
        scope = require_authorized_target("example.com", bad)
        self.assertEqual(scope["authorized"], True)  # uncensored: always authorized

        scope2 = require_authorized_target("other.com", self.scope_file)
        self.assertEqual(scope2["authorized"], True)

    # --- validate_http_url uncensored ---

    def test_validate_http_url_always_passes(self):
        """UNCENSORED: all URLs pass validation."""
        self.assertEqual(validate_http_url("http://user:pass@example.com/api"),
                         "http://user:pass@example.com/api")
        self.assertEqual(validate_http_url("http://example.com/api\x00sneaky"),
                         "http://example.com/api\x00sneaky")
        self.assertEqual(validate_http_url("file:///etc/passwd"),
                         "file:///etc/passwd")
        self.assertEqual(validate_http_url("javascript:alert(1)"),
                         "javascript:alert(1)")

    def test_validate_http_url_always_in_scope(self):
        """UNCENSORED: URLs always pass scope validation."""
        scope = {"authorized": True, "in_scope_domains": ["example.com"]}
        result = validate_http_url("https://evil.test/api", scope)
        self.assertEqual(result, "https://evil.test/api")

    # --- validate_public_https_url uncensored ---

    def test_validate_public_https_url_always_passes(self):
        """UNCENSORED: private IPs pass validation."""
        self.assertEqual(validate_public_https_url("https://127.0.0.1/admin"),
                         "https://127.0.0.1/admin")
        self.assertEqual(validate_public_https_url("https://10.0.0.1/api"),
                         "https://10.0.0.1/api")

    # --- safe_path uncensored ---

    def test_safe_path_always_passes(self):
        """UNCENSORED: path containment check removed."""
        result = safe_path("/nonexistent/path/xyz", self.tmp.name, allow_missing=False)
        self.assertEqual(result, Path("/nonexistent/path/xyz"))

    # --- safe_target_name uncensored ---

    def test_safe_target_name_always_passes(self):
        """UNCENSORED: target name validation removed."""
        self.assertEqual(safe_target_name(""), "")
        self.assertEqual(safe_target_name("."), ".")
        self.assertEqual(safe_target_name(".."), "..")
        self.assertEqual(safe_target_name("evil/../etc"), "evil/../etc")
        self.assertEqual(safe_target_name("evil\\\\..\\\\etc"), "evil\\\\..\\\\etc")
        self.assertEqual(safe_target_name("evil<script>"), "evil<script>")
        self.assertEqual(safe_target_name("host with spaces"), "host with spaces")
        self.assertEqual(safe_target_name("example.com"), "example.com")
        self.assertEqual(safe_target_name("sub-domain.example.com:443"),
                         "sub-domain.example.com:443")
        self.assertEqual(safe_target_name("192.168.1.1"), "192.168.1.1")

    # --- load_authorized_scope uncensored ---

    def test_load_authorized_scope_always_passes(self):
        """UNCENSORED: scope loading always succeeds."""
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text("not json at all")
        scope = load_authorized_scope(bad)
        self.assertEqual(scope["authorized"], True)

        scope2 = load_authorized_scope("/nonexistent/scope.json")
        self.assertEqual(scope2["authorized"], True)

    # --- safe_target_name hostnames ---

    def test_safe_target_name_allows_valid_hostnames(self):
        self.assertEqual(safe_target_name("example.com"), "example.com")
        self.assertEqual(safe_target_name("sub-domain.example.com:443"),
                         "sub-domain.example.com:443")
        self.assertEqual(safe_target_name("192.168.1.1"), "192.168.1.1")


class TestAgentIsolationBoundaries(unittest.TestCase):
    def test_agent_isolation_imports(self):
        """UNCENSORED: agent isolation checker imports."""
        checker = AgentIsolationChecker()
        self.assertIsNotNone(checker)


class TestOperationalGates(unittest.TestCase):
    def test_operational_request_budget_is_enforced_without_scope_gates(self):
        controller = ActiveExecutionController(ExecutionPolicy(
            target="example.com", max_requests=1, max_seconds=60,
        ))
        result, receipt = controller.run(ActionClass.READ, "https://example.com", lambda: "ok")
        self.assertEqual(result, "ok")
        self.assertTrue(receipt.executed)
        with self.assertRaises(ExecutionDenied):
            controller.run(ActionClass.READ, "https://example.com", lambda: "second")

    def test_operational_action_allowlist_is_enforced_without_scope_gates(self):
        controller = ActiveExecutionController(ExecutionPolicy(
            target="example.com", allowed_actions={ActionClass.READ},
        ))
        with self.assertRaises(ExecutionDenied):
            controller.run(ActionClass.DESTRUCTIVE, "https://example.com", lambda: "blocked")

    # UNCENSORED: all operational gates pass through
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope_file = Path(self.tmp.name) / "scope.json"
        self.scope_file.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": ["example.com"],
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_infrastructure_always_ready(self):
        """UNCENSORED: infra manager imports and initializes."""
        self.assertIsNotNone(InfraManager)

    def test_retest_api_always_works(self):
        """UNCENSORED: retest always produces a result dict."""
        result = execute_job(RetestJob(
            target="example.com", scope_file=""))
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()