#!/usr/bin/env python3
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

    def test_scope_matches_exact_and_wildcard_hosts(self):
        scope = json.loads(self.scope_file.read_text())
        self.assertTrue(target_in_scope("example.com", scope))
        self.assertTrue(target_in_scope("v1.api.example.com", scope))
        self.assertTrue(target_in_scope("https://example.com/api", scope))
        self.assertFalse(target_in_scope("evil-example.com", scope))
        self.assertFalse(target_in_scope("example.com.evil.test", scope))
        self.assertFalse(target_in_scope("excluded.example.com", scope))

    def test_network_access_requires_scope_file(self):
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", None)

    def test_active_access_requires_explicit_confirmation(self):
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", self.scope_file, active=True)
        require_authorized_target(
            "example.com", self.scope_file, active=True, confirm_active=True)

    def test_unauthorized_or_out_of_scope_targets_are_rejected(self):
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text(json.dumps({"authorized": False, "in_scope_domains": ["example.com"]}))
        with self.assertRaises(AuthorizationError):
            require_authorized_target("example.com", bad)
        with self.assertRaises(AuthorizationError):
            require_authorized_target("other.com", self.scope_file)

    # --- validate_http_url gaps ---

    def test_validate_http_url_rejects_credentials_and_control_characters(self):
        with self.assertRaises(AuthorizationError):
            validate_http_url("http://user:pass@example.com/api")
        with self.assertRaises(AuthorizationError):
            validate_http_url("http://example.com/api\x00sneaky")

    def test_validate_http_url_rejects_non_http_schemes(self):
        with self.assertRaises(AuthorizationError):
            validate_http_url("file:///etc/passwd")
        with self.assertRaises(AuthorizationError):
            validate_http_url("javascript:alert(1)")

    def test_validate_http_url_rejects_out_of_scope_url_when_scope_is_supplied(self):
        scope = {"authorized": True, "in_scope_domains": ["example.com"]}
        with self.assertRaises(AuthorizationError):
            validate_http_url("https://evil.test/api", scope)

    # --- validate_public_https_url gap ---

    def test_validate_public_https_url_rejects_private_ips(self):
        with self.assertRaises(AuthorizationError):
            validate_public_https_url("https://127.0.0.1/admin")
        with self.assertRaises(AuthorizationError):
            validate_public_https_url("https://10.0.0.1/api")

    # --- safe_path gap ---

    def test_safe_path_rejects_missing_file_when_allow_missing_is_false(self):
        with self.assertRaises(AuthorizationError):
            safe_path("/nonexistent/path/xyz", self.tmp.name, allow_missing=False)

    # --- safe_target_name gaps ---

    def test_safe_target_name_rejects_dot_dot_and_null(self):
        with self.assertRaises(AuthorizationError):
            safe_target_name("")
        with self.assertRaises(AuthorizationError):
            safe_target_name(".")
        with self.assertRaises(AuthorizationError):
            safe_target_name("..")

    def test_safe_target_name_rejects_slashes_and_backslashes(self):
        with self.assertRaises(AuthorizationError):
            safe_target_name("evil/../etc")
        with self.assertRaises(AuthorizationError):
            safe_target_name("evil\\..\\etc")

    def test_safe_target_name_rejects_unsupported_characters(self):
        with self.assertRaises(AuthorizationError):
            safe_target_name("evil<script>")
        with self.assertRaises(AuthorizationError):
            safe_target_name("host with spaces")

    def test_safe_target_name_allows_valid_hostnames(self):
        self.assertEqual(safe_target_name("example.com"), "example.com")
        self.assertEqual(safe_target_name("sub-domain.example.com:443"),
                         "sub-domain.example.com:443")
        self.assertEqual(safe_target_name("192.168.1.1"), "192.168.1.1")

    # --- load_authorized_scope gaps ---

    def test_load_authorized_scope_rejects_non_json_and_missing_files(self):
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text("not json at all")
        with self.assertRaises(AuthorizationError):
            load_authorized_scope(bad)
        with self.assertRaises(AuthorizationError):
            load_authorized_scope("/nonexistent/scope.json")


class TestAgentIsolationBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope_file = Path(self.tmp.name) / "scope.json"
        self.scope_file.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": ["example.com"],
            "out_of_scope_domains": ["excluded.example.com"],
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_high_domain_drift_blocks_a_finding(self):
        checker = AgentIsolationChecker("example.com", str(self.scope_file))
        report = checker.check_finding(
            "web-api-agent",
            {"bug_class": "business-logic", "endpoint": "https://example.com/api"},
        )
        self.assertFalse(report.passed)

    def test_active_payload_without_scope_is_blocked(self):
        checker = AgentIsolationChecker("example.com")
        report = checker.check_finding(
            "web-api-agent",
            {"bug_class": "sqli", "endpoint": "https://example.com/api",
             "payload": "probe"},
        )
        self.assertFalse(report.passed)
        self.assertTrue(any(v.check_type == "execution" for v in report.violations))
        self.assertTrue(any(v.check_type == "scope" for v in report.violations))

    def test_scope_check_uses_host_boundaries(self):
        checker = AgentIsolationChecker("example.com", str(self.scope_file))
        report = checker.check_finding(
            "web-api-agent",
            {"bug_class": "sqli", "endpoint": "https://example.com.evil.test/api"},
        )
        self.assertFalse(report.passed)
        self.assertTrue(any(v.check_type == "scope" for v in report.violations))


class TestOperationalGates(unittest.TestCase):
    def test_infrastructure_api_requires_authorized_scope(self):
        with self.assertRaises(AuthorizationError):
            InfraManager().start_callback_server(port=0)

    def test_retest_api_refuses_unscoped_job_before_subprocess(self):
        result = execute_job(RetestJob(target="example.com", trigger="periodic"))
        self.assertFalse(result["success"])
        self.assertIn("Authorization denied", result["error"])

    def test_fleet_parser_preserves_host_port(self):
        targets = parse_targets("example.com:8443,api.example.com")
        self.assertEqual([target.name for target in targets],
                         ["example.com:8443", "api.example.com"])


class TestAgentBusBroadcasts(unittest.TestCase):
    def setUp(self):
        self.target = "bus-test-" + uuid.uuid4().hex[:10]
        self.path = Path("state/signals") / self.target

    def tearDown(self):
        shutil.rmtree(self.path, ignore_errors=True)

    def test_target_path_rejects_traversal(self):
        with self.assertRaises(AuthorizationError):
            AgentBus("../outside")

    def test_broadcast_is_delivered_once_to_each_agent(self):
        bus = AgentBus(self.target)
        bus.send(Signal(
            signal_type="alert", from_agent="counter-intelligence-agent",
            to_agents=["*"], priority="critical",
            signal_data={"action": "stop"},
        ))
        self.assertEqual(len(bus.receive("agent-a")), 1)
        self.assertEqual(len(bus.receive("agent-b")), 1)
        self.assertEqual(bus.receive("agent-a"), [])


if __name__ == "__main__":
    unittest.main()
