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
from tools.safety import AuthorizationError, require_authorized_target, target_in_scope


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
