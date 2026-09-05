#!/usr/bin/env python3
"""Tests for tools/runtime/domain_adapter.py (v1.24.1+)."""
import json
import sys
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime import domain_adapter
from tools.runtime.domain_adapter import (
    DOMAIN_PROBES, dispatch_domain_probe, coverage_report,
    _probe_jwt_forgery, _probe_oauth_flow, _probe_ato_chain,
    _probe_bopla, _probe_graphql_batch, _probe_rag_poisoning,
    _probe_deep_link, _probe_mobile_policy, _probe_llm_contract_triage,
    _probe_price_manipulation, _probe_http_smuggling, _probe_parser_differential,
)


class DomainAdapterCoverage(unittest.TestCase):
    """All 12 previously-orphan domain modules must be exposed."""

    def test_all_12_probes_registered(self):
        expected = {
            "auth.jwt", "auth.oauth", "auth.ato",
            "api.bopla", "api.graphql_batch",
            "llm.rag",
            "mobile.deep_link", "mobile.policy",
            "sc.triage", "sc.price",
            "web.smuggling", "web.parser_diff",
        }
        self.assertEqual(set(DOMAIN_PROBES.keys()), expected)

    def test_dispatch_returns_uniform_signal(self):
        for key, probe in DOMAIN_PROBES.items():
            fn, bug_class, t0 = dispatch_domain_probe(key, "http://x", ["/"])
            self.assertTrue(callable(fn))
            self.assertIsInstance(bug_class, str)
            self.assertIsInstance(t0, str)
            # Run the probe — should never raise.
            signals = fn("http://example.com", ["/api/v1/users"])
            self.assertIsInstance(signals, list)

    def test_dispatch_unknown_returns_empty(self):
        fn, bug_class, t0 = dispatch_domain_probe("does.not.exist", "", [])
        self.assertEqual(fn("http://x", []), [])
        self.assertEqual(bug_class, "generic")

    def test_coverage_report_dict(self):
        report = coverage_report()
        self.assertIsInstance(report, dict)
        self.assertIn("jwt", report)
        self.assertIn("rag", report)


class DomainAdapterSignalSchema(unittest.TestCase):
    """Each probe must return signals matching the mission_runner schema."""

    def _check(self, probe_fn, *args):
        signals = probe_fn(*args)
        self.assertIsInstance(signals, list)
        for sig in signals:
            self.assertIn("signal", sig)
            self.assertIn("winning_technique", sig)
            self.assertIn("bug_class", sig)
            self.assertIn("path", sig)
            self.assertIn("detail", sig)
            self.assertIn("attempts", sig)
            self.assertIsInstance(sig["attempts"], list)
            for att in sig["attempts"]:
                self.assertIn("technique", att)
                self.assertIn("outcome", att)
                self.assertIn("detail", att)

    def test_jwt_signal(self):
        self._check(_probe_jwt_forgery, "http://x", ["/"])

    def test_oauth_signal(self):
        self._check(_probe_oauth_flow, "http://x", ["/"])

    def test_ato_signal(self):
        self._check(_probe_ato_chain, "http://x", ["/"])

    def test_bopla_signal(self):
        self._check(_probe_bopla, "http://x", ["/api"])

    def test_graphql_batch_signal(self):
        self._check(_probe_graphql_batch, "http://x", ["/graphql"])

    def test_rag_poisoning_signal(self):
        self._check(_probe_rag_poisoning, "http://x", ["/"])

    def test_deep_link_signal(self):
        self._check(_probe_deep_link, "http://x", ["/"])

    def test_mobile_policy_signal(self):
        self._check(_probe_mobile_policy, "http://x", ["/"])

    def test_llm_contract_triage_signal(self):
        self._check(_probe_llm_contract_triage, "http://x", ["/"])

    def test_price_manipulation_signal(self):
        self._check(_probe_price_manipulation, "http://x", ["/"])

    def test_http_smuggling_signal(self):
        self._check(_probe_http_smuggling, "http://x", ["/"])

    def test_parser_differential_signal(self):
        self._check(_probe_parser_differential, "http://x", ["/"])


class DomainAdapterMissionRunnerIntegration(unittest.TestCase):
    """mission_runner.DOMAIN_LANES must include all 12 wired domains."""

    def test_mission_runner_domain_lanes(self):
        from tools.runtime import mission_runner
        keys = set(mission_runner.DOMAIN_LANES.keys())
        for k in DOMAIN_PROBES.keys():
            self.assertIn(k, keys,
                          f"domain {k} missing from mission_runner.DOMAIN_LANES")


if __name__ == "__main__":
    unittest.main()
