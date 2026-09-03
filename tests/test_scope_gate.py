#!/usr/bin/env python3
"""Execution-boundary scope gate tests (readiness R1/R2 remediation).

Contracts pinned here:
  * the gate is deny-by-default: target + dot-boundary suffixes + operator
    scope file only; loopback only for local campaigns;
  * rebinding to a different target is refused (one mission per process);
  * http_probe fails CLOSED on out-of-scope URLs (status 0, scope-blocked);
  * the race engine's raw sockets and the live executor obey the same gate;
  * the injected browser driver refuses out-of-scope navigation;
  * the readiness manifest's boundary claims are FUNCTIONALLY verified.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime import scope  # noqa: E402
from tools.runtime.scope import ScopeViolation  # noqa: E402


class ScopeGateSemanticsTest(unittest.TestCase):
    def setUp(self):
        scope.reset()
        self.addCleanup(scope.reset)

    def test_deny_by_default_blocks_foreign_host(self):
        scope.bind_target("http://target.example")
        with self.assertRaises(ScopeViolation):
            scope.check_url("http://evil.example/x")

    def test_target_and_suffixes_allowed(self):
        scope.bind_target("https://api.example.com", ["partner.net"])
        self.assertEqual(scope.check_url("https://api.example.com/a"),
                         "api.example.com")
        self.assertEqual(scope.check_url("http://cdn.partner.net/f"),
                         "cdn.partner.net")
        # Dot-boundary: parent target authorizes subdomains...
        scope.reset()
        scope.bind_target("example.com")
        self.assertEqual(scope.check_url("http://www.example.com/"),
                         "www.example.com")
        # ...but never lookalikes.
        with self.assertRaises(ScopeViolation):
            scope.check_url("http://notexample.com/")

    def test_loopback_only_for_local_campaigns(self):
        scope.bind_target("http://127.0.0.1:8080")
        self.assertEqual(scope.check_url("http://localhost:9999/oast"),
                         "localhost")
        scope.reset()
        scope.bind_target("https://remote.example")
        with self.assertRaises(ScopeViolation):
            scope.check_url("http://127.0.0.1:8080/admin")

    def test_rebind_to_different_target_refused(self):
        scope.bind_target("http://a.example")
        with self.assertRaises(RuntimeError):
            scope.bind_target("http://b.example")

    def test_force_replaces_auto_bind_only(self):
        scope.check_url("http://auto.example/")          # auto-bind
        scope.bind_target("http://explicit.example", force=True)
        state = scope.gate_state()
        self.assertEqual(state["target"], "explicit.example")
        self.assertTrue(state["explicit"])
        scope.reset()
        scope.reset()
        scope.bind_target("http://first.example")
        with self.assertRaises(RuntimeError):
            scope.bind_target("http://second.example", force=True)

    def test_scope_file_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "scope.txt"
            p.write_text("# operator scope\n"
                         "extra.example\n"
                         "https://other.example/path\n"
                         "\n")
            hosts = scope.load_scope_file(str(p))
        self.assertEqual(hosts, ["extra.example", "other.example"])
        scope.bind_target("http://target.example", hosts)
        self.assertEqual(scope.check_url("http://extra.example/"),
                         "extra.example")

    def test_exclusions_beat_wildcard(self):
        """Program carve-outs (beta./community. hosts) are denied even under
        an allow wildcard -- exclusion ALWAYS wins (real-engagement rule)."""
        scope.bind_target("plumsail.com", deny_entries=["beta.plumsail.com"])
        # Wildcard child still allowed...
        self.assertEqual(scope.check_url("https://forms.plumsail.com/"),
                         "forms.plumsail.com")
        # ...but the excluded host and its children are denied.
        with self.assertRaises(ScopeViolation) as ctx:
            scope.check_url("https://beta.plumsail.com/")
        self.assertEqual(ctx.exception.policy, "excluded-by-policy")
        with self.assertRaises(ScopeViolation):
            scope.check_url("https://docs.beta.plumsail.com/")

    def test_exclusion_of_bare_target_denies_even_target(self):
        scope.bind_target("example.com", deny_entries=["example.com"])
        with self.assertRaises(ScopeViolation):
            scope.check_url("https://example.com/")

    def test_add_denies_extends_bound_gate(self):
        scope.bind_target("example.com")
        self.assertEqual(scope.check_url("https://old.example.com/"),
                         "old.example.com")
        scope.add_denies(["old.example.com"])
        with self.assertRaises(ScopeViolation):
            scope.check_url("https://old.example.com/")

    def test_state_reports_mode(self):
        scope.bind_target("http://x.example")
        self.assertEqual(scope.gate_state()["mode"], "deny-by-default")
        scope.reset()
        scope.check_url("http://y.example/")
        self.assertEqual(scope.gate_state()["mode"], "auto-bind")


class ProbeBoundaryTest(unittest.TestCase):
    def setUp(self):
        scope.reset()
        self.addCleanup(scope.reset)

    def test_http_probe_fails_closed(self):
        from tools.runtime.mission_runner import http_probe
        scope.bind_target("http://target.example")
        result = http_probe("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(result.status, 0)
        self.assertIn("scope-blocked", result.body)

    def test_http_probe_allows_in_scope_without_io_gate_error(self):
        from tools.runtime.mission_runner import http_probe
        scope.bind_target("http://127.0.0.1:1")   # closed port, no server
        result = http_probe("http://127.0.0.1:1/api")
        self.assertEqual(result.status, 0)
        self.assertNotIn("scope-blocked", result.body)

    def test_race_engine_fails_closed(self):
        from tools.validation.race_engine import RaceRequest, run_race
        scope.bind_target("http://target.example")
        race = run_race(RaceRequest(url="http://evil.example/win", count=2))
        self.assertEqual(race.statuses, [0, 0])
        self.assertEqual(race.window_ms, 0)
        self.assertIn("scope-blocked", race.error)

    def test_live_executor_fails_closed(self):
        from tools.core.live_executor import ProbeSpec, _send_once
        scope.bind_target("http://target.example")
        status, _h, body, _ms = _send_once(
            ProbeSpec(probe_id="t", method="GET",
                      url="http://evil.example/p"), timeout=5,
            urlopen=lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(status, 0)
        self.assertIn("scope-blocked", body)


class BrowserBoundaryTest(unittest.TestCase):
    def setUp(self):
        scope.reset()
        self.addCleanup(scope.reset)

    def test_driver_navigation_respects_scope(self):
        from tools.runtime.browser_driver import validate_client_side

        class Boom:
            def navigate(self, url):
                raise AssertionError("driver reached despite scope block")

        scope.bind_target("http://target.example")
        ev = validate_client_side(
            {"url": "http://evil.example/payload", "lead_id": "L1"},
            driver=Boom())
        self.assertTrue(str(ev.blocker).startswith("scope-blocked"))
        self.assertFalse(ev.navigated)

    def test_scope_block_is_not_blocked_browser(self):
        """The runner must record scope violations as policy facts, not as
        missing-tooling blocked-browser semantics."""
        source = (Path(__file__).resolve().parent.parent
                  / "tools" / "runtime" / "mission_runner.py").read_text()
        self.assertIn('"scope-blocked"', source)
        self.assertNotIn(
            'record_technique(\n                        lead.lead_id, '
            '"blocked-browser", "blocked",\n                        '
            'detail=blocker)\n                    self._log("scope_violation"',
            source,
            "scope violations must not be recorded under blocked-browser")


class ReadinessClaimVerificationTest(unittest.TestCase):
    def test_boundary_claims_are_functionally_verified(self):
        from tools.readiness import (_verify_scope_gate,
                                     _verify_ssrf_choke_points)
        ok, detail = _verify_scope_gate()
        self.assertTrue(ok, detail)
        ok, detail = _verify_ssrf_choke_points()
        self.assertTrue(ok, detail)

    def test_manifest_reports_only_subprocess_warning(self):
        import tools.readiness as readiness
        report = readiness.validate_manifest(readiness.load_manifest())
        self.assertTrue(report["valid"], report["errors"])
        warnings = [w for w in report["warnings"] if "subprocess" not in w]
        self.assertEqual(warnings, [],
                         f"unexpected warnings: {warnings}")


if __name__ == "__main__":
    unittest.main()
