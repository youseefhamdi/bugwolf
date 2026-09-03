#!/usr/bin/env python3
import argparse
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.execution_controller import ActionClass
from tools.hunt import (
    HuntResult, HuntSession, _action_for_http, _format_structured_json,
    run_idor_check, run_quick_checks,
)


class TestIdorEngine(unittest.TestCase):
    def test_idor_requires_concrete_ids_and_never_sends_literal_placeholder(self):
        session_a = HuntSession(name="a", target="example.com", object_ids=["A"])
        session_b = HuntSession(name="b", target="example.com", object_ids=["B"])
        calls = []

        def fake_fetch(method, url, session, **kwargs):
            calls.append(url)
            if url.endswith("/A") and session.name == "a":
                return 200, '{"owner":"a"}'
            if url.endswith("/B") and session.name == "b":
                return 200, '{"owner":"b"}'
            if url.endswith("/A") and session.name == "b":
                return 200, '{"owner":"a"}'
            return 403, "denied"

        with mock.patch("tools.hunt.curl_fetch", side_effect=fake_fetch):
            results = run_idor_check(
                "https://example.com", session_a, session_b)

        self.assertTrue(results)
        self.assertTrue(all("{id}" not in url for url in calls))
        self.assertTrue(all(r.idor_signal for r in results))
        self.assertTrue(any("Cross-user access" in r.notes for r in results))

    def test_idor_without_two_concrete_id_sets_returns_no_signal(self):
        session_a = HuntSession(name="a", target="example.com")
        session_b = HuntSession(name="b", target="example.com")
        with mock.patch("tools.hunt.curl_fetch") as fetch:
            self.assertEqual(run_idor_check(
                "https://example.com", session_a, session_b), [])
            fetch.assert_not_called()

    def test_blocked_quick_checks_are_exposed_for_bypass_research(self):
        session = HuntSession(name="anon", target="example.com")
        with mock.patch("tools.hunt.curl_fetch", return_value=(403, "blocked")):
            results = run_quick_checks("https://example.com", session)
        self.assertTrue(results)
        self.assertTrue(all(result.status_a == 403 for result in results))
        self.assertTrue(all("blocked" in result.notes for result in results))

    def test_http_methods_map_to_action_classes(self):
        self.assertEqual(_action_for_http("GET"), ActionClass.READ)
        self.assertEqual(_action_for_http("HEAD"), ActionClass.READ)
        self.assertEqual(_action_for_http("OPTIONS"), ActionClass.READ)
        # POST is state-changing and must require the destructive/state-change
        # confirmation, never slip through as a plain active probe.
        self.assertEqual(_action_for_http("POST"), ActionClass.STATE_CHANGE)
        self.assertEqual(_action_for_http("PUT"), ActionClass.STATE_CHANGE)
        self.assertEqual(_action_for_http("PATCH"), ActionClass.STATE_CHANGE)
        self.assertEqual(_action_for_http("DELETE"), ActionClass.DESTRUCTIVE)

    def test_read_only_post_is_opt_in_and_does_not_loosen_other_verbs(self):
        # Default POST maps to STATE_CHANGE — the F1 hardening.
        self.assertEqual(_action_for_http("POST"), ActionClass.STATE_CHANGE)
        # Statically-known read-only POST payloads stay at READ — opt-in only.
        self.assertEqual(_action_for_http("POST", read_only_post=True),
                         ActionClass.READ)
        # Flag must never weaken a more dangerous verb.
        self.assertEqual(_action_for_http("DELETE", read_only_post=True),
                         ActionClass.DESTRUCTIVE)
        self.assertEqual(_action_for_http("PUT", read_only_post=True),
                         ActionClass.STATE_CHANGE)
        self.assertEqual(_action_for_http("PATCH", read_only_post=True),
                         ActionClass.STATE_CHANGE)

    def test_state_changing_idor_methods_are_opt_in(self):
        session_a = HuntSession(name="a", target="example.com", object_ids=["A"])
        session_b = HuntSession(name="b", target="example.com", object_ids=["B"])
        methods = []

        def fake_fetch(method, url, session, **kwargs):
            methods.append(method)
            return 403, "denied"

        with mock.patch("tools.hunt.curl_fetch", side_effect=fake_fetch):
            run_idor_check("https://example.com", session_a, session_b)
        self.assertEqual(set(methods), {"GET"})


class TestScopeGateChokePoint(unittest.TestCase):
    """The 2026-09-03 audit gap: hunt.py's curl paths are the live-replay
    transport for differential_runner, header_trust, and cache_traversal, so
    they must obey the operator scope like every other HTTP lane."""

    def setUp(self):
        import tools.runtime.scope as scope
        scope.reset()
        self.addCleanup(scope.reset)

    def test_curl_fetch_blocks_out_of_scope_url_fail_closed(self):
        from tools.runtime.scope import bind_target
        import tools.hunt as hunt
        bind_target("https://target.example")
        session = HuntSession(name="anon", target="target.example")
        status, body = hunt.curl_fetch(
            "GET", "https://evil.example/x", session)
        self.assertEqual(status, -2)
        self.assertIn("scope-blocked", body)

    def test_curl_fetch_allows_target_host_and_records_auto_bind(self):
        import tools.hunt as hunt
        from tools.runtime.scope import gate_state
        session = HuntSession(name="anon", target="example.com")
        status, _ = hunt.curl_fetch("GET", "https://example.com/x", session)
        self.assertEqual(status, -2)  # denied: no execution controller bound
        self.assertIn("execution controller is required", _)
        self.assertTrue(gate_state()["bound"])
        self.assertFalse(gate_state()["explicit"])  # auto-bind, standalone

    def test_curl_fetch_observation_blocks_out_of_scope_url(self):
        from tools.runtime.scope import bind_target
        import tools.hunt as hunt
        bind_target("https://target.example")
        session = HuntSession(name="anon", target="target.example")
        obs = hunt.curl_fetch_observation(
            "GET", "https://evil.example/x", session)
        self.assertEqual(obs.status, 0)
        self.assertIn("scope-blocked", obs.error)

    def test_explicit_mission_bind_wins_over_earlier_auto_bind(self):
        # A standalone probe auto-binds non-explicitly; a later mission bind
        # replaces it only via force=True (the gate's documented rule: force
        # replaces an AUTO-bind, never an explicit mission bind).
        import tools.hunt as hunt
        from tools.runtime.scope import bind_target, gate_state
        session = HuntSession(name="anon", target="example.com")
        hunt.curl_fetch("GET", "https://example.com/x", session)
        self.assertFalse(gate_state()["explicit"])
        bind_target("https://mission.example", force=True)
        self.assertTrue(gate_state()["explicit"])
        status, body = hunt.curl_fetch(
            "GET", "https://example.com/x", session)
        self.assertEqual(status, -2)
        self.assertIn("scope-blocked", body)

    def test_force_cannot_replace_an_explicit_mission_bind(self):
        import tools.hunt as hunt
        from tools.runtime.scope import bind_target
        bind_target("https://mission.example")
        with self.assertRaises(RuntimeError):
            bind_target("https://other.example", force=True)


class TestFindingPromotionBoundary(unittest.TestCase):
    def test_unvalidated_quick_check_is_an_observation(self):
        args = argparse.Namespace(active=False, idor_only=False)
        result = _format_structured_json(
            "example.com",
            [HuntResult(
                endpoint="https://example.com/.well-known/security.txt",
                notes="Debug/sensitive file exposed",
                status_a=200,
            )],
            args,
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["observations"][0]["state"], "unvalidated")

    def test_oracle_signal_is_a_finding(self):
        args = argparse.Namespace(active=True, idor_only=False)
        result = _format_structured_json(
            "example.com",
            [HuntResult(
                endpoint="https://example.com/api?q=x",
                method="GET", status_a=500,
                observation_state="signal", notes="[high] sqli: status delta",
            )],
            args,
        )
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["bug_class"], "sqli")


if __name__ == "__main__":
    unittest.main()
