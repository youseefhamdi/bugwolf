#!/usr/bin/env python3
"""Model router tests (U5).

Covers:
  * deterministic-tier routing for pure-computation tasks (no model)
  * local_slm routing for bounded probing tasks
  * frontier routing for open-ended reasoning tasks
  * determinism and band stability
  * advisory attach_hint that never mutates the unit contract
  * graceful degradation (never raises, always a fallback)
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.model_router import (  # noqa: E402
    route, route_unit, attach_hint, classify,
    TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER,
    MODEL_NONE, MODEL_SLM, MODEL_FRONTIER,
)


class TestRoutingTiers(unittest.TestCase):
    def test_deterministic_task_needs_no_model(self):
        decision = route(
            "Generate target-specific wordlist from recon urls and js files",
            bug_class="xss", max_iterations=5)
        self.assertEqual(decision.tier, TIER_DETERMINISTIC)
        self.assertEqual(decision.model_preference, MODEL_NONE)
        self.assertTrue(decision.fallback)

    def test_artifact_verification_is_deterministic(self):
        decision = route("Verify research sequence freshness via verify_sequence",
                         max_iterations=1)
        self.assertEqual(decision.tier, TIER_DETERMINISTIC)

    def test_bounded_probing_routes_to_local_slm(self):
        decision = route(
            "Probe the endpoint with SQLi payloads and observe responses",
            bug_class="sqli", max_iterations=15)
        self.assertEqual(decision.tier, TIER_LOCAL)
        self.assertEqual(decision.model_preference, MODEL_SLM)

    def test_chain_synthesis_routes_to_frontier(self):
        decision = route(
            "Synthesize a cross-asset attack chain connecting the findings",
            bug_class="chain", max_iterations=50)
        self.assertEqual(decision.tier, TIER_FRONTIER)
        self.assertEqual(decision.model_preference, MODEL_FRONTIER)

    def test_adversarial_refutation_routes_to_frontier(self):
        decision = route(
            "Adversarially refute the candidate with constrained attacker simulation",
            bug_class="auth_bypass", max_iterations=50)
        self.assertEqual(decision.tier, TIER_FRONTIER)

    def test_classify_bands_are_stable(self):
        self.assertEqual(classify(0.9), TIER_FRONTIER)
        self.assertEqual(classify(0.65), TIER_FRONTIER)
        self.assertEqual(classify(0.5), TIER_LOCAL)
        self.assertEqual(classify(0.35), TIER_LOCAL)
        self.assertEqual(classify(0.2), TIER_DETERMINISTIC)

    def test_deterministic_output(self):
        a = route("Probe endpoint for XSS", bug_class="xss", max_iterations=15)
        b = route("Probe endpoint for XSS", bug_class="xss", max_iterations=15)
        self.assertEqual(a.to_dict(), b.to_dict())


class TestRouteUnit(unittest.TestCase):
    def _unit(self, objective, bug_class="", max_iterations=50):
        return {
            "schema": "bugwolf-research-unit-v1",
            "unit_id": "u-1",
            "objective": objective,
            "bug_class": bug_class,
            "max_iterations": max_iterations,
            "context": {"current_state": "probing"},
            "available_tools": ["http_request", "execute_python"],
        }

    def test_routes_standard_unit(self):
        decision = route_unit(self._unit(
            "Synthesize an exploit chain for account takeover",
            bug_class="account_takeover", max_iterations=50))
        self.assertEqual(decision.tier, TIER_FRONTIER)
        self.assertEqual(decision.task_id, "u-1")

    def test_attach_hint_is_advisory_and_preserves_unit(self):
        unit = self._unit("Probe the login endpoint for rate limiting",
                          max_iterations=10)
        original = dict(unit)
        out = attach_hint(unit)
        self.assertIs(out, unit)  # mutates in place
        for key in ("objective", "bug_class", "max_iterations",
                    "available_tools", "schema"):
            self.assertEqual(unit[key], original[key])
        self.assertIn("model_preference", unit["context"])
        self.assertIn("model_fallback", unit["context"])
        self.assertEqual(unit["context"]["model_routing"]["task_id"], "u-1")

    def test_route_unit_never_raises_on_garbage(self):
        self.assertIsNotNone(route_unit(None))
        self.assertIsNotNone(route_unit("not a dict"))
        self.assertIsNotNone(route_unit({}))
        self.assertIsNotNone(route_unit({"objective": None, "context": "bad"}))

    def test_attach_hint_never_raises_on_garbage(self):
        self.assertIsNone(attach_hint(None))
        self.assertEqual(attach_hint("string"), "string")

    def test_deep_dive_unit_still_routes(self):
        unit = self._unit(
            "Refute the zero-day candidate and build the exploit",
            bug_class="zero_day", max_iterations=50)
        decision = route_unit(unit)
        self.assertIn(decision.tier, {TIER_FRONTIER, TIER_LOCAL})


if __name__ == "__main__":
    unittest.main()
