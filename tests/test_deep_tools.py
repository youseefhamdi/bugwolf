#!/usr/bin/env python3
"""
Tests for the BugWolf deep-hunting tools:
  - tools/impact_focus.py  (criticality router → high/critical focus)
  - tools/differential.py  (sibling-surface divergence detector)
  - tools/deep_chain.py    (transitive multi-hop chain synthesis)

Run:  python3 -m unittest discover -s tests -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.impact_focus import (
    CriticalityRouter, infer_verb, infer_boundary, infer_asset, focus_tier,
)
from tools.differential import DifferentialDetector
from tools.deep_chain import DeepChainSynthesizer, escalate, TERMINAL


# ---------------------------------------------------------------------------
# impact_focus
# ---------------------------------------------------------------------------

class TestCriticalityRouter(unittest.TestCase):

    def setUp(self):
        self.router = CriticalityRouter()

    def test_withdraw_funds_is_critical_and_drain(self):
        s = self.router.score_surface({
            "endpoint": "/api/withdraw", "impact_verb": "withdraw",
            "boundary": "user-to-payment", "asset": "funds",
            "victim_scope": "single-user"})
        self.assertEqual(s.focus, "critical")
        self.assertTrue(s.drain_potential)
        self.assertGreater(s.criticality, 75)

    def test_read_list_is_low_focus(self):
        s = self.router.score_surface({
            "endpoint": "/api/list", "impact_verb": "read"})
        self.assertEqual(s.focus, "low")
        self.assertLess(s.criticality, 35)
        self.assertFalse(s.drain_potential)

    def test_inference_from_endpoint(self):
        verb = infer_verb("/api/admin/role/grant")
        boundary = infer_boundary("/api/admin/role/grant")
        asset = infer_asset("/api/admin/role/grant")
        self.assertEqual(verb, "authorize")
        self.assertEqual(boundary, "user-to-admin")
        self.assertEqual(asset, "admin")

    def test_transfer_funds_inferred(self):
        verb = infer_verb("/api/checkout/transfer")
        asset = infer_asset("/api/checkout/transfer")
        self.assertEqual(verb, "transfer")
        self.assertEqual(asset, "funds")

    def test_route_sorts_highest_first(self):
        surfaces = [
            {"endpoint": "/api/list", "impact_verb": "read"},
            {"endpoint": "/api/withdraw", "impact_verb": "withdraw",
             "boundary": "user-to-payment", "asset": "funds"},
        ]
        scored = self.router.route(surfaces)
        self.assertEqual(scored[0].impact_verb, "withdraw")
        self.assertEqual(scored[-1].impact_verb, "read")
        self.assertTrue(scored[0].criticality > scored[-1].criticality)

    def test_min_focus_filter(self):
        router = CriticalityRouter(min_focus="high")
        surfaces = [
            {"endpoint": "/api/list", "impact_verb": "read"},
            {"endpoint": "/api/withdraw", "impact_verb": "withdraw",
             "boundary": "user-to-payment", "asset": "funds"},
        ]
        scored = router.route(surfaces)
        self.assertTrue(all(s.focus in ("critical", "high") for s in scored))
        self.assertTrue(all(s.impact_verb != "read" for s in scored))

    def test_focus_tier_boundaries(self):
        self.assertEqual(focus_tier(80), "critical")
        self.assertEqual(focus_tier(60), "high")
        self.assertEqual(focus_tier(40), "medium")
        self.assertEqual(focus_tier(10), "low")


# ---------------------------------------------------------------------------
# differential
# ---------------------------------------------------------------------------

class TestDifferentialDetector(unittest.TestCase):

    def setUp(self):
        self.det = DifferentialDetector()

    def test_identical_surfaces_no_divergence(self):
        a = {"id": "A", "endpoint": "/api/v1/x", "auth": True,
             "validation": ["amount"]}
        b = {"id": "B", "endpoint": "/api/v1/x", "auth": True,
             "validation": ["amount"]}
        r = self.det.compare(a, b)
        self.assertEqual(r.divergence_score, 0.0)
        self.assertEqual(r.divergences, [])
        self.assertFalse(r.sibling_drift)

    def test_auth_divergence_on_same_root_is_sibling_drift(self):
        a = {"id": "A", "endpoint_root": "/api/transfer", "auth": True,
             "rate_limited": True, "validation": ["amount"]}
        b = {"id": "B", "endpoint_root": "/api/transfer", "auth": False,
             "rate_limited": True, "validation": ["amount"]}
        r = self.det.compare(a, b)
        self.assertGreater(r.divergence_score, 0)
        self.assertTrue(r.sibling_drift)
        self.assertTrue(any(d.aspect == "auth" for d in r.divergences))
        self.assertIn("auth", r.hypothesis)

    def test_validation_divergence_detected(self):
        a = {"id": "A", "endpoint": "/x", "validation": ["amount", "currency"]}
        b = {"id": "B", "endpoint": "/x", "validation": ["amount"]}
        r = self.det.compare(a, b)
        self.assertTrue(any(d.aspect == "validation" for d in r.divergences))

    def test_different_roots_not_sibling_drift(self):
        a = {"id": "A", "endpoint": "/api/v1/a", "auth": True}
        b = {"id": "B", "endpoint": "/api/v2/b", "auth": False}
        r = self.det.compare(a, b)
        self.assertFalse(r.sibling_drift)
        self.assertEqual(r.hypothesis, "")

    def test_missing_check_is_weaker_leg(self):
        a = {"id": "A", "endpoint": "/x", "auth": False}
        b = {"id": "B", "endpoint": "/x", "auth": True}
        r = self.det.compare(a, b)
        self.assertTrue(r.sibling_drift)
        # probe should point at the weaker leg (A, the one missing auth)
        self.assertIn("A", r.probe_suggestion)


# ---------------------------------------------------------------------------
# deep_chain
# ---------------------------------------------------------------------------

class TestDeepChainSynthesizer(unittest.TestCase):

    def test_escalate_tiers(self):
        self.assertEqual(escalate("low", 2), "high")
        self.assertEqual(escalate("high", 1), "critical")
        self.assertEqual(escalate("critical", 3), "critical")  # capped

    def test_idor_reaches_account_takeover_in_three_hops(self):
        syn = DeepChainSynthesizer(min_hops=2)
        chains = syn.synthesize([{"bug_class": "idor", "severity": "low",
                                  "endpoint": "/api/users/1"}])
        terminal_paths = [c.path for c in chains if c.terminal]
        # idor → mass-assignment → privilege-escalation-web → account-takeover
        self.assertTrue(any(p[-1] == "account-takeover" and len(p) == 4
                            for p in terminal_paths))
        # 3 hops from a low escalates to critical
        three_hop = [c for c in chains if c.hops == 3]
        self.assertTrue(three_hop)
        self.assertTrue(all(c.severity == "critical" for c in three_hop))

    def test_min_hops_filter(self):
        syn = DeepChainSynthesizer(min_hops=3)
        chains = syn.synthesize([{"bug_class": "idor", "severity": "low"}])
        self.assertTrue(chains)
        self.assertTrue(all(c.hops >= 3 for c in chains))

    def test_open_redirect_reaches_ato(self):
        syn = DeepChainSynthesizer(min_hops=2)
        chains = syn.synthesize([{"bug_class": "open-redirect", "severity": "medium"}])
        self.assertTrue(any(c.path == ["open-redirect", "oauth-bypass",
                                       "account-takeover"] for c in chains))
        ato = next(c for c in chains
                   if c.path[-1] == "account-takeover" and c.terminal)
        self.assertIn("account takeover", ato.impact)

    def test_unknown_class_no_chains(self):
        syn = DeepChainSynthesizer(min_hops=2)
        chains = syn.synthesize([{"bug_class": "not-a-class", "severity": "low"}])
        self.assertEqual(chains, [])

    def test_chains_rank_severity_then_hops(self):
        syn = DeepChainSynthesizer(min_hops=2)
        chains = syn.synthesize([
            {"bug_class": "idor", "severity": "low"},
            {"bug_class": "ssrf", "severity": "high"},
        ])
        # ssrf→rce is 1 hop (below min), ssrf→...→rce may be 2 hops; ensure sorted
        sevs = [c.severity for c in chains]
        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        self.assertEqual(sevs, sorted(sevs, key=lambda s: rank[s], reverse=True))

    def test_terminal_set_is_high_value(self):
        self.assertEqual(TERMINAL, {"rce", "account-takeover", "funds-drain",
                                    "mass-data-breach"})


if __name__ == "__main__":
    unittest.main()
