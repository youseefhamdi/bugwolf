"""Week 6 tests: ATO chain planner, failure learning, chain graph AI."""

import tempfile
import unittest

from tools.domains.auth import ato_chain_planner as ato
from tools.intelligence import chain_graph_ai as cga
from tools.intelligence import failure_learning as fl


_TS_KEYS = {"generated_at", "created_at", "last_seen", "first_seen",
            "reviewed_at", "updated_at", "completed_at"}


def _without_ts(obj):
    if isinstance(obj, dict):
        return {k: _without_ts(v) for k, v in obj.items() if k not in _TS_KEYS}
    if isinstance(obj, list):
        return [_without_ts(v) for v in obj]
    return obj


class TestAtoChainPlanner(unittest.TestCase):
    def test_email_ato_chain(self):
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "kind": "email_change",
             "endpoint": "POST /account/email"},
            {"lead_id": "L2", "kind": "password_reset",
             "endpoint": "POST /account/reset"},
        ])
        chains = {p.chain_id: p for p in plan_set.plans}
        self.assertIn("email-ato", chains)
        plan = chains["email-ato"]
        self.assertEqual(plan.severity, "critical")
        self.assertEqual([s.kind for s in plan.steps],
                         ["email_change", "password_reset"])
        self.assertEqual(plan.steps[0].endpoint, "POST /account/email")

    def test_session_theft_chain(self):
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "kind": "xss", "endpoint": "GET /search?q="},
            {"lead_id": "L2", "kind": "session", "endpoint": "GET /session"},
        ])
        chains = {p.chain_id for p in plan_set.plans}
        self.assertIn("session-theft-ato", chains)

    def test_partial_leads_no_speculation(self):
        # Only email_change — the chain requires password_reset too.
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "kind": "email_change",
             "endpoint": "POST /account/email"},
        ])
        self.assertEqual(len(plan_set.plans), 0)

    def test_kind_inference_from_endpoint(self):
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "endpoint": "POST /account/email"},
            {"lead_id": "L2", "endpoint": "POST /account/password/reset"},
        ])
        chains = {p.chain_id for p in plan_set.plans}
        self.assertIn("email-ato", chains)

    def test_oauth_coat_chain(self):
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "kind": "oauth", "endpoint": "/oauth/authorize"},
        ])
        chains = {p.chain_id for p in plan_set.plans}
        self.assertIn("oauth-coat-ato", chains)

    def test_deterministic(self):
        leads = [
            {"lead_id": "L1", "kind": "email_change",
             "endpoint": "POST /account/email"},
            {"lead_id": "L2", "kind": "password_reset",
             "endpoint": "POST /account/reset"},
        ]
        a = _without_ts(ato.plan_chains("acme", leads).to_dict())
        b = _without_ts(ato.plan_chains("acme", leads).to_dict())
        self.assertEqual(a, b)

    def test_write_path(self):
        plan_set = ato.plan_chains("acme", [
            {"lead_id": "L1", "kind": "email_change"},
            {"lead_id": "L2", "kind": "password_reset"},
        ])
        with tempfile.TemporaryDirectory() as td:
            out = ato.write_plan_set(plan_set, base_dir=td)
            self.assertEqual(out.name, "ato-chain-plans.json")
            self.assertIn("discovery", str(out))


class TestFailureLearning(unittest.TestCase):
    FAILURES = [
        {"thread_id": "t-1", "blocker": "403 Forbidden on /admin",
         "bug_class": "idor", "defense": "403 filter",
         "attempts": [
             {"payload": "/admin", "result": "403"},
             {"payload": "/%2e%2e/admin", "result": "200 OK"},
         ]},
        {"thread_id": "t-2", "blocker": "Cloudflare WAF blocked payload",
         "bug_class": "xss", "defense": "Cloudflare WAF",
         "attempts": [{"payload": "<script>alert(1)</script>",
                       "result": "blocked"}]},
    ]

    def test_403_candidates_generated(self):
        report = fl.learn("acme", self.FAILURES)
        techniques = {c.technique for c in report.candidates}
        self.assertIn("double-encoded dot-dot", techniques)
        self.assertIn("semicolon path traversal", techniques)
        self.assertIn("header-based path access", techniques)

    def test_what_worked_extracted(self):
        report = fl.learn("acme", self.FAILURES)
        worked = [c for c in report.candidates
                  if c.provenance == "attempt-result"]
        self.assertTrue(any(c.payload == "/%2e%2e/admin" for c in worked))

    def test_all_quarantined(self):
        report = fl.learn("acme", self.FAILURES)
        self.assertTrue(report.candidates)
        self.assertTrue(all(c.status == "quarantined"
                            for c in report.candidates))

    def test_waf_catalog(self):
        report = fl.learn("acme", [{
            "blocker": "Cloudflare WAF blocked payload",
            "bug_class": "xss", "defense": "Cloudflare WAF",
        }])
        techniques = {c.technique for c in report.candidates}
        self.assertIn("nested tag evasion", techniques)
        self.assertIn("comment injection", techniques)

    def test_memory_records_created(self):
        with tempfile.TemporaryDirectory() as td:
            report = fl.learn("acme", self.FAILURES, base_dir=td)
            self.assertGreaterEqual(len(report.memory_records), 1)

    def test_deterministic(self):
        # The candidate list is purely derived from the failures input; the
        # AdaptiveMemory records are a persistent store (seen_count merges),
        # so determinism is asserted on candidates only.
        a = [c.to_dict() for c in fl.learn("acme", self.FAILURES).candidates]
        b = [c.to_dict() for c in fl.learn("acme", self.FAILURES).candidates]
        self.assertEqual(a, b)


class TestChainGraphAi(unittest.TestCase):
    def test_terminal_gap_proposals(self):
        report = cga.propose("acme", [
            {"lead_id": "L1", "bug_class": "xss-stored"},
        ])
        self.assertTrue(report.proposals)
        ato_p = [p for p in report.proposals if p.to_class == "account-takeover"]
        self.assertEqual(len(ato_p), 1)
        self.assertEqual(ato_p[0].path, ["xss-stored", "account-takeover"])
        self.assertEqual(ato_p[0].missing_classes, ["account-takeover"])

    def test_deterministic_pair_proposal(self):
        report = cga.propose("acme", [
            {"lead_id": "A", "bug_class": "mass-assignment"},
            {"lead_id": "B", "bug_class": "account-takeover"},
        ])
        pair = [p for p in report.proposals
                if p.from_lead == "A" and p.to_lead == "B"]
        self.assertEqual(len(pair), 1)
        self.assertEqual(pair[0].path, ["mass-assignment", "account-takeover"])

    def test_llm_verdict_validated(self):
        # mass-assignment -> account-takeover exists in EDGES: accepted.
        report = cga.propose("acme", [
            {"lead_id": "A", "bug_class": "mass-assignment"},
            {"lead_id": "B", "bug_class": "account-takeover"},
        ], verdicts=[
            {"from_lead": "A", "to_lead": "B", "rationale": "graph supports it"},
        ])
        llm = [p for p in report.proposals if p.source == "llm_validated"]
        self.assertEqual(len(llm), 1)
        self.assertEqual(llm[0].rationale, "graph supports it")

    def test_llm_verdict_rejected(self):
        # xss-stored -> idor has NO path in EDGES: rejected.
        report = cga.propose("acme", [
            {"lead_id": "A", "bug_class": "xss-stored"},
            {"lead_id": "B", "bug_class": "idor"},
        ], verdicts=[
            {"from_lead": "A", "to_lead": "B", "rationale": "no graph path"},
        ])
        llm = [p for p in report.proposals if p.source == "llm_validated"]
        self.assertEqual(len(llm), 0)

    def test_multi_hop_missing_classes(self):
        report = cga.propose("acme", [
            {"lead_id": "L", "bug_class": "idor"},
        ])
        ato_p = [p for p in report.proposals
                 if p.to_class == "account-takeover"]
        self.assertEqual(len(ato_p), 1)
        self.assertIn("mass-assignment", ato_p[0].path)
        self.assertIn("mass-assignment", ato_p[0].missing_classes)

    def test_unknown_class_no_proposals(self):
        report = cga.propose("acme", [
            {"lead_id": "L", "bug_class": "not-a-real-class"},
        ])
        self.assertEqual(len(report.proposals), 0)

    def test_deterministic(self):
        pool = [{"lead_id": "L1", "bug_class": "xss-stored"},
                {"lead_id": "L2", "bug_class": "idor"}]
        a = _without_ts(cga.propose("acme", pool).to_dict())
        b = _without_ts(cga.propose("acme", pool).to_dict())
        self.assertEqual(a, b)

    def test_write_path(self):
        report = cga.propose("acme", [{"lead_id": "L", "bug_class": "idor"}])
        with tempfile.TemporaryDirectory() as td:
            out = cga.write_proposal_set(report, base_dir=td)
            self.assertEqual(out.name, "graph-ai-proposals.json")
            self.assertIn("chains", str(out))


if __name__ == "__main__":
    unittest.main()
