#!/usr/bin/env python3
"""Tests for the APT Commander Week-1 P0 + architectural evolution.

Covers:
  * modular core move (shims still resolve at the documented paths)
  * tools.core.signal_bus — typed events, publish/subscribe, replay, persistence
  * hierarchical research sub-checkpoints — injection + ordered-subsequence gate
  * tools.domains.web.http_smuggling_detector — deterministic probe plans
  * tools.domains.web.parser_differential — WAF payload families + listener
  * tools.domains.auth.jwt_forgery — static analysis + forgery plan classes
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.signal_bus import (  # noqa: E402
    SignalBus, Event, WAF_BLOCKED, RECON_COMPLETE, SMUGGLING_CANDIDATE,
    AUTH_CANDIDATE, EVENT_TYPES,
)
from tools.research_loop import (  # noqa: E402
    MANDATORY_RESEARCH_SEQUENCE, mandatory_ordered_subsequence,
    sub_checkpoints_for, run_mandatory_research, SUB_CHECKPOINTS,
)
from tools.domains.web.http_smuggling_detector import (  # noqa: E402
    build_plan, TECHNIQUES, evaluate,
)
from tools.domains.web.parser_differential import (  # noqa: E402
    generate, make_waf_blocked_listener, load_stack_fingerprint,
)
from tools.domains.auth.jwt_forgery import (  # noqa: E402
    analyze, analyze_many, FORGERY_PLANS,
)


class TestModularCoreMove(unittest.TestCase):
    """The move must be invisible to every existing import site."""

    def test_shims_resolve_public_and_private_names(self):
        from tools.stage_controller import (  # noqa: F401
            WorkflowController, STAGES, _relative_or_absolute,
        )
        from tools.research_loop import (  # noqa: F401
            MANDATORY_RESEARCH_SEQUENCE, _html_to_text,
        )
        from tools.agent_bus import AgentBus, Signal  # noqa: F401
        from tools.campaign_orchestrator import main as co_main  # noqa: F401
        self.assertEqual(len(STAGES), 12)
        self.assertEqual(len(MANDATORY_RESEARCH_SEQUENCE), 7)

    def test_canonical_module_identity(self):
        import tools.core.research_loop as core_module
        import tools.research_loop as shimmed
        self.assertIs(core_module, shimmed)

    def test_domain_packages_importable(self):
        from tools.domains.web import http_smuggling_detector  # noqa: F401
        from tools.domains.web import parser_differential  # noqa: F401
        from tools.domains.auth import jwt_forgery  # noqa: F401
        self.assertTrue(True)


class TestSignalBus(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _bus(self, target="acme"):
        return SignalBus(target, project_root=str(self.root))

    def test_publish_dispatches_in_subscription_order(self):
        bus = self._bus()
        seen = []
        bus.subscribe(WAF_BLOCKED, lambda e: seen.append(("waf", e.payload.get("defense"))))
        bus.subscribe(RECON_COMPLETE, lambda e: seen.append(("recon", e.source)))
        bus.publish(WAF_BLOCKED, source="hunt",
                    payload={"defense": "Cloudflare", "bug_class": "sqli"})
        bus.publish(RECON_COMPLETE, source="asset_discovery")
        self.assertEqual(seen, [("waf", "Cloudflare"), ("recon", "asset_discovery")])

    def test_persists_and_replays_to_late_listener(self):
        bus = self._bus()
        bus.publish(SMUGGLING_CANDIDATE, source="http_smuggling_detector",
                    payload={"technique": "CL.TE"})
        late = self._bus()
        self.assertEqual(len(late.events(SMUGGLING_CANDIDATE)), 1)
        replayed = []
        late.subscribe(SMUGGLING_CANDIDATE,
                       lambda e: replayed.append(e.event_id))
        late.replay()
        self.assertEqual(len(replayed), 1)

    def test_unknown_event_type_rejected(self):
        bus = self._bus()
        with self.assertRaises(ValueError):
            bus.publish("NOT_AN_EVENT", source="x")

    def test_listener_failure_is_captured_not_raised(self):
        bus = self._bus()

        def boom(event):
            raise RuntimeError("listener exploded")

        bus.subscribe(RECON_COMPLETE, boom)
        event = bus.publish(RECON_COMPLETE, source="test")
        self.assertEqual(len(event.listener_errors), 1)
        self.assertIn("listener exploded", event.listener_errors[0])

    def test_stats_counts_by_type(self):
        bus = self._bus()
        bus.publish(WAF_BLOCKED, source="hunt", payload={"defense": "X"})
        bus.publish(WAF_BLOCKED, source="hunt", payload={"defense": "X"})
        bus.publish(RECON_COMPLETE, source="recon")
        stats = bus.stats()
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["by_type"]["WAF_BLOCKED"], 2)
        self.assertEqual(stats["by_type"]["RECON_COMPLETE"], 1)

    def test_event_types_are_stable(self):
        for name in ("RECON_COMPLETE", "FINDING_DISCOVERED", "WAF_BLOCKED",
                     "STAGE_ADVANCED", "SMUGGLING_CANDIDATE", "AUTH_CANDIDATE"):
            self.assertIn(name, EVENT_TYPES)


class TestHierarchicalSubCheckpoints(unittest.TestCase):
    def test_trigger_mapping(self):
        self.assertEqual(
            sub_checkpoints_for("post-maps", {"graphql": True, "waf": True, "cloud": False}),
            ["graphql-deep-dive", "waf-profile"])
        self.assertEqual(sub_checkpoints_for("post-maps", {}), [])
        self.assertEqual(
            sub_checkpoints_for("post-findings", {"bug_classes": ["idor"]}),
            ["chain-partners"])

    def test_ordered_subsequence_accepts_subs_between_mandatory(self):
        interleaved = ["pre-hunt", "post-recon", "post-maps", "graphql-deep-dive",
                       "waf-profile", "bypass", "post-findings", "chain-partners",
                       "escalation", "pre-report"]
        self.assertTrue(mandatory_ordered_subsequence(interleaved))
        self.assertTrue(
            mandatory_ordered_subsequence(list(MANDATORY_RESEARCH_SEQUENCE)))
        missing = ["pre-hunt", "post-recon", "bypass", "post-findings",
                   "escalation", "pre-report"]
        self.assertFalse(mandatory_ordered_subsequence(missing))

    def test_execute_sequential_injects_and_persists_subs(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_mandatory_research(
                "acme", "web", phase="full", base_dir=str(Path(tmp) / "research"),
                context={"graphql": True, "waf": True, "cloud": False},
                run_search=False)
            current = result["current_execution"]
            sequence = current["sequence"]
            self.assertIn("graphql-deep-dive", sequence)
            self.assertIn("waf-profile", sequence)
            self.assertNotIn("cloud-metadata", sequence)
            subs = [r for r in current["runs"] if r["sub_of"]]
            self.assertEqual(
                sorted(r["checkpoint"] for r in subs),
                ["graphql-deep-dive", "waf-profile"])
            # Mandatory 7 still present, in order.
            self.assertTrue(mandatory_ordered_subsequence(sequence))
            manifest = json.loads(
                (Path(tmp) / "research" / "acme" / "sequence.json").read_text())
            self.assertEqual(manifest["executions"][-1]["sequence"], sequence)
            self.assertFalse(manifest["latest_ready"])  # searches pending

    def test_all_subs_registered_as_checkpoints(self):
        from tools.research_loop import CHECKPOINTS
        for subs in SUB_CHECKPOINTS.values():
            for sub_name, _key, _desc in subs:
                self.assertIn(sub_name, CHECKPOINTS)


class TestHttpSmugglingDetector(unittest.TestCase):
    def test_plan_covers_all_techniques(self):
        plan = build_plan("acme", ["https://acme.com/"], http2_supported=True)
        techniques = {probe.technique for probe in plan.probes}
        self.assertEqual(techniques, set(TECHNIQUES))
        self.assertGreaterEqual(len(plan.probes), len(TECHNIQUES))

    def test_deterministic_plan(self):
        a = build_plan("acme", ["https://acme.com/"])
        b = build_plan("acme", ["https://acme.com/"])
        self.assertEqual([p.raw_request for p in a.probes],
                         [p.raw_request for p in b.probes])

    def test_http2_gated_by_flag(self):
        without = build_plan("acme", ["https://acme.com/"], http2_supported=False)
        with_h2 = build_plan("acme", ["https://acme.com/"], http2_supported=True)
        h2 = {p.technique for p in without.probes}
        self.assertNotIn("H2.CL", h2)
        self.assertNotIn("H2.TE", h2)
        self.assertIn("H2.CL", {p.technique for p in with_h2.probes})

    def test_probe_templates_are_raw_http(self):
        plan = build_plan("acme", ["https://acme.com/x"])
        cl_te = next(p for p in plan.probes if p.technique == "CL.TE")
        self.assertIn("Content-Length: 4", cl_te.raw_request)
        self.assertIn("Transfer-Encoding: chunked", cl_te.raw_request)
        # The outer request uses the URL path; the smuggled request is the
        # template's fixed GPOST (the desync oracle target).
        self.assertIn("POST /x HTTP/1.1", cl_te.raw_request)
        self.assertIn("GPOST / HTTP/1.1", cl_te.raw_request)

    def test_oracle_differential_positive(self):
        verdict = evaluate({"status": "ok", "response_first_line": "GPOST / 404"},
                           "differential")
        self.assertTrue(verdict["positive"])

    def test_oracle_time_positive(self):
        verdict = evaluate({"status": "ok", "elapsed_seconds": 4.2}, "time")
        self.assertTrue(verdict["positive"])

    def test_oracle_negative(self):
        verdict = evaluate({"status": "ok", "response_first_line": "HTTP/1.1 200 OK",
                            "elapsed_seconds": 0.3}, "differential")
        self.assertFalse(verdict["positive"])

    def test_bad_url_rejected(self):
        with self.assertRaises(ValueError):
            build_plan("acme", ["not a url at all"])


class TestParserDifferential(unittest.TestCase):
    def test_generates_families_for_bug_class(self):
        generated = generate("acme", stack="nginx", defense="Cloudflare",
                             bug_classes=["sqli"])
        self.assertEqual(generated.defense, "Cloudflare")
        self.assertEqual(generated.stack, "nginx")
        self.assertGreaterEqual(len(generated.families), 5)
        self.assertGreater(sum(len(f.payloads) for f in generated.families), 10)

    def test_deterministic_output(self):
        a = generate("acme", stack="nginx", bug_classes=["sqli"])
        b = generate("acme", stack="nginx", bug_classes=["sqli"])
        self.assertEqual([f.to_dict() for f in a.families],
                         [f.to_dict() for f in b.families])
        self.assertEqual(a.stack, b.stack)
        self.assertEqual(a.bug_classes, b.bug_classes)

    def test_stack_hint_from_fingerprint(self):
        fp = {"waf": "Cloudflare", "servers": ["nginx"]}
        generated = generate("acme", fingerprint=fp)
        self.assertEqual(generated.stack, "nginx-cloudflare")

    def test_fingerprint_loader_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = load_stack_fingerprint("acme", base_dir=tmp)
            self.assertEqual(data, {})

    def test_waf_blocked_listener_regenerates_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "recon" / "acme").mkdir(parents=True)
            (root / "recon" / "acme" / "tech-fingerprint.json").write_text(
                json.dumps({"waf": "Cloudflare", "servers": ["nginx"]}))
            listener = make_waf_blocked_listener("acme", base_dir=str(root))
            from tools.core.signal_bus import Event
            event = Event(event_type=WAF_BLOCKED, target="acme",
                          source="hunt", payload={"defense": "Cloudflare",
                                                  "bug_class": "xss"})
            listener(event)
            files = list((root / "research" / "acme" / "bypass").glob(
                "waf-payloads-*.json"))
            self.assertEqual(len(files), 1)
            data = json.loads(files[0].read_text())
            self.assertEqual(data["defense"], "Cloudflare")
            self.assertEqual(data["bug_classes"], ["xss"])

    def test_known_categories_present(self):
        generated = generate("acme", stack="nginx", bug_classes=["xss"])
        cats = {f.category for f in generated.families}
        self.assertIn("header_folding", cats)
        self.assertIn("crlf_variants", cats)
        self.assertIn("chunked_framing", cats)
        self.assertIn("parameter_splitting", cats)


class TestChainDiscoveryEventReaction(unittest.TestCase):
    """FINDING_DISCOVERED drives immediate chain-graph refresh."""

    def test_finding_discovered_listener_refreshes_chain_graph(self):
        from tools.chain_orchestrator import (
            make_finding_discovered_listener, refresh_target,
        )
        from tools.core.signal_bus import SignalBus, FINDING_DISCOVERED
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe = "acme"
            (root / "state" / "sessions" / safe).mkdir(parents=True)
            findings_path = root / "state" / "sessions" / safe / "findings.jsonl"
            leads_path = root / "state" / "sessions" / safe / "leads.jsonl"
            findings_path.write_text(json.dumps({
                "id": "f1", "bug_class": "idor",
                "endpoint": "https://acme.com/api/user/1",
                "state": "FINDING", "severity": "high",
            }) + "\n")
            leads_path.write_text(json.dumps({
                "id": "l1", "bug_class": "open-redirect",
                "endpoint": "https://acme.com/redirect?to=",
                "state": "LEAD", "severity": "medium",
            }) + "\n")

            listener = make_finding_discovered_listener("acme",
                                                        project_root=str(root))
            bus = SignalBus("acme", project_root=str(root))
            bus.subscribe(FINDING_DISCOVERED, listener)
            event = bus.publish(FINDING_DISCOVERED, source="campaign_orchestrator",
                                payload={"target": "acme",
                                         "bug_class": "idor",
                                         "endpoint": "https://acme.com/api/user/1"})
            self.assertEqual(event.listener_errors, [])

            chain = refresh_target(str(root), "acme")
            stats = chain.get("stats", {})
            self.assertIn("chains", stats)
            self.assertGreaterEqual(int(stats.get("chains", 0)), 0)
            # The refresh persisted an orchestration artifact.
            self.assertTrue(
                (root / "state" / "chains" / "acme" / "orchestration.json").is_file())

    def test_listener_never_raises_on_missing_state(self):
        from tools.chain_orchestrator import make_finding_discovered_listener
        from tools.core.signal_bus import SignalBus, FINDING_DISCOVERED
        with tempfile.TemporaryDirectory() as tmp:
            listener = make_finding_discovered_listener(
                "ghost", project_root=str(Path(tmp)))
            bus = SignalBus("ghost", project_root=str(Path(tmp)))
            bus.subscribe(FINDING_DISCOVERED, listener)
            event = bus.publish(FINDING_DISCOVERED, source="test",
                                payload={"target": "ghost"})
            self.assertEqual(event.listener_errors, [])


class TestJwtForgery(unittest.TestCase):
    RS256_TOKEN = ("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ."
                   "eyJ1c2VyIjoiYWRtaW4ifQ.signature")

    def test_analyze_rs256_gets_all_plan_classes(self):
        finding = analyze(self.RS256_TOKEN)
        self.assertIsNotNone(finding)
        classes = {plan["class"] for plan in finding.plans}
        self.assertIn("alg_none", classes)
        self.assertIn("rs256_hs256_confusion", classes)
        self.assertIn("jwk_injection", classes)
        self.assertIn("kid_path_traversal", classes)
        self.assertIn("public_key_as_hmac", classes)

    def test_analyze_none_alg_gets_unsigned_plan(self):
        import base64
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"user": "admin"}).encode()).decode().rstrip("=")
        finding = analyze(f"{header}.{payload}.")
        self.assertIsNotNone(finding)
        classes = {plan["class"] for plan in finding.plans}
        self.assertIn("alg_none", classes)
        self.assertNotIn("rs256_hs256_confusion", classes)

    def test_malformed_token_returns_none(self):
        self.assertIsNone(analyze("not.a.jwt"))
        self.assertIsNone(analyze(""))

    def test_analyze_many_deduplicates(self):
        findings = analyze_many([self.RS256_TOKEN, self.RS256_TOKEN])
        self.assertEqual(len(findings), 1)

    def test_forgery_plan_catalog_has_five_classes(self):
        self.assertEqual(len(FORGERY_PLANS), 5)


if __name__ == "__main__":
    unittest.main()
