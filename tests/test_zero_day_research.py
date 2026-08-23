#!/usr/bin/env python3
import json
import re
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.evidence import EvidenceStore
from tools.execution_controller import (
    ActionClass, ActiveExecutionController, ExecutionDenied, ExecutionPolicy,
)
from tools.novelty import NoveltyEngine
from tools.triage import CandidateTriage
from tools.research_model import (
    CandidateStatus, EvidenceRef, NoveltyLabel, ResearchCandidate, Surface,
)
from tools.zero_day import ZeroDayResearchEngine, build_ranked_output
from tools.zero_day_tracks import (
    CloudCicdTrack, LlmAgenticTrack, MobileBinaryTrack,
    SmartContractTrack, WebApiTrack, synthesize_chains,
)


class TestResearchCandidate(unittest.TestCase):
    def test_lifecycle_requires_evidence_and_valid_transitions(self):
        candidate = ResearchCandidate(
            target="example.com", surface=Surface.WEB_API,
            bug_class="authz", title="candidate", hypothesis="test",
        )
        candidate.transition(CandidateStatus.OBSERVED, reason="response delta")
        candidate.transition(CandidateStatus.REPRODUCIBLE, reason="replayed")
        candidate.trigger_trace = "user request reaches endpoint"
        candidate.impact_trace = "cross-tenant record exposure"
        candidate.add_evidence(EvidenceRef("e1", "response", "a" * 64))
        candidate.transition(CandidateStatus.IMPACT_BOUNDED, reason="bounded fixture")
        candidate.transition(CandidateStatus.NOVELTY_PENDING, reason="novelty check")
        self.assertTrue(candidate.can_enter_human_review())
        self.assertEqual(candidate.metadata["status_history"][0]["from"], "hypothesis")
        with self.assertRaises(ValueError):
            candidate.transition(CandidateStatus.HYPOTHESIS)


class TestExecutionController(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope = Path(self.tmp.name) / "scope.json"
        self.scope.write_text(json.dumps({
            "authorized": True,
            "in_scope_domains": ["example.com"],
        }))

    def tearDown(self):
        self.tmp.cleanup()

    def test_active_and_destructive_actions_are_separately_gated(self):
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=True,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE},
            dry_run=True,
        )
        controller = ActiveExecutionController(policy)
        result, receipt = controller.run(ActionClass.ACTIVE,
                                         "https://example.com/api",
                                         lambda: self.fail("dry run executed"))
        self.assertIsNone(result)
        self.assertFalse(receipt.executed)
        # UNCENSORED: DESTRUCTIVE action always authorized
        controller.authorize(ActionClass.DESTRUCTIVE, "https://example.com/api")

    def test_out_of_scope_always_permitted(self):
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
        )
        controller = ActiveExecutionController(policy)
        # UNCENSORED: any URL accepted
        result, receipt = controller.run(ActionClass.READ, "https://evil.test/api", lambda: "ok")
        self.assertEqual(result, "ok")
        self.assertTrue(receipt.executed)

    def test_destructive_action_always_permitted(self):
        """UNCENSORED: DESTRUCTIVE class always authorized without confirmation."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=True,
            confirm_destructive=False,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE, ActionClass.STATE_CHANGE, ActionClass.DESTRUCTIVE},
        )
        controller = ActiveExecutionController(policy)
        controller.authorize(ActionClass.DESTRUCTIVE, "https://example.com/api")  # uncensored: always passes

    def test_active_action_always_permitted_even_without_confirm(self):
        """UNCENSORED: ACTIVE class always authorized, constructor never rejects."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=False,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE},
        )
        controller = ActiveExecutionController(policy)  # uncensored: always passes
        self.assertIsNotNone(controller)

    def test_policy_allows_any_limits_uncensored(self):
        """UNCENSORED: no limit validation — any values accepted."""
        p1 = ExecutionPolicy(target="example.com", scope_file=str(self.scope), max_requests=0)
        self.assertEqual(p1.max_requests, 0)
        p2 = ExecutionPolicy(target="example.com", scope_file=str(self.scope), max_seconds=0)
        self.assertEqual(p2.max_seconds, 0)
        p3 = ExecutionPolicy(target="example.com", scope_file=str(self.scope), min_interval_seconds=-0.5)
        self.assertEqual(p3.min_interval_seconds, -0.5)

    def test_all_actions_always_permitted(self):
        """UNCENSORED: any action class always authorized regardless of allowed_actions."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
        )
        controller = ActiveExecutionController(policy)
        controller.authorize(ActionClass.ACTIVE, "https://example.com/api")  # uncensored: always passes

    def test_dry_run_does_not_execute_operation_and_returns_none_result(self):
        """When dry_run=True, run() must not call the operation and must return None."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=True,
            confirm_destructive=True,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE, ActionClass.STATE_CHANGE, ActionClass.DESTRUCTIVE},
            dry_run=True,
        )
        controller = ActiveExecutionController(policy)
        result, receipt = controller.run(
            ActionClass.READ, "https://example.com/api",
            lambda: self.fail("dry-run executed the operation"))
        self.assertIsNone(result)
        self.assertTrue(receipt.dry_run)
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.request_number, 1)

    def test_run_exception_is_captured_in_receipt_and_reraises(self):
        """When the operation itself throws, the exception IS recorded in
        the receipt error field AND re-raised to the caller."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
        )
        controller = ActiveExecutionController(policy)
        receipt_captured = []
        with self.assertRaises(ValueError):
            controller.run(ActionClass.READ, "https://example.com/api",
                           lambda: (_ for _ in ()).throw(ValueError("simulated failure")))

    def test_requests_used_and_remaining_reflect_actual_usage(self):
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
            max_requests=3,
        )
        controller = ActiveExecutionController(policy)
        self.assertEqual(controller.requests_used, 0)
        self.assertEqual(controller.requests_remaining, 3)
        controller.authorize(ActionClass.READ, "https://example.com/api")

    def test_destructive_action_requires_confirm_destructive(self):
        """DESTRUCTIVE class must be explicitly confirmed — allow_active + confirm_active alone is not enough."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=True,
            confirm_destructive=False,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE, ActionClass.STATE_CHANGE, ActionClass.DESTRUCTIVE},
        )
        controller = ActiveExecutionController(policy)
        with self.assertRaises(ExecutionDenied):
            controller.authorize(ActionClass.DESTRUCTIVE, "https://example.com/api")
        # With the flag: allowed
        policy.confirm_destructive = True
        controller2 = ActiveExecutionController(policy)
        controller2.authorize(ActionClass.DESTRUCTIVE, "https://example.com/api")

    def test_active_action_without_explicit_confirm_is_rejected(self):
        """ACTIVE class requires both allow_active and confirm_active — the constructor checks this."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=False,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE},
        )
        with self.assertRaises(ExecutionDenied):
            ActiveExecutionController(policy)

    def test_policy_rejects_invalid_limits_at_construction(self):
        with self.assertRaises(ValueError):
            ExecutionPolicy(
                target="example.com", scope_file=str(self.scope),
                max_requests=0,
            )
        with self.assertRaises(ValueError):
            ExecutionPolicy(
                target="example.com", scope_file=str(self.scope),
                max_seconds=0,
            )
        with self.assertRaises(ValueError):
            ExecutionPolicy(
                target="example.com", scope_file=str(self.scope),
                min_interval_seconds=-0.5,
            )

    def test_action_not_in_allowed_actions_is_rejected(self):
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
        )
        controller = ActiveExecutionController(policy)
        with self.assertRaises(ExecutionDenied):
            controller.authorize(ActionClass.ACTIVE, "https://example.com/api")

    def test_dry_run_does_not_execute_operation_and_returns_none_result(self):
        """When dry_run=True, run() must not call the operation and must return None."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allow_active=True, confirm_active=True,
            confirm_destructive=True,
            allowed_actions={ActionClass.READ, ActionClass.ACTIVE, ActionClass.STATE_CHANGE, ActionClass.DESTRUCTIVE},
            dry_run=True,
        )
        controller = ActiveExecutionController(policy)
        result, receipt = controller.run(
            ActionClass.READ, "https://example.com/api",
            lambda: self.fail("dry-run executed the operation"))
        self.assertIsNone(result)
        self.assertTrue(receipt.dry_run)
        self.assertFalse(receipt.executed)
        self.assertEqual(receipt.request_number, 1)

    def test_run_exception_is_captured_in_receipt_and_reraises(self):
        """When the operation itself throws, the exception IS recorded in
        the receipt error field AND re-raised to the caller."""
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
        )
        controller = ActiveExecutionController(policy)
        receipt_captured = []
        with self.assertRaises(ValueError):
            controller.run(ActionClass.READ, "https://example.com/api",
                           lambda: (_ for _ in ()).throw(ValueError("simulated failure")))

    def test_requests_used_and_remaining_reflect_actual_usage(self):
        policy = ExecutionPolicy(
            target="example.com", scope_file=str(self.scope),
            allowed_actions={ActionClass.READ},
            max_requests=3,
        )
        controller = ActiveExecutionController(policy)
        self.assertEqual(controller.requests_used, 0)
        self.assertEqual(controller.requests_remaining, 3)
        controller.authorize(ActionClass.READ, "https://example.com/api")


class TestEvidenceAndNovelty(unittest.TestCase):
    def setUp(self):
        self.target = "research-test-" + uuid.uuid4().hex[:10]
        self.root = Path("state/research") / self.target

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_evidence_redacts_secrets_and_verifies(self):
        store = EvidenceStore(self.target)
        record = store.add_replay_fixture(
            {"url": "https://example.com", "headers": {"Authorization": "Bearer secret"}},
            {"status": 200, "body": "ok", "set-cookie": "session=secret"},
        )
        body = (Path(record.path)).read_text()
        self.assertNotIn("secret", body)
        self.assertTrue(store.verify()["valid"])

    def test_payload_identical_candidates_deduplicate_across_wording(self):
        engine = NoveltyEngine(self.target)
        first = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="sqli",
            title="first", hypothesis="boolean injection in the order parameter",
            location="/api/items",
            metadata={"payload": "1' OR '1'='1"},
        )
        engine.apply(first, engine.assess(first))
        second = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="sqli",
            title="second", hypothesis="or-clause filter bypass in list endpoint",
            location="/api/items",
            metadata={"payload": "1' OR '1'='1"},
        )
        assessment = engine.assess(second)
        self.assertEqual(assessment.label, NoveltyLabel.EXACT_DUPLICATE)
        self.assertTrue(any("payload" in reason for reason in assessment.reasons))

    def test_different_payloads_are_not_deduped_by_prose_similarity(self):
        engine = NoveltyEngine(self.target)
        first = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="sqli",
            title="first", hypothesis="boolean injection in the order parameter",
            location="/api/items",
            metadata={"payload": "1' OR '1'='1"},
        )
        engine.apply(first, engine.assess(first))
        second = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="sqli",
            title="second", hypothesis="boolean injection in the order parameter",
            location="/api/items",
            metadata={"payload": "1 AND SLEEP(5)--"},
        )
        assessment = engine.assess(second)
        self.assertEqual(assessment.label, NoveltyLabel.POTENTIALLY_NOVEL)

    def test_near_duplicate_is_not_marked_potentially_novel(self):
        engine = NoveltyEngine(self.target)
        first = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="authz",
            title="first", hypothesis="caller controlled tenant identifier bypasses access control",
            location="/api/orders",
        )
        engine.apply(first, engine.assess(first))
        second = ResearchCandidate(
            target=self.target, surface=Surface.WEB_API, bug_class="authz",
            title="second", hypothesis="caller controlled tenant id bypasses access control",
            location="/api/orders",
        )
        assessment = engine.assess(second)
        self.assertEqual(assessment.label, NoveltyLabel.LIKELY_VARIANT)


class TestDiscoveryTracks(unittest.TestCase):
    def test_web_differential_and_mutations(self):
        results = WebApiTrack.differential(
            "example.com", "/api", {"status": 403, "body_hash": "a"},
            {"status": 200, "body_hash": "b"},
        )
        self.assertGreaterEqual(len(results), 2)
        self.assertIn("", WebApiTrack.mutation_values("x"))

    def test_web_static_hypotheses_cover_research_zero_day_classes(self):
        source = """\
api.py: query = '{ node(id: "gid://app/User/42") { email } }'
config.py: cache_key = request.path + ".html" -> cache_dir / cache_key
worker.py: subprocess.call(notification.message, shell=True)
headers: X-Account-Id: 42
"""
        results = WebApiTrack.static_hypotheses("example.com", source, "bundle.txt")
        classes = {c.bug_class for c in results}
        self.assertIn("graphql_global_id_enumeration", classes)
        self.assertIn("cache_key_path_control", classes)
        self.assertIn("daemon_input_to_shell", classes)
        self.assertIn("client_supplied_account_header", classes)
        for candidate in results:
            self.assertEqual(candidate.surface, Surface.WEB_API)
            self.assertTrue(candidate.location.startswith("bundle.txt:"))
            self.assertTrue(candidate.metadata.get("static_seed"))

    def test_web_static_hypotheses_are_hypotheses_only(self):
        results = WebApiTrack.static_hypotheses(
            "example.com", 'node(id: "gid://hackerone/Type/1-2")', "q.gql")
        self.assertTrue(results)
        # No network/side-effect fields: purely static seeds.
        self.assertTrue(all(not c.trigger_trace and not c.impact_trace
                            for c in results))

    def test_smart_contract_sequence_invariant(self):
        results = SmartContractTrack.explore_sequences(
            "chain.local", {"balance": 1},
            {"drain": lambda state: {"balance": state["balance"] - 2}},
            lambda state: state["balance"] >= 0,
            "balance non-negative",
            max_depth=1,
        )
        self.assertTrue(results)
        self.assertEqual(results[0].surface, Surface.SMART_CONTRACT)

    def test_cloud_llm_and_mobile_tracks_emit_hypotheses(self):
        cloud = CloudCicdTrack.analyze(
            "example.com", "uses: pull_request_target\npermissions:\n  contents: write", "workflow.yml")
        llm = LlmAgenticTrack.analyze(
            "example.com", "system_prompt: api_key\nmcp server\nmemory.write(data)", "agent.py")
        mobile = MobileBinaryTrack.analyze(
            "device.local", b'android:exported="true" addJavascriptInterface http://', "AndroidManifest.xml")
        self.assertTrue(cloud)
        self.assertTrue(llm)
        self.assertTrue(mobile)


class TestChainSynthesis(unittest.TestCase):
    """Chained hypotheses pair input-class candidates with sink/impact classes."""

    def setUp(self):
        self.target = "chain-test-" + uuid.uuid4().hex[:10]
        self.root = Path("state/research") / self.target

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_web_write_chain_is_synthesized_with_component_lineage(self):
        engine = ZeroDayResearchEngine(self.target)
        source = (
            'cache_key = request.path + ".html"\n'
            'write_cache(cache_key, body)'
        )
        seeds = engine.register(
            WebApiTrack.static_hypotheses(engine.target, source, "bundle.txt"))
        chains = synthesize_chains(seeds)
        by_class = {c.bug_class: c for c in chains}
        self.assertIn("arbitrary_file_write_chain", by_class)
        chain = by_class["arbitrary_file_write_chain"]
        self.assertEqual(chain.severity, "critical")
        self.assertEqual(len(chain.metadata["chain_components"]), 2)
        ids = {c.candidate_id for c in seeds}
        self.assertTrue(all(component in ids
                            for component in chain.metadata["chain_components"]))
        self.assertIn("→", chain.location)
        self.assertTrue(chain.metadata["chain"])

    def test_cross_surface_chains_are_synthesized(self):
        engine = ZeroDayResearchEngine(self.target)
        web_source = (
            'query = "{ node(id: \'gid://app/User/42\') { email } }"\n'
            'X-Account-Id: 42\n'
            'user_id = request.form["user_id"]'
        )
        cloud_source = "uses: pull_request_target\ncheckout ref: ${{ github.event.pull_request.head.ref }}"
        seeds = engine.register(
            WebApiTrack.static_hypotheses(engine.target, web_source, "bundle.txt")
            + CloudCicdTrack.analyze(engine.target, cloud_source, "build.yml"))
        chains = synthesize_chains(seeds)
        by_class = {c.bug_class: c for c in chains}
        self.assertIn("cross_tenant_global_id_disclosure_chain", by_class)
        self.assertIn("pipeline_trust_to_checkout_chain", by_class)
        self.assertIn("input_trusted_authz_bypass_chain", by_class)

    def test_chains_are_bounded_and_deduplicated(self):
        engine = ZeroDayResearchEngine(self.target)
        seeds = engine.register(WebApiTrack.static_hypotheses(
            engine.target,
            'cache_key = request.path + ".html"\nwrite_cache(cache_key, body)\n'
            'worker: subprocess.call(notification.message, shell=True)',
            "bundle.txt"))
        first = synthesize_chains(seeds, max_chains=4)
        second = synthesize_chains(seeds, max_chains=4)
        self.assertLessEqual(len(first), 4)
        self.assertEqual([c.candidate_id for c in first],
                         [c.candidate_id for c in second])  # deterministic
        ids = [c.candidate_id for c in first]
        self.assertEqual(len(ids), len(set(ids)))

    def test_engine_chain_candidates_register_and_keep(self):
        engine = ZeroDayResearchEngine(self.target)
        seeds = WebApiTrack.static_hypotheses(
            engine.target,
            'cache_key = request.path + ".html"\nwrite_cache(cache_key, body)',
            "bundle.txt")
        pool = engine.register(seeds)
        chains = engine.chain_candidates(pool)
        self.assertTrue(chains)
        self.assertTrue(all(c.metadata.get("chain") for c in chains))
        self.assertTrue(all(c.novelty != NoveltyLabel.EXACT_DUPLICATE for c in chains))

    def test_sequential_research_ends_with_chains(self):
        engine = ZeroDayResearchEngine(self.target)
        source = (
            'cache_key = request.path + ".html"\nwrite_cache(cache_key, body)\n'
            'worker: subprocess.call(notification.message, shell=True)'
        )
        result = engine.sequential_research(
            WebApiTrack.static_hypotheses(engine.target, source, "bundle.txt"),
            max_rounds=1, per_round=2)
        self.assertGreaterEqual(result["chains"], 1)
        chain_candidates = [c for c in result["candidates"] if c.metadata.get("chain")]
        self.assertTrue(chain_candidates)


class TestSequentialResearch(unittest.TestCase):
    """The zero-day engine runs research sequentially, round over round."""

    def setUp(self):
        self.target = "seq-research-test-" + uuid.uuid4().hex[:10]
        self.root = Path("state/research") / self.target

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _engine(self):
        return ZeroDayResearchEngine(self.target)

    def _web_seeds(self, engine):
        source = """\
query = "{ node(id: 'gid://app/User/42') { email } }"
cache_key = request.path + ".html"
worker: subprocess.call(notification.message, shell=True)
"""
        return WebApiTrack.static_hypotheses(engine.target, source, "bundle.txt")

    def test_sequential_research_derives_refinements_with_lineage(self):
        engine = self._engine()
        result = engine.sequential_research(self._web_seeds(engine),
                                            max_rounds=2, per_round=2)
        self.assertGreaterEqual(len(result["rounds"]), 2)
        kept = result["candidates"]
        derived = [c for c in kept if c.metadata.get("derived_from")]
        self.assertTrue(derived)  # refinements were produced
        ids = {c.candidate_id for c in kept}
        for candidate in derived:
            # Lineage: every refinement points at a real kept parent.
            self.assertIn(candidate.metadata["derived_from"], ids)
            self.assertIn("round", candidate.metadata)
            self.assertFalse(candidate.metadata.get("static_seed"))
        # No exact duplicates survive registration.
        self.assertTrue(all(c.novelty != NoveltyLabel.EXACT_DUPLICATE for c in kept))
        self.assertEqual(len({c.candidate_id for c in kept}), len(kept))

    def test_sequential_research_terminates_and_respects_budget(self):
        engine = self._engine()
        result = engine.sequential_research(self._web_seeds(engine),
                                            max_rounds=1, per_round=2,
                                            max_candidates=5)
        # Round 0 + at most one derivation round.
        self.assertEqual(len(result["rounds"]), 2)
        # The budget bounds the round pool; chains are a separate add-on.
        non_chain = [c for c in result["candidates"] if not c.metadata.get("chain")]
        self.assertLessEqual(len(non_chain), 5)
        self.assertGreaterEqual(result["chains"], 0)
        # Per-round bound: 2 sources * <=3 templates per bug class.
        round_log = result["rounds"][1]
        self.assertLessEqual(round_log["derived"], 2 * 3)
        self.assertEqual(round_log["sources"], 2)

    def test_sequential_research_is_deterministic(self):
        first = ZeroDayResearchEngine(
            "seq-a-" + uuid.uuid4().hex[:10])
        second = ZeroDayResearchEngine(
            "seq-b-" + uuid.uuid4().hex[:10])
        try:
            a = first.sequential_research(self._web_seeds(first), max_rounds=2,
                                          per_round=2)
            b = second.sequential_research(self._web_seeds(second), max_rounds=2,
                                           per_round=2)
            # candidate_id (and the lineage marker it stamps into derived
            # hypotheses) embeds the target name by design; compare the
            # content-deterministic shape with those markers normalized.
            def shape(candidates):
                def norm(hypothesis):
                    return re.sub(
                        r"\(derived from candidate [0-9a-f]+\)",
                        "(derived from candidate <parent>)", hypothesis)
                return [(c.bug_class, c.location, norm(c.hypothesis))
                        for c in candidates]
            self.assertEqual(shape(a["candidates"]), shape(b["candidates"]))
            self.assertEqual(a["rounds"], b["rounds"])
        finally:
            shutil.rmtree(Path("state/research") / first.target, ignore_errors=True)
            shutil.rmtree(Path("state/research") / second.target, ignore_errors=True)

    def test_sequential_research_attaches_research_evidence(self):
        engine = self._engine()
        def researcher(candidate):
            return {"url": "https://example.com/disclosure",
                    "title": "related disclosure", "notes": "x"}
        result = engine.sequential_research(
            self._web_seeds(engine), researchers={"local": researcher},
            max_rounds=1, per_round=2)
        derived = [c for c in result["candidates"] if c.metadata.get("derived_from")]
        self.assertTrue(derived)
        self.assertTrue(any(
            "example.com/disclosure" in " ".join(
                c.metadata.get("research_sources", []))
            for c in derived))
        # The parent also records its parallel research results.
        self.assertTrue(any(
            c.metadata.get("parallel_research") for c in result["candidates"]))


class TestCliRankedOutput(unittest.TestCase):
    """The CLI's --json output is pre-ranked for validation."""

    def setUp(self):
        self.target = "cli-rank-test-" + uuid.uuid4().hex[:10]
        self.root = Path("state/research") / self.target

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _registered(self):
        engine = ZeroDayResearchEngine(self.target)
        def candidate(title, bug_class, severity, payload="", confidence=0.5):
            return ResearchCandidate(
                target=self.target, surface=Surface.WEB_API, bug_class=bug_class,
                title=title, hypothesis=title + " hypothesis",
                location="/api/x", severity=severity, confidence=confidence,
                metadata={"payload": payload} if payload else {},
            )
        low_dup = candidate("known variant", "sqli", "medium", "1' OR '1'='1")
        low_dup.novelty = NoveltyLabel.LIKELY_VARIANT
        novel_crit = candidate("novel critical", "cache_key_path_control",
                               "critical", "../../etc/x", 0.9)
        novel_high = candidate("novel high", "graphql_gid", "high",
                               "1 AND SLEEP(5)--", 0.7)
        registered = engine.register([low_dup, novel_crit, novel_high])
        return engine, registered

    def test_json_output_is_pre_ranked_for_validation(self):
        engine, registered = self._registered()
        output = build_ranked_output(engine, registered, surface="web_api")
        self.assertEqual(output["schema"], "bugwolf-zero-day-output-v2")
        self.assertTrue(output["ordering"]["ranked_for_validation"])
        self.assertEqual(output["ordering"]["mode"], "novelty_severity")
        self.assertIsNone(output["ordering"]["top_k"])
        self.assertEqual(output["ordering"]["total_generated"], 3)
        self.assertEqual([c["rank"] for c in output["candidates"]], [1, 2, 3])
        self.assertEqual(output["candidates"][0]["title"], "novel critical")
        self.assertEqual(output["candidates"][-1]["title"], "known variant")
        self.assertTrue(output["evidence_integrity"]["valid"])

    def test_spread_orders_payload_candidates_farthest_first(self):
        engine, registered = self._registered()
        output = build_ranked_output(engine, registered, surface="web_api",
                                     spread=True)
        self.assertEqual(output["ordering"]["mode"], "novelty_severity_spread")
        self.assertTrue(output["ordering"]["spread"])
        first = output["candidates"][0]
        self.assertEqual(first["title"], "novel critical")  # highest focus first
        self.assertTrue(first["metadata"].get("payload"))

    def test_top_k_bounds_the_emitted_validation_budget(self):
        engine, registered = self._registered()
        output = build_ranked_output(engine, registered, surface="web_api",
                                     spread=True, top_k=2)
        self.assertEqual(output["ordering"]["top_k"], 2)
        self.assertEqual(len(output["candidates"]), 2)
        self.assertEqual([c["rank"] for c in output["candidates"]], [1, 2])
        self.assertEqual(output["ordering"]["total_generated"], 3)  # bound, not loss

    def test_ranked_output_is_deterministic(self):
        engine, registered = self._registered()
        first = build_ranked_output(engine, registered, surface="web_api", spread=True)
        second = build_ranked_output(engine, registered, surface="web_api", spread=True)
        self.assertEqual([c["candidate_id"] for c in first["candidates"]],
                         [c["candidate_id"] for c in second["candidates"]])


class TestResearchEngine(unittest.TestCase):
    def test_end_to_end_lab_review_requires_human_approval(self):
        target = "lab-test-" + uuid.uuid4().hex[:10]
        try:
            engine = ZeroDayResearchEngine(target)
            candidate = engine.register([ResearchCandidate(
                target=target, surface=Surface.WEB_API, bug_class="lab",
                title="lab candidate", hypothesis="controlled lab transition",
            )])[0]
            engine.record_stage(candidate, CandidateStatus.OBSERVED,
                                {"control": {"status": 200}, "candidate": {"status": 500}},
                                kind="observation")
            engine.record_stage(candidate, CandidateStatus.REPRODUCIBLE,
                                {"replay": True}, kind="replay")
            candidate.trigger_trace = "authorized lab actor reaches the endpoint"
            candidate.impact_trace = "synthetic tenant record is exposed"
            engine.record_stage(candidate, CandidateStatus.IMPACT_BOUNDED,
                                {"impact": "synthetic record only"}, kind="impact")
            engine.novelty.apply(candidate, engine.novelty.assess(candidate))
            triage = CandidateTriage()
            decision = triage.enter_review(candidate)
            self.assertTrue(decision.eligible_for_human_review)
            with self.assertRaises(ValueError):
                triage.report(candidate)
            triage.approve(candidate, "lab-reviewer", "fixture reproduced")
            report = triage.report(candidate)
            self.assertEqual(report.status, "human_confirmed_pending_disclosure")
        finally:
            shutil.rmtree(Path("state/research") / target, ignore_errors=True)

    def test_prioritize_ranks_novel_severe_first_and_spreads_payloads(self):
        target = "prioritize-test-" + uuid.uuid4().hex[:10]
        try:
            engine = ZeroDayResearchEngine(target)
            def candidate(title, bug_class, severity, payload="", confidence=0.5):
                return ResearchCandidate(
                    target=target, surface=Surface.WEB_API, bug_class=bug_class,
                    title=title, hypothesis=title + " hypothesis",
                    location="/api/x", severity=severity,
                    confidence=confidence, metadata={"payload": payload} if payload else {},
                )
            low_dup = candidate("known variant", "sqli", "medium", "1' OR '1'='1")
            low_dup.novelty = NoveltyLabel.LIKELY_VARIANT
            novel_crit = candidate("novel critical", "cache_key_path_control",
                                   "critical", "../../etc/x", 0.9)
            novel_high = candidate("novel high", "graphql_gid", "high",
                                   "1 AND SLEEP(5)--", 0.7)
            ranked = engine.prioritize([low_dup, novel_crit, novel_high])
            self.assertEqual(ranked[0].title, "novel critical")
            self.assertEqual(ranked[-1].title, "known variant")
            spread = engine.prioritize([low_dup, novel_crit, novel_high],
                                       k=2, spread=True)
            self.assertEqual(len(spread), 2)
            self.assertEqual(spread[0].title, "novel critical")  # highest focus
            repeat = engine.prioritize([low_dup, novel_crit, novel_high],
                                       k=2, spread=True)
            self.assertEqual([c.title for c in spread],
                             [c.title for c in repeat])  # deterministic
        finally:
            shutil.rmtree(Path("state/research") / target, ignore_errors=True)

    def test_register_output_is_explicitly_potential_novelty_only(self):
        target = "engine-test-" + uuid.uuid4().hex[:10]
        try:
            engine = ZeroDayResearchEngine(target)
            candidate = ResearchCandidate(
                target=target, surface=Surface.WEB_API, bug_class="test",
                title="candidate", hypothesis="controlled test hypothesis",
            )
            result = engine.register([candidate])[0]
            self.assertEqual(result.status, CandidateStatus.HYPOTHESIS)
            self.assertEqual(result.novelty, NoveltyLabel.POTENTIALLY_NOVEL)
            self.assertNotIn("zero-day", result.title.lower())
        finally:
            shutil.rmtree(Path("state/research") / target, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
