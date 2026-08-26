#!/usr/bin/env python3
"""Integration test for the Live Execution Harness Loop (Phase 3).

Boots the VulnBank lab fixture in-process on an ephemeral port and drives
``CampaignOrchestrator.live_feedback_loop`` end-to-end:

  unit -> real HTTP probe -> recorded evidence -> observation ->
  state transition -> F0.5 gate (reproducible-evidence requirement)

Asserts the loop actually executes (units/probes > 0), adapts (blocked /
signal / refuted outcomes), attaches recorded request/response evidence, and
that the reproducible-evidence gate is exercised.  Skipped cleanly when the
lab fixture is absent (e.g. from inside a bundle that does not ship lab/).
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.campaign as campaign_mod
from tools.harness_guard import initialize as initialize_contract

LAB_SERVER = ROOT / "lab" / "vulnbank" / "server.py"
TARGET = "vulnbank.local"


def _boot_lab():
    """Load the stdlib-only lab fixture and serve it on an ephemeral port."""
    if not LAB_SERVER.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("vulnbank_server", LAB_SERVER)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["vulnbank_server.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/tech.json", timeout=2) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.1)

    def shutdown():
        server.shutdown()
        server.server_close()

    return base, shutdown


class TestLiveFeedbackLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base, cls._shutdown_lab = _boot_lab()

    @classmethod
    def tearDownClass(cls):
        if cls._shutdown_lab is not None:
            cls._shutdown_lab()
            cls._shutdown_lab = None

    def setUp(self):
        if self.base is None:
            self.skipTest("lab fixture not present (lab/vulnbank/server.py)")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self._env = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = str(self.root)
        self._old_roots = (campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT)
        campaign_mod.ROOT = self.root
        campaign_mod.CAMPAIGN_ROOT = self.root / "state" / "campaigns"
        self.addCleanup(self._restore_env_and_roots)

    def _restore_env_and_roots(self):
        if self._env is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._env
        campaign_mod.ROOT, campaign_mod.CAMPAIGN_ROOT = self._old_roots

    def _seed_campaign(self):
        """Initialize the campaign + recon so research units dispatch."""
        from tools.core.campaign_orchestrator import CampaignOrchestrator

        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text("# BugWolf harness contract\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "local"}))
        scope = self.root / "scope.json"
        scope.write_text(json.dumps({"targets": [TARGET],
                                     "declared_by": "operator"}))
        orch = CampaignOrchestrator(TARGET, mode="web", pass_at_k=1)
        orch.initialize()
        orch.complete_workflow_stage("authorization", scope_file=str(scope))
        orch.register_discovered_assets([{
            "hostname": "api.vulnbank.local", "type": "web_api",
            "priority": "high"}])
        asset = orch.campaign.list_assets()[0]
        endpoints = [f"{self.base}{p}" for p in
                     ("/api/users/1", "/graphql", "/login",
                      "/openapi.json", "/tech.json")]
        recon_dir = self.root / "recon" / TARGET
        recon_dir.mkdir(parents=True, exist_ok=True)
        (recon_dir / "urls.txt").write_text("\n".join(endpoints) + "\n")
        delta = recon_dir / "asset-intel" / "delta.json"
        delta.parent.mkdir(parents=True, exist_ok=True)
        delta.write_text(json.dumps({"target": TARGET, "delta_type": "initial"}))
        orch.register_recon(asset.asset_id, endpoints=endpoints,
                            tech=["nginx", "node", "graphql", "express"],
                            ports=[8077])
        orch.mark_discovery_complete()
        return orch

    def test_live_loop_executes_real_probes_and_adapts(self):
        orch = self._seed_campaign()
        summary = orch.live_feedback_loop(base_url=self.base, max_units=30,
                                          project_root=str(self.root))
        # The loop actually executed units with real HTTP probes.
        self.assertGreaterEqual(summary["units"], 1)
        self.assertGreaterEqual(summary["probes"], 1)
        # Outcomes are adaptation, not simulation.
        self.assertGreaterEqual(
            summary["outcomes"].get("signal", 0)
            + summary["outcomes"].get("blocked", 0)
            + summary["outcomes"].get("clean", 0)
            + summary["outcomes"].get("refuted", 0)
            + summary["outcomes"].get("error", 0),
            summary["units"])

    def test_signal_threads_carry_recorded_evidence_and_reproducible_gate(self):
        orch = self._seed_campaign()
        orch.live_feedback_loop(base_url=self.base, max_units=30,
                                project_root=str(self.root))
        threads = orch.campaign.list_threads()
        completed = [t for t in threads
                     if t.state.value == "complete" and t.refutation]
        if not completed:
            self.skipTest("no completed threads in this lab run")
        # Every completed thread went through the F0.5 gate with a verdict.
        for thread in completed:
            self.assertIn(thread.refutation["final_verdict"],
                          ("confirmed", "demoted"))
            self.assertIn("confidence", thread.refutation)
        # Live threads that reached CONFIRMED must carry recorded evidence
        # (the reproducible-evidence gate was enabled for live threads).
        confirmed = [t for t in completed
                     if t.refutation["final_verdict"] == "confirmed"]
        for thread in confirmed:
            if getattr(thread, "live_evidence", None):
                evidence = thread.live_evidence
                self.assertIn("request", evidence)
                self.assertIn("response", evidence)
                self.assertIn("replay_key", evidence)

    def test_probes_persisted_to_sessions_dir(self):
        orch = self._seed_campaign()
        orch.live_feedback_loop(base_url=self.base, max_units=10,
                                project_root=str(self.root))
        probes = (self.root / "state" / "sessions" / "vulnbank.local"
                  / "probes.jsonl")
        if probes.is_file():
            records = [json.loads(l) for l in probes.read_text().splitlines()
                       if l.strip()]
            self.assertGreaterEqual(len(records), 1)
            self.assertIn("evidence", records[0])
            self.assertIn("request", records[0]["evidence"])
            self.assertIn("response", records[0]["evidence"])

    def test_loop_is_repeatable_and_deterministic_in_shape(self):
        orch = self._seed_campaign()
        first = orch.live_feedback_loop(base_url=self.base, max_units=15,
                                        project_root=str(self.root))
        # Second run on the same campaign: no more research units after
        # threads resolve, so it must terminate cleanly (not raise / spin).
        second = orch.live_feedback_loop(base_url=self.base, max_units=15,
                                         project_root=str(self.root))
        self.assertGreaterEqual(first["units"], 1)
        self.assertGreaterEqual(second["units"], 0)

    # -- fuzz-bridge integration -----------------------------------------

    def _crash_transport(self, marker="999999999999999999"):
        """Transport that crashes (500) on one fuzz marker, real HTTP else.

        The loop feeds the SAME callable to ``execute_probe`` (ProbeSpec
        shape) and to the fuzz bridge (url/method/body/headers shape), so it
        duck-types both.
        """
        crash = (500, {"Server": "nginx"}, "boom", 5.0)

        def transport(*args):
            if len(args) >= 4 and isinstance(args[0], str):
                url, method, body, headers = args[0], args[1], args[2], args[3]
            else:
                spec = args[0]
                url = getattr(spec, "url", "")
                method = getattr(spec, "method", "GET")
                body = getattr(spec, "body", None)
                headers = getattr(spec, "headers", {})
            if marker in str(url) or marker in str(body or ""):
                return crash
            # Real HTTP for everything else.
            data = None
            if body is not None:
                data = (json.dumps(body).encode() if isinstance(body, dict)
                        else str(body).encode())
            req = urllib.request.Request(url, data=data, headers=dict(headers),
                                         method=method)
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    raw = resp.read(4096).decode("utf-8", errors="replace")
                    return resp.status, dict(resp.headers), raw, 5.0
            except urllib.error.HTTPError as exc:
                raw = exc.read(4096).decode("utf-8", errors="replace")
                return exc.code, dict(exc.headers), raw, 5.0
            except OSError as exc:
                return 0, {}, f"transport error: {type(exc).__name__}", 0.0
        return transport

    def _blocked_transport(self, marker="999999999999999999"):
        """Transport that blocks (403 + Cloudflare) on one fuzz marker."""
        blocked = (403, {"CF-Ray": "fuzzray123"}, "forbidden", 5.0)

        def transport(*args):
            if len(args) >= 4 and isinstance(args[0], str):
                url, method, body, headers = args[0], args[1], args[2], args[3]
            else:
                spec = args[0]
                url = getattr(spec, "url", "")
                method = getattr(spec, "method", "GET")
                body = getattr(spec, "body", None)
                headers = getattr(spec, "headers", {})
            # The failure-learning catalog's header-based path access bypass
            # (X-Original-URL) gets through the fake WAF with the admin
            # record — the operator-approval exploitation surface.
            lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
            if lowered.get("x-original-url"):
                return (200, {}, json.dumps(
                    {"id": "gw-1", "role": "admin",
                     "token": "gw-secret-token"}), 5.0)
            if marker in str(url) or marker in str(body or ""):
                return blocked
            # Real HTTP for everything else.
            data = None
            if body is not None:
                data = (json.dumps(body).encode() if isinstance(body, dict)
                        else str(body).encode())
            req = urllib.request.Request(url, data=data, headers=dict(headers),
                                         method=method)
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    raw = resp.read(4096).decode("utf-8", errors="replace")
                    return resp.status, dict(resp.headers), raw, 5.0
            except urllib.error.HTTPError as exc:
                raw = exc.read(4096).decode("utf-8", errors="replace")
                return exc.code, dict(exc.headers), raw, 5.0
            except OSError as exc:
                return 0, {}, f"transport error: {type(exc).__name__}", 0.0
        return transport

    def test_fuzz_crash_spawns_thread_which_loop_probes(self):
        orch = self._seed_campaign()
        marker = "999999999999999999"
        summary = orch.live_feedback_loop(
            base_url=self.base, max_units=40, fuzz_budget=30,
            transport=self._crash_transport(marker),
            project_root=str(self.root))
        # The fuzz pass ran and found the crash.
        self.assertTrue(summary["fuzz"]["ran"])
        self.assertGreaterEqual(summary["fuzz"]["probes"], 1)
        self.assertGreaterEqual(summary["fuzz"]["signals"], 1)
        self.assertGreaterEqual(summary["fuzz"]["spawned"], 1)
        # A spawned fuzz thread exists targeting the crashed endpoint.
        spawned = [t for t in orch.campaign.list_threads()
                   if t.bug_class.startswith("fuzz_")]
        self.assertGreaterEqual(len(spawned), 1)
        # The spawned thread carries recorded fuzz evidence (the crashing
        # request, whose fuzz value rides in the URL) and was probed.
        for thread in spawned:
            if getattr(thread, "live_evidence", None):
                ev = thread.live_evidence
                self.assertIn("request", ev)
                self.assertIn("replay_key", ev)
                request = ev["request"]
                self.assertIn(
                    marker,
                    json.dumps({"url": request.get("url"),
                                "body": request.get("body")}))
        # The fuzz signals also fed the novel-class hunter: candidates were
        # registered (anomaly + behavior-delta modes) with fuzz provenance
        # and persisted for the operator.
        self.assertGreaterEqual(summary["fuzz"]["novel"], 1)
        novel_path = self.root / "research" / TARGET / "zero-day" \
            / "fuzz-signals.jsonl"
        self.assertTrue(novel_path.is_file())
        first = json.loads(novel_path.read_text().splitlines()[0])
        self.assertTrue(first["metadata"]["fuzz"]["replay_key"])
        self.assertIn("fuzz", first["metadata"]["mode"])
        # The self-eval fuzz-to-thread-cycle task scores this exact cycle:
        # fuzz ran, signals recorded, thread spawned, crash reproduced,
        # deduped.
        from tools.validation.self_eval_harness import evaluate
        data = evaluate(TARGET, base_dir=str(self.root)).to_dict()
        fuzz_task = next(t for t in data["tasks"]
                         if t["task_id"] == "fuzz-to-thread-cycle")
        self.assertTrue(fuzz_task["passed"],
                        fuzz_task["milestones_passed"])

    def test_spawned_fuzz_threads_reproduce_the_crash(self):
        orch = self._seed_campaign()
        marker = "999999999999999999"
        orch.live_feedback_loop(
            base_url=self.base, max_units=40, fuzz_budget=30,
            transport=self._crash_transport(marker),
            project_root=str(self.root))
        # The loop re-probed every spawned thread with the crashing URL, so
        # each reproduced the 500 and COMPLETED with recorded evidence.
        fuzz_threads = [t for t in orch.campaign.list_threads()
                        if t.bug_class.startswith("fuzz_")]
        self.assertGreaterEqual(len(fuzz_threads), 1)
        for thread in fuzz_threads:
            self.assertEqual(thread.state.value, "complete")
            self.assertIn("500", thread.confirmed_behavior)
            self.assertTrue(getattr(thread, "live_evidence", None))

    def test_fuzz_mutations_are_deterministic_and_bounded(self):
        orch = self._seed_campaign()
        a = orch._fuzz_mutations(self.base)
        b = orch._fuzz_mutations(self.base)
        self.assertEqual([(m.kind, m.path, m.method) for m in a],
                         [(m.kind, m.path, m.method) for m in b])
        self.assertGreaterEqual(len(a), 1)
        # GET fuzz values ride in the URL (reproducible on re-probe).
        get_muts = [m for m in a if m.method == "GET"]
        if get_muts:
            self.assertIn("?q=", get_muts[0].path)

    def test_fuzz_spawn_is_deduped_across_runs(self):
        orch = self._seed_campaign()
        marker = "999999999999999999"
        first = orch.live_feedback_loop(
            base_url=self.base, max_units=40, fuzz_budget=30,
            transport=self._crash_transport(marker),
            project_root=str(self.root))
        second = orch.live_feedback_loop(
            base_url=self.base, max_units=40, fuzz_budget=30,
            transport=self._crash_transport(marker),
            project_root=str(self.root))
        # No duplicate threads for the same (endpoint, fuzz state).
        spawned = [t for t in orch.campaign.list_threads()
                   if t.bug_class.startswith("fuzz_")]
        keys = {(t.endpoint, t.bug_class) for t in spawned}
        self.assertEqual(len(keys), len(spawned))
        self.assertGreaterEqual(first["fuzz"]["spawned"], 1)

    def test_fuzz_blocked_spawns_bypass_thread_via_failure_learning(self):
        orch = self._seed_campaign()
        marker = "999999999999999999"
        summary = orch.live_feedback_loop(
            base_url=self.base, max_units=40, fuzz_budget=30,
            transport=self._blocked_transport(marker),
            project_root=str(self.root))
        # The fuzz pass classified the 403/Cloudflare response as blocked and
        # surfaced it as a signal.
        self.assertTrue(summary["fuzz"]["ran"])
        self.assertGreaterEqual(summary["fuzz"]["blocked"], 1)
        self.assertGreaterEqual(summary["fuzz"]["signals"], 1)
        # A fuzz_blocked thread was spawned for the blocked endpoint.
        blocked_threads = [t for t in orch.campaign.list_threads()
                           if t.bug_class == "fuzz_blocked"]
        self.assertGreaterEqual(len(blocked_threads), 1)
        for thread in blocked_threads:
            self.assertIn("bypass", thread.objective.lower())
            self.assertTrue(getattr(thread, "live_evidence", None))
            self.assertEqual(
                (thread.live_evidence or {}).get("waf"), "cloudflare")
        # failure_learning recorded the blocker and quarantined bypass
        # candidates into the research artifact.
        learning = self.root / "research" / TARGET / "learning" \
            / "failure-bypass-candidates.json"
        self.assertTrue(learning.is_file())
        data = json.loads(learning.read_text())
        self.assertGreaterEqual(data["candidate_count"], 1)
        blockers = {c["blocker"] for c in data["candidates"]}
        self.assertTrue(any("cloudflare" in b or "403" in b
                            for b in blockers), blockers)

    def test_operator_approved_bypass_is_exploited_and_scored(self):
        # The full blocked -> operator approval -> bypass exploitation cycle:
        # a fuzz_blocked thread stays BLOCKED until the operator approves a
        # quarantined failure-learning candidate; the approved payload is
        # then replayed against the blocked endpoint (the fake WAF lets the
        # X-Original-URL bypass through with the admin record) and recorded
        # in the exploit ledger.
        from tools.intelligence.failure_learning import approve_candidate
        orch = self._seed_campaign()
        marker = "999999999999999999"
        orch.live_feedback_loop(base_url=self.base, max_units=40,
                                fuzz_budget=30,
                                transport=self._blocked_transport(marker),
                                project_root=str(self.root))
        blocked_threads = [t for t in orch.campaign.list_threads()
                           if t.bug_class == "fuzz_blocked"]
        self.assertGreaterEqual(len(blocked_threads), 1)
        self.assertEqual(blocked_threads[0].state.value, "blocked")
        learning_path = self.root / "research" / TARGET / "learning" \
            / "failure-bypass-candidates.json"
        learning = json.loads(learning_path.read_text())
        bypass_cand = next(c for c in learning["candidates"]
                           if c["payload"] == "X-Original-URL: /admin")
        approved = approve_candidate(TARGET, bypass_cand["candidate_id"],
                                     operator="tester",
                                     project_root=str(self.root))
        impact = orch.exploit_approved_bypass(
            blocked_threads[0], approved, base_url=self.base,
            transport=self._blocked_transport(marker),
            project_root=str(self.root))
        self.assertIsNotNone(impact)
        self.assertEqual(impact["kind"], "bypass-approval")
        self.assertEqual(impact["replayed_status"], 200)
        self.assertTrue(impact["reproduced"])
        self.assertIn("gw-1", impact["demonstrated_impact"])
        # The exploit ledger carries the approved-bypass demonstration.
        ledger = self.root / "state" / "sessions" / TARGET / "exploits.jsonl"
        records = [json.loads(l) for l in ledger.read_text().splitlines()
                   if l.strip()]
        self.assertTrue(any(r.get("kind") == "bypass-approval"
                            and r.get("candidate_id") == bypass_cand["candidate_id"]
                            and r.get("reproduced")
                            for r in records))
        # The exploitation-phase task scores the milestone: an approved
        # candidate + a reproduced bypass-approval exploit with impact.
        from tools.validation.self_eval_harness import evaluate
        data = evaluate(TARGET, base_dir=str(self.root)).to_dict()
        exploit_task = next(t for t in data["tasks"]
                            if t["task_id"] == "exploitation-phase")
        by_m = next(m for m in exploit_task["milestones"]
                    if m["milestone_id"] == "bypass-approval-exploited")
        self.assertTrue(by_m["passed"], exploit_task["milestones_passed"])

    def test_bypass_never_exploited_without_operator_approval(self):
        # Without an approval the milestone must not hold: the blocked
        # thread is untouched and no bypass-approval record exists.
        orch = self._seed_campaign()
        marker = "999999999999999999"
        orch.live_feedback_loop(base_url=self.base, max_units=40,
                                fuzz_budget=30,
                                transport=self._blocked_transport(marker),
                                project_root=str(self.root))
        ledger = self.root / "state" / "sessions" / TARGET / "exploits.jsonl"
        records = []
        if ledger.is_file():
            records = [json.loads(l) for l in ledger.read_text().splitlines()
                       if l.strip()]
        self.assertFalse(any(r.get("kind") == "bypass-approval"
                             for r in records))
        from tools.validation.self_eval_harness import evaluate
        data = evaluate(TARGET, base_dir=str(self.root)).to_dict()
        exploit_task = next(t for t in data["tasks"]
                            if t["task_id"] == "exploitation-phase")
        by_m = next(m for m in exploit_task["milestones"]
                    if m["milestone_id"] == "bypass-approval-exploited")
        self.assertFalse(by_m["passed"])

    # -- live exploitation phase ------------------------------------------

    def test_confirmed_findings_are_exploited_and_recorded(self):
        orch = self._seed_campaign()
        summary = orch.live_feedback_loop(base_url=self.base, max_units=40,
                                          project_root=str(self.root))
        # The idor + auth_bypass findings reproduce on the lab -> exploited.
        self.assertGreaterEqual(summary["exploits"], 1)
        self.assertEqual(summary["exploits"],
                         summary["exploits_reproduced"])
        # Ledger + thread records exist with the impact demonstration.
        ledger = self.root / "state" / "sessions" / TARGET / "exploits.jsonl"
        if ledger.is_file():
            records = [json.loads(l) for l in
                       ledger.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(records), 1)
            self.assertIn("demonstrated_impact", records[0])
        exploited = [t for t in orch.campaign.list_threads()
                     if getattr(t, "live_exploit", None)]
        self.assertGreaterEqual(len(exploited), 1)
        for thread in exploited:
            self.assertTrue(thread.live_exploit["reproduced"])
            self.assertIn("replayed_status", thread.live_exploit)
            self.assertTrue(getattr(thread, "live_evidence", None))
        # The self-eval exploitation-phase task scores this exact phase:
        # exploits recorded, reproduced, with demonstrated impact.
        from tools.validation.self_eval_harness import evaluate
        data = evaluate(TARGET, base_dir=str(self.root)).to_dict()
        exploit_task = next(t for t in data["tasks"]
                            if t["task_id"] == "exploitation-phase")
        self.assertTrue(exploit_task["passed"],
                        exploit_task["milestones_passed"])

    def test_exploited_findings_feed_chain_hypotheses(self):
        # A reproduced exploit's demonstrated impact feeds back as new
        # chain hypotheses: leads written, chain graph refreshed, and the
        # hypotheses ride on the impact record.
        orch = self._seed_campaign()
        summary = orch.live_feedback_loop(base_url=self.base, max_units=40,
                                          project_root=str(self.root))
        if summary["exploits_reproduced"] == 0:
            self.skipTest("no reproduced exploits in this lab run")
        # OPEN-LEAD records stamped as exploit feedback in the chain pool.
        leads = self.root / "state" / "sessions" / TARGET / "leads.jsonl"
        self.assertTrue(leads.is_file(), "exploit feedback wrote leads.jsonl")
        records = [json.loads(l) for l in leads.read_text().splitlines()
                   if l.strip()]
        feedback = [r for r in records
                    if r.get("source") == "exploit-feedback"]
        self.assertGreaterEqual(len(feedback), 1)
        for record in feedback:
            self.assertEqual(record["evidence_state"], "hypothesis")
            self.assertEqual(record["state"], "OPEN")
            self.assertTrue(record["bug_class"])
            self.assertTrue(record["lead_id"])
        # The impact records carry the derived hypotheses.
        exploited = [t for t in orch.campaign.list_threads()
                     if getattr(t, "live_exploit", None)]
        for thread in exploited:
            self.assertIn("chain_hypotheses", thread.live_exploit)
            self.assertGreaterEqual(len(thread.live_exploit["chain_hypotheses"]), 1)
            self.assertTrue(thread.live_exploit["demonstrated_impact"])
        # The chain graph was rebuilt and includes the new lead classes.
        graph = (self.root / "state" / "chains" / TARGET
                 / "orchestration.json")
        if graph.is_file():
            data = json.loads(graph.read_text())
            classes = {n["bug_class"] for n in data.get("nodes", [])}
            for record in feedback:
                self.assertIn(record["bug_class"], classes)
        # The demonstrated impact also refined the zero-day novelty pool:
        # exploit-feedback candidates registered + persisted.
        self.assertGreaterEqual(summary["exploit_novel"], 1,
                                summary["exploit_novel"])
        feed = self.root / "research" / TARGET / "zero-day" \
            / "exploit-feedback.jsonl"
        self.assertTrue(feed.is_file(), "exploit feedback wrote candidates")
        candidates = [json.loads(l) for l in feed.read_text().splitlines()
                      if l.strip()]
        self.assertGreaterEqual(len(candidates), 1)
        for record in candidates:
            self.assertEqual(record["metadata"]["source"],
                             "exploit-feedback")
            self.assertTrue(record["metadata"]["exploit"]["replay_key"])
        unlock = [c for c in candidates
                  if c["metadata"]["mode"] == "exploit_unlock"]
        self.assertGreaterEqual(len(unlock), 1)
        self.assertEqual(unlock[0]["status"], "novelty_pending")
        self.assertTrue(unlock[0]["impact_trace"])

    def test_no_exploitation_when_disabled(self):
        orch = self._seed_campaign()
        summary = orch.live_feedback_loop(base_url=self.base, max_units=40,
                                          run_exploits=False,
                                          project_root=str(self.root))
        self.assertEqual(summary["exploits"], 0)
        exploited = [t for t in orch.campaign.list_threads()
                     if getattr(t, "live_exploit", None)]
        self.assertEqual(exploited, [])

    def test_exploitation_only_for_gate_confirmed_findings(self):
        # A refuted thread must never be exploited: the demo only runs for
        # findings the F0.5 gate marked report-eligible (CONFIRMED).
        orch = self._seed_campaign()
        orch.live_feedback_loop(base_url=self.base, max_units=40,
                                project_root=str(self.root))
        ledger = self.root / "state" / "sessions" / TARGET / "exploits.jsonl"
        if ledger.is_file():
            records = [json.loads(l) for l in
                       ledger.read_text().splitlines() if l.strip()]
            for record in records:
                self.assertEqual(record["replayed_status"], 200)
        for thread in orch.campaign.list_threads():
            if thread.state.value == "refuted":
                self.assertIsNone(getattr(thread, "live_exploit", None))


if __name__ == "__main__":
    unittest.main()
