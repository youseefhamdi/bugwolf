#!/usr/bin/env python3
"""End-to-end deep-dive campaign integration test (U1–U5 together).

Boots the VulnBank lab fixture (``lab/vulnbank/server.py``, stdlib-only)
in-process on an ephemeral port, then drives the full BugWolf pipeline the
way an operator would:

  U4 pass@k variants  ->  U2 artifact bridging  ->  U3 strict F0.5 gate  ->
  U1 fast-path hook   ->  U5 model routing      ->  12-stage workflow
  (append-only triage hash-chaining)            ->  live probe pass (Phase 3)
  ->  fuzz-to-thread reproduce cycle            ->  exploit-with-impact
  ->  10-task self-eval

This mirrors ``/tmp/e2e_deep_dive.py`` (the manual E2E driver) as a
repeatable, isolated test: no fixed port, no external process, workspace in
a temp dir, and the lab fixture is skipped cleanly when absent (e.g. when
run from inside a bundle that does not ship ``lab/``).
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
from tools.core.stage_controller import WorkflowError

LAB_SERVER = ROOT / "lab" / "vulnbank" / "server.py"
TARGET = "vulnbank.local"

RESEARCH_SEQUENCE = [
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
]


def _boot_lab():
    """Load the stdlib-only lab fixture and serve it on an ephemeral port.

    Returns (base_url, shutdown) or (None, None) when the fixture is absent.
    """
    if not LAB_SERVER.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("vulnbank_server", LAB_SERVER)
    module = importlib.util.module_from_spec(spec)
    # server.py derives PORT from sys.argv[1] at import time — shield it from
    # the unittest argv (e.g. the test module name) so import cannot fail.
    saved_argv = sys.argv
    sys.argv = ["vulnbank_server.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv

    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

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


class TestE2EDeepDiveCampaign(unittest.TestCase):
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

    # -- lab helper ---------------------------------------------------------

    def _lab(self, path, *, post=None):
        data = json.dumps(post).encode() if post is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())

    # -- the campaign -------------------------------------------------------

    def test_full_deep_dive_campaign_exercises_u1_to_u5(self):
        from tools.core.campaign_orchestrator import CampaignOrchestrator
        from tools.core.signal_bus import (
            SignalBus, SMUGGLING_CANDIDATE, AUTH_CANDIDATE,
        )

        # ---- bootstrap workspace + workflow ------------------------------
        initialize_contract(str(self.root))
        (self.root / "BUGWOLF.md").write_text(
            "# BugWolf harness contract\n`BUGWOLF-HARNESS-CONTRACT-V2`\n")
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "environment.json").write_text(
            json.dumps({"location": "local"}))
        scope = self.root / "scope.json"
        scope.write_text(json.dumps({"targets": [TARGET],
                                     "declared_by": "operator",
                                     "note": "local lab fixture"}))

        orch = CampaignOrchestrator(TARGET, mode="web", pass_at_k=3)
        orch.initialize()
        orch.complete_workflow_stage("authorization", scope_file=str(scope))

        # ---- U4: register asset + recon from the live lab surface --------
        orch.register_discovered_assets([{
            "hostname": "api.vulnbank.local", "type": "web_api",
            "priority": "high"}])
        asset = orch.campaign.list_assets()[0]
        endpoints = [f"{self.base}{p}" for p in
                     ("/api/users", "/graphql", "/login",
                      "/openapi.json", "/tech.json", "/api/ingest",
                      "/api/gateway")]

        # Recon artifacts first, so asset-intelligence hashes them in.
        recon_dir = self.root / "recon" / TARGET
        recon_dir.mkdir(parents=True, exist_ok=True)
        (recon_dir / "urls.txt").write_text("\n".join(endpoints) + "\n")
        delta = recon_dir / "asset-intel" / "delta.json"
        delta.parent.mkdir(parents=True, exist_ok=True)
        delta.write_text(json.dumps({
            "target": TARGET, "new_hosts": ["api.vulnbank.local"],
            "new_endpoints": endpoints, "delta_type": "initial"}, indent=2))

        orch.register_recon(asset.asset_id, endpoints=endpoints,
                            tech=["nginx", "node", "graphql", "express"],
                            ports=[8077])
        orch.mark_discovery_complete()

        # ---- U2: deterministic artifacts from the live lab ---------------
        from tools.domains.web.parser_differential import (
            generate as pd_generate, write_payloads)
        from tools.domains.web.http_smuggling_detector import (
            build_plan, write_plan)
        from tools.domains.auth.jwt_forgery import (
            analyze as jwt_analyze, JwtAnalysis, write_analysis)
        from tools.domains.api.graphql_batch_analyzer import (
            analyze as gql_analyze, write_analysis as gql_write)
        from tools.domains.api.bopla_matrix import build_matrix, write_matrix
        from tools.domains.auth.oauth_flow_analyzer import (
            OAuthFlow, analyze as oauth_analyze, write_analysis as oauth_write)
        from tools.domains.auth.ato_chain_planner import (
            plan_chains, write_plan_set as ato_write)
        from tools.intelligence.seed_advisor import (
            advise as seed_advise, write_report as seed_write)
        from tools.validation.verification_lab import (
            plan_labs, write_plan_set as lab_write)
        from tools.intelligence.chain_graph_ai import (
            propose as chain_propose, write_proposal_set as chain_write)
        from tools.domains.cloud.iam_privesc_graph import (
            analyze as iam_analyze, write_analysis as iam_write)
        from tools.domains.mobile.deep_link_analyzer import (
            analyze as dl_analyze, write_analysis as dl_write)
        from tools.domains.mobile.mobile_policy_checker import (
            analyze as mp_analyze, write_result as mp_write)
        from tools.domains.smart_contracts.llm_contract_triage import (
            triage as ct_triage, write_report as ct_write)
        from tools.domains.smart_contracts.price_manipulation_analyzer import (
            analyze as pm_analyze, write_analysis as pm_write)
        from tools.domains.llm.agentic_tool_auth import (
            analyze as ta_analyze, write_analysis as ta_write)
        from tools.domains.llm.rag_memory_poisoning import (
            analyze as rag_analyze, write_analysis as rag_write)

        bus = SignalBus(TARGET, project_root=str(self.root))
        fp = self._lab("/tech.json")
        openapi = self._lab("/openapi.json")
        pd_set = pd_generate(TARGET, stack="nginx", defense="Cloudflare",
                             bug_classes=["sqli", "xss"], fingerprint=fp)
        write_payloads(pd_set, project_root=str(self.root))
        write_plan(build_plan(TARGET, [f"{self.base}/login"]),
                   project_root=str(self.root))
        token = self._lab("/login", post={"username": "alice"})["token"]
        jwt_finding = jwt_analyze(token)
        write_analysis(JwtAnalysis(target=TARGET, generated_at="",
                                   findings=[jwt_finding]),
                       project_root=str(self.root))
        bus.publish(SMUGGLING_CANDIDATE, source="http_smuggling_detector",
                    payload={"technique": "CL.TE", "url": f"{self.base}/login",
                             "confidence": 0.9,
                             "rationale": "smuggling-plan generated"})
        bus.publish(AUTH_CANDIDATE, source="jwt_forgery",
                    payload={"token_hash": "lab-token", "alg": "HS256",
                             "plan_classes": ["alg-confusion"]})

        gql_query = "{ __typename }"
        self._lab("/graphql", post={"query": gql_query})
        gql_write(gql_analyze(TARGET, query=gql_query),
                  project_root=str(self.root))
        bus.publish("GRAPHQL_CANDIDATE", source="graphql_batch_analyzer",
                    payload={"endpoint": f"{self.base}/graphql",
                             "plan_count": 1})
        write_matrix(build_matrix(TARGET, openapi,
                                  observed_bodies=[{"id": "42"}]),
                     project_root=str(self.root))
        oauth_write(oauth_analyze(TARGET, [OAuthFlow(
            authorize_url=f"{self.base}/login", token_url=f"{self.base}/login",
            callback_url=f"{self.base}/callback", client_id="vulnbank",
            response_type="token", scope="profile",
            params={"client_id": "vulnbank",
                    "redirect_uri": f"{self.base}/callback"})]),
            project_root=str(self.root))
        ato_write(plan_chains(TARGET, [
            {"kind": "weak-jwt", "url": f"{self.base}/login"},
            {"kind": "idor", "url": f"{self.base}/api/users"}]),
            project_root=str(self.root))
        lab_write(plan_labs(TARGET, [
            {"finding_id": "e2e-idor", "bug_class": "idor"},
            {"finding_id": "e2e-jwt", "bug_class": "auth_bypass"}]),
            project_root=str(self.root))
        chain_write(chain_propose(TARGET, [
            {"id": "e2e-idor", "bug_class": "idor"},
            {"id": "e2e-jwt", "bug_class": "auth_bypass"}]),
            project_root=str(self.root))
        iam_write(iam_analyze(TARGET, {"Statement": [
            {"Effect": "Allow",
             "Action": ["iam:PutUserPolicy", "iam:CreateAccessKey"],
             "Resource": "*"}]}), project_root=str(self.root))
        dl_write(dl_analyze(TARGET, summary={"surfaces": [
            {"platform": "android", "scheme": "vulnbank", "host": "account",
             "path": "users/{id}", "component": "AccountActivity",
             "exported": True, "action": "VIEW"},
            {"platform": "ios", "scheme": "vulnbank", "host": "login",
             "path": "/callback", "component": "LoginVC",
             "exported": False}]}), project_root=str(self.root))
        mp_write(mp_analyze(TARGET, summary={"findings": [
            {"finding_id": "mp-clear-1", "platform": "android",
             "check": "cleartext_traffic", "severity": "high",
             "component": "AndroidManifest",
             "detail": "usesCleartextTraffic=true for api.vulnbank.local",
             "validation_steps": [f"load {self.base}/login"]},
            {"finding_id": "mp-exported-1", "platform": "android",
             "check": "exported_component", "severity": "medium",
             "component": "AccountActivity",
             "detail": "exported deep-link activity accepts arbitrary ids",
             "validation_steps":
                 ["adb shell am start -a VIEW -d vulnbank://account/users/2"]}]}),
            project_root=str(self.root))
        ct_write(ct_triage(TARGET, [
            {"candidate_id": "ct-1", "bug_class": "reentrancy",
             "code_slice": "balance[msg.sender] -= amount; "
                           "(bool ok, ) = msg.sender.call{value: amount}(\"\");"},
            {"candidate_id": "ct-2", "bug_class": "flash_loan",
             "code_slice": "pool.getReserves(); uint price = reserve1 / reserve0;"}]),
            project_root=str(self.root))
        pm_write(pm_analyze(TARGET, "VulnBankSwap",
                            "function getReserves() external returns (uint r0, uint r1) {\n"
                            "    (r0, r1) = pair.getReserves();\n"
                            "}\n"
                            "function onFlashLoan(address, uint, uint, bytes calldata) external {\n"
                            "    uint price = reserve1 / reserve0;\n"
                            "    if (price > threshold) { mint(burnRatio); }\n"
                            "}"),
            project_root=str(self.root))
        ta_write(ta_analyze(TARGET, inventory=[
            {"tool": "transfer",
             "args": {"to": "user_input", "amount": "user_input"},
             "identity": "support-agent", "description": "transfer funds"},
            {"tool": "fetch_url", "args": {"url": "web_content"},
             "identity": "research-agent", "description": "fetch page"},
            {"tool": "execute_sql", "args": {"query": "user_input"},
             "identity": "support-agent", "description": "lookup user"}]),
            project_root=str(self.root))
        rag_write(rag_analyze(TARGET, {
            "name": "vulnbank-support-rag", "store_type": "vector_db",
            "write_back": True, "sanitization": False,
            "provenance_tagging": False,
            "sources": [
                {"type": "user_uploads", "trust": "low",
                 "description": "support ticket attachments"},
                {"type": "docs", "trust": "high",
                 "description": "official API docs"}]}),
            project_root=str(self.root))

        # ---- drive thread units: pass@k variants, gate, routing ----------
        special = {"idor": "rich", "sql_injection": "bare",
                   "auth_bypass": "rich"}
        u2_sample = None
        u5_sample = None
        completed = 0
        for _ in range(80):
            unit = orch.get_next_research_unit()
            if unit is None:
                break
            if unit.get("campaign_phase") != "researching":
                break
            if u2_sample is None:
                u2_sample = unit
            if u5_sample is None:
                u5_sample = unit
            tid = unit["context"]["thread_id"]
            bc = unit.get("bug_class", "")
            thread = orch.campaign.get_thread(tid)
            variant = getattr(thread, "pass_variant", 0)
            if variant == 0 and bc in special:
                mode = special[bc]
            else:
                mode = "refute"  # best-pass-wins: only variant 0 explores
            if mode == "rich":
                thread.evidence_ids = [f"ev-{bc}-1", f"ev-{bc}-2"]
                orch.campaign.save_thread(thread)
                orch.register_thread_result(
                    tid,
                    observation=f"{bc}: probe against /api/users/2 "
                                f"reproduced the flaw",
                    conclusion="confirmed", new_state="complete",
                    confirmed_behavior=(
                        f"{bc} confirmed: cross-account access to /api/users/2"))
                completed += 1
            elif mode == "bare":
                orch.register_thread_result(
                    tid, observation="weak signal only",
                    conclusion="confirmed", new_state="complete")
                completed += 1
            else:
                orch.register_thread_result(
                    tid, observation="no signal across baseline probes",
                    conclusion="not vulnerable", new_state="refuted")

        threads = orch.campaign.list_threads()
        by_variant = {}
        for t in threads:
            by_variant.setdefault(t.pass_variant, 0)
            by_variant[t.pass_variant] += 1
        state = orch.campaign.load()

        # U4: pass@k spawned k variants per bug class, dispatch reached all.
        self.assertGreaterEqual(len(threads), 20)
        self.assertEqual(sorted(by_variant), [0, 1, 2])
        self.assertEqual(len({by_variant[v] for v in by_variant}), 1)
        self.assertGreaterEqual(completed, 3)

        # U3: strict gate — demoted finding quarantined, not in ledger.
        quarantine = self.root / "state" / "learning" / f"{TARGET}.jsonl"
        findings_ledger = (self.root / "state" / "sessions" / TARGET
                           / "findings.jsonl")
        self.assertTrue(quarantine.is_file())
        self.assertEqual(len(quarantine.read_text().splitlines()), 1)
        self.assertTrue(findings_ledger.is_file())
        self.assertEqual(len(findings_ledger.read_text().splitlines()), 2)
        self.assertEqual(state.total_findings, 3)
        self.assertEqual(state.report_eligible_findings, 2)

        # Seed proposals need real dispatched units (captured during loop).
        seed_write(seed_advise(TARGET, [
            {"unit_id": u["context"]["thread_id"], "mode": "web",
             "suggested_approaches": u.get("suggested_approaches") or []}
            for u in (u2_sample, u5_sample) if u]),
            project_root=str(self.root))

        # ---- U1: fast-path research hook ----------------------------------
        from tools.research_loop import run_mandatory_research, fast_path_signals
        fired = []

        def on_checkpoint(result, context):
            fired.append((result["checkpoint"],
                          [s["trigger"] for s in fast_path_signals(result)]))

        run_mandatory_research(TARGET, "web", phase="full",
                               base_dir=str(self.root / "research"),
                               run_search=False, on_checkpoint=on_checkpoint)
        self.assertEqual(len(fired), 7)  # one per mandatory checkpoint
        fired_triggers = {sig for _, sigs in fired for sig in sigs}
        self.assertIn("canonical-source-fresh", fired_triggers)

        # Offline pass leaves searches pending; represent the operator's
        # completed live pass so the workflow's research stage is fresh.
        fresh_seq = self.root / "research" / TARGET / "sequence.json"
        fresh_seq.write_text(json.dumps({
            "schema": "research_execution/sequential-v1", "target": TARGET,
            "executions": [{
                "sequence": RESEARCH_SEQUENCE,
                "runs": [{"checkpoint": ck, "pending_searches": 0,
                          "latest_ready": True} for ck in RESEARCH_SEQUENCE],
                "latest_required": True, "latest_ready": True}],
            "latest_ready": True}, indent=2))

        # ---- U5: model routing --------------------------------------------
        audit_path = (self.root / "state" / "campaigns" / TARGET
                      / "audit.jsonl")
        routing_tiers = []
        if audit_path.is_file():
            for line in audit_path.read_text().splitlines():
                rec = json.loads(line)
                if rec.get("event") == "unit_routed":
                    tier = rec["data"].get("model_tier")
                    if tier and tier not in routing_tiers:
                        routing_tiers.append(tier)
        self.assertIn("local_slm", routing_tiers)
        self.assertIn("frontier", routing_tiers)

        self.assertIsNotNone(u5_sample)
        u5_ctx = u5_sample["context"]
        self.assertIn("model_tier", u5_ctx)
        self.assertIn("model_preference", u5_ctx)

        # U2: deterministic evidence bridged into unit context.
        self.assertIsNotNone(u2_sample)
        evidence = u2_sample["context"]["deterministic_evidence"]
        for family in ("waf_payloads", "smuggling_plan", "jwt_plans",
                       "graphql_plans", "bopla_matrix", "oauth_plans",
                       "ato_plans", "iam_privesc", "deep_link_plans",
                       "mobile_policy", "contract_plans", "llm_plans"):
            self.assertIn(family, evidence)

        # ---- complete the 12-stage workflow ------------------------------
        def complete(stage, **kw):
            try:
                orch.complete_workflow_stage(stage, **kw)
                return "recorded"
            except WorkflowError as exc:
                return f"skipped ({exc})"

        # Early stages (setup .. maps) are auto-completed by register_recon /
        # mark_discovery_complete, so "skipped (blocked; current required
        # stage is ...)" is the expected outcome for those — never a real
        # integrity failure. Stages from research onward must record.
        for stage in ("research", "coverage-plan", "validation", "triage"):
            kw = {}
            if stage in ("validation", "triage"):
                kw["artifacts"] = [
                    str(self.root / "recon" / TARGET / "recon-complete.json")]
            result = complete(stage, **kw)
            self.assertEqual(result, "recorded", f"{stage}: {result}")

        # Append-safe triage hash-chaining: append after triage recorded
        # hashes, then complete report -> integrity gate must tolerate it.
        with quarantine.open("a") as f:
            f.write(json.dumps({
                "kind": "low-confidence-finding",
                "technique_id": "post-triage-append",
                "status": "candidate", "confidence": 0.1}) + "\n")
        report_result = complete("report", artifacts=[
            str(self.root / "recon" / TARGET / "recon-complete.json")])
        self.assertEqual(report_result, "recorded",
                         f"report: {report_result}")

        wf = orch.workflow_status()
        self.assertIn(wf["current_stage"], (None, "COMPLETE"))

        # ---- Phase 3: genuine live probe pass (self-eval task 8) ---------
        # Run real probe sets through the live executor against the running
        # lab — recorded request/response evidence, no simulation.  The unit
        # mix is chosen so the recorded verdicts are deterministic: the idor
        # probe reproduces the BOLA (200 -> signal), the sql-injection probe
        # comes back clean (404, no error body), and the auth_bypass probe
        # signals (POST /login -> 200) — three records, two verdicts, replay
        # keys attached.  This is exactly what eval task 8
        # (live-execution-loop) scores.
        from tools.core.live_executor import execute_probe

        def _live_unit(bug_class, path, **kw):
            return {"bug_class": bug_class, "endpoint": f"{self.base}{path}",
                    "context": {"thread_id": f"e2e-live-{bug_class}"}, **kw}

        live_probes = [
            execute_probe(_live_unit("idor", "/api/users/1"),
                          self.base, project_root=str(self.root)),
            execute_probe(_live_unit("sql_injection", "/api/users"),
                          self.base, project_root=str(self.root)),
            execute_probe(_live_unit("auth_bypass", "/login", method="POST"),
                          self.base, project_root=str(self.root)),
        ]
        self.assertEqual([p.status for p in live_probes], [200, 404, 200])
        for probe in live_probes:
            self.assertTrue(probe.evidence.get("request"), probe.probe_id)
            self.assertTrue(probe.evidence.get("replay_key"), probe.probe_id)
        probes_path = self.root / "state" / "sessions" / "127.0.0.1" \
            / "probes.jsonl"
        self.assertTrue(probes_path.is_file())
        self.assertGreaterEqual(len(probes_path.read_text().splitlines()), 3)

        # ---- Phase 3: fuzz -> spawn -> reproduce cycle (self-eval task 9) -
        # The lab's /api/ingest endpoint deterministically 5xxes on fuzz
        # boundary/injection input.  One fuzz pass finds the crash, spawns a
        # research thread targeting it, and the loop re-probes that thread
        # with the crashing URL — the 500 reproduces and COMPLETES with
        # recorded evidence, deduped per (endpoint, fuzz state).
        # Budget covers the full registered surface (7 endpoints x 6
        # mutations) so the /api/ingest crash and /api/gateway block are
        # actually fuzzed.
        fuzz_summary = orch._fuzz_and_spawn_threads(
            base_url=self.base, budget=50, project_root=str(self.root))
        self.assertGreaterEqual(fuzz_summary["spawned"], 1)
        cycle = orch.live_feedback_loop(
            base_url=self.base, max_units=10, project_root=str(self.root))
        fuzz_threads = [t for t in orch.campaign.list_threads()
                        if t.bug_class.startswith("fuzz_")]
        self.assertGreaterEqual(len(fuzz_threads), 1)
        # Crash threads (ingest) COMPLETED with the 500 reproduced; blocked
        # threads (gateway WAF) went BLOCKED for an operator decision.
        crash_threads = [t for t in fuzz_threads
                         if t.bug_class == "fuzz_crash"]
        blocked_threads = [t for t in fuzz_threads
                           if t.bug_class == "fuzz_blocked"]
        self.assertGreaterEqual(len(crash_threads), 1)
        for thread in crash_threads:
            self.assertEqual(thread.state.value, "complete")
            self.assertIn("500", thread.confirmed_behavior)
            self.assertTrue(getattr(thread, "live_evidence", None))
        self.assertGreaterEqual(len(blocked_threads), 1)
        keys = {(t.endpoint, t.bug_class) for t in fuzz_threads}
        self.assertEqual(len(keys), len(fuzz_threads))

        # ---- Phase 3: operator-approved bypass exploitation (task 10) ----
        # The gateway fuzz_blocked thread stays BLOCKED until an operator
        # approves a quarantined failure-learning candidate; the approved
        # payload is then replayed against the blocked endpoint and the
        # impact lands in the exploit ledger.
        from tools.intelligence.failure_learning import approve_candidate
        learning_path = self.root / "research" / TARGET / "learning" \
            / "failure-bypass-candidates.json"
        self.assertTrue(learning_path.is_file(), "blocked -> learn wrote ledger")
        learning = json.loads(learning_path.read_text())
        bypass_cand = next(c for c in learning["candidates"]
                           if c["payload"] == "X-Original-URL: /admin")
        self.assertEqual(bypass_cand["status"], "quarantined")
        approved = approve_candidate(
            TARGET, bypass_cand["candidate_id"], operator="e2e-operator",
            project_root=str(self.root))
        blocked_thread = next(t for t in orch.campaign.list_threads()
                              if t.bug_class == "fuzz_blocked")
        self.assertEqual(blocked_thread.state.value, "blocked")
        impact = orch.exploit_approved_bypass(
            blocked_thread, approved, base_url=self.base,
            project_root=str(self.root))
        self.assertIsNotNone(impact, "approved bypass replayed live")
        self.assertEqual(impact["kind"], "bypass-approval")
        self.assertEqual(impact["candidate_id"], bypass_cand["candidate_id"])
        self.assertEqual(impact["approved_by"], "e2e-operator")
        self.assertEqual(impact["replayed_status"], 200)
        self.assertTrue(impact["reproduced"])
        self.assertIn("gw-1", impact["demonstrated_impact"])

        # ---- Phase 3: exploitation evidence (self-eval task 10) ----------
        # The fuzz-cycle live loop replayed the confirmed crash finding:
        # the exploit ledger carries the impact demonstration.
        exploits = self.root / "state" / "sessions" / TARGET \
            / "exploits.jsonl"
        self.assertTrue(exploits.is_file())
        exploit_records = [json.loads(line)
                           for line in exploits.read_text().splitlines()
                           if line.strip()]
        self.assertGreaterEqual(len(exploit_records), 1)
        self.assertTrue(all(r["reproduced"] for r in exploit_records))
        self.assertTrue(any(str(r.get("demonstrated_impact") or "").strip()
                            for r in exploit_records))

        # ---- self-eval harness: all 10 tasks, 100% milestones ------------
        from tools.validation.self_eval_harness import evaluate
        data = evaluate(TARGET, base_dir=str(self.root)).to_dict()
        self.assertEqual(data["tasks_passed"], data["task_count"])
        self.assertEqual(data["task_count"], 10)
        self.assertEqual(data["score_pct"], 100.0)
        self.assertEqual(data["milestone_pct"], 100.0)
        for task in data["tasks"]:
            self.assertTrue(task["passed"], task["task_id"])


if __name__ == "__main__":
    unittest.main()
