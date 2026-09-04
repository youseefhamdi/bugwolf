#!/usr/bin/env python3
"""Multi-agent layer tests: agent registry, agent-aware model routing,
multi-agent team engine, scheduler bindings, generator sync, MCP surface."""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.core.agent_registry import (  # noqa: E402
    AgentRegistry, AgentRegistryError, TIERS, LANES)
from tools.core.model_router import (  # noqa: E402
    route_agent_dispatch, route_unit_agent,
    TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER)
from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.team import (  # noqa: E402
    TeamEngine, TeamMessage, WAVE_ORDER, MEMBER_DONE, MEMBER_FAILED)


def _mission(tmp: str, **kw) -> MissionSpec:
    defaults = dict(mission_id="m-test", target="stub.local",
                    domains=["web_api", "auth"],
                    budget={"max_agents": 12, "max_parallel_tasks": 4})
    defaults.update(kw)
    return MissionSpec(**defaults)


def _ok_worker(payload):
    return {"status": MEMBER_DONE,
            "summary": f"{payload['role']} done at {payload['tier']}"}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestAgentRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = AgentRegistry()

    def test_catalog_shape(self):
        roles = self.reg.all_roles()
        self.assertEqual(len(roles), len(set(roles)))
        self.assertGreaterEqual(len(roles), 22)
        for role in roles:
            spec = self.reg.get(role)
            self.assertIn(spec.tier_affinity, TIERS)
            for lane in spec.lanes:
                self.assertIn(lane, LANES)
            self.assertTrue(spec.scope_required)
            self.assertTrue(spec.sandbox_required)
            self.assertTrue(spec.harness_role.startswith("bugwolf:"))

    def test_playbooks_exist_and_verify(self):
        for role in self.reg.all_roles():
            path = self.reg.playbook_path(role)
            self.assertTrue(path.is_file(), f"missing playbook for {role}")
            text = self.reg.load_prompt(role)
            self.assertGreater(len(text), 200, role)
            # tamper guard: modified text must not verify
            with self.assertRaises(AgentRegistryError):
                self.reg.verify_prompt(role, text + "tampered")

    def test_select_by_bug_class_is_deterministic(self):
        a = self.reg.select(bug_class="ssrf")
        b = self.reg.select(bug_class="ssrf")
        self.assertEqual(a.role, b.role)
        self.assertEqual(a.role, "web-api")
        self.assertEqual(self.reg.select(bug_class="race_condition").role,
                         "business-logic")
        self.assertEqual(self.reg.select(bug_class="jwt_attack").role,
                         "crypto-math")
        self.assertEqual(self.reg.select(bug_class="prompt_injection").role,
                         "llm-ai")
        self.assertEqual(self.reg.select(bug_class="reentrancy").role,
                         "smart-contract")

    def test_select_domain_generalist_then_fallback(self):
        self.assertEqual(self.reg.select(domain="auth").role,
                         "access-control")
        # unknown bug class + unknown domain -> lane workflow fallback
        spec = self.reg.select(bug_class="nonexistent_class",
                               domain="nonexistent_domain", lane="hunt")
        self.assertTrue(spec.role)

    def test_dispatch_for_contract(self):
        d = self.reg.dispatch_for(bug_class="ssrf", domain="web_api")
        for key in ("agent_role", "harness_role", "tier",
                    "model_preference", "fallback_preference", "lane",
                    "scope_required", "sandbox_required"):
            self.assertIn(key, d)
        self.assertEqual(d["harness_role"], "bugwolf:web-api")
        self.assertTrue(d["scope_required"] and d["sandbox_required"])

    def test_compose_team_deterministic_and_capped(self):
        args = dict(domains=["web_api", "auth"],
                    bug_classes=["ssrf", "race_condition"])
        t1 = self.reg.compose_team(max_agents=12, **args)
        t2 = self.reg.compose_team(max_agents=12, **args)
        self.assertEqual(t1["roster"], t2["roster"])
        self.assertEqual(t1["digest"], t2["digest"])
        # workflow agents always present
        for role in self.reg.workflow_roles():
            self.assertIn(role, t1["roster"])
        capped = self.reg.compose_team(max_agents=3, **args)
        self.assertEqual(len(capped["roster"]), 3)

    def test_unknown_role_raises(self):
        with self.assertRaises(AgentRegistryError):
            self.reg.get("no-such-agent")


# ---------------------------------------------------------------------------
# Model-router agent dispatch
# ---------------------------------------------------------------------------


class TestAgentDispatchRouting(unittest.TestCase):
    def test_frontier_affinity_floor(self):
        out = route_agent_dispatch(bug_class="xss", affinity=TIER_FRONTIER)
        self.assertEqual(out["tier"], TIER_FRONTIER)
        self.assertGreaterEqual(out["complexity"], 0.65)

    def test_deterministic_affinity_never_frontier(self):
        out = route_agent_dispatch(bug_class="zero_day",
                                   objective="synthesize novel exploit chain",
                                   affinity=TIER_DETERMINISTIC)
        self.assertEqual(out["tier"], TIER_DETERMINISTIC)
        self.assertNotEqual(out["model_preference"], "frontier-reasoning")

    def test_local_affinity_and_fallback(self):
        out = route_agent_dispatch(bug_class="information_disclosure",
                                   affinity=TIER_LOCAL)
        self.assertIn(out["tier"], (TIER_LOCAL, TIER_DETERMINISTIC))
        self.assertTrue(out["fallback_preference"] in ("", "none", "slm-fast"))

    def test_invalid_affinity_raises(self):
        with self.assertRaises(ValueError):
            route_agent_dispatch(affinity="quantum")

    def test_route_unit_agent_binds_agent(self):
        unit = {"unit_id": "u1", "objective": "probe IDOR on /api/orders",
                "bug_class": "idor",
                "context": {"domain": "web_api"}}
        out = route_unit_agent(unit)
        # idor is owned by the access-control specialist (registry order)
        self.assertEqual(out["agent_role"], "access-control")
        self.assertEqual(out["harness_role"], "bugwolf:access-control")
        self.assertIn(out["tier"], TIERS)
        # malformed input never raises; selection degrades to a workflow
        # agent (deterministic fallback), never an exception
        degenerate = route_unit_agent(None)
        self.assertIn(degenerate["tier"], TIERS)
        self.assertTrue(degenerate["agent_role"])


# ---------------------------------------------------------------------------
# Team engine
# ---------------------------------------------------------------------------


class TestTeamEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_plan_waves_and_ordering(self):
        engine = TeamEngine(_mission(self.root), worker=_ok_worker,
                            project_root=self.root)
        out = engine.plan(bug_classes=["ssrf", "race_condition"])
        self.assertTrue(out["team_id"])
        self.assertEqual(out["totals"]["members"], len(engine.members))
        for wave in {m.wave for m in engine.members.values()}:
            self.assertIn(wave, WAVE_ORDER)
        # deterministic roster
        engine2 = TeamEngine(_mission(self.root), worker=_ok_worker,
                             project_root=self.root)
        engine2.plan(bug_classes=["ssrf", "race_condition"])
        self.assertEqual(sorted(m.role for m in engine2.members.values()),
                         sorted(m.role for m in engine.members.values()))
        # checkpoint on disk
        self.assertTrue((Path(self.root) / "state/orchestrator/m-test/team/"
                         "state.json").is_file())

    def test_run_all_waves_complete(self):
        engine = TeamEngine(_mission(self.root), worker=_ok_worker,
                            project_root=self.root)
        out = engine.run(bug_classes=["ssrf"])
        self.assertEqual(out["status"], "complete")
        self.assertEqual(out["totals"].get(MEMBER_DONE),
                         out["totals"]["members"])
        runs = (Path(self.root) / "state/orchestrator/m-test/team/"
                "runs.jsonl").read_text().strip().splitlines()
        events = [json.loads(l)["event"] for l in runs]
        self.assertIn("started", events)
        self.assertIn("finished", events)
        self.assertEqual(events.count("started"), events.count("finished"))

    def test_messages_route_to_target_role(self):
        seen = {}

        def worker(payload):
            seen[payload["role"]] = payload
            out = {"status": MEMBER_DONE}
            if payload["role"] == "web-api":
                out["messages"] = [{"to_role": "verify", "kind": "lead",
                                    "body": {"lead": "lead-1"}}]
            return out

        engine = TeamEngine(_mission(self.root, domains=["web_api"]),
                            worker=worker, project_root=self.root)
        engine.run()
        self.assertIn("lead-1", json.dumps(
            [m.body for m in engine.messages]))
        verify_payload = seen.get("verify")
        self.assertIsNotNone(verify_payload)
        leads = [m for m in verify_payload["messages"]
                 if m.get("kind") == "lead"]
        self.assertTrue(leads)
        msgs_path = (Path(self.root) / "state/orchestrator/m-test/team/"
                     "messages.jsonl")
        self.assertTrue(msgs_path.is_file())

    def test_worker_failure_never_sinks_wave(self):
        def worker(payload):
            if payload["role"] == "web-api":
                raise RuntimeError("probe exploded")
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root, domains=["web_api"]),
                            worker=worker, project_root=self.root)
        out = engine.run()
        self.assertEqual(out["status"], "complete")
        self.assertGreaterEqual(out["totals"].get(MEMBER_FAILED, 0), 1)
        failed = [m for m in engine.members.values()
                  if m.status == MEMBER_FAILED]
        self.assertEqual(failed[0].role, "web-api")

    def test_no_worker_blockeds_degraded_not_fake(self):
        engine = TeamEngine(_mission(self.root), worker=None,
                            project_root=self.root)
        out = engine.run()
        self.assertEqual(out["status"], "complete")
        for m in engine.members.values():
            self.assertEqual(m.result.get("status"), "BLOCKED")
            self.assertIn("dispatch_payload_keys", m.result)

    def test_crash_resume_recovered_stale_worker(self):
        engine = TeamEngine(_mission(self.root), worker=_ok_worker,
                            project_root=self.root)
        engine.plan(bug_classes=["ssrf"])
        member = next(iter(engine.members.values()))
        stale = (datetime.now(timezone.utc) - timedelta(minutes=20)
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")
        member.status = "running"
        member.worker_id = "worker-deadbeef"
        member.heartbeat_at = stale
        engine.checkpoint()

        engine2 = TeamEngine.load("m-test", project_root=self.root,
                                  worker=_ok_worker)
        out = engine2.resume()
        self.assertEqual(out["status"], "complete")
        recovered = [m for m in engine2.members.values()
                     if m.member_id == member.member_id]
        self.assertGreaterEqual(recovered[0].attempt, 2)
        runs = (Path(self.root) / "state/orchestrator/m-test/team/"
                "runs.jsonl").read_text()
        self.assertIn("recovered", runs)

    def test_resume_terminal_members_never_rerun(self):
        engine = TeamEngine(_mission(self.root), worker=_ok_worker,
                            project_root=self.root)
        engine.run()
        attempts = {m.member_id: m.attempt for m in engine.members.values()}
        engine2 = TeamEngine.load("m-test", project_root=self.root,
                                  worker=_ok_worker)
        engine2.resume()
        for m in engine2.members.values():
            self.assertEqual(m.attempt, attempts[m.member_id])

    def test_dispatch_payload_carries_scope_sandbox_and_prompt(self):
        seen = []

        def worker(payload):
            seen.append(payload)
            return {"status": MEMBER_DONE}

        engine = TeamEngine(_mission(self.root), worker=worker,
                            project_root=self.root)
        engine.run()
        p = seen[0]
        self.assertTrue(p["scope_required"] and p["sandbox_required"])
        self.assertGreater(len(p["prompt"]), 200)  # playbook body present
        self.assertTrue(p["prompt_digest"])
        self.assertEqual(p["mission"]["mission_id"], "m-test")

    def test_load_missing_state_raises(self):
        with self.assertRaises(FileNotFoundError):
            TeamEngine.load("m-nope", project_root=self.root)


# ---------------------------------------------------------------------------
# Scheduler bindings + generator + bridge surface
# ---------------------------------------------------------------------------


class TestSchedulerAgentBindings(unittest.TestCase):
    def test_lane_roots_get_agent_bindings(self):
        from tools.runtime.scheduler import Scheduler
        with tempfile.TemporaryDirectory() as tmp:
            sched = Scheduler(_mission(tmp), project_root=tmp)
            sched.plan_mission()
            bindings = sched.attach_agent_bindings()
            self.assertTrue(bindings)
            for node in sched._nodes.values():
                if node.spec["task_type"] != "dispatch":
                    continue
                inputs = node.spec["inputs"]
                self.assertTrue(inputs.get("agent_role"))
                self.assertTrue(inputs.get("harness_role", "")
                                .startswith("bugwolf:"))
                self.assertIn(inputs.get("tier_affinity"), TIERS)


class TestGeneratorSync(unittest.TestCase):
    def test_generated_agents_in_sync(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, "scripts/generate_agents.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0,
                         f"drift: {proc.stdout or proc.stderr}")


class TestBridgeTeamSurface(unittest.TestCase):
    def test_dispatch_agents_and_team(self):
        sys.path.insert(0, str(ROOT / "bridge"))
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "bugwolf_mcp", ROOT / "bridge" / "bugwolf-mcp.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            sys.path.remove(str(ROOT / "bridge"))
        with tempfile.TemporaryDirectory() as tmp:
            listing = mod.dispatch("tools/list", {})
            names = [t["name"] for t in listing["tools"]]
            self.assertIn("bugwolf_agents", names)
            self.assertIn("bugwolf_team", names)
            res = mod.dispatch("tools/call", {"name": "bugwolf_agents",
                                              "arguments": {"verify": 1}})
            value = json.loads(res["content"][0]["text"])
            self.assertTrue(value["verified"])
            plan = mod.dispatch("tools/call", {
                "name": "bugwolf_team",
                "arguments": {"action": "plan", "mission_id": "m-mcp",
                              "target": "stub.local",
                              "project_root": tmp,
                              "domains": ["web_api"],
                              "bug_classes": ["ssrf"]}})
            value = json.loads(plan["content"][0]["text"])
            self.assertEqual(value["totals"]["members"],
                             len(value["waves"].get("hunt", []))
                             + len(value["waves"].get("recon", []))
                             + len(value["waves"].get("verify", []))
                             + len(value["waves"].get("report", [])))
            # dispatch() raises for unknown actions; the stdio main() loop
            # converts that into a JSON-RPC error object so the bridge
            # process itself never crashes
            with self.assertRaises(ValueError) as ctx:
                mod.dispatch("tools/call", {
                    "name": "bugwolf_team",
                    "arguments": {"action": "explode",
                                  "mission_id": "m-mcp"}})
            self.assertIn("action must be", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
