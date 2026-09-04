#!/usr/bin/env python3
"""Phase 6 tests: persistent modes + T3-T4 ladder + plugin package.

Contracts under test (plan v2 section 6):
  * Five mode state machines with explicit entry, tick, and completion
    predicates; resume replays the JSONL tail.
  * Escalation ladder T3-T4 wired to deep-dive; R4 research refresh
    records durable refs and grows the required technique set (research
    output is never self-satisfying); BUDGET-EXHAUSTED only after matrix
    recorded-tried + research + ladder T4.
  * Terminal states are FINAL: a later replay can never overwrite
    BUDGET-EXHAUSTED/PWNED with REFUTED.
  * Stop/resume: open leads re-dispatch FIRST; completed deterministic
    work never re-runs.
  * Plugin package: plugin.json + hooks.json parse; all 8 commands exist;
    the hook shim is thin (JSON in -> JSONL append + JSON decision out);
    the MCP bridge speaks JSON-RPC and exposes the orchestrator tools.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
import time
import http.server
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec, ContractViolation
from tools.runtime.lead_protocol import LeadStore, TIER_T4
from tools.runtime.modes import (
    ModeEngine, MODES, deep_dive_candidates, escalate_to_t3, t4_swarm_plan,
    MODE_RESEARCH, MODE_DEEP_DIVE,
)
from tools.runtime.mission_runner import MissionRunner

ROOT = Path(__file__).resolve().parents[1]
STUB_TARGET = ROOT / "tests" / "_stub_target.py"


def _boot_stub_target():
    spec = importlib.util.spec_from_file_location("stub_target", STUB_TARGET)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["_stub_target.py"]
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
    return base, (lambda: (server.shutdown(), server.server_close()))


class EnvMixin:
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name

    def tearDown(self):
        # Restore BEFORE cleanup (the cross-suite poisoning lesson).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        self._td.cleanup()


class ModesTest(EnvMixin, unittest.TestCase):
    """Mode state machines: entry, tick, completion, stop/resume."""

    def _mission(self, mission_id="m6", target="stub.local"):
        return MissionSpec(mission_id=mission_id, target=target,
                           domains=["web_api"], budget={"max_agents": 8})

    def test_five_modes_exist(self):
        self.assertEqual(len(MODES), 5)
        for mode in ("research", "verify", "deep-dive", "coverage",
                     "report"):
            self.assertIn(mode, MODES)

    def test_unknown_mode_rejected(self):
        engine = ModeEngine(self._mission())
        with self.assertRaises(ValueError):
            engine.enter("not-a-mode")

    def test_entry_guards(self):
        engine = ModeEngine(self._mission("m-guards"))
        # verify with zero open leads -> violation
        with self.assertRaises(ContractViolation):
            engine.run("verify", max_ticks=1)
        # report with zero open leads and nothing terminal: report tick
        # itself is allowed (assembly of empty artifacts), but deep-dive
        # with no stalled candidate is a violation.
        with self.assertRaises(ContractViolation):
            engine.run("deep-dive", max_ticks=1)

    def test_research_mode_completes_queue_dry(self):
        engine = ModeEngine(self._mission("m-research"), budget_ticks=3)
        outcome = engine.run("research")
        self.assertEqual(outcome["completion"], "queue_dry")
        self.assertEqual(outcome["ticks"], 1)

    def test_deep_dive_ladder_t0_to_t4_to_terminal(self):
        store = LeadStore("m-dd").load()
        lead = store.open_lead(title="stalled", mission_id="m-dd",
                               target="stub.local", bug_class="generic",
                               surface="/x")
        engine = ModeEngine(self._mission("m-dd"), budget_ticks=8)
        outcome = engine.run("deep-dive")
        # T3 escalation -> T4 swarm -> chain terminal: 3 ticks.
        self.assertEqual(outcome["completion"], "chain_terminal")
        self.assertEqual(outcome["ticks"], 3)
        final = LeadStore("m-dd").load().get(lead.lead_id)
        self.assertEqual(final.tier, TIER_T4)
        # Ladder substrate is deterministic and operator-visible.
        self.assertTrue(escalate_to_t3(final)["to_tier"], 3)
        self.assertEqual(t4_swarm_plan(final)["k"], 4)
        self.assertEqual(deep_dive_candidates([]), [])

    def test_stop_resume_replays_jsonl_tail(self):
        store = LeadStore("m-sr").load()
        lead = store.open_lead(title="open", mission_id="m-sr",
                               target="stub.local", bug_class="generic",
                               surface="/x")
        engine = ModeEngine(self._mission("m-sr"), budget_ticks=2)
        engine.run("research")
        # Real flow: a pending task carries the open lead (as lane results
        # attach them via scheduler.record).  It must re-dispatch FIRST.
        sched = engine.scheduler
        sched.plan_mission()
        pre = sched.runnable()[0]
        sched.start(pre.task_id)
        sched.record_preflight({"sha256": "0" * 64, "digest": "d",
                                "connections": {}})
        sched._add({"task_id": "lane-900-lead", "task_type": "dispatch",
                    "domain": "web_api", "mission_id": "m-sr",
                    "title": "open-lead lane", "priority": 9,
                    "status": "pending"},
                   lead_ids=[lead.lead_id])
        sched.save()
        plan = engine.stop()  # freeze + resume in one contract
        # Open leads first (R6): the pending lead task jumps the queue.
        self.assertIn("lane-900-lead", plan["lead_first"])
        self.assertIn(lead.lead_id, plan["open_leads"])
        mode, ticks = engine._replay()
        self.assertEqual(mode, "research")
        self.assertEqual(ticks, 2)  # refresh tick + queue-dry tick
        # The journal is durable JSONL.
        journal = Path(engine.journal_path).read_text().strip().splitlines()
        actions = [json.loads(l)["action"] for l in journal]
        self.assertIn("enter", actions)
        self.assertIn("stop", actions)
        self.assertIn("resume", actions)

    def test_report_mode_writes_artifact(self):
        store = LeadStore("m-rep").load()
        lead = store.open_lead(title="f", mission_id="m-rep",
                               target="stub.local", bug_class="generic",
                               surface="/x")
        store.close_pwned(lead.lead_id, evidence_ref="replay-1")
        engine = ModeEngine(self._mission("m-rep"), budget_ticks=2)
        outcome = engine.run("report")
        self.assertEqual(outcome["completion"], "report_artifacts_complete")
        artifact = json.loads(
            Path(engine.dir, "report.json").read_text())
        self.assertEqual(len(artifact["findings"]), 1)
        self.assertEqual(artifact["findings"][0]["lead_id"], lead.lead_id)


class LadderTest(EnvMixin, unittest.TestCase):
    """R4 research semantics + terminal finality + e2e exhaustion."""

    def test_record_research_grows_required_set(self):
        store = LeadStore("m-r4").load()
        lead = store.open_lead(title="t", mission_id="m-r4",
                               target="x", bug_class="generic", surface="/y")
        before = store.untried_techniques(lead)
        store.record_research(lead.lead_id, "q-hash",
                              techniques=["param-wrap"])
        after = store.untried_techniques(
            LeadStore("m-r4").load().get(lead.lead_id))
        # Research output JOINS the required set -- never satisfies it.
        self.assertIn("param-wrap", after)
        self.assertEqual(len(after), len(before) + 1)
        self.assertTrue(after[-1] == "param-wrap")

    def test_terminal_states_are_final(self):
        store = LeadStore("m-final").load()
        lead = store.open_lead(title="t", mission_id="m-final", target="x",
                               bug_class="generic", surface="/y")
        store.record_technique(lead.lead_id, "direct-attempt", "tried")
        store.record_research(lead.lead_id, "q", techniques=[])
        fresh = LeadStore("m-final").load().get(lead.lead_id)
        # Force the ladder substrate: record everything + escalate.
        for t in ("parameter-mutation", "context-switch",
                  "encoding-variant"):
            store.record_technique(lead.lead_id, t, "tried")
        store.escalate(lead.lead_id, TIER_T4, reason="test")
        blockers = store.exhaustion_blockers(store.get(lead.lead_id))
        self.assertEqual(blockers, [])
        store.close_exhausted(lead.lead_id, operator_note="test")
        # A later replay must NEVER overwrite exhaustion with REFUTED.
        after = store.close_refuted(lead.lead_id,
                                    counter_evidence="late replay")
        self.assertEqual(after.status, "BUDGET-EXHAUSTED")
        # ... and PWNED is equally final.
        other = store.open_lead(title="t2", mission_id="m-final",
                                target="x", bug_class="generic",
                                surface="/z")
        store.close_pwned(other.lead_id, evidence_ref="ev")
        final = store.close_refuted(other.lead_id,
                                    counter_evidence="late replay")
        self.assertEqual(final.status, "PWNED")


class LadderE2ETest(EnvMixin, unittest.TestCase):
    """Full mission: a generic lead walks the ladder to a terminal state."""

    def test_generic_lead_exhausts_with_full_audit_trail(self):
        boot = _boot_stub_target()
        if boot is None:
            self.skipTest("stub target missing")
        self.base, self._shutdown = boot
        self.addCleanup(self._shutdown)
        mission = MissionSpec(
            mission_id="m6-e2e", target=self.base,
            domains=["recon", "web_api", "verify", "report"],
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 600})
        runner = MissionRunner(mission, project_root=self._td.name,
                               base_url=self.base, paths=["/graphql"])
        try:
            report = runner.run()
        finally:
            runner.close()
        store = LeadStore("m6-e2e").load()
        leads = store.list_leads()
        self.assertEqual(len(leads), 1)
        lead = leads[0]
        # The ladder ran to completion: matrix recorded-tried, research
        # recorded, T4 reached, terminal BUDGET-EXHAUSTED (nothing on the
        # stub's /graphql surface wins the generic matrix -- honest).
        self.assertEqual(lead.status, "BUDGET-EXHAUSTED")
        self.assertEqual(lead.tier, TIER_T4)
        self.assertEqual(store.exhaustion_blockers(lead), [])
        tried = {e["technique"] for e in lead.technique_log}
        self.assertTrue({"direct-attempt", "parameter-mutation",
                         "context-switch", "encoding-variant"} <= tried)
        self.assertEqual(len(lead.research_refs), 1)
        # Zero refuted: terminal states were never overwritten.
        self.assertEqual(report["counts"]["refuted"], 0)
        self.assertEqual(report["counts"]["open"], 0)


class PluginPackageTest(EnvMixin, unittest.TestCase):
    """Plugin package: manifest, hooks shim, commands, MCP bridge."""

    def test_plugin_manifest_and_hooks_parse(self):
        plugin = json.loads(
            (ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin["name"], "bugwolf")
        for rel in plugin["commands"]:
            self.assertTrue((ROOT / rel).is_file(), rel)
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        self.assertIn("SessionStart", hooks["hooks"])
        self.assertIn("Stop", hooks["hooks"])

    def test_all_eight_commands_exist_with_frontmatter(self):
        names = ["bugwolf", "bugwolf-plan", "bugwolf-run", "bugwolf-status",
                 "bugwolf-review", "bugwolf-report", "bugwolf-stop",
                 "bugwolf-resume"]
        for name in names:
            path = ROOT / "commands" / f"{name}.md"
            self.assertTrue(path.is_file(), name)
            text = path.read_text()
            self.assertTrue(text.startswith("---"), name)
            self.assertIn("description:", text.split("---")[1], name)

    def test_hook_shim_thin_contract(self):
        env = dict(os.environ, BUGWOLF_PROJECT_ROOT=self._td.name,
                   BUGWOLF_MISSION_ID="m-hook")
        for action in ("session-start", "stop", "resume"):
            proc = subprocess.run(
                ["python3", str(ROOT / "hooks" / "bugwolf_stop_hook.py"),
                 action], input="{}", capture_output=True, text=True,
                env=env, timeout=10)
            self.assertEqual(proc.returncode, 0, action)
            decision = json.loads(proc.stdout)
            self.assertTrue(decision["continue"])
        journal = (Path(self._td.name) / "state" / "orchestrator"
                   / "m-hook" / "hooks.jsonl").read_text().strip()
        lines = [json.loads(l) for l in journal.splitlines()]
        self.assertEqual([l["hook"] for l in lines],
                         ["session-start", "stop", "resume"])

    def test_hook_shim_survives_garbage_stdin(self):
        proc = subprocess.run(
            ["python3", str(ROOT / "hooks" / "bugwolf_stop_hook.py"),
             "stop"], input="not-json{{", capture_output=True, text=True,
            env=dict(os.environ, BUGWOLF_PROJECT_ROOT=self._td.name),
            timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(json.loads(proc.stdout)["continue"])

    def test_mcp_bridge_protocol(self):
        env = dict(os.environ, BUGWOLF_PROJECT_ROOT=self._td.name)
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
             "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "bugwolf_plan",
                        "arguments": {"mission_id": "m-mcp",
                                      "target": "stub.local"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "no/such",
             "params": {}},
        ]
        proc = subprocess.run(
            ["python3", str(ROOT / "bridge" / "bugwolf-mcp.py")],
            input="\n".join(json.dumps(m) for m in messages) + "\n",
            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0)
        replies = [json.loads(l)
                   for l in proc.stdout.strip().splitlines() if l.strip()]
        self.assertEqual(len(replies), 4)
        self.assertEqual(replies[0]["result"]["serverInfo"]["name"],
                         "bugwolf")
        tool_names = {t["name"]
                      for t in replies[1]["result"]["tools"]}
        self.assertEqual(tool_names, {"bugwolf_status", "bugwolf_plan",
                                      "bugwolf_run", "bugwolf_leads",
                                      "bugwolf_mode", "bugwolf_agents",
                                      "bugwolf_team"})
        planned = json.loads(
            replies[2]["result"]["content"][0]["text"])
        self.assertTrue(any(t.startswith("pf-")
                            for t in planned["planned"]))
        self.assertIn("error", replies[3])


if __name__ == "__main__":
    unittest.main()
