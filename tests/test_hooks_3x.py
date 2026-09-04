#!/usr/bin/env python3
"""Hooks 3.2 + 3.3 + cockpit 3.4 tests (master plan Phase 3 completion).

Locked contract:

  * 3.2 UserPromptSubmit: mission context injected via
    hookSpecificOutput.additionalContext (never a block); target/boundary
    from the scope contract; open-lead count; TARGET MODEL STALE warning
    past the freshness window; no-model nudge when bound; silent when
    nothing applies;
  * 3.3 PostToolUse: HTTP-ish tool outputs auto-captured into
    state/orchestrator/<mission>/evidence.jsonl — hash-chained
    (prev_head -> entry_hash, head persisted in evidence_head), each
    record carrying replay_key = SHA-256(mission, target, method, path,
    chain head); non-HTTP payloads capture 0; garbage stdin never fatal;
  * 3.4 SessionStart cockpit: scope state, preflight digest, sandbox
    kill-switch + grants, leads by status, mode state, and target-model
    freshness (absent/present/stale with age_hours);
  * both hook shims stay thin: JSON in -> JSON out -> exit 0;
  * hooks.json registers UserPromptSubmit + PostToolUse + the cockpit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hooks import bugwolf_hooks as bh  # noqa: E402

HOOK = ROOT / "hooks" / "bugwolf_hooks.py"


class _Workspace:
    """A temp workspace with state helpers."""

    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix="bw-hooks-"))
        self.env_over = {
            "BUGWOLF_PROJECT_ROOT": str(self.path),
            "BUGWOLF_MISSION_ID": "m-test",
        }

    @property
    def state(self) -> Path:
        return self.path / "state"

    def bind_contract(self, target="target.example"):
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "scope_contract.json").write_text(json.dumps({
            "schema": "bugwolf-scope-contract/v1", "mission_id": "m-test",
            "target": target, "extra_hosts": [], "deny_entries": [],
            "mode": "deny-by-default",
            "written_at": datetime.now(timezone.utc).isoformat(),
        }), encoding="utf-8")

    def write_model(self, *, age_h: float = 0.0,
                    target: str = "target.example"):
        slug = target
        d = self.state / "targets" / slug / "model"
        d.mkdir(parents=True, exist_ok=True)
        generated = datetime.now(timezone.utc) - timedelta(hours=age_h)
        (d / "u9-target-model.json").write_text(json.dumps({
            "schema": "bugwolf-u-artifact/v1", "stage": "U9",
            "target": target, "generated_at": generated.isoformat(),
            "data": {}, "assumptions": [], "inputs": {},
            "artifact_hash": "x"}), encoding="utf-8")

    @property
    def mission_dir(self) -> Path:
        return self.state / "orchestrator" / "m-test"

    def evidence(self) -> list:
        path = self.mission_dir / "evidence.jsonl"
        if not path.exists():
            return []
        return [json.loads(l) for l in
                path.read_text(encoding="utf-8").splitlines() if l.strip()]


class _HookTest(unittest.TestCase):
    def setUp(self):
        self._ws = _Workspace()
        self._patch = unittest.mock.patch.dict(os.environ,
                                               self._ws.env_over)
        self._patch.start()
        self.addCleanup(self._patch.stop)


class TestUserPromptSubmit(_HookTest):
    def test_inert_without_contract(self):
        decision = bh.user_prompt_submit()
        self.assertTrue(decision["continue"])
        self.assertNotIn("hookSpecificOutput", decision)

    def test_bound_contract_injects_mission_context(self):
        self._ws.bind_contract("target.example")
        decision = bh.user_prompt_submit()
        ctx = decision["hookSpecificOutput"]
        self.assertEqual(ctx["hookEventName"], "UserPromptSubmit")
        self.assertIn("target=target.example", ctx["additionalContext"])
        self.assertIn("deny-by-default", ctx["additionalContext"])

    def test_stale_model_warning_names_the_window(self):
        self._ws.bind_contract()
        self._ws.write_model(age_h=30.0)
        decision = bh.user_prompt_submit()
        ctx = decision["hookSpecificOutput"]["additionalContext"]
        self.assertIn("TARGET MODEL STALE", ctx)
        self.assertIn("30", ctx)
        self.assertIn("/bugwolf-understand", ctx)

    def test_absent_model_nudge_when_bound(self):
        self._ws.bind_contract()               # no model written
        decision = bh.user_prompt_submit()
        ctx = decision["hookSpecificOutput"]["additionalContext"]
        self.assertIn("no Target Model", ctx)

    def test_fresh_model_is_silent(self):
        self._ws.bind_contract()
        self._ws.write_model(age_h=1.0)
        decision = bh.user_prompt_submit()
        ctx = decision.get("hookSpecificOutput", {}).get(
            "additionalContext", "")
        self.assertNotIn("STALE", ctx)
        self.assertNotIn("no Target Model", ctx)


class TestModelFreshness(_HookTest):
    def test_absent_without_target(self):
        self.assertEqual(bh.model_freshness()["state"], "no-target")

    def test_absent_with_target(self):
        self._ws.bind_contract()
        self.assertEqual(bh.model_freshness()["state"], "absent")

    def test_present_with_age(self):
        self._ws.bind_contract()
        self._ws.write_model(age_h=2.0)
        fresh = bh.model_freshness()
        self.assertEqual(fresh["state"], "present")
        self.assertGreaterEqual(fresh["age_hours"], 1.9)
        self.assertFalse(fresh["stale"])

    def test_stale_past_window(self):
        self._ws.bind_contract()
        self._ws.write_model(age_h=48.0)
        fresh = bh.model_freshness()
        self.assertTrue(fresh["stale"])

    def test_custom_window_via_env(self):
        os.environ["BUGWOLF_MODEL_MAX_AGE_H"] = "0.5"
        try:
            self._ws.bind_contract()
            self._ws.write_model(age_h=1.0)
            self.assertTrue(bh.model_freshness()["stale"])
        finally:
            del os.environ["BUGWOLF_MODEL_MAX_AGE_H"]


class TestPostToolUse(_HookTest):
    def test_non_http_payload_captures_zero(self):
        decision = bh.post_tool_use({"tool_name": "calc",
                                     "tool_output": {"result": 42}})
        self.assertEqual(decision["captured"], 0)
        self.assertEqual(self._ws.evidence(), [])

    def test_http_record_captured_with_replay_key(self):
        decision = bh.post_tool_use({
            "tool_name": "bugwolf_http_replay",
            "tool_output": {"status": 200, "method": "GET",
                            "path": "/api/users/1",
                            "sent_bytes": "GET /api/users/1 HTTP/1.1\r\n\r\n",
                            "raw_response": 'HTTP/1.1 200 OK\r\n\r\n{"id": 1}'}})
        self.assertEqual(decision["captured"], 1)
        (record,) = self._ws.evidence()
        self.assertEqual(record["schema"], "bugwolf-evidence/v1")
        self.assertEqual(record["status"], 200)
        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["prev_head"], "")
        self.assertEqual(record["replay_key"], decision["replay_keys"][0])
        # replay_key binds mission+target+method+path+chain head
        import hashlib
        expected = hashlib.sha256("\x1f".join(
            ("m-test", "", "GET", "/api/users/1", "")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(record["replay_key"], expected)

    def test_chain_grows_and_head_persists(self):
        bh.post_tool_use({"tool_name": "t", "tool_output": {
            "status": 200, "method": "GET", "path": "/a"}})
        bh.post_tool_use({"tool_name": "t", "tool_output": {
            "status": 403, "method": "GET", "path": "/b"}})
        records = self._ws.evidence()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["prev_head"], records[0]["entry_hash"])
        self.assertNotEqual(records[0]["entry_hash"],
                            records[1]["entry_hash"])
        head = (self._ws.mission_dir / "evidence_head").read_text(
            encoding="utf-8")
        self.assertEqual(head, records[1]["entry_hash"])

    def test_tampering_is_detectable(self):
        bh.post_tool_use({"tool_name": "t", "tool_output": {
            "status": 200, "method": "GET", "path": "/a"}})
        records = self._ws.evidence()
        tampered = dict(records[0])
        tampered["status"] = 500               # forged status
        import hashlib
        recomputed = hashlib.sha256(
            (tampered["prev_head"] +
             json.dumps({k: v for k, v in tampered.items()
                         if k != "entry_hash"}, sort_keys=True, default=str))
            .encode("utf-8")).hexdigest()
        self.assertNotEqual(recomputed, records[0]["entry_hash"])

    def test_nested_payloads_are_walker_reachable(self):
        decision = bh.post_tool_use({"tool_name": "batch", "tool_output": {
            "result": {"data": [{"status": 404, "method": "POST",
                                 "path": "/api/checkout"}]}}})
        self.assertEqual(decision["captured"], 1)

    def test_bugwolf_replay_report_captured_natively(self):
        """bugwolf's own replay reports (sent_bytes + status) capture with
        method/path parsed from the request wire text."""
        decision = bh.post_tool_use({
            "tool_name": "bugwolf_http_replay",
            "tool_output": {"mode": "raw", "host": "target.example",
                            "status": 200, "body_bytes": 93,
                            "sent_bytes": "POST /api/checkout HTTP/1.1"
                                          "\r\nHost: x\r\n\r\n",
                            "raw_response": 'HTTP/1.1 200 OK\r\n\r\n'
                                            '{"total": 25}'}})
        self.assertEqual(decision["captured"], 1)
        record = self._ws.evidence()[0]
        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["path"], "/api/checkout")
        self.assertIn("POST /api/checkout", record["request_bytes"])

    def test_raw_http_capture_form(self):
        decision = bh.post_tool_use({"tool_name": "t", "tool_output": {
            "raw_response": "HTTP/1.1 503 Service Unavailable\r\n\r\n"}})
        self.assertEqual(decision["captured"], 1)
        self.assertEqual(self._ws.evidence()[0]["status"], 503)


class TestCockpit(_HookTest):
    def test_empty_workspace_cockpit(self):
        decision = bh.session_start()
        cockpit = decision["cockpit"]
        self.assertEqual(cockpit["schema"], "bugwolf-cockpit/v1")
        self.assertFalse(cockpit["scope"]["bound"])
        self.assertEqual(cockpit["preflight_digest"], "")
        self.assertFalse(cockpit["sandbox"]["kill_switch"])
        self.assertEqual(cockpit["leads"], {"total": 0,
                                            "by_status": {}})
        self.assertIsNone(cockpit["mode"]["mode"])
        self.assertIn(cockpit["target_model"]["state"],
                      ("no-target", "absent"))

    def test_full_cockpit(self):
        self._ws.bind_contract("target.example")
        self._ws.write_model(age_h=1.0)
        (self._ws.state / "preflight").mkdir(parents=True)
        (self._ws.state / "preflight" / "manifest.json").write_text(
            json.dumps({"digest": "deadbeef"}))
        (self._ws.state / "sandbox").mkdir(parents=True)
        (self._ws.state / "sandbox" / "grants.json").write_text(
            json.dumps({"curl": {}, "python3": {}}))
        self._ws.mission_dir.mkdir(parents=True)
        (self._ws.mission_dir / "leads").mkdir()
        (self._ws.mission_dir / "leads" / "leads.jsonl").write_text(
            json.dumps({"lead_id": "L1", "status": "OPEN"}) + "\n" +
            json.dumps({"lead_id": "L2", "status": "PWNED"}) + "\n")
        (self._ws.mission_dir / "modes.jsonl").write_text(
            json.dumps({"mode": "verify", "ts": "t"}) + "\n")
        cockpit = bh.session_start()["cockpit"]
        self.assertTrue(cockpit["scope"]["bound"])
        self.assertEqual(cockpit["scope"]["target"], "target.example")
        self.assertEqual(cockpit["preflight_digest"], "deadbeef")
        self.assertEqual(cockpit["sandbox"]["grants"], 2)
        self.assertEqual(cockpit["leads"]["by_status"],
                         {"OPEN": 1, "PWNED": 1})
        self.assertEqual(cockpit["mode"]["mode"], "verify")
        self.assertEqual(cockpit["target_model"]["state"], "present")
        self.assertFalse(cockpit["target_model"]["stale"])

    def test_kill_switch_visible(self):
        (self._ws.state / "sandbox").mkdir(parents=True)
        (self._ws.state / "sandbox" / "KILL_SWITCH").write_text("")
        self.assertTrue(bh.session_start()["cockpit"]["sandbox"]
                        ["kill_switch"])


class TestShimProcess(_HookTest):
    """The shim subprocess: JSON in -> JSON out -> exit 0, always."""

    def _run(self, action: str, stdin: str = "{}") -> dict:
        proc = subprocess.run(
            ["python3", str(HOOK), action], input=stdin,
            capture_output=True, text=True,
            env=dict(os.environ, **self._ws.env_over), timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_all_three_actions_exit_zero(self):
        for action in ("user-prompt-submit", "post-tool-use",
                       "session-start"):
            decision = self._run(action)
            self.assertTrue(decision.get("continue"), action)

    def test_garbage_stdin_never_fatal(self):
        for action in ("user-prompt-submit", "post-tool-use",
                       "session-start"):
            decision = self._run(action, stdin="not-json{{{")
            self.assertTrue(decision.get("continue"), action)

    def test_unknown_action_inert(self):
        decision = self._run("nonsense-action")
        self.assertTrue(decision["continue"])

    def test_shim_is_stdlib_only(self):
        """No third-party imports: hooks must run in any Python."""
        source = HOOK.read_text(encoding="utf-8")
        import ast
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(
                        alias.name.split(".")[0] in
                        ("requests", "mitmproxy", "playwright"), alias.name)
            if isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                self.assertNotIn(top, ("requests", "mitmproxy",
                                       "playwright"), node.module)


class TestHooksJsonRegistration(unittest.TestCase):
    def test_all_three_registered(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())[
            "hooks"]
        self.assertIn("UserPromptSubmit", hooks)
        self.assertIn("PostToolUse", hooks)
        session_cmds = [h["command"]
                        for entry in hooks["SessionStart"]
                        for h in entry["hooks"]]
        self.assertTrue(any("bugwolf_hooks.py session-start" in c
                            for c in session_cmds))
        ups_cmds = [h["command"] for entry in hooks["UserPromptSubmit"]
                    for h in entry["hooks"]]
        self.assertTrue(any("user-prompt-submit" in c for c in ups_cmds))
        post_cmds = [h["command"] for entry in hooks["PostToolUse"]
                     for h in entry["hooks"]]
        self.assertTrue(any("post-tool-use" in c for c in post_cmds))


if __name__ == "__main__":
    unittest.main()
