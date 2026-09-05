#!/usr/bin/env python3
"""PreToolUse scope-enforcement hook tests (master plan Phase 3.1).

Acceptance: the deny-by-default boundary holds at the HARNESS level —
outside the model.  While a mission contract exists, out-of-scope and
policy-excluded hosts in Bash commands / WebFetch URLs are denied (exit 2
+ structured decision + policy fact on stderr, the reason the model sees);
without a contract the hook is inert (zero UX cost); harness failures
fail open (a broken hook must never block the operator's session).

Every hook case runs the REAL script as a subprocess against a temp
workspace — the same way Claude Code invokes it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HOOK = ROOT / "hooks" / "bugwolf_pretool_scope_hook.py"


def _run_hook(event: dict, workspace: str, mission_id: str = "") -> subprocess.CompletedProcess:
    env = {**os.environ, "BUGWOLF_PROJECT_ROOT": workspace}
    if mission_id:
        env["BUGWOLF_MISSION_ID"] = mission_id
    else:
        env.pop("BUGWOLF_MISSION_ID", None)
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event), capture_output=True, text=True,
        env=env, timeout=30)


def _write_contract(workspace: str, *, target: str,
                    extra=(), denies=(), mission_id="m-hook") -> None:
    contract = {
        "schema": "bugwolf-scope-contract/v1",
        "mission_id": mission_id,
        "target": target,
        "extra_hosts": sorted(extra),
        "deny_entries": sorted(denies),
        "mode": "deny-by-default",
    }
    state = Path(workspace) / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "scope_contract.json").write_text(json.dumps(contract))


def _bash(command: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


class TestHookEnforcement(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def test_inert_without_contract(self):
        out = _run_hook(_bash("curl https://evil.example/x"), self.ws)
        self.assertEqual(out.returncode, 0)
        self.assertEqual(out.stdout.strip(), "")

    def test_in_scope_bash_allowed(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook(_bash("curl -s https://target.example/api/users/1"),
                        self.ws)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_subdomain_allowed_suffix_rule(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook(_bash("curl https://api.target.example/v1"), self.ws)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_out_of_scope_denied_with_policy_fact(self):
        _write_contract(self.ws, target="target.example",
                        mission_id="m-deny")
        out = _run_hook(_bash("curl -s https://evil.example/exfil"), self.ws)
        self.assertEqual(out.returncode, 2)
        decision = json.loads(out.stdout)
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("evil.example", decision["permissionDecisionReason"])
        self.assertIn("evil.example", out.stderr)
        self.assertIn("harness", out.stderr)

    def test_deny_entry_beats_target_wildcard(self):
        _write_contract(self.ws, target="target.example",
                        denies=["beta.target.example"])
        out = _run_hook(_bash("curl https://beta.target.example/admin"),
                        self.ws)
        self.assertEqual(out.returncode, 2)
        self.assertIn("EXCLUDED", out.stderr)

    def test_lookalike_host_not_authorized_by_suffix(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook(_bash("curl https://nottarget.example/"), self.ws)
        self.assertEqual(out.returncode, 2)

    def test_host_header_override_detected(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook(_bash(
            "curl -H 'Host: evil.test' https://target.example/"), self.ws)
        self.assertEqual(out.returncode, 2)
        self.assertIn("evil.test", out.stderr)

    def test_webfetch_url_enforced(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook({"tool_name": "WebFetch",
                         "tool_input": {"url": "https://evil.example/page"}},
                        self.ws)
        self.assertEqual(out.returncode, 2)
        out2 = _run_hook({"tool_name": "WebFetch",
                          "tool_input": {"url": "https://target.example/page"}},
                         self.ws)
        self.assertEqual(out2.returncode, 0)

    def test_loopback_rule_mirrors_engine_gate(self):
        # local campaign: loopback allowed
        _write_contract(self.ws, target="127.0.0.1")
        out = _run_hook(_bash("curl http://localhost:8080/health"), self.ws)
        self.assertEqual(out.returncode, 0, out.stderr)
        # remote campaign: loopback SSRF-style fetch denied
        _write_contract(self.ws, target="in-scope.example")
        out2 = _run_hook(_bash("curl http://127.0.0.1:9090/metrics"), self.ws)
        self.assertEqual(out2.returncode, 2)

    def test_other_tools_untouched(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook({"tool_name": "Read",
                         "tool_input": {"file_path": "/etc/passwd"}}, self.ws)
        self.assertEqual(out.returncode, 0)

    def test_plain_bash_without_network_allowed(self):
        _write_contract(self.ws, target="target.example")
        out = _run_hook(_bash("ls -la && grep -r TODO src/"), self.ws)
        self.assertEqual(out.returncode, 0)

    def test_malformed_stdin_fails_open(self):
        _write_contract(self.ws, target="target.example")
        out = subprocess.run(
            [sys.executable, str(HOOK)], input="not json{",
            capture_output=True, text=True,
            env={**os.environ, "BUGWOLF_PROJECT_ROOT": self.ws}, timeout=30)
        self.assertEqual(out.returncode, 0)

    def test_mission_id_mismatch_fails_closed(self):
        _write_contract(self.ws, target="target.example", mission_id="m-owner")
        out = _run_hook(_bash("curl https://target.example/"), self.ws,
                        mission_id="m-other")
        self.assertEqual(out.returncode, 2)
        self.assertIn("mission_id", out.stderr)

    def test_denial_is_journaled(self):
        _write_contract(self.ws, target="target.example",
                        mission_id="m-journal")
        _run_hook(_bash("curl https://evil.example/x"), self.ws)
        journal = Path(self.ws) / "state" / "orchestrator" / "m-journal" \
            / "hooks.jsonl"
        self.assertTrue(journal.exists())
        line = json.loads(journal.read_text().splitlines()[-1])
        self.assertEqual(line["event"], "denied")
        self.assertEqual(line["hosts"], ["evil.example"])

    def test_clear_subcommand_removes_contract(self):
        _write_contract(self.ws, target="target.example")
        out = subprocess.run(
            [sys.executable, str(HOOK), "clear"], capture_output=True,
            text=True, env={**os.environ, "BUGWOLF_PROJECT_ROOT": self.ws},
            timeout=30)
        self.assertEqual(out.returncode, 0)
        self.assertFalse(
            (Path(self.ws) / "state" / "scope_contract.json").exists())
        # and the hook is inert again
        out2 = _run_hook(_bash("curl https://evil.example/x"), self.ws)
        self.assertEqual(out2.returncode, 0)


class TestContractPersistence(unittest.TestCase):
    """The engine-side writer the mission runner calls (same workspace
    resolution as the hook: BUGWOLF_PROJECT_ROOT)."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.ws = self._td.name
        self._saved = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self.ws

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved
        self._td.cleanup()

    def test_write_reflects_gate_state_and_hook_sees_it(self):
        from tools.runtime import scope as scope_mod
        scope_mod.reset()
        scope_mod.bind_target("https://target.example",
                              deny_entries=["beta.target.example"])
        try:
            contract = scope_mod.write_scope_contract("m-live")
            self.assertEqual(contract["target"], "target.example")
            self.assertEqual(contract["deny_entries"],
                             ["beta.target.example"])
            # the REAL hook, in the SAME workspace, enforces it:
            out = _run_hook(_bash("curl https://beta.target.example/"),
                            self.ws)
            self.assertEqual(out.returncode, 2)
            out2 = _run_hook(_bash("curl https://target.example/"), self.ws)
            self.assertEqual(out2.returncode, 0)
        finally:
            scope_mod.reset()
            scope_mod.clear_scope_contract(root=self.ws)

    def test_clear_mismatched_mission_does_not_remove_contract(self):
        _write_contract(self.ws, target="target.example", mission_id="m-owner")
        from tools.runtime import scope as scope_mod
        self.assertFalse(scope_mod.clear_scope_contract(
            root=self.ws, mission_id="m-other"))
        self.assertTrue((Path(self.ws) / "state" / "scope_contract.json").exists())

    def test_clear_makes_hook_inert(self):
        from tools.runtime import scope as scope_mod
        scope_mod.reset()
        scope_mod.bind_target("https://target.example")
        scope_mod.write_scope_contract("m-clear")
        try:
            self.assertTrue(
                (Path(self.ws) / "state" / "scope_contract.json").exists())
        finally:
            scope_mod.reset()
        scope_mod.clear_scope_contract(root=self.ws)
        self.assertFalse(
            (Path(self.ws) / "state" / "scope_contract.json").exists())
        out = _run_hook(_bash("curl https://evil.example/"), self.ws)
        self.assertEqual(out.returncode, 0)


class TestHookRegistration(unittest.TestCase):
    def test_pretooluse_registered_in_hooks_json(self):
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
        pre = hooks["hooks"]["PreToolUse"]
        self.assertEqual(pre[0]["matcher"], "Bash|WebFetch")
        self.assertIn("bugwolf_pretool_scope_hook.py", pre[0]["hooks"][0]["command"])
        self.assertTrue(HOOK.is_file())


if __name__ == "__main__":
    unittest.main()
