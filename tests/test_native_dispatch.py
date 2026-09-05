#!/usr/bin/env python3
"""Native in-process dispatch tests: argv construction, honest result
parsing, subprocess discipline, and engine-through-native round trip."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.native_dispatch import NativeTaskWorker  # noqa: E402
from tools.runtime.team import TeamEngine  # noqa: E402
from tools.reliability import ResourceLimitError  # noqa: E402


def _mission(tmp: str, **kw) -> MissionSpec:
    defaults = dict(mission_id="m-native", target="stub.local",
                    domains=["web_api", "auth"],
                    budget={"max_agents": 12, "max_parallel_tasks": 4})
    defaults.update(kw)
    return MissionSpec(**defaults)


def _ok_worker(payload):
    return {"status": "DONE", "summary": f"{payload['role']} ok"}


class NativeArgvTests(unittest.TestCase):
    """Command construction is argv-only and preference-honest."""

    def _worker(self, **kw):
        return NativeTaskWorker(_mission("/tmp"), **kw)

    def test_default_argv_shape(self):
        argv = self._worker()._argv_for({"model_preference": ""})
        self.assertEqual(argv[:4], ["claude", "--print",
                                    "--output-format", "json"])

    def test_default_map_pins_router_preferences(self):
        # Zero-config pinning: the router's preference strings resolve
        # through DEFAULT_MODEL_MAP without an operator model_map.
        from tools.runtime.native_dispatch import DEFAULT_MODEL_MAP
        w = self._worker()
        self.assertEqual(w._model_flag("slm-fast"), "haiku")
        self.assertEqual(w._model_flag("frontier-reasoning"), "sonnet")
        self.assertEqual(w._model_flag("none"), "")
        self.assertIn("slm-fast", DEFAULT_MODEL_MAP)
        self.assertIn("frontier-reasoning", DEFAULT_MODEL_MAP)

    def test_router_preferences_reach_argv(self):
        w = self._worker()
        argv = w._argv_for({"model_preference": "slm-fast"})
        self.assertEqual(argv[argv.index("--model") + 1], "haiku")
        argv = w._argv_for({"model_preference": "frontier-reasoning"})
        self.assertEqual(argv[argv.index("--model") + 1], "sonnet")

    def test_none_preference_stays_flagless(self):
        # Deterministic members warrant no model call: "none" maps to ""
        # and its fallback (also "none") must not resurrect a pin.
        argv = self._worker()._argv_for({
            "model_preference": "none", "fallback_preference": "none"})
        self.assertNotIn("--model", argv)

    def test_unknown_primary_degrades_to_fallback(self):
        w = self._worker()
        argv = w._argv_for({"model_preference": "quantum-9000",
                            "fallback_preference": "slm-fast"})
        self.assertEqual(argv[argv.index("--model") + 1], "haiku")

    def test_unknown_primary_and_fallback_stay_flagless(self):
        # Never guess: both unmapped -> no --model at all.
        argv = self._worker()._argv_for({
            "model_preference": "quantum-9000",
            "fallback_preference": "quantum-9001"})
        self.assertNotIn("--model", argv)

    def test_operator_map_overrides_per_key(self):
        w = self._worker(model_map={"slm-fast": "glm-air"})
        self.assertEqual(w._model_flag("slm-fast"), "glm-air")
        # non-overridden default keys survive the merge
        self.assertEqual(w._model_flag("frontier-reasoning"), "sonnet")
        argv = w._argv_for({"model_preference": "slm-fast"})
        self.assertEqual(argv[argv.index("--model") + 1], "glm-air")

    def test_default_map_merges_operator_empty_value(self):
        # An operator can pin a preference to "" to force the harness
        # default (e.g. run everything on the session's model).
        w = self._worker(model_map={"frontier-reasoning": ""})
        argv = w._argv_for({"model_preference": "frontier-reasoning",
                            "fallback_preference": "slm-fast"})
        # primary unmapped-to-empty degrades to the fallback's pin
        self.assertEqual(argv[argv.index("--model") + 1], "haiku")

    def test_known_model_preference_maps_to_model_flag(self):
        w = self._worker(model_map={"slm-fast": "haiku"})
        argv = w._argv_for({"model_preference": "slm-fast"})
        self.assertIn("--model", argv)
        self.assertEqual(argv[argv.index("--model") + 1], "haiku")

    def test_unknown_preference_is_dropped_not_guessed(self):
        w = self._worker(model_map={"slm-fast": "haiku"})
        argv = w._argv_for({"model_preference": "quantum-9000"})
        self.assertNotIn("--model", argv)

    def test_default_pins_agent_role(self):
        # Zero-config subagent pinning: the payload's harness_role becomes
        # --agent so headless runs execute the specialist playbook.
        argv = self._worker()._argv_for({"harness_role": "bugwolf:waf-bypass"})
        self.assertIn("--agent", argv)
        self.assertEqual(argv[argv.index("--agent") + 1],
                         "bugwolf:waf-bypass")

    def test_missing_harness_role_stays_flagless(self):
        # No role in the payload -> no guess, no flag (engine always sets
        # it, but the worker must not invent one).
        for payload in ({}, {"harness_role": ""}, {"harness_role": "   "}):
            argv = self._worker()._argv_for(payload)
            self.assertNotIn("--agent", argv)

    def test_pin_agent_false_opts_out(self):
        w = self._worker(pin_agent=False)
        argv = w._argv_for({"harness_role": "bugwolf:waf-bypass"})
        self.assertNotIn("--agent", argv)

    def test_command_builder_wins_over_pinning(self):
        # The operator builder fully replaces argv construction: no pin,
        # no model flag leak through.
        w = self._worker(command_builder=lambda p: ["fake-cli", "--headless"])
        argv = w._argv_for({"harness_role": "bugwolf:waf-bypass",
                            "model_preference": "slm-fast"})
        self.assertEqual(argv, ["fake-cli", "--headless"])

    def test_pin_ordering_model_then_agent_then_extra(self):
        argv = self._worker(extra_args=["--verbose"])._argv_for({
            "harness_role": "bugwolf:waf-bypass",
            "model_preference": "slm-fast"})
        self.assertLess(argv.index("--model"), argv.index("--agent"))
        self.assertLess(argv.index("--agent"), argv.index("--verbose"))

    def test_extra_args_append(self):
        argv = self._worker(extra_args=["--verbose"])._argv_for({})
        self.assertIn("--verbose", argv)

    def test_custom_builder_wins(self):
        seen = {}

        def builder(payload):
            seen.update(payload)
            return ["fake-cli", "--headless"]

        argv = self._worker(command_builder=builder)._argv_for({"a": 1})
        self.assertEqual(argv, ["fake-cli", "--headless"])
        self.assertEqual(seen.get("a"), 1)

    def test_empty_builder_argv_rejected(self):
        w = self._worker(command_builder=lambda p: [])
        with self.assertRaises(ValueError):
            w._argv_for({})


class NativeResultParsingTests(unittest.TestCase):
    """Subprocess outcomes map to honest member terminals."""

    def _worker(self):
        return NativeTaskWorker(_mission("/tmp"))

    def _proc(self, code=0, out=b"", err=b""):
        return subprocess.CompletedProcess(["claude"], code, out, err)

    def test_nonzero_exit_is_failed(self):
        res = self._worker()._parse_result(self._proc(3, err=b"boom"))
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("boom", res["summary"])

    def test_empty_output_is_failed(self):
        res = self._worker()._parse_result(self._proc(0, out=b"  \n"))
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("no output", res["summary"])

    def test_plain_text_is_failed_with_contract_error(self):
        res = self._worker()._parse_result(
            self._proc(0, out=b"recon finished, 12 hosts"))
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("12 hosts", res["summary"])
        self.assertEqual(res["contract_error"], "invalid_json")

    def test_json_error_is_failed(self):
        res = self._worker()._parse_result(
            self._proc(0, out=json.dumps({"is_error": True,
                                          "result": "denied"}).encode()))
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("denied", res["summary"])

    def test_json_result_is_done(self):
        res = self._worker()._parse_result(
            self._proc(0, out=json.dumps({"result": "found 2 leads"}).encode()))
        self.assertEqual(res["status"], "DONE")
        self.assertEqual(res["summary"], "found 2 leads")

    def test_lead_status_passthrough(self):
        res = self._worker()._parse_result(
            self._proc(0, out=json.dumps(
                {"result": "rce confirmed via canary echo",
                 "lead_status": "PWNED"}).encode()))
        self.assertEqual(res["status"], "DONE")
        self.assertEqual(res["lead_status"], "PWNED")

    def test_lead_status_invalid_ignored(self):
        res = self._worker()._parse_result(
            self._proc(0, out=json.dumps(
                {"result": "x", "lead_status": "TOTAL-VICTORY"}).encode()))
        self.assertNotIn("lead_status", res)


class NativeTimeoutTests(unittest.TestCase):
    """Budget expiry is honest: BUDGET-EXHAUSTED, process group killed."""

    def test_timeout_returns_budget_exhausted(self):
        w = NativeTaskWorker(
            _mission("/tmp"), timeout_seconds=1,
            command_builder=lambda p: ["sleep", "30"])
        res = w({"prompt": "x"})
        self.assertEqual(res["status"], "BUDGET-EXHAUSTED")
        self.assertTrue(res["timed_out"])

    def test_timeout_is_capped_at_reliability_limit(self):
        w = NativeTaskWorker(_mission("/tmp"), timeout_seconds=99999)
        self.assertEqual(w.timeout_seconds, 3600)


class NativeFailureTests(unittest.TestCase):
    """Spawn failures and output caps map to honest FAILED."""

    def test_missing_cli_is_failed_not_crash(self):
        w = NativeTaskWorker(_mission("/tmp"), cli="definitely-not-a-cli-xyz")
        res = w({"prompt": "x"})
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("spawn error", res["summary"])

    def test_output_cap_is_failed(self):
        # Bounded 100KB overflow — an infinite generator (yes) would be
        # buffered fully by communicate() before the cap check fires.
        w = NativeTaskWorker(
            _mission("/tmp"), max_output_bytes=1024, timeout_seconds=10,
            command_builder=lambda p: [
                "sh", "-c", "head -c 100000 /dev/zero | tr '\\0' 'x'"])
        res = w({"prompt": "x"})
        self.assertEqual(res["status"], "FAILED")
        self.assertIn("cap", res["summary"])


class EngineThroughNativeTests(unittest.TestCase):
    """The engine accepts the native worker and records its terminals."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bw-native-")

    def test_engine_runs_with_native_worker(self):
        # Real subprocess path: a fake CLI proves the engine -> worker ->
        # spawn -> parse -> terminal chain end-to-end.
        fake = Path(self.root) / "fake-cli.sh"
        fake.write_text(
            "#!/bin/sh\n"
            "prompt=$(cat)\n"
            "printf '%s' '{\"result\": \"member work done\"}'\n")
        fake.chmod(0o755)
        engine = TeamEngine(
            _mission(self.root), project_root=self.root,
            worker=NativeTaskWorker(_mission(self.root), cli=str(fake)))
        engine.plan(bug_classes=["ssrf"])
        engine.run()
        self.assertEqual(engine.state["status"], "complete")
        for member in engine.members.values():
            self.assertEqual(member.status, "DONE",
                             f"{member.role}: {member.result}")

    def test_engine_records_native_timeout_honestly(self):
        engine = TeamEngine(
            _mission(self.root), project_root=self.root,
            worker=NativeTaskWorker(
                _mission(self.root), timeout_seconds=1,
                command_builder=lambda p: ["sleep", "30"]),
            stale_seconds=60)
        engine.plan(bug_classes=["ssrf"])
        engine.run()
        for member in engine.members.values():
            self.assertEqual(member.status, "BUDGET-EXHAUSTED",
                             f"{member.role}: {member.result}")

    def test_plain_worker_still_accepted(self):
        engine = TeamEngine(_mission(self.root), project_root=self.root,
                            worker=_ok_worker)
        engine.plan(bug_classes=["ssrf"])
        engine.run()
        self.assertEqual(engine.state["status"], "complete")


if __name__ == "__main__":
    unittest.main()
