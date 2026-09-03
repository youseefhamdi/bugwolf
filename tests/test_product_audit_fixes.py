#!/usr/bin/env python3
"""Regression tests for the product-readiness audit fixes.

Contracts pinned here (product audit, HIGH findings):
  1. Scheduler.save() never persists account passwords/tokens -- graph.json
     carries only __redacted__ sentinels; the in-memory spec is untouched.
  2. Scheduler.load() + AccountMatrix degrade safely on resume: redacted
     credentials are treated as absent, never replayed at a target.
  3. The race engine validates TLS certificates by default.
  4. The hook shim journals only allowlisted keys -- no caller-controlled
     payload dump into the mission journal.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.scheduler import Scheduler  # noqa: E402
from tools.runtime.accounts import AccountMatrix, REDACTED  # noqa: E402


class CredentialRedactionTest(unittest.TestCase):
    """graph.json must be credential-free (HIGH audit finding #1)."""

    def test_save_never_persists_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            mission = MissionSpec(
                mission_id="audit-redact", target="http://127.0.0.1:1",
                accounts=[{"label": "A", "username": "u", "password": "S3cret-PW",
                           "token": "tok-abc123", "login_path": "/login"}])
            sched = Scheduler(mission, project_root=td)
            sched.plan_mission()
            sched.save()

            raw = (Path(td) / "state" / "orchestrator" / "audit-redact"
                   / "graph.json").read_text()
            self.assertNotIn("S3cret-PW", raw, "password leaked to disk")
            self.assertNotIn("tok-abc123", raw, "token leaked to disk")
            stored = json.loads(raw)["mission"]["accounts"][0]
            self.assertEqual(stored["password"], REDACTED)
            self.assertEqual(stored["token"], REDACTED)
            # Non-credential fields survive for honest resume context.
            self.assertEqual(stored["username"], "u")
            self.assertEqual(stored["login_path"], "/login")
            # In-memory spec is untouched so live lanes still bind.
            self.assertEqual(sched.mission.accounts[0]["password"], "S3cret-PW")

    def test_load_roundtrip_has_no_secret_and_degrades_safely(self):
        with tempfile.TemporaryDirectory() as td:
            mission = MissionSpec(
                mission_id="audit-resume", target="http://127.0.0.1:1",
                accounts=[{"label": "B", "token": "live-token-xyz"}])
            Scheduler(mission, project_root=td).plan_mission()

            loaded = Scheduler.load("audit-resume", project_root=td)
            self.assertNotIn("live-token-xyz", json.dumps(loaded.mission.to_dict()))
            # from_specs treats the sentinel as absent and says so.
            matrix = AccountMatrix.from_specs("http://127.0.0.1:1",
                                              loaded.mission.accounts)
            notes = matrix.bind(login_fn=lambda *a, **k: (500, ""))
            self.assertTrue(any("redacted" in n for n in notes),
                            f"resume must disclose redaction: {notes}")
            # A redacted token must never become a live binding.
            binding = matrix._bindings["B"]
            self.assertNotEqual(binding.token, "live-token-xyz")
            self.assertNotEqual(binding.token, REDACTED)

    def test_redacted_password_never_reaches_login_payload(self):
        matrix = AccountMatrix.from_specs("http://127.0.0.1:1", [
            {"label": "A", "username": "u", "password": REDACTED,
             "login_path": "/login"}])
        captured = {}

        def fake_login(url, payload):
            captured.update(payload)
            return (500, "")

        matrix.bind(login_fn=fake_login)
        self.assertNotEqual(captured.get("password"), REDACTED,
                            "sentinel must not be replayed at the target")


class RaceTlsDefaultTest(unittest.TestCase):
    """TLS verification defaults ON (HIGH audit finding: MITM owns the race)."""

    def test_default_request_verifies_tls(self):
        from tools.validation.race_engine import RaceRequest
        self.assertTrue(RaceRequest(url="https://x.example").verify_tls)

    def test_insecure_mode_still_available_explicitly(self):
        from tools.validation.race_engine import RaceRequest
        req = RaceRequest(url="https://x.example", verify_tls=False)
        self.assertFalse(req.verify_tls)


class HookJournalAllowlistTest(unittest.TestCase):
    """Hook events journal only allowlisted keys (audit finding #4)."""

    def _run_hook(self, event: dict, action: str = "stop") -> dict:
        import importlib.util
        hook = Path(__file__).resolve().parent.parent / "hooks" / "bugwolf_stop_hook.py"
        spec = importlib.util.spec_from_file_location("bw_hook", hook)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as td:
            env = {"BUGWOLF_PROJECT_ROOT": td, "BUGWOLF_MISSION_ID": "m1",
                   "PATH": os.environ.get("PATH", "")}
            stdin = io.StringIO(json.dumps(event))
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("sys.stdin", stdin), \
                 mock.patch("sys.stdout", new=io.StringIO()) as out:
                mod.main()
            decision = json.loads(out.getvalue())
            journal = (Path(td) / "state" / "orchestrator" / "m1"
                       / "hooks.jsonl").read_text()
        decision["_journal"] = [json.loads(l) for l in journal.splitlines()]
        return decision

    def test_only_allowlisted_keys_journalled(self):
        self._run_hook({
            "mission_id": "m1", "reason": "operator-stop", "trigger": "cli",
            "evil_key": "X" * 4096, "password": "hunter2", "nested": {"a": 1},
        })
        # Re-run through the public path so the journal file is checked.
        with tempfile.TemporaryDirectory() as td:
            env = {"BUGWOLF_PROJECT_ROOT": td, "BUGWOLF_MISSION_ID": "m1",
                   "PATH": os.environ.get("PATH", "")}
            stdin = io.StringIO(json.dumps({
                "mission_id": "m1", "reason": "op", "evil_key": "X" * 4096,
                "password": "hunter2"}))
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("sys.stdin", stdin), \
                 mock.patch("sys.stdout", new=io.StringIO()):
                import runpy
                try:
                    runpy.run_path(
                        str(Path(__file__).resolve().parent.parent
                            / "hooks" / "bugwolf_stop_hook.py"),
                        run_name="__main__")
                except SystemExit as exc:  # normal exit path of the shim
                    self.assertEqual(exc.code, 0)
            raw = (Path(td) / "state" / "orchestrator" / "m1"
                   / "hooks.jsonl").read_text()
        self.assertNotIn("evil_key", raw)
        self.assertNotIn("hunter2", raw)
        line = json.loads(raw.splitlines()[-1])
        self.assertEqual(line["reason"], "op")
        self.assertIn("hook", line)
        self.assertIn("ts", line)

    def test_non_dict_event_is_survivable(self):
        decision = self._run_hook(["not", "a", "dict"])
        self.assertTrue(decision["continue"])


if __name__ == "__main__":
    unittest.main()
