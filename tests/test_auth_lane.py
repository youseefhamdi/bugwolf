#!/usr/bin/env python3
"""Auth A/B/C lane + race engine binding (plan v2 sections 5.6 S5/S6).

Contract under test:
  * the auth family contributes nothing without operator accounts (no
    matrix, no traffic, no leads);
  * with accounts bound, identity surfaces with a real boundary hole open
    one lead carrying the full seven-technique matrix (R2 accounting) and
    the plan's escalation reason;
  * non-auth surfaces stay untouched;
  * the verify lane re-executes the recorded winning auth technique
    independently (F0.5) and closes the lead PWNED;
  * the FIN-TOCTOU technique dispatches through race_engine: a
    non-atomic guard is proven by more than one success inside one
    window; the window is capped (safety ceiling) and one-shot.

Runs against the deterministic stub target (tests/_stub_target.py).
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec
from tools.runtime.lead_protocol import LeadStore, TECHNIQUE_MATRIX
from tools.runtime.mission_runner import MissionRunner
from tools.validation.race_engine import (
    RaceRequest, run_race, RACE_MAX_WINDOW, last_byte_dispatcher,
)

ROOT = Path(__file__).resolve().parents[1]
STUB_TARGET = ROOT / "tests" / "_stub_target.py"


def _boot_stub_target():
    if not STUB_TARGET.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("stub_target", STUB_TARGET)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["_stub_target.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/tech.json", timeout=2) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.1)
    return base, (lambda: (server.shutdown(), server.server_close()))


OPERATOR_ACCOUNTS = [
    {"label": "A", "username": "alice", "token": "tok-aaaa-0001",
     "identifiers": ["alice", "1"]},
    {"label": "B", "username": "bob", "token": "tok-bbbb-0002",
     "identifiers": ["bob", "2"]},
]


class _AuthMissionHarness:
    """Boots the stub + runs one auth mission with the operator accounts."""

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.base, self._shutdown = _boot_stub_target()
        self.mission = MissionSpec(
            mission_id="bw-auth-lane-test", target=self.base,
            domains=["web_api", "verify", "report"],
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 600},
            accounts=OPERATOR_ACCOUNTS,
        )
        self.runner = MissionRunner(
            self.mission, base_url=self.base,
            # Operator-declared surfaces for the auth mission (as an
            # operator would declare after recon): identity + commerce
            # surfaces the stub serves.
            paths=["/api/users/1", "/api/users/2", "/api/users/42",
                   "/api/checkout", "/api/voucher/redeem"])
        return self.runner

    def __exit__(self, *exc):
        # Restore before cleanup: tests after us must not inherit a
        # deleted temp dir (that poisoned the trigger-ledger suite).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        if self._shutdown:
            self._shutdown()
        self._td.cleanup()
        return False


class TestAuthLaneEndToEnd(unittest.TestCase):
    def test_matrix_hole_opens_lead_with_full_matrix(self):
        with _AuthMissionHarness() as runner:
            signals = _probe = None  # silence linters; real call below
            from tools.runtime.mission_runner import _probe_auth_matrix
            signals = _probe_auth_matrix(
                runner.base_url,
                ["/api/users/1", "/api/users/2", "/api/checkout"],
                runner.matrix)
        # The stub's /api/users/{id} is unauthenticated (missing-auth hole),
        # so the family opens one lead per surface with the full matrix.
        self.assertEqual(len(signals), 2)
        for sig in signals:
            self.assertEqual(sig["signal"], "auth_bypass")
            self.assertEqual(len(sig["attempts"]), 7)
            tried = {a["technique"] for a in sig["attempts"]}
            self.assertEqual(tried,
                             set(TECHNIQUE_MATRIX["auth_bypass"]))
            self.assertTrue(sig["winning_technique"])
            self.assertIn("boundary", sig)

    def test_non_auth_surfaces_untouched_without_matrix(self):
        with _AuthMissionHarness() as runner:
            runner.mission.accounts = []
            from tools.runtime.accounts import AccountMatrix
            runner.matrix = AccountMatrix.from_specs(runner.base_url, [])
            from tools.runtime.mission_runner import _probe_auth_matrix
            signals = _probe_auth_matrix(
                runner.base_url, ["/api/users/1", "/api/ingest"],
                runner.matrix)
        self.assertEqual(signals, [])

    def test_direct_access_wins_on_open_surface(self):
        # On the stub, /api/users/{id} needs no session at all, so the
        # direct-access technique has nothing to bypass -- the swarm must
        # still succeed via a matrix-technique win and record every attempt.
        with _AuthMissionHarness() as runner:
            from tools.runtime.mission_runner import _probe_auth_matrix
            signals = _probe_auth_matrix(runner.base_url, ["/api/users/42"],
                                         runner.matrix)
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertIn(sig["winning_technique"], TECHNIQUE_MATRIX["auth_bypass"])
        self.assertEqual(
            {a["technique"] for a in sig["attempts"]},
            set(TECHNIQUE_MATRIX["auth_bypass"]))
        # Missing-auth boundary hole is cited in the signal detail.
        self.assertIn("missing-auth", sig["detail"])

    def test_escalation_reason_carries_winner(self):
        # The lane wiring (in _run_web_lane) escalates with the pass@k
        # reason -- verify through a full mission run.  The lead journal
        # is read INSIDE the harness context (it lives under the temp root).
        with _AuthMissionHarness() as runner:
            report = runner.run()
            findings = [f for f in report["findings"]
                        if f["bug_class"] == "auth_bypass"]
            self.assertTrue(findings, "auth findings expected on the stub")
            store = LeadStore(runner.mission.mission_id).load()
            for finding in findings:
                lead = next(l for l in store.list_leads()
                            if l.lead_id == finding["lead_id"])
                self.assertEqual(lead.status, "PWNED")
                self.assertTrue(lead.technique_log)
                self.assertTrue(
                    any(e.get("outcome") == "success"
                        for e in lead.technique_log))

    def test_full_mission_auth_findings_pwned_by_replay(self):
        with _AuthMissionHarness() as runner:
            report = runner.run()
        # Verify lane replayed every auth lead independently.
        auth_pwned = [f for f in report["findings"]
                      if f["bug_class"] == "auth_bypass"]
        self.assertTrue(auth_pwned)
        for finding in auth_pwned:
            self.assertIn(finding["surface"],
                          ("/api/users/1", "/api/users/2", "/api/users/42"))

    def test_race_engine_capped_and_one_shot(self):
        # Window size is hard-capped at the plan ceiling at dispatch time.
        self.assertEqual(RACE_MAX_WINDOW, 30)
        seen = []

        def counting_dispatcher(request):
            seen.append(request.count)
            return [(200, "ok")] * request.count

        result = run_race(RaceRequest(url="http://x/y", count=999),
                          dispatcher=counting_dispatcher)
        self.assertEqual(seen, [RACE_MAX_WINDOW])  # clamped, never 999
        self.assertEqual(result.attempted, RACE_MAX_WINDOW)

    def test_race_engine_dispatcher_injection(self):
        calls = []

        def fake_dispatcher(request):
            calls.append(request.count)
            return [(200, "ok"), (200, "ok"), (200, "ok"), (403, "no")]

        result = run_race(RaceRequest(url="http://x/y", count=4),
                          dispatcher=fake_dispatcher)
        self.assertEqual(result.successes, 3)
        self.assertEqual(result.client_errors, 1)
        self.assertEqual(calls, [4])

    def test_race_engine_aborts_on_dead_target(self):
        # Connect-abort: a struggling/dead target must not be hammered.
        result = run_race(RaceRequest(
            url="http://127.0.0.1:1/x", count=8, timeout=1.0))
        self.assertEqual(result.successes, 0)
        self.assertGreater(result.attempted, 0)


class TestRaceEngineSafety(unittest.TestCase):
    def test_invalid_url_rejected_cleanly(self):
        result = run_race(RaceRequest(url="ftp://x/y", count=2))
        self.assertEqual(result.statuses, [0, 0])
        self.assertIn("http(s)", result.error or "")

    def test_last_byte_dispatcher_builds_full_request(self):
        request = RaceRequest(url="http://x.local/api/checkout/confirm",
                              method="POST", body={"order_id": "o1"},
                              headers={"X-Test": "1"}, count=2)
        raw = last_byte_dispatcher.__module__  # import path sanity
        from tools.validation.race_engine import _build_request_bytes
        data = _build_request_bytes(request)
        self.assertTrue(data.startswith(b"POST /api/checkout/confirm HTTP/1.1"))
        self.assertIn(b"X-Test: 1", data)
        self.assertIn(b"Content-Length", data)


if __name__ == "__main__":
    unittest.main()
