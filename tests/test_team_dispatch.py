#!/usr/bin/env python3
"""Task-tool dispatch bridge tests: atomic queue, claim ownership,
honest timeout, engine-through-queue round trip, CLI exit codes."""

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.contracts import MissionSpec  # noqa: E402
from tools.runtime.team import TeamEngine  # noqa: E402
from tools.runtime.team_dispatch import (  # noqa: E402
    TaskToolWorker, cli_next, cli_complete, cli_fail, cli_release,
    bind_heartbeat, SCHEMA)


def _mission(tmp: str, **kw) -> MissionSpec:
    defaults = dict(mission_id="m-dispatch", target="stub.local",
                    domains=["web_api"],
                    budget={"max_agents": 8, "max_parallel_tasks": 3})
    defaults.update(kw)
    return MissionSpec(**defaults)


def _drain_once(root: Path, mission_id: str, summary: str = "done",
                status: str = "DONE") -> bool:
    """Simulate the harness: claim one job, complete it."""
    job = cli_next(root, mission_id, worker_id="harness-test")
    if job is None:
        return False
    cli_complete(root, mission_id, job["job_id"], worker_id="harness-test",
                 summary=summary, status=status)
    return True


class TestQueueSemantics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _enqueue(self, member_id="tm-001", role="web-api"):
        mission = _mission(self.root)
        worker = TaskToolWorker(mission, project_root=self.root,
                                poll_interval=0.05, timeout_seconds=5)
        payload = {"member_id": member_id, "role": role,
                   "harness_role": f"bugwolf:{role}", "wave": "hunt",
                   "tier": "local_slm", "model_preference": "slm-fast",
                   "fallback_preference": "none",
                   "scope_required": True, "sandbox_required": True,
                   "prompt_digest": "abc123",
                   "mission": {"target": "stub.local", "objective": ""}}
        return worker, payload

    def test_job_file_shape(self):
        worker, payload = self._enqueue()
        result_holder = {}

        def harness():
            result_holder["job"] = cli_next(self.root, "m-dispatch",
                                            worker_id="h1", block_seconds=8)

        t = threading.Thread(target=harness)
        t.start()
        result = worker(payload)
        t.join(timeout=5)
        job = result_holder["job"]
        self.assertIsNotNone(job)
        self.assertEqual(job["harness_role"], "bugwolf:web-api")
        self.assertEqual(job["schema"], SCHEMA)
        self.assertTrue(job["scope_required"] and job["sandbox_required"])
        self.assertEqual(result["status"], "BUDGET-EXHAUSTED")  # never completed

    def test_claim_exclusivity(self):
        worker, payload = self._enqueue()
        threading.Thread(target=worker, args=(payload,), daemon=True).start()
        # claim with blocking wait until the job file lands
        j1 = cli_next(self.root, "m-dispatch", worker_id="w1", block_seconds=8)
        j2 = cli_next(self.root, "m-dispatch", worker_id="w2")
        self.assertIsNotNone(j1)
        self.assertIsNone(j2)  # O_EXCL: second claimer gets nothing
        cli_complete(self.root, "m-dispatch", j1["job_id"],
                     worker_id="w1", summary="ok")
        time.sleep(0.5)  # engine thread observes the result

    def test_ownership_rejection(self):
        worker, payload = self._enqueue()
        jobs = self.root / "state/orchestrator/m-dispatch/team/dispatch/jobs"
        jobs.mkdir(parents=True, exist_ok=True)
        job_file = jobs / "job-x.json"
        job_file.write_text(json.dumps(
            {"schema": SCHEMA, "job_id": "job-x", "status": "pending"}))
        cli_next(self.root, "m-dispatch", worker_id="owner")  # claims job-x
        with self.assertRaises(PermissionError):
            cli_complete(self.root, "m-dispatch", "job-x",
                         worker_id="impostor", summary="stolen")
        with self.assertRaises(PermissionError):
            cli_fail(self.root, "m-dispatch", "job-x",
                     worker_id="impostor", reason="stolen")
        with self.assertRaises(PermissionError):
            cli_release(self.root, "m-dispatch", "job-x",
                        worker_id="impostor")
        # the real owner can complete
        out = cli_complete(self.root, "m-dispatch", "job-x",
                           worker_id="owner", summary="legit")
        self.assertEqual(out["status"], "DONE")

    def test_result_identity_and_status_are_validated(self):
        worker, payload = self._enqueue(member_id="tm-identity")
        result_holder = {}

        def harness():
            job = cli_next(self.root, "m-dispatch", worker_id="h1",
                           block_seconds=5)
            result_holder["job"] = job
            result_path = worker.results_dir() / f"{job['job_id']}.json"
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text(json.dumps({
                "job_id": "different-job",
                "mission_id": "different-mission",
                "status": "DONE",
                "summary": "spoofed",
            }))

        t = threading.Thread(target=harness)
        t.start()
        result = worker(payload)
        t.join(timeout=5)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["contract_error"], "identity_mismatch")
        rejection_log = worker.dispatch_dir() / "rejections.jsonl"
        self.assertTrue(rejection_log.is_file())
        self.assertIn("identity mismatch", rejection_log.read_text())

    def test_timeout_expires_job_and_rejects_late_completion(self):
        mission = _mission(self.root)
        worker = TaskToolWorker(mission, project_root=self.root,
                                poll_interval=0.05, timeout_seconds=1)
        payload = {"member_id": "tm-009", "role": "web-api",
                   "harness_role": "bugwolf:web-api", "wave": "hunt",
                   "tier": "local_slm", "model_preference": "slm-fast",
                   "fallback_preference": "none", "scope_required": True,
                   "sandbox_required": True, "prompt_digest": "d",
                   "mission": {"target": "t", "objective": ""}}
        start = time.monotonic()
        result = worker(payload)
        elapsed = time.monotonic() - start
        self.assertEqual(result["status"], "BUDGET-EXHAUSTED")
        self.assertTrue(result.get("timed_out"))
        self.assertGreaterEqual(elapsed, 0.9)  # really waited, not faked

    def test_release_returns_job_to_queue(self):
        jobs = self.root / "state/orchestrator/m-dispatch/team/dispatch/jobs"
        jobs.mkdir(parents=True, exist_ok=True)
        (jobs / "job-y.json").write_text(json.dumps(
            {"schema": SCHEMA, "job_id": "job-y", "status": "pending"}))
        cli_next(self.root, "m-dispatch", worker_id="w1")
        cli_release(self.root, "m-dispatch", "job-y", worker_id="w1")
        again = cli_next(self.root, "m-dispatch", worker_id="w2")
        self.assertIsNotNone(again)
        self.assertEqual(again["job_id"], "job-y")

    def test_bind_heartbeat_refreshes_member(self):
        from tools.runtime.team import TeamMember
        mission = _mission(self.root)
        engine = TeamEngine(mission, worker=None, project_root=self.root)
        member = TeamMember(member_id="tm-100", role="recon",
                            harness_role="bugwolf:recon", wave="recon",
                            status="running", heartbeat_at="2000-01-01T00:00:00Z")
        engine.members["tm-100"] = member
        worker = TaskToolWorker(mission, project_root=self.root)
        self.assertFalse(hasattr(worker, "_heartbeat_cb"))
        bind_heartbeat(engine, worker)
        self.assertTrue(callable(worker._heartbeat_cb))
        worker._heartbeat_cb("tm-100")
        self.assertNotEqual(member.heartbeat_at, "2000-01-01T00:00:00Z")


class TestEngineThroughQueue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_full_mission_via_file_queue(self):
        """Engine -> queue -> simulated harness -> engine, all via files."""
        mission = _mission(self.root)
        worker = TaskToolWorker(mission, project_root=self.root,
                                poll_interval=0.05, timeout_seconds=30)
        engine = TeamEngine(mission, worker=worker, project_root=self.root)
        engine.plan(bug_classes=["ssrf"])

        # harness-side drain loop (stands in for the Claude Code session)
        handled = []

        def harness():
            while True:
                job = cli_next(self.root, "m-dispatch",
                               worker_id="harness-main", block_seconds=1)
                if job is None:
                    if len(handled) >= len(engine.members):
                        return
                    continue
                handled.append(job["role"])
                cli_complete(self.root, "m-dispatch", job["job_id"],
                             worker_id="harness-main",
                             summary=f"{job['role']} via Task tool",
                             status="DONE",
                             messages=[{"to_role": "verify", "kind": "lead",
                                        "body": {"lead": job["role"]}}]
                             if job["role"] == "web-api" else [])

        t = threading.Thread(target=harness, daemon=True)
        t.start()
        outcome = engine.run()
        t.join(timeout=10)
        self.assertEqual(outcome["status"], "complete")
        self.assertEqual(sorted(handled),
                         sorted(m.role for m in engine.members.values()))
        for m in engine.members.values():
            self.assertEqual(m.status, "DONE")
            self.assertEqual(m.result.get("worker_id"), "harness-main")
        # every dispatch was through the durable queue
        runs = (self.root / "state/orchestrator/m-dispatch/team/"
                "runs.jsonl").read_text()
        self.assertIn("started", runs)
        dispatch_dir = self.root / "state/orchestrator/m-dispatch/team/dispatch"
        self.assertTrue((dispatch_dir / "results").is_dir())

    def test_engine_timeout_marks_member_budget_exhausted(self):
        """No harness ever completes: members close BUDGET-EXHAUSTED, honestly."""
        mission = _mission(self.root)
        worker = TaskToolWorker(mission, project_root=self.root,
                                poll_interval=0.05, timeout_seconds=1)
        engine = TeamEngine(mission, worker=worker, project_root=self.root)
        outcome = engine.run(bug_classes=["ssrf"])
        self.assertEqual(outcome["status"], "complete")  # waves all closed
        for m in engine.members.values():
            self.assertEqual(m.status, "BUDGET-EXHAUSTED")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def _run(self, *extra):
        cmd = [sys.executable, "-m", "tools.runtime.team_dispatch",
               "--mission", "m-cli", "--project-root", self.root,
               "--worker-id", "cli-w", *extra]
        return subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                              text=True, timeout=60)

    def test_cli_round_trip_and_exit_codes(self):
        # empty queue
        p = self._run("--next", "--json")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["job"], None)
        # seed a job file directly
        jobs = Path(self.root) / "state/orchestrator/m-cli/team/dispatch/jobs"
        jobs.mkdir(parents=True, exist_ok=True)
        (jobs / "job-c1.json").write_text(json.dumps(
            {"schema": SCHEMA, "job_id": "job-c1", "status": "pending",
             "harness_role": "bugwolf:web-api"}))
        p = self._run("--next", "--json")
        self.assertEqual(p.returncode, 0)
        job = json.loads(p.stdout)["job"]
        self.assertEqual(job["job_id"], "job-c1")
        self.assertIn("Task(subagent_type", json.loads(p.stdout)["hint"])
        # complete it (owner ok)
        p = self._run("--complete", "job-c1", "--summary", "done it",
                      "--status", "DONE", "--json")
        self.assertEqual(p.returncode, 0)
        # result file landed
        res = Path(self.root) / ("state/orchestrator/m-cli/team/dispatch/"
                                 "results/job-c1.json")
        self.assertEqual(json.loads(res.read_text())["status"], "DONE")
        # ownership via CLI: another worker claims a fresh job, cli-w is rejected
        (jobs / "job-c2.json").write_text(json.dumps(
            {"schema": SCHEMA, "job_id": "job-c2", "status": "pending"}))
        other = subprocess.run(
            [sys.executable, "-m", "tools.runtime.team_dispatch",
             "--mission", "m-cli", "--project-root", self.root,
             "--worker-id", "someone-else", "--next"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        self.assertEqual(other.returncode, 0)
        p = self._run("--complete", "job-c2", "--summary", "stolen")
        self.assertEqual(p.returncode, 3)  # PermissionError -> exit 3
        p = self._run("--release", "job-c2")
        self.assertEqual(p.returncode, 3)  # release by non-owner also rejected
        # invalid status rejected with exit 2 (owner claim still intact)
        p = subprocess.run(
            [sys.executable, "-m", "tools.runtime.team_dispatch",
             "--mission", "m-cli", "--project-root", self.root,
             "--worker-id", "someone-else", "--complete", "job-c2",
             "--status", "WAT"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)

    def test_cli_fail_path(self):
        jobs = Path(self.root) / "state/orchestrator/m-cli/team/dispatch/jobs"
        jobs.mkdir(parents=True, exist_ok=True)
        (jobs / "job-f1.json").write_text(json.dumps(
            {"schema": SCHEMA, "job_id": "job-f1", "status": "pending"}))
        self._run("--next")
        p = self._run("--fail", "job-f1", "--reason", "subagent crashed")
        self.assertEqual(p.returncode, 0)
        res = Path(self.root) / ("state/orchestrator/m-cli/team/dispatch/"
                                 "results/job-f1.json")
        self.assertEqual(json.loads(res.read_text())["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
