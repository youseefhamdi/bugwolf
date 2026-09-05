#!/usr/bin/env python3
"""Phase 4.B distributed pool integration tests.

Runs the entire distributed surface against a LIVE Redis at
127.0.0.1:6379.  Assumes redis-cli ping returns PONG; if not, the
whole test class is skipped.

Tests cover:

  * RedisClient round-trips + unavailable mode
  * JobState submit/claim/complete + dead-letter behaviour
  * Master scope enforcement + worker healthchecks
  * Worker heartbeat + run_once + opt-in refusal
  * Recovery reaping + dead-job purging
  * LoadBalancer selection + capacity tracking
  * ResultDedup fingerprinting + batch dedup
  * IPC bridge stub-safety

Covers ~30 cases.  Uses unittest.TestCase; stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugwolf.distributed.redis_client import RedisClient, _UNAVAILABLE
from bugwolf.distributed.state import Job, JobState, Worker as StateWorker
from bugwolf.distributed.master import Master, ScopeRule, ScopeRefused
from bugwolf.distributed.worker import Worker, WorkerConfig, WorkerRefused
from bugwolf.distributed.recovery import RecoveryManager
from bugwolf.distributed.load_balancer import LoadBalancer
from bugwolf.distributed.result_dedup import ResultDedup
from bugwolf.distributed.ipc_bridge import (
    is_rust_binary_available,
    run_rust_healthcheck,
    run_rust_bench,
)


def _redis_alive() -> bool:
    try:
        out = subprocess.run(
            ["redis-cli", "ping"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return "PONG" in out.stdout
    except Exception:
        return False


_REDIS_OK = _redis_alive()


def _flush(redis: RedisClient) -> None:
    """Flush the test keyspaces."""
    for pat in ["jobs:*", "queue:*", "worker:*", "dedup:*", "master:*"]:
        for k in redis.keys(pat):
            redis.delete(k)


class _Base(unittest.TestCase):
    """Common base that flushes the test keyspaces once per class."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _REDIS_OK:
            raise unittest.SkipTest("redis-server not reachable on 127.0.0.1:6379")
        # 3.0s socket_timeout so BRPOP timeout=1 has headroom.
        cls.redis = RedisClient(socket_timeout=3.0)
        _flush(cls.redis)

    def setUp(self) -> None:
        # Reset the client so a previous test that timed out
        # (e.g. brpop timeout=0) doesn't leave the connection marked
        # unavailable.
        if hasattr(self, "redis"):
            self.redis.reset()
        _flush(self.redis)

    @classmethod
    def tearDownClass(cls) -> None:
        if _REDIS_OK:
            try:
                _flush(cls.redis)
            except Exception:
                pass


# =====================================================================
# RedisClient tests
# =====================================================================


class TestRedisClient(_Base):
    def test_ping(self) -> None:
        self.assertTrue(self.redis.ping())

    def test_set_get_roundtrip(self) -> None:
        self.assertTrue(self.redis.set("bw:test:setget", "hello"))
        self.assertEqual(self.redis.get("bw:test:setget"), "hello")
        self.redis.delete("bw:test:setget")

    def test_lpush_lpop(self) -> None:
        self.redis.delete("bw:test:list")
        self.assertEqual(self.redis.lpush("bw:test:list", "a"), 1)
        self.assertEqual(self.redis.lpush("bw:test:list", "b"), 2)
        self.assertEqual(self.redis.rpop("bw:test:list"), "a")
        self.assertEqual(self.redis.rpop("bw:test:list"), "b")
        self.assertIsNone(self.redis.rpop("bw:test:list"))
        self.redis.delete("bw:test:list")

    def test_brpop_timeout(self) -> None:
        self.redis.delete("bw:test:brpop")
        res = self.redis.brpop("bw:test:brpop", timeout=1)
        self.assertIsNone(res)

    def test_hset_hgetall(self) -> None:
        self.redis.delete("bw:test:h")
        self.redis.hset("bw:test:h", "f1", "v1")
        self.redis.hset("bw:test:h", "f2", "v2")
        d = self.redis.hgetall("bw:test:h")
        self.assertEqual(d.get("f1"), "v1")
        self.assertEqual(d.get("f2"), "v2")
        self.redis.delete("bw:test:h")

    def test_sadd_smembers(self) -> None:
        self.redis.delete("bw:test:s")
        self.redis.sadd("bw:test:s", "x")
        self.redis.sadd("bw:test:s", "y")
        self.redis.sadd("bw:test:s", "x")
        members = self.redis.smembers("bw:test:s")
        self.assertEqual(members, {"x", "y"})
        self.redis.delete("bw:test:s")

    def test_expire(self) -> None:
        self.redis.set("bw:test:exp", "1")
        self.assertEqual(self.redis.expire("bw:test:exp", 60), 1)
        self.redis.delete("bw:test:exp")

    def test_unavailable_returns_none(self) -> None:
        bad = RedisClient(host="127.0.0.1", port=1, socket_timeout=0.3)
        self.assertFalse(bad.ping())
        self.assertIsNone(bad.get("anything"))
        self.assertIsNone(bad.brpop("anything", timeout=0))

    def test_reset(self) -> None:
        bad = RedisClient(host="127.0.0.1", port=1, socket_timeout=0.3)
        bad.ping()  # forces unavailable
        bad.reset()
        self.assertEqual(bad._state, "idle")  # type: ignore[attr-defined]


# =====================================================================
# JobState tests
# =====================================================================


class TestJobState(_Base):
    def test_submit_claim_complete(self) -> None:
        js = JobState(self.redis, max_attempts=2)
        job = Job(
            job_id="j-1",
            target="example.com",
            scanner="nmap",
            created_at=time.time(),
        )
        self.assertTrue(js.submit(job))
        claimed = js.claim("w-1", timeout=1)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.job_id, "j-1")
        self.assertEqual(claimed.status, "running")
        self.assertEqual(claimed.attempts, 1)
        self.assertEqual(claimed.worker_id, "w-1")
        js.complete("j-1", {"findings": ["open-port:22"]})
        h = self.redis.hgetall("jobs:j-1")
        self.assertEqual(h.get("status"), "done")
        # Result pushed onto queue:results
        self.assertGreaterEqual(self.redis.llen("queue:results"), 1)

    def test_failed_requeues(self) -> None:
        js = JobState(self.redis, max_attempts=2)
        job = Job(job_id="j-2", target="example.com", scanner="x", created_at=time.time())
        js.submit(job)
        js.claim("w-1", timeout=1)
        js.fail("j-2", "boom")
        h = self.redis.hgetall("jobs:j-2")
        self.assertEqual(h.get("status"), "queued")  # requeued, not dead yet

    def test_second_failure_dead(self) -> None:
        js = JobState(self.redis, max_attempts=2)
        job = Job(job_id="j-3", target="example.com", scanner="x", created_at=time.time())
        js.submit(job)
        js.claim("w-1", timeout=1)
        js.fail("j-3", "boom-1")  # attempts=1, requeues
        # Now consume and fail again
        js.claim("w-1", timeout=1)
        js.fail("j-3", "boom-2")  # attempts=2 >= max_attempts=2, dead
        h = self.redis.hgetall("jobs:j-3")
        self.assertEqual(h.get("status"), "dead")
        dead = js.dead_jobs()
        self.assertEqual(len(dead), 1)
        self.assertEqual(dead[0].job_id, "j-3")

    def test_stats_shape(self) -> None:
        js = JobState(self.redis)
        s = js.stats()
        self.assertIn("queued", s)
        self.assertIn("running", s)
        self.assertIn("done", s)
        self.assertIn("failed", s)
        self.assertIn("dead", s)
        self.assertIn("workers", s)

    def test_unavailable_mode(self) -> None:
        bad = RedisClient(host="127.0.0.1", port=1, socket_timeout=0.3)
        js = JobState(bad, max_attempts=2)
        # Should not raise; returns False / None.
        self.assertFalse(
            js.submit(Job(job_id="x", target="y", scanner="z", created_at=0.0))
        )
        self.assertIsNone(js.claim("w", timeout=0))


# =====================================================================
# Master tests
# =====================================================================


class TestMaster(_Base):
    def test_submit_campaign_in_scope(self) -> None:
        rules = [ScopeRule(pattern="example.com", allow=True)]
        master = Master(self.redis, scope_rules=rules)
        ids = master.submit_campaign(
            ["example.com", "api.example.com"], scanner="nmap"
        )
        self.assertEqual(len(ids), 2)
        for jid in ids:
            h = self.redis.hgetall(f"jobs:{jid}")
            self.assertEqual(h.get("status"), "queued")

    def test_submit_campaign_out_of_scope_refused(self) -> None:
        rules = [ScopeRule(pattern="example.com", allow=True)]
        master = Master(self.redis, scope_rules=rules)
        with self.assertRaises(ScopeRefused):
            master.submit_campaign(["evil.org"], scanner="nmap")

    def test_submit_no_rules_fail_closed(self) -> None:
        master = Master(self.redis, scope_rules=[])
        with self.assertRaises(ScopeRefused):
            master.submit_campaign(["example.com"], scanner="nmap")

    def test_healthcheck_marks_dead(self) -> None:
        rules = [ScopeRule(pattern="example.com", allow=True)]
        master = Master(self.redis, scope_rules=rules)
        # register a worker with stale heartbeat
        sw = StateWorker(
            worker_id="w-stale",
            host="127.0.0.1",
            last_heartbeat=time.time() - 9999,
            jobs_completed=0,
            jobs_failed=0,
            state="idle",
        )
        master.state.register_worker(sw)
        report = master.healthcheck_workers(heartbeat_timeout=10.0)
        self.assertIn("w-stale", report["dead"])
        h = self.redis.hgetall("worker:w-stale")
        self.assertEqual(h.get("state"), "dead")

    def test_drain_results(self) -> None:
        rules = [ScopeRule(pattern="example.com", allow=True)]
        master = Master(self.redis, scope_rules=rules)
        # simulate a completed job
        self.redis.lpush("queue:results", json.dumps({"job_id": "j-1", "result": {"x": 1}}))
        self.redis.lpush("queue:results", json.dumps({"job_id": "j-2", "result": {"x": 2}}))
        drained = master.drain_results()
        self.assertEqual(len(drained), 2)
        self.assertEqual(self.redis.llen("queue:results"), 0)

    def test_shutdown_sets_flag(self) -> None:
        rules = [ScopeRule(pattern="example.com", allow=True)]
        master = Master(self.redis, scope_rules=rules)
        master.shutdown()
        self.assertTrue(master.is_shutdown_requested())


# =====================================================================
# Worker tests
# =====================================================================


class TestWorker(_Base):
    def test_heartbeat_sets_fields(self) -> None:
        cfg = WorkerConfig(worker_id="w-test", host="127.0.0.1")
        w = Worker(self.redis, cfg)
        w.heartbeat(state="idle")
        h = self.redis.hgetall("worker:w-test")
        self.assertEqual(h.get("worker_id"), "w-test")
        self.assertEqual(h.get("state"), "idle")
        self.assertGreaterEqual(float(h.get("last_heartbeat") or 0), time.time() - 5)

    def test_run_once_empty_queue(self) -> None:
        cfg = WorkerConfig(worker_id="w-empty", host="127.0.0.1")
        w = Worker(self.redis, cfg)
        self.assertIsNone(w.run_once(timeout=0))

    def test_run_once_completes_fake_job(self) -> None:
        cfg = WorkerConfig(worker_id="w-busy", host="127.0.0.1")
        w = Worker(self.redis, cfg)
        js = JobState(self.redis)
        js.submit(Job(job_id="fw-1", target="example.com", scanner="stub", created_at=time.time()))
        result = w.run_once(timeout=1)
        self.assertIsNotNone(result)
        self.assertEqual(result.get("scanner"), "stub")
        h = self.redis.hgetall("jobs:fw-1")
        self.assertEqual(h.get("status"), "done")
        # Result should be in queue:results
        self.assertGreaterEqual(self.redis.llen("queue:results"), 1)

    def test_run_forever_respects_max(self) -> None:
        cfg = WorkerConfig(worker_id="w-loop", host="127.0.0.1")
        w = Worker(self.redis, cfg)
        n = w.run_forever(max_iterations=3, claim_timeout=0)
        self.assertEqual(n, 3)

    def test_opt_in_refused(self) -> None:
        cfg = WorkerConfig(worker_id="w-evil", opt_in_destructive=True)
        w = Worker(self.redis, cfg)
        # master has opt_in_destructive=0 (default)
        with self.assertRaises(WorkerRefused):
            w.run_once(timeout=0)
        # now grant opt-in
        self.redis.set("master:opt_in_destructive", "1")
        # should no longer raise at the opt-in check
        # (no job available so it returns None)
        self.assertIsNone(w.run_once(timeout=0))


# =====================================================================
# Recovery tests
# =====================================================================


class TestRecovery(_Base):
    def test_reap_orphans(self) -> None:
        rm = RecoveryManager(self.redis)
        # Inject an orphaned job: status=running, started_at=old
        self.redis.hset("jobs:orphan-1", "job_id", "orphan-1")
        self.redis.hset("jobs:orphan-1", "status", "running")
        self.redis.hset("jobs:orphan-1", "started_at", str(time.time() - 9999))
        self.redis.hset("jobs:orphan-1", "attempts", "1")
        self.redis.sadd("jobs:running", "orphan-1")
        n = rm.reap_orphans(running_timeout=10.0)
        self.assertEqual(n, 1)
        h = self.redis.hgetall("jobs:orphan-1")
        self.assertEqual(h.get("status"), "queued")
        self.assertIn("orphan-1", self.redis.smembers("jobs:queued"))

    def test_purge_dead_jobs(self) -> None:
        rm = RecoveryManager(self.redis)
        self.redis.hset("jobs:dead-1", "job_id", "dead-1")
        self.redis.hset("jobs:dead-1", "status", "dead")
        self.redis.hset("jobs:dead-1", "last_updated", str(time.time() - 9999))
        self.redis.sadd("jobs:dead", "dead-1")
        n = rm.purge_dead_jobs(max_age=10.0)
        self.assertEqual(n, 1)
        self.assertNotIn("dead-1", self.redis.smembers("jobs:dead"))

    def test_health_report_shape(self) -> None:
        rm = RecoveryManager(self.redis)
        rep = rm.health_report()
        self.assertIn("orphans_reaped", rep)
        self.assertIn("dead_purged", rep)
        self.assertIn("last_run", rep)
        self.assertIn("stats", rep)


# =====================================================================
# LoadBalancer tests
# =====================================================================


class TestLoadBalancer(_Base):
    def setUp(self) -> None:
        # Flush stale worker state from previous classes.
        for k in self.redis.keys("worker:*"):
            self.redis.delete(k)

    def test_select_worker_no_workers(self) -> None:
        lb = LoadBalancer(self.redis)
        self.assertIsNone(lb.select_worker({}))

    def test_select_worker_returns_least_loaded(self) -> None:
        lb = LoadBalancer(self.redis)
        lb.register_worker("w-a", capacity=4)
        lb.register_worker("w-b", capacity=4)
        lb.incr_load("w-a")
        lb.incr_load("w-a")
        lb.incr_load("w-b")
        winner = lb.select_worker({})
        self.assertEqual(winner, "w-b")

    def test_register_incr_decr_consistent(self) -> None:
        lb = LoadBalancer(self.redis)
        lb.register_worker("w-x", capacity=4)
        lb.incr_load("w-x")
        lb.incr_load("w-x")
        self.assertEqual(self.redis.hget("worker:w-x", "jobs_running"), "2")
        lb.decr_load("w-x")
        self.assertEqual(self.redis.hget("worker:w-x", "jobs_running"), "1")
        lb.decr_load("w-x")
        lb.decr_load("w-x")  # floor at 0
        self.assertEqual(self.redis.hget("worker:w-x", "jobs_running"), "0")

    def test_capacity_report(self) -> None:
        lb = LoadBalancer(self.redis)
        lb.register_worker("w-1", capacity=4)
        lb.incr_load("w-1")
        rep = lb.capacity_report()
        self.assertIn("w-1", rep)
        self.assertEqual(rep["w-1"]["capacity"], 4)
        self.assertEqual(rep["w-1"]["jobs_running"], 1)
        self.assertAlmostEqual(rep["w-1"]["utilization"], 0.25)


# =====================================================================
# ResultDedup tests
# =====================================================================


class TestResultDedup(_Base):
    def setUp(self) -> None:
        self.redis.delete("dedup:results")
        self.rd = ResultDedup(self.redis, ttl=60)

    def test_same_fingerprint_detected(self) -> None:
        r = {"scanner": "x", "target": "t", "evidence": "e"}
        self.assertFalse(self.rd.is_duplicate(r))
        self.rd.remember(r)
        self.assertTrue(self.rd.is_duplicate(r))

    def test_dedup_batch_drops_dups(self) -> None:
        batch = [
            {"scanner": "x", "target": "t", "evidence": "e"},
            {"scanner": "x", "target": "t", "evidence": "e"},  # dup
            {"scanner": "x", "target": "t", "evidence": "f"},  # diff
        ]
        out = self.rd.dedup_batch(batch)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["evidence"], "e")
        self.assertEqual(out[1]["evidence"], "f")

    def test_unavailable_mode_pass_through(self) -> None:
        bad = RedisClient(host="127.0.0.1", port=1, socket_timeout=0.3)
        rd = ResultDedup(bad, ttl=60)
        self.assertFalse(rd.is_duplicate({"scanner": "x", "target": "t", "evidence": "e"}))
        # remember() should also not raise
        rd.remember({"scanner": "x", "target": "t", "evidence": "e"})


# =====================================================================
# IPC bridge tests
# =====================================================================


class TestIPCBridge(unittest.TestCase):
    def test_binary_not_available(self) -> None:
        # Pass an explicit non-existent path → must report not available
        self.assertFalse(is_rust_binary_available("__nonexistent_bugwolf_rs_binary__"))

    def test_healthcheck_unavailable(self) -> None:
        # Must not raise even though binary is absent
        out = run_rust_healthcheck(binary_path="/nonexistent/healthcheck")
        self.assertEqual(out, "unavailable")

    def test_bench_unavailable(self) -> None:
        out = run_rust_bench(iterations=10, binary_path="/nonexistent/bench")
        self.assertEqual(out.get("status"), "unavailable")


if __name__ == "__main__":
    unittest.main()
