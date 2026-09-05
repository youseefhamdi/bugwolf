# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-state-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Job and Worker state manager.

Stores ``Job`` and ``Worker`` records in Redis hashes and uses
plain list/set primitives for queues, dead-jobs, and live-worker
tracking.  ``JobState`` is the only thing that should touch the
``jobs:*``, ``queue:*``, ``worker:*``, and ``jobs:dead`` keyspaces
directly; the rest of the distributed layer talks to it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .redis_client import RedisClient, _UNAVAILABLE


SCHEMA = "bugwolf-distributed-state-v1"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Job:
    job_id: str
    target: str
    scanner: str
    created_at: float
    status: str = "queued"
    result: Optional[dict] = None
    error: Optional[str] = None
    attempts: int = 0
    started_at: Optional[float] = None
    worker_id: Optional[str] = None
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "scanner": self.scanner,
            "created_at": str(self.created_at),
            "status": self.status,
            "result": self.result if self.result is not None else "",
            "error": self.error if self.error is not None else "",
            "attempts": str(self.attempts),
            "started_at": str(self.started_at) if self.started_at is not None else "",
            "worker_id": self.worker_id if self.worker_id is not None else "",
            "last_updated": str(self.last_updated),
        }

    @classmethod
    def from_hash(cls, h: Dict[str, str]) -> "Job":
        def _f(name: str, default: str = "") -> str:
            return h.get(name, default) or default

        result_raw = _f("result")
        result: Optional[dict] = None
        if result_raw:
            try:
                result = json.loads(result_raw)
            except (ValueError, TypeError):
                result = {"raw": result_raw}

        err = _f("error") or None
        worker = _f("worker_id") or None
        started_raw = _f("started_at")
        started = float(started_raw) if started_raw else None
        return cls(
            job_id=_f("job_id"),
            target=_f("target"),
            scanner=_f("scanner"),
            created_at=float(_f("created_at") or 0.0),
            status=_f("status") or "queued",
            result=result,
            error=err,
            attempts=int(_f("attempts") or 0),
            started_at=started,
            worker_id=worker,
            last_updated=float(_f("last_updated") or 0.0),
        )


@dataclass
class Worker:
    worker_id: str
    host: str
    last_heartbeat: float
    jobs_completed: int
    jobs_failed: int
    state: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "host": self.host,
            "last_heartbeat": str(self.last_heartbeat),
            "jobs_completed": str(self.jobs_completed),
            "jobs_failed": str(self.jobs_failed),
            "state": self.state,
        }

    @classmethod
    def from_hash(cls, h: Dict[str, str]) -> "Worker":
        return cls(
            worker_id=h.get("worker_id", ""),
            host=h.get("host", ""),
            last_heartbeat=float(h.get("last_heartbeat") or 0.0),
            jobs_completed=int(h.get("jobs_completed") or 0),
            jobs_failed=int(h.get("jobs_failed") or 0),
            state=h.get("state", "idle"),
        )


# ---------------------------------------------------------------------------
# JobState
# ---------------------------------------------------------------------------


class JobState:
    """Manages jobs and worker liveness."""

    def __init__(self, redis: RedisClient, max_attempts: int = 3) -> None:
        self.redis = redis
        self.max_attempts = int(max_attempts)

    # ---- job lifecycle ----

    def submit(self, job: Job) -> bool:
        """Register a job and enqueue it.  Returns False if Redis is down."""
        d = job.to_dict()
        ok = True
        for k, v in d.items():
            if not self.redis.hset(f"jobs:{job.job_id}", k, v):
                ok = False
        self.redis.sadd("jobs:queued", job.job_id)
        self.redis.lpush("queue:pending", job.job_id)
        return ok

    def claim(self, worker_id: str, *, timeout: int = 1) -> Optional[Job]:
        """Pop the next job from the pending queue and mark it running."""
        # timeout=0 means "non-blocking" in our semantics; BRPOP treats
        # 0 as "block forever", so use RPOP for the non-blocking case.
        if int(timeout) <= 0:
            job_id = self.redis.rpop("queue:pending")
            if job_id is None:
                return None
        else:
            popped = self.redis.brpop("queue:pending", timeout=timeout)
            if popped is None:
                return None
            _, job_id = popped
        if not job_id:
            return None
        h = self.redis.hgetall(f"jobs:{job_id}")
        if not h:
            return None
        job = Job.from_hash(h)
        job.attempts += 1
        job.worker_id = worker_id
        job.started_at = time.time()
        job.status = "running"
        job.last_updated = time.time()
        self._write(job)
        self.redis.srem("jobs:queued", job_id)
        self.redis.sadd("jobs:running", job_id)
        return job

    def complete(self, job_id: str, result: dict) -> None:
        h = self.redis.hgetall(f"jobs:{job_id}")
        if not h:
            return
        job = Job.from_hash(h)
        job.status = "done"
        job.result = result
        job.last_updated = time.time()
        self._write(job)
        self.redis.srem("jobs:running", job_id)
        self.redis.sadd("jobs:done", job_id)
        # bump worker's jobs_completed
        if job.worker_id:
            current = self.redis.hget(f"worker:{job.worker_id}", "jobs_completed")
            try:
                n = int(current or 0) + 1
            except ValueError:
                n = 1
            self.redis.hset(f"worker:{job.worker_id}", "jobs_completed", str(n))
            self.redis.lpush("queue:results", json.dumps({"job_id": job_id, "result": result}))
            # bump load balancer's jobs_running counter (decrement)
            running = self.redis.hget(f"worker:{job.worker_id}", "jobs_running")
            try:
                rn = max(0, int(running or 0) - 1)
            except ValueError:
                rn = 0
            self.redis.hset(f"worker:{job.worker_id}", "jobs_running", str(rn))

    def fail(self, job_id: str, error: str) -> None:
        h = self.redis.hgetall(f"jobs:{job_id}")
        if not h:
            return
        job = Job.from_hash(h)
        job.error = error
        job.last_updated = time.time()
        if job.attempts >= self.max_attempts:
            job.status = "dead"
            self._write(job)
            self.redis.srem("jobs:running", job_id)
            self.redis.sadd("jobs:dead", job_id)
        else:
            self.requeue(job_id, status="queued", error=error)
        # bump jobs_failed regardless
        if job.worker_id:
            current = self.redis.hget(f"worker:{job.worker_id}", "jobs_failed")
            try:
                n = int(current or 0) + 1
            except ValueError:
                n = 1
            self.redis.hset(f"worker:{job.worker_id}", "jobs_failed", str(n))

    def requeue(self, job_id: str, *, status: str = "queued", error: Optional[str] = None) -> None:
        h = self.redis.hgetall(f"jobs:{job_id}")
        if not h:
            return
        job = Job.from_hash(h)
        job.status = status
        if error is not None:
            job.error = error
        job.worker_id = None
        job.last_updated = time.time()
        self._write(job)
        self.redis.srem("jobs:running", job_id)
        self.redis.sadd("jobs:queued", job_id)
        self.redis.lpush("queue:pending", job_id)

    def dead_jobs(self) -> List[Job]:
        ids = self.redis.smembers("jobs:dead")
        out: List[Job] = []
        for jid in ids:
            h = self.redis.hgetall(f"jobs:{jid}")
            if h:
                out.append(Job.from_hash(h))
        return out

    def stats(self) -> Dict[str, Any]:
        return {
            "queued": len(self.redis.smembers("jobs:queued")),
            "running": len(self.redis.smembers("jobs:running")),
            "done": len(self.redis.smembers("jobs:done")),
            "failed": len(self.redis.smembers("jobs:failed")),
            "dead": len(self.redis.smembers("jobs:dead")),
            "workers": len(self.redis.keys("worker:*")),
            "pending_queue_len": self.redis.llen("queue:pending"),
        }

    # ---- worker tracking ----

    def register_worker(self, worker: Worker) -> None:
        d = worker.to_dict()
        for k, v in d.items():
            self.redis.hset(f"worker:{worker.worker_id}", k, v)

    def workers(self) -> List[Worker]:
        keys = self.redis.keys("worker:*")
        out: List[Worker] = []
        for k in keys:
            h = self.redis.hgetall(k)
            if h:
                out.append(Worker.from_hash(h))
        return out

    def mark_dead(self, worker_id: str) -> None:
        self.redis.hset(f"worker:{worker_id}", "state", "dead")

    # ---- internals ----

    def _write(self, job: Job) -> None:
        d = job.to_dict()
        for k, v in d.items():
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            elif v is None:
                v = ""
            self.redis.hset(f"jobs:{job.job_id}", k, str(v))


__all__ = ["SCHEMA", "Job", "Worker", "JobState"]
