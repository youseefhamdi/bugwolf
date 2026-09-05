# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-recovery-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Queue + recovery housekeeping.

Requeues jobs whose owning worker died (running for too long without
completing), purges dead jobs past their retention window, and reports
health metrics.  All operations are stub-safe (no-ops when Redis is
down) and never raise.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from .redis_client import RedisClient
from .state import Job, JobState


SCHEMA = "bugwolf-distributed-recovery-v1"


class RecoveryManager:
    """Reaps orphaned jobs and purges stale dead jobs."""

    def __init__(self, redis: RedisClient) -> None:
        self.redis = redis
        self.state = JobState(redis)
        self._last_run: float = 0.0
        self._orphans_reaped: int = 0
        self._dead_purged: int = 0

    # ------------------------------------------------------------------
    # Orphan reaping
    # ------------------------------------------------------------------

    def reap_orphans(self, running_timeout: float = 60.0) -> int:
        """Requeue jobs whose worker died mid-flight.

        A job is "orphaned" when ``status="running"`` and
        ``started_at`` is older than ``now - running_timeout``.
        """
        now = time.time()
        running = self.redis.smembers("jobs:running")
        reaped = 0
        for jid in running:
            h = self.redis.hgetall(f"jobs:{jid}")
            if not h:
                continue
            try:
                started = float(h.get("started_at") or 0.0)
            except ValueError:
                started = 0.0
            status = h.get("status") or ""
            if status != "running":
                # Stale membership — clean it up.
                self.redis.srem("jobs:running", jid)
                continue
            if started <= 0 or (now - started) < running_timeout:
                continue
            # Move back to pending.
            try:
                self.state.requeue(jid, status="queued", error="recovered:orphan")
                reaped += 1
            except Exception:  # noqa: BLE001
                continue
        self._orphans_reaped += reaped
        self._last_run = now
        return reaped

    # ------------------------------------------------------------------
    # Dead-job purging
    # ------------------------------------------------------------------

    def purge_dead_jobs(self, max_age: float = 86400.0) -> int:
        """Drop dead jobs whose ``last_updated`` is older than ``max_age``."""
        now = time.time()
        dead = self.redis.smembers("jobs:dead")
        purged = 0
        for jid in dead:
            h = self.redis.hgetall(f"jobs:{jid}")
            if not h:
                # Stale set member — clean up.
                self.redis.srem("jobs:dead", jid)
                continue
            try:
                last = float(h.get("last_updated") or 0.0)
            except ValueError:
                last = 0.0
            if last > 0 and (now - last) < max_age:
                continue
            self.redis.delete(f"jobs:{jid}")
            self.redis.srem("jobs:dead", jid)
            purged += 1
        self._dead_purged += purged
        self._last_run = now
        return purged

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_report(self) -> Dict[str, Any]:
        """Return a snapshot of the manager's recent activity."""
        stats = self.state.stats()
        return {
            "orphans_reaped": self._orphans_reaped,
            "dead_purged": self._dead_purged,
            "last_run": self._last_run,
            "stats": stats,
        }


__all__ = ["SCHEMA", "RecoveryManager"]
