# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-loadbalancer-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Worker load balancer.

Selects the least-loaded live worker for a given job.  Tracks
``capacity`` and ``jobs_running`` counters on the ``worker:{id}``
hash.  When Redis is unavailable every operation is a no-op.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .redis_client import RedisClient


SCHEMA = "bugwolf-distributed-loadbalancer-v1"


_INTERNAL_DENY = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")


class LoadBalancer:
    """Pick the least-loaded worker; track per-worker capacity."""

    def __init__(self, redis: RedisClient) -> None:
        self.redis = redis

    # ------------------------------------------------------------------
    # Worker registry
    # ------------------------------------------------------------------

    def register_worker(self, worker_id: str, capacity: int = 4) -> None:
        """Record a worker with its capacity and zero running jobs."""
        self.redis.hset(f"worker:{worker_id}", "worker_id", worker_id)
        self.redis.hset(f"worker:{worker_id}", "capacity", str(int(capacity)))
        self.redis.hset(f"worker:{worker_id}", "jobs_running", "0")

    # ------------------------------------------------------------------
    # Load tracking
    # ------------------------------------------------------------------

    def incr_load(self, worker_id: str) -> None:
        cur = self.redis.hget(f"worker:{worker_id}", "jobs_running")
        try:
            n = int(cur or 0) + 1
        except ValueError:
            n = 1
        self.redis.hset(f"worker:{worker_id}", "jobs_running", str(n))

    def decr_load(self, worker_id: str) -> None:
        cur = self.redis.hget(f"worker:{worker_id}", "jobs_running")
        try:
            n = max(0, int(cur or 0) - 1)
        except ValueError:
            n = 0
        self.redis.hset(f"worker:{worker_id}", "jobs_running", str(n))

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select_worker(self, job: dict) -> Optional[str]:
        """Return the worker_id with the lowest ``jobs_running``/``capacity`` ratio.

        Filters out workers whose state is ``dead`` or whose ratio is
        already at or above 1.0.  Returns ``None`` if no worker is
        available.
        """
        keys = self.redis.keys("worker:*")
        if not keys:
            return None

        best: Optional[str] = None
        best_ratio: float = float("inf")
        for k in keys:
            h = self.redis.hgetall(k)
            if not h:
                continue
            state = h.get("state", "idle")
            if state == "dead":
                continue
            try:
                cap = int(h.get("capacity") or 0)
                running = int(h.get("jobs_running") or 0)
            except ValueError:
                continue
            if cap <= 0:
                continue
            ratio = running / cap
            if ratio >= 1.0:
                continue
            if ratio < best_ratio:
                best_ratio = ratio
                best = h.get("worker_id") or k.split(":", 1)[-1]
        return best

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def capacity_report(self) -> Dict[str, Dict[str, Any]]:
        """Return ``{worker_id: {capacity, jobs_running, utilization}}``."""
        keys = self.redis.keys("worker:*")
        out: Dict[str, Dict[str, Any]] = {}
        for k in keys:
            h = self.redis.hgetall(k)
            if not h:
                continue
            wid = h.get("worker_id") or k.split(":", 1)[-1]
            try:
                cap = int(h.get("capacity") or 0)
                running = int(h.get("jobs_running") or 0)
            except ValueError:
                cap = 0
                running = 0
            util = (running / cap) if cap > 0 else 0.0
            out[wid] = {
                "capacity": cap,
                "jobs_running": running,
                "utilization": util,
                "state": h.get("state", "idle"),
            }
        return out


__all__ = ["SCHEMA", "LoadBalancer"]
