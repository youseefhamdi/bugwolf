# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Bugwolf distributed scanner pool.

Re-exports the public surface of the package so callers can do
``from bugwolf.distributed import Master, Worker, JobState, ...``.
"""

from .redis_client import RedisClient, _UNAVAILABLE, _UnavailableType
from .state import Job, Worker, JobState
from .master import Master, ScopeRule, ScopeRefused
from .worker import WorkerConfig, WorkerRefused
from . import worker as _worker_mod  # noqa: F401
from .recovery import RecoveryManager
from .load_balancer import LoadBalancer
from .result_dedup import ResultDedup
from .ipc_bridge import (
    is_rust_binary_available,
    run_rust_healthcheck,
    run_rust_bench,
)


Worker = _worker_mod.Worker  # explicit re-export


__all__ = [
    "SCHEMA",
    "RedisClient",
    "_UNAVAILABLE",
    "_UnavailableType",
    "Job",
    "Worker",
    "JobState",
    "Master",
    "ScopeRule",
    "ScopeRefused",
    "WorkerConfig",
    "WorkerRefused",
    "RecoveryManager",
    "LoadBalancer",
    "ResultDedup",
    "is_rust_binary_available",
    "run_rust_healthcheck",
    "run_rust_bench",
]


SCHEMA = "bugwolf-distributed-v1"
