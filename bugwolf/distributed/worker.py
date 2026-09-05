# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-worker-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Worker node.

Pulls jobs from the master queue, runs a scanner coroutine, pushes
results back.  Refuses to execute destructive jobs unless the master
has set ``master:opt_in_destructive=1``.  Run timeout is enforced via
``signal.alarm`` (main thread only) with a graceful fallback to
``threading.Timer`` when signals are unavailable.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .redis_client import RedisClient
from .state import JobState, Worker


SCHEMA = "bugwolf-distributed-worker-v1"


class WorkerRefused(Exception):
    """Raised when a worker refuses to run (e.g. opt-in not granted)."""


@dataclass
class WorkerConfig:
    worker_id: str
    host: str = "127.0.0.1"
    heartbeat_interval: float = 5.0
    scan_timeout: float = 60.0
    opt_in_destructive: bool = False
    allow_internal: bool = False


# ---------------------------------------------------------------------------
# Scanner registry stub
# ---------------------------------------------------------------------------


def _default_registry(scanner_name: str) -> Callable[[str], Dict[str, Any]]:
    """Stub registry — records that no real scanner is registered."""

    def _runner(target: str) -> Dict[str, Any]:
        return {
            "scanner": scanner_name,
            "target": target,
            "evidence": f"no scanner registered for {scanner_name!r}",
            "stub": True,
            "ts": time.time(),
        }

    return _runner


# ---------------------------------------------------------------------------
# Timeout helpers
# ---------------------------------------------------------------------------


class _ScanTimeout(Exception):
    pass


def _run_with_timeout(fn: Callable[[], Any], timeout: float) -> Any:
    """Run ``fn`` with a wall-clock timeout.

    Tries ``signal.alarm`` first (POSIX main thread).  Falls back to a
    ``threading.Timer`` that raises into the main thread via
    ``_thread.interrupt_main`` when signals are unavailable.
    """
    if timeout <= 0:
        return fn()

    # signal-based timeout (main thread only)
    use_signal = (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "alarm")
        and threading.current_thread() is threading.main_thread()
    )

    if use_signal:

        def _handler(signum, frame):  # noqa: ARG001
            raise _ScanTimeout(f"scan exceeded {timeout}s")

        old = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(max(1, int(timeout)))
        try:
            return fn()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
    else:
        # threading-based timeout — works on non-main threads but
        # relies on interrupt_main() to bubble up.
        result: Dict[str, Any] = {"value": None, "raised": None}

        def _wrap() -> None:
            try:
                result["value"] = fn()
            except BaseException as exc:  # pragma: no cover
                result["raised"] = exc

        t = threading.Thread(target=_wrap, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            try:
                import _thread  # noqa: WPS433
                _thread.interrupt_main()
            except Exception:
                pass
            raise _ScanTimeout(f"scan exceeded {timeout}s")
        if result["raised"] is not None:
            raise result["raised"]
        return result["value"]


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class Worker:
    """A single worker node."""

    def __init__(
        self,
        redis: RedisClient,
        config: WorkerConfig,
        scanner_registry: Optional[Callable[[str], Callable[[str], Any]]] = None,
    ) -> None:
        self.redis = redis
        self.config = config
        self.state = JobState(redis)
        self.registry = scanner_registry or _default_registry
        self._last_heartbeat: float = 0.0

    # ------------------------------------------------------------------
    # Permissions
    # ------------------------------------------------------------------

    def _check_opt_in(self) -> None:
        if not self.config.opt_in_destructive:
            return
        v = self.redis.get("master:opt_in_destructive")
        if v != "1":
            raise WorkerRefused(
                "worker has opt_in_destructive=True but master did not grant opt-in"
            )

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def heartbeat(self, *, state: str = "idle") -> None:
        self._last_heartbeat = time.time()
        wid = self.config.worker_id
        self.redis.hset(f"worker:{wid}", "worker_id", wid)
        self.redis.hset(f"worker:{wid}", "host", self.config.host)
        self.redis.hset(f"worker:{wid}", "last_heartbeat", str(self._last_heartbeat))
        self.redis.hset(f"worker:{wid}", "state", state)

    # ------------------------------------------------------------------
    # Job execution
    # ------------------------------------------------------------------

    def run_once(self, *, timeout: int = 1) -> Optional[Dict[str, Any]]:
        """Claim one job, run it, push the result.

        Returns the result dict on success, ``None`` if no job was
        available, or a dict ``{"error": str}`` on failure.
        """
        self._check_opt_in()
        self.heartbeat(state="idle")
        job = self.state.claim(self.config.worker_id, timeout=timeout)
        if job is None:
            return None
        self.heartbeat(state="busy")

        runner = self.registry(job.scanner)

        def _invoke() -> Dict[str, Any]:
            return runner(job.target)

        try:
            result = _run_with_timeout(_invoke, self.config.scan_timeout)
            if not isinstance(result, dict):
                result = {"value": result}
            self.state.complete(job.job_id, result)
            return result
        except _ScanTimeout as exc:
            err = f"timeout: {exc}"
            self.state.fail(job.job_id, err)
            return {"error": err, "job_id": job.job_id}
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            self.state.fail(job.job_id, err)
            return {"error": err, "job_id": job.job_id}

    def run_forever(self, max_iterations: int = 100, *, claim_timeout: int = 1) -> int:
        """Loop until shutdown or max iterations."""
        iterations = 0
        for _ in range(int(max_iterations)):
            v = self.redis.get("master:shutdown")
            if v == "1":
                break
            res = self.run_once(timeout=claim_timeout)
            iterations += 1
            if res is None:
                # No job available; still counts as an iteration but
                # we add a tiny sleep to avoid burning CPU.
                time.sleep(0.01)
        return iterations


__all__ = ["SCHEMA", "Worker", "WorkerConfig", "WorkerRefused"]
