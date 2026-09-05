# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-master-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Master coordinator.

Submits campaigns (after scope enforcement), tracks worker liveness,
drains results, and signals shutdown.  Scope checking is fail-closed:
if no rules are configured, no target passes.  ``allow_internal``
defaults to False; ``opt_in_destructive`` defaults to False.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .redis_client import RedisClient
from .state import Job, JobState, Worker


SCHEMA = "bugwolf-distributed-master-v1"


_INTERNAL_PATTERNS: Tuple[str, ...] = (
    r"^localhost$",
    r"^127\.",
    r"^10\.",
    r"^192\.168\.",
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^::1$",
    r"\.local$",
    r"\.internal$",
    r"\.intranet$",
)


class ScopeRefused(Exception):
    """Raised when a target fails scope enforcement."""


@dataclass
class ScopeRule:
    pattern: str
    allow: bool = True


def _strip_host(target: str) -> str:
    if "://" in target:
        try:
            return (urlparse(target).hostname or "").lower().rstrip(".")
        except ValueError:
            return target.lower().rstrip(".")
    return target.lower().rstrip(".")


def _is_internal(host: str) -> bool:
    if not host:
        return False
    for pat in _INTERNAL_PATTERNS:
        if re.search(pat, host):
            return True
    return False


def _domain_matches(host: str, pattern: str) -> bool:
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if not h or not p:
        return False
    if h == p:
        return True
    return h.endswith("." + p)


class Master:
    """Coordinates jobs and worker liveness."""

    def __init__(
        self,
        redis: RedisClient,
        scope_rules: Sequence[Any],
        allow_internal: bool = False,
        opt_in_destructive: bool = False,
    ) -> None:
        self.redis = redis
        self.state = JobState(redis)
        self.scope_rules: List[ScopeRule] = [
            ScopeRule(pattern=str(r.pattern), allow=bool(getattr(r, "allow", True)))
            for r in (scope_rules or [])
        ]
        self.allow_internal = bool(allow_internal)
        self.opt_in_destructive = bool(opt_in_destructive)
        # Publish the opt-in flag so workers can refuse dangerous jobs
        self.redis.set("master:opt_in_destructive", "1" if self.opt_in_destructive else "0")
        self.redis.set("master:allow_internal", "1" if self.allow_internal else "0")

    # ------------------------------------------------------------------
    # Scope enforcement (fail-closed)
    # ------------------------------------------------------------------

    def is_allowed_target(self, target: str) -> Tuple[bool, str]:
        """Return ``(allowed, reason)``.

        Fail-closed: if ``scope_rules`` is empty, nothing is allowed.
        Internal targets require ``allow_internal=True``.
        """
        host = _strip_host(target)
        if not host:
            return False, "empty_target"

        if _is_internal(host):
            if not self.allow_internal:
                return False, "internal_denied"

        # Destructive opt-in: target patterns tagged with allow=False
        # are always denied; we treat any rule with allow=False as a
        # denylist entry.
        for rule in self.scope_rules:
            if not rule.allow and _domain_matches(host, rule.pattern):
                return False, f"denylisted:{rule.pattern}"

        # Allow list — at least one rule must match.
        if not self.scope_rules:
            return False, "no_rules_configured"
        for rule in self.scope_rules:
            if rule.allow and _domain_matches(host, rule.pattern):
                return True, "allow"
        return False, "no_rule_match"

    def submit_campaign(
        self,
        targets: Iterable[str],
        scanner: str,
        job_id_prefix: str = "job",
    ) -> List[str]:
        """Create one job per target.  Out-of-scope targets raise."""
        out: List[str] = []
        for i, target in enumerate(targets):
            allowed, reason = self.is_allowed_target(target)
            if not allowed:
                raise ScopeRefused(f"target {target!r} refused: {reason}")
            ts = time.time()
            jid = f"{job_id_prefix}-{int(ts * 1000)}-{i}"
            job = Job(
                job_id=jid,
                target=target,
                scanner=scanner,
                created_at=ts,
                status="queued",
            )
            self.state.submit(job)
            out.append(jid)
        return out

    # ------------------------------------------------------------------
    # Worker liveness
    # ------------------------------------------------------------------

    def healthcheck_workers(self, heartbeat_timeout: float = 30.0) -> Dict[str, Any]:
        workers = self.state.workers()
        now = time.time()
        alive: List[str] = []
        dead: List[str] = []
        for w in workers:
            if (now - w.last_heartbeat) <= heartbeat_timeout and w.state != "dead":
                alive.append(w.worker_id)
            else:
                self.state.mark_dead(w.worker_id)
                dead.append(w.worker_id)
        return {"alive": alive, "dead": dead, "total": len(workers)}

    # ------------------------------------------------------------------
    # Result drainage
    # ------------------------------------------------------------------

    def drain_results(self, max_items: int = 100) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(int(max_items)):
            raw = self.redis.rpop("queue:results")
            if raw is None:
                break
            try:
                out.append(json.loads(raw))
            except (ValueError, TypeError):
                out.append({"raw": raw})
        return out

    # ------------------------------------------------------------------
    # Shutdown signal
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        self.redis.set("master:shutdown", "1")
        self.redis.expire("master:shutdown", 60)

    def is_shutdown_requested(self) -> bool:
        v = self.redis.get("master:shutdown")
        return v == "1"


__all__ = ["SCHEMA", "Master", "ScopeRule", "ScopeRefused"]
