# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-resultdedup-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""Result deduplication.

Fingerprints each result (scanner, target, evidence) with SHA-256 of
canonical JSON and stores it in a Redis set.  ``is_duplicate`` fails
OPEN on outage — if Redis is unreachable we let results through so
the pool doesn't silently lose findings.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from .redis_client import RedisClient


SCHEMA = "bugwolf-distributed-resultdedup-v1"


class ResultDedup:
    """SHA-256 fingerprint dedup with TTL'd set membership."""

    def __init__(self, redis: RedisClient, ttl: int = 3600) -> None:
        self.redis = redis
        self.ttl = int(ttl)

    # ------------------------------------------------------------------
    # Fingerprint
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint(result: Dict[str, Any]) -> str:
        """SHA-256 of canonical JSON of ``{scanner, target, evidence}``."""
        payload = {
            "scanner": result.get("scanner", ""),
            "target": result.get("target", ""),
            "evidence": result.get("evidence", ""),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Membership
    # ------------------------------------------------------------------

    def is_duplicate(self, result: Dict[str, Any]) -> bool:
        """Check if ``result``'s fingerprint is already known.

        Fails OPEN on Redis outage — returns False so we don't drop
        findings during an outage.
        """
        fp = self.fingerprint(result)
        # If Redis is unavailable we cannot know — fail open.
        members = self.redis.smembers("dedup:results")
        if not members and not self.redis._ensure():  # type: ignore[attr-defined]
            return False
        return fp in members

    def remember(self, result: Dict[str, Any]) -> None:
        """Add ``result`` to the dedup set and bump TTL."""
        fp = self.fingerprint(result)
        self.redis.sadd("dedup:results", fp)
        self.redis.expire("dedup:results", self.ttl)

    # ------------------------------------------------------------------
    # Batch API
    # ------------------------------------------------------------------

    def dedup_batch(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only first-seen results (by fingerprint)."""
        seen: set = set()
        out: List[Dict[str, Any]] = []
        for r in results:
            fp = self.fingerprint(r)
            if fp in seen:
                continue
            seen.add(fp)
            out.append(r)
        # Remember the survivors so subsequent batches can detect them.
        for r in out:
            self.remember(r)
        return out


__all__ = ["SCHEMA", "ResultDedup"]
