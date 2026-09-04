#!/usr/bin/env python3
"""Concurrency and rate governance (Phase 1.6).

Pure, deterministic state machines that protect the three things a fast
replay engine can overwhelm: the target server, the AI model, and BugWolf
itself.  Time is always passed in as ``now`` (ms) so every machine is
unit-testable with no clock and no sleeps.

    CircuitBreaker  -- stop hammering a host that keeps failing
    AimdLimiter     -- additive-increase / multiplicative-decrease concurrency
    TokenBucket     -- requests-per-second ceiling
    GlobalBudget    -- hard cap on total requests per session (anti self-DoS)

No network, no dependencies.
"""

from __future__ import annotations

from typing import Dict, Optional

SCHEMA = "bugwolf-replay-governor/v1"

DEFAULTS = {
    "connect_timeout_s": 10.0,
    "total_timeout_s": 30.0,
    "max_retries": 2,
    "retry_backoff_s": (1.0, 2.0),
    "per_host_concurrency_start": 2,
    "per_host_concurrency_max": 20,
    "rate_limit_start_rps": 5.0,
    "circuit_breaker_threshold": 5,
    "circuit_breaker_cooldown_ms": 30_000,
    "global_request_budget": 5_000,
    "response_body_cap_bytes": 5 * 1024 * 1024,
}


class CircuitBreaker:
    """Per-host circuit breaker: opens after ``threshold`` consecutive
    failures, refuses until ``cooldown_ms`` elapses, then half-open probes.
    One success closes; one failure re-opens."""

    def __init__(self, threshold: int = DEFAULTS["circuit_breaker_threshold"],
                 cooldown_ms: int = DEFAULTS["circuit_breaker_cooldown_ms"]) -> None:
        self.threshold = threshold
        self.cooldown_ms = cooldown_ms
        self.failures = 0
        self.state = "closed"        # closed | open | half-open
        self.opened_at = 0

    def can_request(self, now: float) -> bool:
        if self.state == "open":
            if now - self.opened_at >= self.cooldown_ms:
                self.state = "half-open"
                return True
            return False
        return True

    def on_success(self) -> None:
        self.failures = 0
        self.state = "closed"

    def on_failure(self, now: float) -> None:
        self.failures += 1
        if self.state == "half-open" or self.failures >= self.threshold:
            self.state = "open"
            self.opened_at = now

    @property
    def current(self) -> str:
        return self.state


class AimdLimiter:
    """Additive-increase / multiplicative-decrease per-host concurrency.

    Starts conservative; every ``window`` successes in a row adds one slot,
    any failure (timeout, 5xx storm, circuit event) halves the slots.
    """

    def __init__(self, start: int = DEFAULTS["per_host_concurrency_start"],
                 max_concurrency: int = DEFAULTS["per_host_concurrency_max"]) -> None:
        self.start = max(1, start)
        self.max_concurrency = max(self.start, max_concurrency)
        self.limit = self.start
        self._streak = 0

    def on_success(self, window: int = 10) -> None:
        self._streak += 1
        if self._streak >= window:
            self._streak = 0
            self.limit = min(self.max_concurrency, self.limit + 1)

    def on_failure(self) -> None:
        self._streak = 0
        self.limit = max(1, self.limit // 2)

    def can_send(self, in_flight: int) -> bool:
        return in_flight < self.limit


class TokenBucket:
    """Classic token bucket: ``rate`` tokens/second, ``burst`` capacity."""

    def __init__(self, rate_rps: float = DEFAULTS["rate_limit_start_rps"],
                 burst: Optional[int] = None) -> None:
        self.rate = max(0.1, float(rate_rps))
        self.burst = burst if burst is not None else max(1, int(self.rate))
        self.tokens = float(self.burst)
        self.last_refill = 0.0

    def can_request(self, now: float) -> bool:
        if self.last_refill == 0.0:
            self.last_refill = now
        elapsed = max(0.0, now - self.last_refill) / 1000.0
        self.tokens = min(float(self.burst), self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class GlobalBudget:
    """Session-wide hard cap on total sends — the anti-self-DoS floor."""

    def __init__(self, budget: int = DEFAULTS["global_request_budget"]) -> None:
        self.budget = budget
        self.spent = 0

    def can_request(self) -> bool:
        return self.spent < self.budget

    def record(self) -> None:
        self.spent += 1

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.spent)


class Governor:
    """Composite governance for one replay session (per-host state)."""

    def __init__(self, *, rate_rps: float = DEFAULTS["rate_limit_start_rps"],
                 budget: int = DEFAULTS["global_request_budget"]) -> None:
        self.rate = TokenBucket(rate_rps)
        self.budget = GlobalBudget(budget)
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._limiters: Dict[str, AimdLimiter] = {}
        self.blocked_reason: Optional[str] = None

    def _breaker(self, host: str) -> CircuitBreaker:
        if host not in self._breakers:
            self._breakers[host] = CircuitBreaker()
        return self._breakers[host]

    def _limiter(self, host: str) -> AimdLimiter:
        if host not in self._limiters:
            self._limiters[host] = AimdLimiter()
        return self._limiters[host]

    def allow(self, host: str, now: float, in_flight: int = 0) -> bool:
        """Admission decision for one send. Sets ``blocked_reason`` when
        refusing so callers record a policy fact, not a mystery."""
        if not self.budget.can_request():
            self.blocked_reason = "global budget exhausted"
            return False
        if not self._breaker(host).can_request(now):
            self.blocked_reason = f"circuit open for {host}"
            return False
        if not self._limiter(host).can_send(in_flight):
            self.blocked_reason = f"concurrency limit for {host}"
            return False
        if not self.rate.can_request(now):
            self.blocked_reason = "rate limit"
            return False
        self.blocked_reason = None
        return True

    def record_success(self, host: str) -> None:
        self._breaker(host).on_success()
        self._limiter(host).on_success()
        self.budget.record()

    def record_failure(self, host: str, now: float) -> None:
        self._breaker(host).on_failure(now)
        self._limiter(host).on_failure()
        self.budget.record()

    def status(self) -> Dict[str, str]:
        return {host: breaker.current
                for host, breaker in self._breakers.items()}
