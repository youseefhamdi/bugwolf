#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter identity_segregation.py:1-240 (1.5.j)
## Source: BugWolf accounts/identity.py (in-house, Phase 0)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

4-kind identity model.

bug-bounty programs typically have at least these four identity kinds:

  * anonymous       — no session
  * authenticated_a — low-privilege authenticated user (the "user")
  * authenticated_b — privileged authenticated user (the "admin")
  * service         — backend service / machine identity (CI, cron, etc.)

The :class:`IdentitySegregator` answers: *can this identity access this
resource?* — with a variant-by-variant coverage matrix used by the
harness smoke tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Iterable, Mapping, Tuple


SCHEMA = "bugwolf-identity-segregation/v1"


class IdentityKind(str, Enum):
    """The four identity kinds."""

    ANONYMOUS = "anonymous"
    AUTHENTICATED_A = "authenticated_a"
    AUTHENTICATED_B = "authenticated_b"
    SERVICE = "service"


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------

# Each resource declares which identity kinds MAY access it.
_DEFAULT_MATRIX: Dict[str, FrozenSet[IdentityKind]] = {
    "/": frozenset({IdentityKind.ANONYMOUS, IdentityKind.AUTHENTICATED_A,
                    IdentityKind.AUTHENTICATED_B, IdentityKind.SERVICE}),
    "/login": frozenset({IdentityKind.ANONYMOUS}),
    "/api/me": frozenset({IdentityKind.AUTHENTICATED_A, IdentityKind.AUTHENTICATED_B}),
    "/admin": frozenset({IdentityKind.AUTHENTICATED_B}),
    "/admin/users": frozenset({IdentityKind.AUTHENTICATED_B}),
    "/internal/healthz": frozenset({IdentityKind.SERVICE}),
    "/internal/metrics": frozenset({IdentityKind.SERVICE}),
    "/api/v1/search": frozenset({IdentityKind.ANONYMOUS, IdentityKind.AUTHENTICATED_A}),
}


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AccessDecision:
    """Outcome of a single :meth:`IdentitySegregator.check` call."""

    actor: str
    resource: str
    actor_kind: IdentityKind
    allowed: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "actor": self.actor,
            "resource": self.resource,
            "actor_kind": self.actor_kind.value,
            "allowed": bool(self.allowed),
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Segregator
# ---------------------------------------------------------------------------

class IdentitySegregator:
    """Variant-by-variant coverage checker for the 4-kind identity model."""

    SCHEMA = SCHEMA
    KIND_COUNT: int = 4

    def __init__(self, *,
                 matrix: Mapping[str, FrozenSet[IdentityKind]] = None) -> None:
        self._matrix: Dict[str, FrozenSet[IdentityKind]] = dict(matrix or _DEFAULT_MATRIX)
        self._kinds: Dict[str, IdentityKind] = {
            "anonymous": IdentityKind.ANONYMOUS,
            "auth_a": IdentityKind.AUTHENTICATED_A,
            "auth_b": IdentityKind.AUTHENTICATED_B,
            "service": IdentityKind.SERVICE,
        }

    def kinds(self) -> Tuple[IdentityKind, ...]:
        return (IdentityKind.ANONYMOUS, IdentityKind.AUTHENTICATED_A,
                IdentityKind.AUTHENTICATED_B, IdentityKind.SERVICE)

    def classify(self, actor: str) -> IdentityKind:
        """Map a free-form actor name to an :class:`IdentityKind`."""
        a = (actor or "").strip().lower()
        return self._kinds.get(a, IdentityKind.ANONYMOUS)

    def check(self, actor: str, resource: str) -> bool:
        """Return ``True`` if ``actor`` may access ``resource``."""
        kind = self.classify(actor)
        allowed_kinds = self._matrix.get(resource)
        if allowed_kinds is None:
            # Unknown resource = deny by default (fail closed).
            return False
        return kind in allowed_kinds

    def decision(self, actor: str, resource: str) -> AccessDecision:
        """Same as :meth:`check` but returns the full :class:`AccessDecision`."""
        kind = self.classify(actor)
        allowed_kinds = self._matrix.get(resource)
        if allowed_kinds is None:
            return AccessDecision(actor, resource, kind, False,
                                  reason="resource-not-declared")
        if kind not in allowed_kinds:
            return AccessDecision(actor, resource, kind, False,
                                  reason=f"{kind.value}-not-allowed")
        return AccessDecision(actor, resource, kind, True,
                              reason="allowed-by-matrix")

    def coverage(self, *, resources: Iterable[str] = None) -> Dict[str, int]:
        """Return ``{resource: count_of_kinds_allowed}`` for the variant matrix."""
        rows = list(resources or self._matrix.keys())
        return {r: len(self._matrix.get(r, frozenset())) for r in rows}


__all__ = ["SCHEMA", "IdentityKind", "AccessDecision", "IdentitySegregator"]