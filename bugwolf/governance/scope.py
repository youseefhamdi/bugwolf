"""Strict scope binding (Phase 1.4 — Governance Core).

Thin delegation over the existing :mod:`tools.runtime.scope` gate.  The
governance core never duplicates the gate's logic; instead it wraps the
gate with:

  * a stricter :meth:`check_url` that ALSO asserts the action class is
    allowed (the runtime gate only checks host);
  * an approval registry that records approvals for destructive
    action classes before they are dispatched;
  * a single :func:`bind_governance` entry point that operators can
    call once per mission.

The 5 audit-cited ``# UNCENSORED:`` bypasses are already closed in
Phase 0; this module adds the SEMANTIC permission layer that runs
*before* any payload hits the wire.

No external deps; stdlib only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

from ._canonical import SCHEMA as _SCHEMA
from .approval import Approval, ApprovalStatus

# Re-export the runtime scope gate's exception so callers depending on
# :mod:`bugwolf.governance.scope` can catch ScopeViolation without
# importing :mod:`tools.runtime.scope` directly.
try:  # pragma: no cover - import surface; covered by tests
    from tools.runtime.scope import ScopeViolation  # noqa: F401
except Exception:  # pragma: no cover - tools.* may not be on sys.path
    ScopeViolation = PermissionError  # type: ignore[assignment,misc]

SCHEMA = "bugwolf-governance-v1"

# Action classes that REQUIRE an explicit approval before dispatch.
DESTRUCTIVE_ACTIONS = {
    "delete", "put", "patch", "remove", "destroy",
    "kill", "shutdown", "reset", "purge", "drop",
}


@dataclass
class GovernanceHandle:
    """The handle returned by :func:`bind_governance`.

    Provides a small, audit-friendly surface over the runtime scope
    gate.  All methods are thin delegators — the actual authority
    decisions live in :mod:`tools.runtime.scope` and
    :class:`bugwolf.governance.approval.Approval`.
    """

    target: str
    mission_id: str
    allowed_actions: List[str]
    scope_ref: str
    approval: Approval

    schema: str = _SCHEMA

    def check_url(self, url: str, action_class: str) -> str:
        """Check both host AND action class against the gate."""
        from tools.runtime import scope as _scope
        host = _scope.check_url(url)
        self.require_action_authorized(action_class)
        return host

    def require_action_authorized(self, action: str) -> None:
        """Raise :class:`PermissionError` if ``action`` is disallowed."""
        if not action:
            raise PermissionError("action class is required")
        if self.allowed_actions:
            normalized = action.upper()
            if not any(a.upper() == normalized for a in self.allowed_actions):
                raise PermissionError(
                    f"action {action!r} not in allowed_actions "
                    f"{self.allowed_actions!r}")
        if self._is_destructive(action):
            candidate = {
                "target": self.target,
                "action": action,
            }
            if not self.approval.is_approved(candidate):
                raise PermissionError(
                    f"destructive action {action!r} requires an active "
                    f"approval for target {self.target!r}")

    def register_approval(self, target: str, action: str, *,
                          ttl: Optional[int] = None) -> Any:
        """Record an operator approval for ``(target, action)``."""
        record = self.approval.request(
            target=target,
            action=action,
            ttl_seconds=ttl,
        )
        return self.approval.grant(record.approval_id, target=target)

    # -- internals ----------------------------------------------------------

    def _is_destructive(self, action: str) -> bool:
        normalized = action.lower()
        return any(token in normalized for token in DESTRUCTIVE_ACTIONS)


def bind_governance(
    *,
    target: Optional[str] = None,
    mission_id: Optional[str] = None,
    allowed_actions: Optional[List[str]] = None,
    scope_ref: str = "",
    root: Optional[Path] = None,
) -> GovernanceHandle:
    """Bind the runtime scope gate AND return a governance handle.

    If ``target`` is omitted, the handle binds to the CURRENT process
    gate's target (the mission runner already called
    :func:`tools.runtime.scope.bind_target`).  If the gate has not been
    bound yet, the call raises so a "bind to nothing" mission cannot
    accidentally authorize the first URL it sees.
    """
    from tools.runtime import scope as _scope

    if target is None:
        gate = _scope.gate_state()
        target = str(gate.get("target") or "")
        if not target:
            raise RuntimeError(
                "bind_governance: no target supplied and runtime gate "
                "has not been bound; call bind_target first")
        # Honor the gate's already-declared extra hosts / denies.
        _scope.bind_target(
            target,
            extra_hosts=gate.get("extra_hosts"),
            deny_entries=gate.get("deny_entries"),
        )
    else:
        _scope.bind_target(target)

    if not mission_id:
        raise ValueError("bind_governance requires mission_id")

    approval = Approval(root=root)
    return GovernanceHandle(
        target=str(target),
        mission_id=str(mission_id),
        allowed_actions=list(allowed_actions or []),
        scope_ref=str(scope_ref or ""),
        approval=approval,
    )


__all__ = [
    "SCHEMA",
    "GovernanceHandle",
    "DESTRUCTIVE_ACTIONS",
    "bind_governance",
    "ScopeViolation",
    "ScopeVerdict",
    "ScopeRule",
    "ScopeContext",
    "enforce_scope",
]


# =============================================================================
# Appendix A — ScopeRule / ScopeContext / enforce_scope (Phase 1.4 deeper)
# =============================================================================
#
# The shallow ``bind_governance`` above answers ``is this host in scope?``
# but the plan's Appendix A demands the SEMANTIC form:
#
#   * per-pattern rules with expiry + reason;
#   * deny-by-default (``default_deny=True``);
#   * explicit ``requires_approval`` channel (vs ``in_scope`` allow);
#   * suffix-confusion guard (``notexample.com`` must NOT match
#     ``example.com`` without an explicit dot-boundary anchor);
#   * deny-wins ordering — a single DENY in any matching rule shadows
#     every ALLOW;
#   * ``enforce_scope`` is the entry point used by the audit hook and the
#     mission runner; it raises :class:`ScopeViolation` on DENY so the
#     caller never has to remember to check the verdict.
#
# Everything here is stdlib-only.
# -----------------------------------------------------------------------------


class ScopeVerdict(str, Enum):
    """Semantic outcome of :meth:`ScopeContext.check`."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# Rule types the appendix enumerates.
_RULE_TYPES = frozenset({"domain", "ip", "cidr", "regex", "wildcard"})

# Tokens that flag a pattern as a wildcard / open-ended target.  These
# are rejected outright when the rule claims ALLOW — only DENY may use
# them (so the operator can set ``*.example.com`` as a deny rule without
# a follow-up ALLOW being forced to also be a wildcard).
_WILDCARD_TOKENS = ("*", "?", "[", "]")


@dataclass
class ScopeRule:
    """One entry of the operator scope file (Appendix A schema)."""

    pattern: str
    rule_type: str  # one of "domain" | "ip" | "cidr" | "regex" | "wildcard"
    action: str  # ScopeVerdict value: ALLOW | DENY | REQUIRE_APPROVAL
    expires_at: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, str) or not self.pattern.strip():
            raise ValueError("ScopeRule.pattern must be a non-empty string")
        self.pattern = self.pattern.strip()
        if self.rule_type not in _RULE_TYPES:
            raise ValueError(
                f"ScopeRule.rule_type must be one of {sorted(_RULE_TYPES)}; "
                f"got {self.rule_type!r}")
        try:
            self._verdict = ScopeVerdict(self.action)
        except ValueError as exc:
            raise ValueError(
                f"ScopeRule.action must be a ScopeVerdict value "
                f"({[v.value for v in ScopeVerdict]}); got {self.action!r}"
            ) from exc
        # Plan R-scope invariant: wildcard ALLOW is forbidden (the
        # classic ``--scope *.example.com`` footgun that lets an
        # operator grant the whole internet).  DENY may still use
        # wildcards (e.g. ``*.suspicious.example`` as a deny rule).
        if self.rule_type == "wildcard" and self._verdict == ScopeVerdict.ALLOW:
            raise ValueError(
                "wildcard patterns are forbidden for ALLOW rules "
                "(plan R-scope: prefer explicit domain rules)")
        self.action = self._verdict.value
        if self.expires_at is not None:
            self._expiry_ts = _parse_iso8601(self.expires_at)
        else:
            self._expiry_ts = None

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self._expiry_ts is None:
            return False
        if now is None:
            now = datetime.now(timezone.utc).timestamp()
        return now > self._expiry_ts

    def matches(self, target: str) -> bool:
        """Return True iff ``target`` falls under this rule's pattern.

        ``target`` may be a hostname, an IP literal, an IPv4 CIDR host, or
        a URL — the rule type picks the matcher.
        """
        if not target:
            return False
        value = _strip_url(target) if "://" in target else target.strip()
        if self.rule_type == "domain":
            return _domain_matches(value, self.pattern)
        if self.rule_type == "ip":
            return _ip_matches(value, self.pattern)
        if self.rule_type == "cidr":
            return _cidr_matches(value, self.pattern)
        if self.rule_type == "regex":
            try:
                return bool(re.search(self.pattern, value))
            except re.error:
                return False
        if self.rule_type == "wildcard":
            return _wildcard_matches(value, self.pattern)
        return False


@dataclass
class ScopeContext:
    """Container for in-scope / out-of-scope / requires-approval rule sets."""

    in_scope: List[ScopeRule] = field(default_factory=list)
    out_of_scope: List[ScopeRule] = field(default_factory=list)
    requires_approval: List[ScopeRule] = field(default_factory=list)
    default_deny: bool = True

    def check(self, target: str, *,
              now: Optional[float] = None) -> ScopeVerdict:
        """Return the semantic verdict for ``target``.

        Deny-wins ordering:

          1. If ANY out-of-scope rule matches AND is not expired, DENY.
          2. Else if ANY requires-approval rule matches AND is not
             expired, REQUIRE_APPROVAL.
          3. Else if ANY in-scope rule matches AND is not expired,
             ALLOW.
          4. Else default_deny ? DENY : REQUIRE_APPROVAL.

        The suffix-confusion guard is enforced inside the matchers
        (``notexample.com`` MUST NOT match ``example.com``).
        """
        if not target:
            return ScopeVerdict.DENY if self.default_deny else ScopeVerdict.REQUIRE_APPROVAL

        # DENY beats everything.
        for rule in self.out_of_scope:
            if rule.is_expired(now):
                continue
            if rule.matches(target):
                return ScopeVerdict.DENY

        # REQUIRE_APPROVAL next (it is "narrower than ALLOW but wider
        # than nothing").
        for rule in self.requires_approval:
            if rule.is_expired(now):
                continue
            if rule.matches(target):
                return ScopeVerdict.REQUIRE_APPROVAL

        for rule in self.in_scope:
            if rule.is_expired(now):
                continue
            if rule.matches(target):
                return ScopeVerdict.ALLOW

        return ScopeVerdict.DENY if self.default_deny else ScopeVerdict.REQUIRE_APPROVAL

    def _is_suffix_confusion(self, target: str) -> bool:
        """Return True if ``target`` would be confused with a wildcard.

        The guard rejects hostnames that contain another hostname as a
        suffix without a dot boundary (``notexample.com`` vs
        ``example.com``).  Used by tests and the preflight check.
        """
        if not target:
            return False
        value = _strip_url(target) if "://" in target else target.strip().lower()
        value = value.rstrip(".")
        for bucket in (self.in_scope, self.out_of_scope, self.requires_approval):
            for rule in bucket:
                if rule.rule_type == "wildcard" or rule.rule_type == "regex":
                    continue
                pat = rule.pattern.lower().rstrip(".")
                if not pat or pat == value:
                    continue
                # dot-boundary match ⇒ not confusion
                if value.endswith("." + pat):
                    continue
                # plain suffix match without a dot boundary ⇒ confusion
                if value.endswith(pat):
                    return True
        return False


def enforce_scope(target: str, context: ScopeContext, *,
                  now: Optional[float] = None) -> ScopeVerdict:
    """Run :meth:`ScopeContext.check` and raise on DENY.

    Returns ALLOW or REQUIRE_APPROVAL; raises :class:`ScopeViolation` on
    DENY.  The exception carries the offending host so the caller can
    log it without re-parsing.
    """
    verdict = context.check(target, now=now)
    if verdict == ScopeVerdict.DENY:
        host = _strip_url(target) if "://" in target else (target or "")
        raise ScopeViolation(str(target), host)
    return verdict


# -----------------------------------------------------------------------------
# Matchers (kept private — they exist to make :class:`ScopeRule` work, not to
# be a public API).
# -----------------------------------------------------------------------------


def _strip_url(value: str) -> str:
    try:
        parsed = urlparse(value if "://" in value else "//" + value)
        return (parsed.hostname or parsed.path or value).lower().rstrip(".")
    except ValueError:
        return value.strip().lower().rstrip(".")


def _domain_matches(host: str, pattern: str) -> bool:
    h = host.lower().rstrip(".")
    p = pattern.lower().rstrip(".")
    if not h or not p:
        return False
    if h == p:
        return True
    # dot-boundary suffix match — ``api.example.com`` matches ``example.com``
    # but ``notexample.com`` does NOT.
    return h.endswith("." + p)


def _ip_matches(host: str, pattern: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        target = ipaddress.ip_address(pattern)
        return ip == target
    except ValueError:
        return False


def _cidr_matches(host: str, pattern: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        net = ipaddress.ip_network(pattern, strict=False)
        return ip in net
    except ValueError:
        return False


def _wildcard_matches(host: str, pattern: str) -> bool:
    """Strict glob: only ``*`` is honored, anchored to the whole string."""
    if not any(tok in pattern for tok in _WILDCARD_TOKENS):
        # A wildcard pattern without any wildcard tokens is treated as a
        # plain domain (defensive — operators sometimes omit the type).
        return _domain_matches(host, pattern)
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return bool(re.match(regex, host))


def _parse_iso8601(value: str) -> float:
    """Parse an ISO-8601 string into a UTC unix timestamp."""
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()