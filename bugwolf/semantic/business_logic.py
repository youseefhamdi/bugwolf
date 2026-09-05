"""Race conditions, workflow bypass, and TOCTOU detection (Phase 3.3).

Three classes of business-logic bug, each backed by a small probe loop
that calls a transport the orchestrator (or the test harness) injects.

  1. **Race conditions** — fire N concurrent requests at the same
     endpoint and check for inconsistent state (e.g. "balance went
     below zero", "user got two discount codes", "withdraw succeeded
     twice").

  2. **Workflow bypass** — given an ordered list of :class:`WorkflowStep`,
     try skipping intermediate steps (especially payment / verification
     steps) and observe whether the final step still succeeds.

  3. **TOCTOU** — given a state-before and state-after snapshot of a
     resource, look for values that are checked in one place and used
     in another with an exploitable gap.

STUB-SAFE: the detector never reaches out on its own.  Every call
goes through the injected transport, which is expected to return a
dict.  When the transport is None or raises, we degrade to a
deterministic "no signal" result for that probe.

## Source:  bugwolf/semantic/business_logic.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WorkflowStep:
    """One step in a multi-step business workflow."""

    name: str
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    expected_status: Tuple[int, ...] = (200, 201, 202, 204)
    required: bool = True
    role: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "headers": dict(self.headers),
            "body": self.body[:200],
            "expected_status": list(self.expected_status),
            "required": self.required,
            "role": self.role,
        }


@dataclass(frozen=True)
class RaceFinding:
    """One observation that suggests a TOCTOU / race condition."""

    kind: str                     # "race-condition"
    severity: str
    endpoint: str
    method: str
    evidence: str
    fix: str
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.6

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "fix": self.fix,
            "detail": dict(self.detail),
            "confidence": round(float(self.confidence), 4),
        }


@dataclass(frozen=True)
class WorkflowBypassFinding:
    """One observation that a step can be skipped or out-of-order."""

    kind: str                     # "workflow-bypass"
    severity: str
    endpoint: str
    method: str
    evidence: str
    fix: str
    skipped_step: str
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.7

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "fix": self.fix,
            "skipped_step": self.skipped_step,
            "detail": dict(self.detail),
            "confidence": round(float(self.confidence), 4),
        }


@dataclass(frozen=True)
class TOCTOUFinding:
    """A state field that is checked in one place and used elsewhere."""

    kind: str                     # "toctou"
    severity: str
    operation: str
    evidence: str
    fix: str
    field: str
    before: Any = None
    after: Any = None
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.55

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "operation": self.operation,
            "evidence": self.evidence,
            "fix": self.fix,
            "field": self.field,
            "before": self.before,
            "after": self.after,
            "detail": dict(self.detail),
            "confidence": round(float(self.confidence), 4),
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Status codes that are normally considered "the operation succeeded".
_SUCCESS_CODES: Tuple[int, ...] = (200, 201, 202, 203, 204, 206)

# Numeric / monetary JSON paths we look at when checking for "balance
# went below zero" style race conditions.  We use a flat list of field
# names for portability.
_NUMERIC_BALANCE_FIELDS: Tuple[str, ...] = (
    "balance", "credit", "debit", "amount", "funds", "quota",
    "tokens", "points", "inventory", "stock", "count",
)

# Heuristic "this body says we were charged" tokens.
_PAYMENT_TOKENS: Tuple[re.Pattern, ...] = (
    re.compile(r"\b(charged|payment\s+successful|paid|receipt|order\s+confirmed)\b",
               re.IGNORECASE),
    re.compile(r"\"(?:status|state)\"\s*:\s*\"(?:paid|complete|confirmed|settled|success)\"",
               re.IGNORECASE),
)

# Steps whose names look like they should NOT be skippable.
_SENSITIVE_STEP_KEYWORDS: Tuple[str, ...] = (
    "payment", "pay", "charge", "checkout", "billing",
    "verify", "verification", "confirm", "approval",
    "2fa", "mfa", "captcha", "csrf", "nonce", "challenge",
    "consent", "tos", "terms", "agree", "authorization",
    "review", "moderation", "kyc",
)


# ---------------------------------------------------------------------------
# BusinessLogicDetector
# ---------------------------------------------------------------------------

class BusinessLogicDetector:
    """Detect race conditions, workflow bypass, and TOCTOU at the API edge."""

    def __init__(self) -> None:
        self.balance_fields: Tuple[str, ...] = _NUMERIC_BALANCE_FIELDS
        self.success_codes: Tuple[int, ...] = _SUCCESS_CODES
        self.sensitive_keywords: Tuple[str, ...] = _SENSITIVE_STEP_KEYWORDS

    # ------------------------------------------------------------------ race

    def detect_race(
        self,
        endpoint: str,
        *,
        concurrency: int = 10,
        transport: Callable[..., Dict[str, Any]],
    ) -> List[RaceFinding]:
        """Fire ``concurrency`` parallel requests at ``endpoint``.

        The detector doesn't actually create threads; the contract is
        that ``transport`` is called N times and the detector inspects
        the responses.  In tests the mock transport can record each
        call and return a deterministic response per call index.  In
        production the orchestrator is responsible for the
        concurrency.

        We never raise.  Returns ``[]`` if ``transport`` is missing or
        every call fails.
        """
        if not endpoint or transport is None:
            return []
        try:
            n = max(1, int(concurrency))
        except (TypeError, ValueError):
            n = 10

        responses: List[Dict[str, Any]] = []
        try:
            for _ in range(n):
                try:
                    r = transport("POST", endpoint, headers=None, body=None)
                except TypeError:
                    r = transport("POST", endpoint, None, None)
                except Exception as exc:  # noqa: BLE001
                    log.debug("race: transport raised: %r", exc)
                    r = None
                responses.append(r if r is not None else {})
        except Exception as exc:  # noqa: BLE001
            log.debug("race: outer loop failed: %r", exc)
            return []

        return self._analyse_race_responses(endpoint, responses, n)

    def _analyse_race_responses(
        self,
        endpoint: str,
        responses: List[Dict[str, Any]],
        n: int,
    ) -> List[RaceFinding]:
        findings: List[RaceFinding] = []
        statuses = [self._status(r) for r in responses]
        success_count = sum(1 for s in statuses if s in self.success_codes)
        if success_count <= 1:
            # No multi-success pattern — at most one request would
            # have made it through, which is the *safe* behaviour.
            return findings
        # Multi-success: the operation completed more than once.  If
        # the body contains a monetary / inventory field, that's
        # almost always exploitable.
        for field_name in self.balance_fields:
            values = [self._extract_numeric(r, field_name) for r in responses]
            if any(v is None for v in values):
                continue
            if any(v is None for v in values):
                continue
            # Find a monotonic-decrease pattern: balance should NEVER go
            # negative if only one op succeeded.
            negatives = sum(1 for v in values if v is not None and v < 0)
            if negatives > 0:
                findings.append(RaceFinding(
                    kind="race-condition",
                    severity="critical",
                    endpoint=endpoint,
                    method="POST",
                    evidence=(
                        f"{success_count}/{n} parallel POSTs to {endpoint} "
                        f"returned success; field {field_name!r} went "
                        f"negative ({values[:5]})"
                    ),
                    fix=(
                        "Wrap the read-modify-write in a row-level lock "
                        "or an atomic SQL UPDATE with a balance guard. "
                        "Use SELECT ... FOR UPDATE on the balance row, or "
                        "an UPDATE ... WHERE balance >= amount pattern."
                    ),
                    detail={
                        "field": field_name,
                        "values": values,
                        "success_count": success_count,
                    },
                    confidence=0.85,
                ))
                continue
            # Multi-success without negatives but with multiple
            # positive deltas: still suspicious if the response
            # carries a counter that should only have been
            # incremented once.
            positive = sum(1 for v in values if v is not None and v > 0)
            if positive > 1:
                findings.append(RaceFinding(
                    kind="race-condition",
                    severity="high",
                    endpoint=endpoint,
                    method="POST",
                    evidence=(
                        f"{positive}/{n} parallel POSTs to {endpoint} "
                        f"returned success; field {field_name!r} "
                        f"incremented multiple times ({values[:5]})"
                    ),
                    fix=(
                        "Make the increment atomic (INSERT ... ON "
                        "CONFLICT DO NOTHING, or UPDATE ... RETURNING "
                        "with a single-row guard). Ensure the operation "
                        "is idempotent OR that a uniqueness constraint "
                        "blocks the duplicate."
                    ),
                    detail={
                        "field": field_name,
                        "values": values,
                        "success_count": success_count,
                    },
                    confidence=0.7,
                ))
        # If the body says "payment successful" multiple times, that's
        # a charge-bug regardless of any balance field.
        payment_hits = 0
        for r in responses:
            body = str(r.get("body", "") if r else "")
            if any(p.search(body) for p in _PAYMENT_TOKENS):
                payment_hits += 1
        if payment_hits > 1:
            findings.append(RaceFinding(
                kind="race-condition",
                severity="critical",
                endpoint=endpoint,
                method="POST",
                evidence=(
                    f"{payment_hits}/{n} parallel POSTs to {endpoint} "
                    f"returned a payment-confirmed body — likely double "
                    f"charge"
                ),
                fix=(
                    "Add a unique idempotency-key check OR a single-row "
                    "DB constraint that prevents the second charge from "
                    "committing. Use a UNIQUE index on the "
                    "(user_id, intent_id) pair."
                ),
                detail={
                    "payment_hits": payment_hits,
                    "n": n,
                },
                confidence=0.8,
            ))
        return findings

    # ------------------------------------------------------------------ workflow

    def detect_workflow_bypass(
        self,
        steps: Sequence[WorkflowStep],
        transport: Callable[..., Dict[str, Any]],
    ) -> List[WorkflowBypassFinding]:
        """For each ``required`` step that is NOT first, try to skip it.

        We do this by replaying only the steps before the candidate
        plus the final step, and observe whether the final step still
        succeeds.  This catches the classic "I never paid, but I got
        the order" bypass.
        """
        if not steps or transport is None:
            return []
        findings: List[WorkflowBypassFinding] = []
        steps_list: List[WorkflowStep] = list(steps)
        if len(steps_list) < 2:
            return findings
        last = steps_list[-1]
        for i, step in enumerate(steps_list[:-1]):
            if not step.required:
                continue
            if not self._is_sensitive(step):
                continue
            # Replay the steps that PRECEDE the candidate, then the
            # last step directly.  If the last step returns success,
            # the candidate was effectively bypassed.
            preceding = steps_list[:i] + steps_list[i + 1:-1]
            for s in preceding:
                self._call_step(transport, s)
            last_resp = self._call_step(transport, last)
            if last_resp is None:
                continue
            status = self._status(last_resp)
            if status in self.success_codes:
                findings.append(WorkflowBypassFinding(
                    kind="workflow-bypass",
                    severity="critical",
                    endpoint=last.url or step.url,
                    method=last.method,
                    evidence=(
                        f"Skipped required step {step.name!r} (idx={i}) "
                        f"and the final step {last.name!r} still "
                        f"returned status {status}"
                    ),
                    fix=(
                        "Persist a per-session state machine: only the "
                        "next valid transition is reachable. The final "
                        "endpoint must verify the prior step actually "
                        "completed for THIS session, not just trust "
                        "that the caller reached it."
                    ),
                    skipped_step=step.name,
                    detail={
                        "skipped_index": i,
                        "skipped_url": step.url,
                        "final_url": last.url,
                        "final_status": status,
                    },
                    confidence=0.85,
                ))
        return findings

    # ------------------------------------------------------------------ toctou

    def detect_toctou(
        self,
        state_before: Dict[str, Any],
        state_after: Dict[str, Any],
        operation: str,
    ) -> List[TOCTOUFinding]:
        """Compare two state snapshots and look for exploitable gaps.

        The classic TOCTOU pattern: a check happens against state
        snapshot A, but the operation commits against state snapshot
        B.  When we observe the two snapshots, we look for fields that
        changed in a way that *should* have invalidated the check.

        We never raise.
        """
        findings: List[TOCTOUFinding] = []
        if not isinstance(state_before, dict) or not isinstance(state_after, dict):
            return findings
        op = (operation or "operation").strip() or "operation"
        b_keys = set(state_before.keys())
        a_keys = set(state_after.keys())
        all_keys = b_keys | a_keys
        for key in sorted(all_keys):
            b = state_before.get(key)
            a = state_after.get(key)
            if b == a:
                continue
            # 1) Monotonic guard tripped: a numeric field was checked
            #    as >= X, then a withdrawal / decrement / negative
            #    operation reduced it below X.
            if isinstance(b, (int, float)) and isinstance(a, (int, float)):
                if b >= 0 and a < 0:
                    findings.append(TOCTOUFinding(
                        kind="toctou",
                        severity="critical",
                        operation=op,
                        evidence=(
                            f"{op!r}: field {key!r} went from "
                            f"{b!r} to {a!r} — guard that was checking "
                            f"non-negative passed at snapshot A, but the "
                            f"final value is negative"
                        ),
                        fix=(
                            "Use an atomic conditional update: "
                            "UPDATE ... SET amount = amount - :delta "
                            "WHERE amount >= :delta. Reject if 0 rows "
                            "are affected."
                        ),
                        field=key, before=b, after=a,
                        detail={"kind": "balance-flipped-negative"},
                        confidence=0.85,
                    ))
                    continue
                if a > b and self._looks_like_quota_key(key):
                    findings.append(TOCTOUFinding(
                        kind="toctou",
                        severity="high",
                        operation=op,
                        evidence=(
                            f"{op!r}: quota-like field {key!r} increased "
                            f"from {b!r} to {a!r} across the operation"
                        ),
                        fix=(
                            "Quotas should be monotonically decreasing "
                            "on consumption. If the field can grow, "
                            "ensure the increment is gated by an "
                            "explicit authorize step."
                        ),
                        field=key, before=b, after=a,
                        detail={"kind": "quota-increased"},
                        confidence=0.55,
                    ))
                continue
            # 2) Boolean "ownership" / "active" flag flipped.
            if isinstance(b, bool) and isinstance(a, bool):
                if b and not a:
                    findings.append(TOCTOUFinding(
                        kind="toctou",
                        severity="high",
                        operation=op,
                        evidence=(
                            f"{op!r}: boolean flag {key!r} flipped "
                            f"True→False across the operation — if the "
                            f"check used the prior value, the operation "
                            f"completed against a stale state"
                        ),
                        fix=(
                            "Re-check the boolean at commit time inside "
                            "the same transaction that performs the "
                            "write; do not rely on a snapshot read "
                            "outside of the transaction."
                        ),
                        field=key, before=b, after=a,
                        detail={"kind": "boolean-flipped"},
                        confidence=0.7,
                    ))
                continue
            # 3) String identity / role changed but operation succeeded.
            if isinstance(b, str) and isinstance(a, str) and b and a and b != a:
                if self._looks_like_identity_key(key):
                    findings.append(TOCTOUFinding(
                        kind="toctou",
                        severity="medium",
                        operation=op,
                        evidence=(
                            f"{op!r}: identity-like field {key!r} "
                            f"changed from {b!r} to {a!r} during the "
                            f"operation — the check at snapshot A may "
                            f"no longer apply"
                        ),
                        fix=(
                            "Re-validate the identity field at write "
                            "time. If a user is being assigned a new "
                            "value for this field, invalidate any "
                            "session / cache entry tied to the old "
                            "value."
                        ),
                        field=key, before=b, after=a,
                        detail={"kind": "identity-changed"},
                        confidence=0.5,
                    ))
        return findings

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _status(resp: Dict[str, Any]) -> int:
        try:
            s = int(resp.get("status", 0))
        except (TypeError, ValueError):
            return 0
        return s

    def _call_step(
        self,
        transport: Callable[..., Dict[str, Any]],
        step: WorkflowStep,
    ) -> Optional[Dict[str, Any]]:
        try:
            try:
                return transport(step.method, step.url,
                                 headers=step.headers or {},
                                 body=step.body or "")
            except TypeError:
                return transport(step.method, step.url,
                                 step.headers or {},
                                 step.body or "")
        except Exception as exc:  # noqa: BLE001
            log.debug("workflow: step transport error: %r", exc)
            return None

    def _is_sensitive(self, step: WorkflowStep) -> bool:
        haystack = " ".join((
            step.name or "", step.role or "", step.url or "",
            step.body or "",
        )).lower()
        for kw in self.sensitive_keywords:
            if kw in haystack:
                return True
        return False

    @staticmethod
    def _extract_numeric(resp: Dict[str, Any], field: str) -> Optional[float]:
        if not isinstance(resp, dict):
            return None
        body = resp.get("body", "")
        if body is None:
            return None
        if not isinstance(body, str):
            try:
                body = str(body)
            except Exception:  # noqa: BLE001
                return None
        # Try direct field first.
        m = re.search(rf'"{re.escape(field)}"\s*:\s*(-?\d+(?:\.\d+)?)',
                      body)
        if m:
            try:
                return float(m.group(1))
            except (TypeError, ValueError):
                return None
        # Maybe a top-level field in the parsed dict.
        parsed = resp.get("json")
        if isinstance(parsed, dict):
            v = parsed.get(field)
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                try:
                    return float(v)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _looks_like_quota_key(key: str) -> bool:
        k = key.lower()
        return any(t in k for t in (
            "balance", "credit", "quota", "token", "point",
            "stock", "inventory", "count", "limit", "budget",
            "remaining", "available",
        ))

    @staticmethod
    def _looks_like_identity_key(key: str) -> bool:
        k = key.lower()
        return any(t in k for t in (
            "owner", "user", "user_id", "userid", "account",
            "email", "tenant", "org", "role", "scope",
            "subject", "sub", "principal", "actor",
        ))


__all__ = [
    "SCHEMA", "WorkflowStep", "RaceFinding", "WorkflowBypassFinding",
    "TOCTOUFinding", "BusinessLogicDetector",
]
