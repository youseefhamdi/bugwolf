"""Multi-step workflow analysis (Phase 3.3).

While :class:`bugwolf.semantic.business_logic.BusinessLogicDetector`
inspects the bypass of a *required* step,
:class:`StatefulWorkflowAnalyzer` looks at the cross-step properties
of the workflow as a whole:

  * Missing CSRF on state-changing steps (no CSRF token in headers
    or body, no ``SameSite`` cookie hint, no ``Origin``/``Referer``
    enforcement).
  * Missing step validation — given a sequence of steps, we ask
    whether the *server* validates the order.  We probe by skipping
    a step (similar to the business-logic detector) and report
    additional signals: missing CSRF + missing validation in the
    same step is a much stronger bug than either in isolation.
  * Idempotency violations — replaying a state-changing step N
    times and observing >1 success.
  * Replay attack vectors — replaying the same step with the same
    body / token and observing divergent state (e.g. two debits
    on the same intent).

STUB-SAFE: every probe goes through the injected transport.  We
never raise.

## Source:  bugwolf/semantic/stateful_workflow.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WorkflowStep
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
    stateful: bool = True
    requires_csrf: bool = True
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
            "stateful": self.stateful,
            "requires_csrf": self.requires_csrf,
            "role": self.role,
        }


# ---------------------------------------------------------------------------
# WorkflowFinding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WorkflowFinding:
    """One observation on a multi-step workflow."""

    kind: str                     # "missing-csrf" / "step-bypass" /
                                  # "idempotency-violation" / "replay-attack"
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Header / body / cookie patterns that suggest a CSRF token is in
# place.  When ALL of them are absent, the step is a finding.
_CSRF_HEADER_TOKENS: Tuple[str, ...] = (
    "x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken",
    "x-requested-with",
)
_CSRF_BODY_TOKENS: Tuple[str, ...] = (
    "csrf", "csrfmiddlewaretoken", "_csrf", "xsrf",
    "anti-forgery", "antiforgery",
)
_CSRF_COOKIE_TOKENS: Tuple[str, ...] = (
    "csrf", "csrf_token", "csrftoken", "xsrf", "xsrf-token",
)
_SAMESITE_COOKIE_RE = re.compile(r"samesite\s*=\s*(strict|lax|none)",
                                  re.IGNORECASE)

# Tokens in the body that suggest an action with idempotency /
# state-changing semantics.
_STATE_CHANGING_TOKENS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("payment", re.compile(r"\b(pay|charge|checkout|receipt)\b",
                           re.IGNORECASE)),
    ("withdraw", re.compile(r"\b(withdraw|transfer|wire)\b",
                            re.IGNORECASE)),
    ("create", re.compile(r"\b(create|register|signup|enrol)\b",
                          re.IGNORECASE)),
    ("update", re.compile(r"\b(update|edit|modify|change)\b",
                          re.IGNORECASE)),
    ("delete", re.compile(r"\b(delete|remove|purge|disable)\b",
                          re.IGNORECASE)),
    ("redeem", re.compile(r"\b(redeem|claim|consume|use)\b",
                          re.IGNORECASE)),
)


# ---------------------------------------------------------------------------
# StatefulWorkflowAnalyzer
# ---------------------------------------------------------------------------

class StatefulWorkflowAnalyzer:
    """Multi-step workflow analyzer — never raises."""

    def __init__(self) -> None:
        self.state_changing_methods: Tuple[str, ...] = (
            "POST", "PUT", "PATCH", "DELETE",
        )
        self.csrf_header_tokens: Tuple[str, ...] = _CSRF_HEADER_TOKENS
        self.csrf_body_tokens: Tuple[str, ...] = _CSRF_BODY_TOKENS
        self.csrf_cookie_tokens: Tuple[str, ...] = _CSRF_COOKIE_TOKENS

    # ------------------------------------------------------------------ api

    def analyze(
        self,
        steps: Sequence[WorkflowStep],
        transport: Callable[..., Dict[str, Any]],
    ) -> List[WorkflowFinding]:
        """Run every workflow-level check on ``steps``.

        ``transport`` is the injected callable.  When it is None we
        return an empty list immediately.  We never raise.
        """
        if not steps or transport is None:
            return []
        steps_list: List[WorkflowStep] = list(steps)
        findings: List[WorkflowFinding] = []
        # 1) Missing CSRF on state-changing steps.
        for s in steps_list:
            f = self._check_csrf(s)
            if f is not None:
                findings.append(f)
        # 2) Idempotency: replay the same state-changing step N times
        #    and see if it succeeds >1.
        for s in steps_list:
            for f in self._check_idempotency(s, transport):
                findings.append(f)
        # 3) Replay attack: same headers/body, observe divergent
        #    state across two calls.
        for s in steps_list:
            for f in self._check_replay(s, transport):
                findings.append(f)
        # 4) Step-bypass on the workflow as a whole.
        for f in self._check_step_validation(steps_list, transport):
            findings.append(f)
        return findings

    # ------------------------------------------------------------------ checks

    def _check_csrf(self, step: WorkflowStep) -> Optional[WorkflowFinding]:
        if not step.requires_csrf:
            return None
        if step.method.upper() not in self.state_changing_methods:
            return None
        # 1) Header token?
        header_blob = " ".join(f"{k}:{v}" for k, v in (step.headers or {}).items())
        header_blob_l = header_blob.lower()
        for tok in self.csrf_header_tokens:
            if tok in header_blob_l:
                return None
        # 2) Body token?
        body_l = (step.body or "").lower()
        for tok in self.csrf_body_tokens:
            if tok in body_l:
                return None
        # 3) SameSite cookie hint?
        if _SAMESITE_COOKIE_RE.search(header_blob):
            return None
        # None of the three -> finding.
        if not (step.headers or {}).get("Cookie"):
            return WorkflowFinding(
                kind="missing-csrf",
                severity="high",
                endpoint=step.url,
                method=step.method,
                evidence=(
                    f"State-changing step {step.name!r} has no CSRF "
                    f"header token, no CSRF body field, and no "
                    f"SameSite cookie hint"
                ),
                fix=(
                    "Require a CSRF token on every state-changing "
                    "request: issue a token bound to the session, "
                    "echo it in a header or body field, and validate "
                    "it server-side. Set SameSite=Strict or Lax on "
                    "the session cookie."
                ),
                detail={
                    "step": step.name,
                    "headers": sorted((step.headers or {}).keys()),
                    "body_len": len(step.body or ""),
                },
                confidence=0.7,
            )
        return WorkflowFinding(
            kind="missing-csrf",
            severity="medium",
            endpoint=step.url,
            method=step.method,
            evidence=(
                f"State-changing step {step.name!r} sends a Cookie "
                f"but has no CSRF token in headers or body and no "
                f"SameSite hint"
            ),
            fix=(
                "Add an explicit CSRF token check. A Cookie alone is "
                "not enough if the browser auto-attaches it on "
                "cross-site requests."
            ),
            detail={
                "step": step.name,
                "headers": sorted((step.headers or {}).keys()),
            },
            confidence=0.55,
        )

    def _check_idempotency(
        self,
        step: WorkflowStep,
        transport: Callable[..., Dict[str, Any]],
    ) -> List[WorkflowFinding]:
        out: List[WorkflowFinding] = []
        if step.method.upper() not in self.state_changing_methods:
            return out
        if not self._looks_state_changing(step):
            return out
        # Replay 3 times; an idempotent step should return the same
        # status / body for all 3.
        statuses: List[int] = []
        bodies: List[str] = []
        for _ in range(3):
            resp = self._call_step(transport, step)
            if resp is None:
                continue
            statuses.append(self._status(resp))
            bodies.append(str(resp.get("body", "") or ""))
        success = sum(1 for s in statuses if s in step.expected_status
                      or (200 <= s < 300))
        if success > 1 and len(set(bodies)) == 1 and bodies[0]:
            # Same body, multiple successes -> the operation claims
            # to have happened multiple times.
            out.append(WorkflowFinding(
                kind="idempotency-violation",
                severity="high",
                endpoint=step.url,
                method=step.method,
                evidence=(
                    f"Step {step.name!r} replayed 3 times; "
                    f"{success}/3 returned success with the SAME body "
                    f"— likely a duplicated side-effect"
                ),
                fix=(
                    "Make the step idempotent: require an "
                    "idempotency-key header that is unique per "
                    "operation, and reject duplicates server-side. "
                    "Alternatively, gate the operation behind a "
                    "single-row DB constraint."
                ),
                detail={"statuses": statuses, "bodies_match": True},
                confidence=0.75,
            ))
        elif success > 1 and len(set(bodies)) > 1:
            out.append(WorkflowFinding(
                kind="replay-attack",
                severity="high",
                endpoint=step.url,
                method=step.method,
                evidence=(
                    f"Step {step.name!r} replayed 3 times; "
                    f"{success}/3 returned success but the body "
                    f"CHANGED across replays — replay-attack vector"
                ),
                fix=(
                    "Bind a nonce / idempotency-key to each "
                    "operation. Reject any subsequent call that "
                    "presents the same key. Make sure server-side "
                    "validation of the key is constant-time."
                ),
                detail={"statuses": statuses, "bodies_match": False},
                confidence=0.8,
            ))
        return out

    def _check_replay(
        self,
        step: WorkflowStep,
        transport: Callable[..., Dict[str, Any]],
    ) -> List[WorkflowFinding]:
        out: List[WorkflowFinding] = []
        if step.method.upper() not in self.state_changing_methods:
            return out
        if not self._looks_state_changing(step):
            return out
        # A token / auth header that doesn't change between calls is
        # the classic replay signal: the server accepted the same
        # authenticated request twice.
        a = self._call_step(transport, step)
        b = self._call_step(transport, step)
        if a is None or b is None:
            return out
        sa, sb = self._status(a), self._status(b)
        if (sa in step.expected_status or 200 <= sa < 300) and (
                sb in step.expected_status or 200 <= sb < 300):
            body_a = str(a.get("body", "") or "")
            body_b = str(b.get("body", "") or "")
            # If both succeed and the body is identical and the step
            # is *clearly* state-changing, that's a replay bug.
            if body_a and body_a == body_b and self._is_payment_like(step):
                out.append(WorkflowFinding(
                    kind="replay-attack",
                    severity="critical",
                    endpoint=step.url,
                    method=step.method,
                    evidence=(
                        f"Step {step.name!r} accepted TWO identical "
                        f"payment-like calls and returned success on "
                        f"both — replay → double-charge"
                    ),
                    fix=(
                        "Require a unique idempotency-key per "
                        "operation. Reject any second call that "
                        "presents the same key. Use a single-row DB "
                        "constraint to back the check."
                    ),
                    detail={"statuses": [sa, sb]},
                    confidence=0.9,
                ))
        return out

    def _check_step_validation(
        self,
        steps: List[WorkflowStep],
        transport: Callable[..., Dict[str, Any]],
    ) -> List[WorkflowFinding]:
        """For each step that is not the first, try skipping it.

        This is similar to the business-logic workflow bypass but
        expressed in this module's vocabulary so the operator can
        tell which analyzer produced the finding.
        """
        out: List[WorkflowFinding] = []
        if len(steps) < 3:
            return out
        last = steps[-1]
        for i, step in enumerate(steps[:-1]):
            if not step.stateful:
                continue
            if i == 0:
                continue
            # Replay the steps before and after, skipping this one.
            skipped_call = list(steps[:i]) + list(steps[i + 1:])
            for s in skipped_call:
                self._call_step(transport, s)
            last_resp = self._call_step(transport, last)
            if last_resp is None:
                continue
            status = self._status(last_resp)
            if status in last.expected_status or 200 <= status < 300:
                out.append(WorkflowFinding(
                    kind="step-bypass",
                    severity="high",
                    endpoint=last.url,
                    method=last.method,
                    evidence=(
                        f"Step {step.name!r} (idx={i}) was skipped "
                        f"and the workflow still completed at "
                        f"{last.name!r} with status {status}"
                    ),
                    fix=(
                        "Persist a per-session state machine: only "
                        "the next valid transition is reachable. "
                        "The final endpoint must verify the prior "
                        "step actually completed for THIS session."
                    ),
                    detail={
                        "skipped_index": i,
                        "skipped_name": step.name,
                        "final_name": last.name,
                        "final_status": status,
                    },
                    confidence=0.8,
                ))
        return out

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _status(resp: Dict[str, Any]) -> int:
        try:
            return int(resp.get("status", 0))
        except (TypeError, ValueError):
            return 0

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
            log.debug("workflow: transport error: %r", exc)
            return None

    @staticmethod
    def _looks_state_changing(step: WorkflowStep) -> bool:
        blob = " ".join((
            step.name or "", step.url or "", step.body or "",
            " ".join(f"{k}:{v}" for k, v in (step.headers or {}).items()),
        )).lower()
        for _label, pat in _STATE_CHANGING_TOKENS:
            if pat.search(blob):
                return True
        return False

    @staticmethod
    def _is_payment_like(step: WorkflowStep) -> bool:
        blob = " ".join((
            step.name or "", step.url or "", step.body or "",
        )).lower()
        for kw in ("pay", "charge", "checkout", "billing",
                   "invoice", "stripe", "payment", "amount",
                   "currency", "transfer", "withdraw"):
            if kw in blob:
                return True
        return False


__all__ = [
    "SCHEMA", "WorkflowStep", "WorkflowFinding", "StatefulWorkflowAnalyzer",
]
