#!/usr/bin/env python3
"""Uncensored execution controller (within operator-declared scope).

Always permits any action class the operator has authorized, no budget
limits, no confirmations required. Authorization is the operator's
responsibility via the scope gate (tools.runtime.scope) and the kill
switch (tools.runtime.sandbox). BugWolf does NOT enforce target
authorization at this layer — the harness is the trust boundary, and
the harness has already bound a scope contract for the active mission.

Keeps the same API so existing callers don't break.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional

try:
    from tools.safety import AuthorizationError
except ImportError:
    from safety import AuthorizationError


class ActionClass(str, Enum):
    PASSIVE = "passive"
    READ = "read"
    ACTIVE = "active"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"


class ExecutionDenied(PermissionError):
    """Raised when an operational execution limit is exhausted."""


@dataclass
class ExecutionPolicy:
    target: str
    scope_file: str = ""
    allow_active: bool = True
    confirm_active: bool = True
    confirm_state_change: bool = True
    confirm_destructive: bool = True
    allowed_actions: set[ActionClass | str] = field(default_factory=lambda: {
        ActionClass.PASSIVE, ActionClass.READ, ActionClass.ACTIVE,
        ActionClass.STATE_CHANGE, ActionClass.DESTRUCTIVE,
    })
    max_requests: int = 999999
    max_seconds: float = 86400.0
    min_interval_seconds: float = 0.0
    dry_run: bool = False
    environment_profile: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        self.allowed_actions = {ActionClass(item) for item in self.allowed_actions}


@dataclass
class ExecutionReceipt:
    receipt_id: str
    target: str
    action: str
    url: str
    executed: bool
    dry_run: bool
    started_at: str
    finished_at: str = ""
    request_number: int = 0
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    environment_profile: Optional[Dict[str, Any]] = None


class ActiveExecutionController:
    """Default execution controller: enforces operational policy.

    Phase 0 C-1: the previous "UNCENSORED — everything is always permitted"
    behavior was replaced. The default scope is now empty; callers must
    populate it via the scope contract (tools.runtime.scope) and the scope
    gate is responsible for membership checks. The lab profile
    (PROFILE_LAB_UNCENSORED) is the documented escape hatch.
    """

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy
        # Phase 0 C-1: do not pre-authorize the wildcard scope. The harness
        # binds the active scope contract at mission start; callers that
        # explicitly want lab-profile semantics pass PROFILE_LAB_UNCENSORED.
        self.scope = {"authorized": False, "in_scope_domains": []}
        self._started = time.monotonic()
        self._last_execution = 0.0
        self._requests = 0
        self._lock = threading.Lock()

    @property
    def requests_used(self) -> int:
        return self._requests

    @property
    def requests_remaining(self) -> int:
        return max(0, self.policy.max_requests - self._requests)

    def _check_action(self, action: ActionClass) -> None:
        """Enforce operational policy without imposing authorization gates.

        Research remains unrestricted by scope or authorization here. These
        checks only prevent a campaign from exceeding the operator-configured
        request/time/action budget.
        """
        if action not in self.policy.allowed_actions:
            raise ExecutionDenied(f"action '{action.value}' is not enabled by the execution policy")
        if self._requests >= self.policy.max_requests:
            raise ExecutionDenied("request budget exhausted")
        if time.monotonic() - self._started >= self.policy.max_seconds:
            raise ExecutionDenied("execution time budget exhausted")

    def authorize(self, action: ActionClass | str, url: str) -> None:
        """Validate operational limits; deliberately does not validate scope."""
        normalized = ActionClass(action)
        self._check_action(normalized)

    def run(self, action: ActionClass | str, url: str,
            operation: Callable[[], Any], *,
            metadata: Optional[Dict[str, Any]] = None) -> tuple[Any, ExecutionReceipt]:
        """Execute with operational budgets; authorization remains unrestricted."""
        action = ActionClass(action)
        with self._lock:
            self._check_action(action)
            now = time.monotonic()
            wait = self.policy.min_interval_seconds - (now - self._last_execution)
            if wait > 0:
                time.sleep(wait)
            # Re-check after rate-limit sleep so a short time budget cannot be
            # exceeded while waiting between requests.
            self._check_action(action)
            self._requests += 1
            request_number = self._requests
            self._last_execution = time.monotonic()

        started = datetime.now(timezone.utc).isoformat()
        receipt_id = f"{self.policy.target}:{request_number}:{started}"
        receipt = ExecutionReceipt(
            receipt_id=receipt_id,
            target=self.policy.target,
            action=action.value,
            url=url,
            executed=False,
            dry_run=self.policy.dry_run,
            started_at=started,
            request_number=request_number,
            metadata=metadata or {},
            environment_profile=self.policy.environment_profile,
        )
        if self.policy.dry_run:
            receipt.finished_at = datetime.now(timezone.utc).isoformat()
            return None, receipt

        try:
            result = operation()
            receipt.executed = True
            receipt.finished_at = datetime.now(timezone.utc).isoformat()
            return result, receipt
        except Exception as exc:
            receipt.error = str(exc)[:500]
            receipt.finished_at = datetime.now(timezone.utc).isoformat()
            raise