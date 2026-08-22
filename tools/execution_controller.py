#!/usr/bin/env python3
"""Bounded execution policy for BugWolf research experiments.

This controller is deliberately transport-agnostic: discovery tracks provide
an operation callable, while this module enforces scope, confirmations,
request/time budgets, and rate limits before the callable executes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional

try:
    from tools.safety import (
        AuthorizationError, load_authorized_scope, require_authorized_target,
        target_in_scope, validate_http_url,
    )
except ImportError:  # direct script execution
    from safety import (
        AuthorizationError, load_authorized_scope, require_authorized_target,
        target_in_scope, validate_http_url,
    )


class ActionClass(str, Enum):
    PASSIVE = "passive"
    READ = "read"
    ACTIVE = "active"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"


class ExecutionDenied(PermissionError):
    """Raised before an operation is allowed to execute."""


@dataclass
class ExecutionPolicy:
    target: str
    scope_file: str
    allow_active: bool = False
    confirm_active: bool = False
    confirm_state_change: bool = False
    confirm_destructive: bool = False
    allowed_actions: set[ActionClass | str] = field(default_factory=lambda: {
        ActionClass.PASSIVE, ActionClass.READ,
    })
    max_requests: int = 100
    max_seconds: float = 900.0
    min_interval_seconds: float = 0.0
    dry_run: bool = False
    environment_profile: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        self.allowed_actions = {ActionClass(item) for item in self.allowed_actions}
        if self.max_requests < 1:
            raise ValueError("max_requests must be positive")
        if self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")
        if self.min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative")


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
    """Enforce an explicit policy around a single research session."""

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy
        self.scope = load_authorized_scope(policy.scope_file)
        # Validate the root target immediately. This also rejects missing or
        # unauthorized scope before any track can submit an operation.
        try:
            require_authorized_target(
                policy.target,
                policy.scope_file,
                active=policy.allow_active,
                confirm_active=policy.confirm_active,
            )
        except AuthorizationError as exc:
            raise ExecutionDenied(str(exc)) from exc
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
        if action not in self.policy.allowed_actions:
            raise ExecutionDenied(f"action class is not enabled: {action.value}")
        if action == ActionClass.ACTIVE:
            if not self.policy.allow_active or not self.policy.confirm_active:
                raise ExecutionDenied(
                    "active actions require allow_active and confirm_active")
        elif action == ActionClass.STATE_CHANGE:
            if not self.policy.allow_active or not self.policy.confirm_active:
                raise ExecutionDenied("state changes require active confirmation")
            if not self.policy.confirm_state_change:
                raise ExecutionDenied(
                    "state changes require confirm_state_change")
        elif action == ActionClass.DESTRUCTIVE:
            if not self.policy.allow_active or not self.policy.confirm_active:
                raise ExecutionDenied("destructive actions require active confirmation")
            if not self.policy.confirm_destructive:
                raise ExecutionDenied(
                    "destructive actions require confirm_destructive")

    def authorize(self, action: ActionClass | str, url: str) -> None:
        """Validate action, target, and session budgets without executing."""
        action = ActionClass(action)
        self._check_action(action)
        try:
            validate_http_url(url, self.scope)
            if not target_in_scope(url, self.scope):
                raise ExecutionDenied(f"URL is outside the supplied scope: {url}")
        except AuthorizationError as exc:
            raise ExecutionDenied(str(exc)) from exc
        if time.monotonic() - self._started > self.policy.max_seconds:
            raise ExecutionDenied("execution time budget exhausted")
        if self._requests >= self.policy.max_requests:
            raise ExecutionDenied("request budget exhausted")

    def run(self, action: ActionClass | str, url: str,
            operation: Callable[[], Any], *,
            metadata: Optional[Dict[str, Any]] = None) -> tuple[Any, ExecutionReceipt]:
        """Authorize and execute one operation, returning result plus receipt."""
        action = ActionClass(action)
        with self._lock:
            self.authorize(action, url)
            now = time.monotonic()
            wait = self.policy.min_interval_seconds - (now - self._last_execution)
            if wait > 0:
                time.sleep(wait)
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
