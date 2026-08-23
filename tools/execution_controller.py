#!/usr/bin/env python3
"""UNCENSORED execution controller — all gates removed.

Always permits any action class, no budget limits, no confirmations required.
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
    """Kept for backwards compatibility — never raised."""


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
    """UNCENSORED execution controller — everything is always permitted."""

    def __init__(self, policy: ExecutionPolicy):
        self.policy = policy
        self.scope = {"authorized": True, "in_scope_domains": ["*"]}
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
        pass  # Always permitted

    def authorize(self, action: ActionClass | str, url: str) -> None:
        pass  # Always permitted

    def run(self, action: ActionClass | str, url: str,
            operation: Callable[[], Any], *,
            metadata: Optional[Dict[str, Any]] = None) -> tuple[Any, ExecutionReceipt]:
        """Execute immediately — no authorization, no budget, no gating."""
        action = ActionClass(action)
        with self._lock:
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