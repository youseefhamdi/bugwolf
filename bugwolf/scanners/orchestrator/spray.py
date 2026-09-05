"""Credential-spray orchestrator.

Runs a single auth-style probe through a list of (username, password)
pairs and respects a :class:`BudgetGuard` ceiling on attempts.  The
orchestrator itself subclasses :class:`Scanner` so it can be embedded
inside :class:`HuntOrchestrator` chains.

Behaviour:

  * max_attempts default = 64 (well below BugWolf's 200-step floor)
  * respects BudgetGuard.consume(); when exhausted, the loop exits
  * emits one :class:`Finding` per accepted credential (status 200/302
    with a body containing a success marker)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding

from bugwolf.governance.budget import BudgetGuard


logger = logging.getLogger(__name__)


@dataclass
class _SprayBudget:
    """Slim adapter that mimics :class:`BudgetGuard`'s consume API."""

    max_attempts: int

    def consume(self) -> bool:
        if self.max_attempts <= 0:
            return False
        self.max_attempts -= 1
        return True


_DEFAULT_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "Admin123"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
)


class CredentialSpray(Scanner):
    """Credential-spray orchestrator with budget enforcement."""

    name = "credential-spray"
    bug_class = "credential-spray"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = tuple(
        f"{u}:{p}" for (u, p) in _DEFAULT_PAIRS
    )

    def __init__(
        self,
        pairs: Optional[List[Tuple[str, str]]] = None,
        *,
        max_attempts: int = 64,
    ) -> None:
        self._pairs = list(pairs) if pairs else list(_DEFAULT_PAIRS)
        if max_attempts <= 0:
            raise ValueError("max_attempts must be > 0")
        self._max_attempts = int(max_attempts)

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("credential-spray: transport is None; returning []")
            return []
        findings: List[Finding] = []
        budget = _SprayBudget(max_attempts=self._max_attempts)
        # optional external BudgetGuard compatibility (consume() only)
        if isinstance(transport, object) and hasattr(transport,
                                                     "budget") and isinstance(
            getattr(transport, "budget", None), BudgetGuard
        ):
            budget = transport.budget  # type: ignore[assignment]
        for user, pw in self._pairs:
            if not budget.consume():
                logger.warning(
                    "credential-spray: budget exhausted (%d attempts)",
                    self._max_attempts,
                )
                break
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={
                        "Content-Type":
                            "application/x-www-form-urlencoded",
                    },
                    body=f"username={user}&password={pw}",
                )
            except Exception as exc:
                logger.debug("spray: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            if resp.get("status") in (200, 302) and (
                "success" in rbody or "welcome" in rbody
                or "dashboard" in rbody
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=(f"credential {user}:{pw} appeared to "
                              "succeed"),
                    severity="critical",
                    detail={"username": user, "password": pw,
                            "status": resp.get("status"),
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["CredentialSpray"]