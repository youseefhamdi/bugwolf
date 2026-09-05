"""Email pattern inference.

Given a target domain, returns a small set of likely email shapes
(``first@``, ``first.last@``, ``f.last@``, ``firstl@``) so the operator
can validate them via HIBP / hunter.io / SMTP VRFY downstream.

No API key required.  Always returns a deterministic list.
"""

from __future__ import annotations

from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


_PREFIXES = ("admin", "root", "info", "security", "abuse", "noreply",
             "no-reply", "support", "contact", "press", "legal",
             "sales", "marketing", "dev", "test", "staging")


class EmailPatternsModule(PassiveModule):
    name = "email_patterns"
    kind = "email"
    requires_key = False
    env_var = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        now = self.now_iso()
        out: List[PassiveFinding] = []
        for prefix in _PREFIXES[: int(budget)]:
            out.append(PassiveFinding(
                kind="email",
                value=f"{prefix}@{target}",
                source=self.name,
                confidence=0.3,
                seen_at=now,
                extra={"pattern": "role_account"},
            ))
        out.append(PassiveFinding(
            kind="email",
            value=f"first@{target}",
            source=self.name,
            confidence=0.4,
            seen_at=now,
            extra={"pattern": "first_initial_only"},
        ))
        out.append(PassiveFinding(
            kind="email",
            value=f"first.last@{target}",
            source=self.name,
            confidence=0.4,
            seen_at=now,
            extra={"pattern": "first_dot_last"},
        ))
        return out


__all__ = ["EmailPatternsModule"]