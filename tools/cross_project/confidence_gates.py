#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter confidence_gates.py:1-380 (1.5.g)
## Source: BugWolf core/confidence.py (Phase 0 in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

TENTATIVE -> FIRM -> CONFIRMED confidence gates.

A bug-bounty finding has three confidence levels; each gate requires
different evidence.  Findings may never be reported above their actual
level (no inflation), and they may be DOWNGRADED at any time (operator
override).

  TENTATIVE  —  single signal, no reproducer
  FIRM       —  reproducer captured (request/response pair, screenshot,
                curl one-liner)
  CONFIRMED  —  reproducer captured AND impact demonstrated (data
                exfiltration, auth bypass, etc.)

The :class:`ConfidenceGate` API:

  upgrade(evidence) -> ConfidenceLevel   — apply evidence, return new level
  downgrade(reason) -> ConfidenceLevel   — force-downgrade
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional


SCHEMA = "bugwolf-confidence-gate/v1"


class ConfidenceLevel(str, Enum):
    """The three confidence levels, low -> high."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        return {"tentative": 1, "firm": 2, "confirmed": 3}[self.value]


# Evidence field requirements per level.
_REQUIRED_FIELDS = {
    ConfidenceLevel.TENTATIVE: ("signal",),
    ConfidenceLevel.FIRM: ("signal", "reproducer"),
    ConfidenceLevel.CONFIRMED: ("signal", "reproducer", "impact"),
}


@dataclass(frozen=True)
class Evidence:
    """Bundle of evidence captured for a finding.

    * ``signal``      — the original detection (str)
    * ``reproducer``  — a request/response pair, a curl one-liner, etc.
    * ``impact``      — description of what the attacker gains
    """

    signal: str = ""
    reproducer: str = ""
    impact: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Evidence":
        return cls(
            signal=str(data.get("signal") or ""),
            reproducer=str(data.get("reproducer") or ""),
            impact=str(data.get("impact") or ""),
            extras=dict(data.get("extras") or {}),
        )

    def has(self, field_name: str) -> bool:
        return bool(getattr(self, field_name, ""))


@dataclass(frozen=True)
class GateDecision:
    """Result of a single :meth:`ConfidenceGate.upgrade` call."""

    level: ConfidenceLevel
    reason: str
    missing: tuple = ()
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "level": self.level.value,
            "reason": self.reason,
            "missing": list(self.missing),
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }


class ConfidenceGate:
    """Apply evidence -> confidence level transitions."""

    SCHEMA = SCHEMA

    def __init__(self, *, initial: ConfidenceLevel = ConfidenceLevel.TENTATIVE) -> None:
        self._level = initial

    @property
    def level(self) -> ConfidenceLevel:
        return self._level

    def upgrade(self, evidence: Mapping[str, Any] | Evidence) -> GateDecision:
        """Apply ``evidence`` and return the highest level that the
        evidence supports.

        The gate's internal level climbs to match the highest fully-
        supported level whenever new evidence arrives — but never
        *inflates* beyond what the supplied fields actually warrant
        (e.g. adding a ``signal`` to a TENTATIVE gate keeps it
        TENTATIVE; adding ``signal`` + ``reproducer`` promotes to FIRM).
        """
        if not isinstance(evidence, Evidence):
            evidence = Evidence.from_dict(evidence)
        # Determine the highest fully-supported level by the evidence alone.
        supported = ConfidenceLevel.TENTATIVE
        for lvl in (ConfidenceLevel.TENTATIVE,
                    ConfidenceLevel.FIRM,
                    ConfidenceLevel.CONFIRMED):
            if all(evidence.has(f) for f in _REQUIRED_FIELDS[lvl]):
                supported = lvl
        # The gate climbs to match supported (never above).  This is the
        # monotonic-climb rule: each new evidence either keeps or raises
        # the gate, never lowers it within a session (downgrade() is the
        # operator-only escape).
        if supported.rank > self._level.rank:
            self._level = supported
        new_level = self._level
        missing = tuple(
            f for f in _REQUIRED_FIELDS[new_level] if not evidence.has(f))
        decision = GateDecision(
            level=new_level,
            reason="upgrade" if new_level.rank > ConfidenceLevel.TENTATIVE.rank else "no-change",
            missing=missing,
            evidence=evidence,
        )
        return decision

    def downgrade(self, reason: str = "operator-override") -> GateDecision:
        """Force-downgrade the gate to TENTATIVE.

        Operator-driven only; never automatic.
        """
        prior = self._level
        self._level = ConfidenceLevel.TENTATIVE
        return GateDecision(
            level=self._level,
            reason=f"downgrade:{reason} (was {prior.value})",
            missing=(),
            evidence=None,
        )


__all__ = [
    "SCHEMA", "ConfidenceLevel", "Evidence", "GateDecision", "ConfidenceGate",
]