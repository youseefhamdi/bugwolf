## Source: BugWolf Phase 3.5 (in-house) — cross_target chains
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.cross_target — multi-target chain builder.

A :class:`CrossTargetChain` starts at a *primary* target and pivots
into one or more *lateral* targets (subdomains, sibling hosts,
cloud services, mobile API backends, CI runners, internal Jenkins,
etc.). This module is STUB-SAFE — it never raises.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from bugwolf.chain.builder import (
    ChainStep,
    CrossTargetChain,
    SCHEMA,
    Unavailable,
)


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------

class CrossTargetChainBuilder:
    """Build chains that pivot from a primary target to lateral ones."""

    def __init__(self, primary_target: str = ""):
        self.primary_target = str(primary_target or "")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_cross_target_chain(self, *,
                                 primary_target: str,
                                 lateral_targets: Sequence[str],
                                 severity_hint: str = "critical",
                                 bounty_hint: str = "",
                                 references: Sequence[str] = (),
                                 ) -> Union[CrossTargetChain, Unavailable]:
        """Build a cross-target chain.

        Args:
            primary_target: the entry host (e.g. ``"app.example.com"``).
            lateral_targets: hosts to pivot into. May be empty (in
                which case the chain is still valid but contains only
                the primary target).
            severity_hint: maximum severity hint. Used as a ceiling for
                the final severity.
            bounty_hint: optional human-readable bounty range. If not
                supplied, the builder computes one from severity.
            references: optional list of disclosed-report references.
        """
        if not isinstance(primary_target, str) or not primary_target.strip():
            return Unavailable(
                reason="primary_target must be a non-empty string",
                code="invalid_primary",
            )
        if not isinstance(lateral_targets, (list, tuple)):
            return Unavailable(
                reason="lateral_targets must be a list/tuple of strings",
                code="invalid_lateral",
            )
        cleaned_lat: List[str] = []
        for lt in lateral_targets:
            if not isinstance(lt, str):
                continue
            if not lt.strip():
                continue
            if lt == primary_target:
                continue
            cleaned_lat.append(lt.strip())
        # De-duplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for lt in cleaned_lat:
            if lt not in seen:
                seen.add(lt)
                deduped.append(lt)
        laterals = tuple(deduped)

        steps = self._build_steps(primary_target.strip(), laterals)
        severity = self._estimate_severity(severity_hint, len(laterals))
        bounty = bounty_hint or self._estimate_bounty(severity, len(laterals))
        confidence = self._estimate_confidence(len(laterals), steps)
        chain_id = f"xtarget-{hashlib.sha256((primary_target + '|' + '|'.join(laterals)).encode('utf-8')).hexdigest()[:12]}"

        return CrossTargetChain(
            chain_id=chain_id,
            primary_target=primary_target.strip(),
            lateral_targets=laterals,
            steps=steps,
            total_severity=severity,
            estimated_bounty_range=bounty,
            confidence=confidence,
            rationale=self._rationale(primary_target.strip(), laterals),
            references=tuple(references),
        )

    def with_laterals(self, chain: CrossTargetChain,
                      new_laterals: Sequence[str]) -> Union[CrossTargetChain, Unavailable]:
        """Return a new chain with additional lateral targets appended."""
        if not isinstance(chain, CrossTargetChain):
            return Unavailable(reason="chain is not a CrossTargetChain", code="bad_type")
        merged = list(chain.lateral_targets) + list(new_laterals or ())
        return self.build_cross_target_chain(
            primary_target=chain.primary_target,
            lateral_targets=merged,
            severity_hint=chain.total_severity,
            bounty_hint=chain.estimated_bounty_range,
            references=list(chain.references),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_steps(self, primary: str,
                     laterals: Tuple[str, ...]) -> Tuple[ChainStep, ...]:
        steps: List[ChainStep] = [
            ChainStep(
                order=1,
                description=f"Confirm foothold on primary target {primary}",
                protocol="http",
                technique="foothold_confirm",
                destructive=False,
                evidence={"kind": "endpoint", "host": primary},
            ),
        ]
        for i, lateral in enumerate(laterals, start=2):
            steps.append(ChainStep(
                order=i,
                description=f"Pivot from {primary} into lateral {lateral}",
                protocol="http",
                technique="lateral_pivot",
                destructive=False,
                evidence={"kind": "endpoint", "host": lateral},
            ))
        # Closing step
        steps.append(ChainStep(
            order=len(steps) + 1,
            description="Aggregate blast radius across all reached targets",
            protocol="internal",
            technique="blast_radius_aggregate",
            destructive=False,
            evidence={"kind": "metric", "fields": ["hosts", "endpoints"]},
        ))
        return tuple(steps)

    def _estimate_severity(self, hint: str, lateral_count: int) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        h = order.get(str(hint).lower(), 4)
        # Laterals bump severity ceiling
        if lateral_count >= 3 and h < 4:
            h = 4
        elif lateral_count >= 1 and h < 3:
            h = max(h, 3)
        for label, idx in order.items():
            if idx == h:
                return label
        return "critical"

    def _estimate_bounty(self, severity: str, lateral_count: int) -> str:
        base = {
            "info": "$0",
            "low": "$500",
            "medium": "$1,500",
            "high": "$5,000",
            "critical": "$10,000",
        }.get(severity, "$5,000")
        if lateral_count >= 3:
            return f"{base} – $30,000"
        if lateral_count >= 1:
            return f"{base} – $20,000"
        return base

    def _estimate_confidence(self, lateral_count: int,
                            steps: Sequence[ChainStep]) -> float:
        # More laterals = more chance something is missing/fails.
        base = 0.6
        penalty = min(0.15, 0.05 * max(0, lateral_count - 1))
        if not steps:
            base -= 0.1
        return round(max(0.1, min(0.95, base - penalty)), 4)

    def _rationale(self, primary: str, laterals: Tuple[str, ...]) -> str:
        if not laterals:
            return f"Single-target chain anchored on {primary}."
        if len(laterals) == 1:
            return f"Pivot from {primary} into lateral host {laterals[0]}."
        return (
            f"Multi-target chain: {primary} pivots into "
            f"{len(laterals)} lateral hosts "
            f"({', '.join(laterals[:3])}{'…' if len(laterals) > 3 else ''})."
        )


__all__ = [
    "SCHEMA",
    "CrossTargetChainBuilder",
]
