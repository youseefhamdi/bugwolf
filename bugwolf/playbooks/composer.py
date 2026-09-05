"""Compose multiple typed playbooks into a single merged plan.

Phase 1.2 ``ComposedPlaybook`` aggregates the payloads and evidence of
several :class:`Playbook` instances and resolves their budget / governance
using a strictest-union policy:

* ``max_requests``           -> ``min``  (smallest budget wins)
* ``max_wall_clock``         -> ``min``
* ``min_interval_ms``        -> ``max``  (slowest throttle wins)
* ``requires_approval``      -> ``OR``   (any member requires -> composed requires)
* ``scope_class``            -> most restrictive (``destructive`` > ``active`` > ``passive``)
* ``destructive_allowed``    -> ``AND``  (every member must allow -> composed allows)
* ``require_reproducible_evidence`` -> ``AND``
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from bugwolf.playbooks.base import (
    BudgetSpec,
    EvidenceSpec,
    GovernanceSpec,
    PayloadSpec,
    Playbook,
    PlaybookLoader,
    PlaybookValidationError,
)


_SCOPE_CLASS_RANK = {"passive": 0, "active": 1, "destructive": 2}


@dataclass
class ComposedPlaybook:
    name: str
    playbooks: Tuple[str, ...]
    merged_payloads: Tuple[PayloadSpec, ...] = ()
    merged_evidence: Tuple[EvidenceSpec, ...] = ()
    total_budget: BudgetSpec = field(default_factory=BudgetSpec)
    governance: GovernanceSpec = field(default_factory=GovernanceSpec)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "playbooks": list(self.playbooks),
            "merged_payloads": [
                {
                    "id": p.id,
                    "request": dict(p.request),
                    "expected_status": p.expected_status,
                    "expected_body_match": p.expected_body_match,
                    "sinks": list(p.sinks),
                    "requires_scope_verb": p.requires_scope_verb,
                }
                for p in self.merged_payloads
            ],
            "merged_evidence": [
                {"type": e.kind, "target": e.target, "config": dict(e.config)}
                for e in self.merged_evidence
            ],
            "total_budget": {
                "max_requests": self.total_budget.max_requests,
                "max_wall_clock": self.total_budget.max_wall_clock,
                "min_interval_ms": self.total_budget.min_interval_ms,
            },
            "governance": {
                "requires_approval": self.governance.requires_approval,
                "scope_class": self.governance.scope_class,
                "require_reproducible_evidence": self.governance.require_reproducible_evidence,
                "destructive_allowed": self.governance.destructive_allowed,
                "notes": self.governance.notes,
            },
        }


class PlaybookComposer:
    """Loads and composes typed playbooks from a directory."""

    def __init__(self, playbook_dir: Path) -> None:
        self.playbook_dir = Path(playbook_dir)
        if not self.playbook_dir.is_dir():
            raise NotADirectoryError(self.playbook_dir)
        self._cache: Dict[str, Playbook] = {}
        self._loader = PlaybookLoader()

    def load(self, name: str) -> Playbook:
        if name in self._cache:
            return self._cache[name]
        for ext in (".yaml", ".yml"):
            candidate = self.playbook_dir / f"{name}{ext}"
            if candidate.is_file():
                pb = self._loader.load(candidate)
                self._cache[name] = pb
                return pb
        raise FileNotFoundError(
            f"playbook {name!r} not found in {self.playbook_dir}"
        )

    def _load_all_members(self, names: List[str]) -> List[Playbook]:
        resolved: List[Playbook] = []
        for n in names:
            resolved.append(self.load(n))
        return resolved

    @staticmethod
    def _merge_payloads(playbooks: List[Playbook], dedupe: bool) -> Tuple[PayloadSpec, ...]:
        merged: List[PayloadSpec] = []
        seen: set = set()
        for pb in playbooks:
            for p in pb.payloads:
                if dedupe:
                    key = (p.id, p.request.get("method"), p.request.get("path"))
                    if key in seen:
                        continue
                    seen.add(key)
                merged.append(p)
        return tuple(merged)

    @staticmethod
    def _merge_evidence(playbooks: List[Playbook]) -> Tuple[EvidenceSpec, ...]:
        merged: List[EvidenceSpec] = []
        seen: set = set()
        for pb in playbooks:
            for ev in pb.evidence:
                key = (ev.kind, ev.target)
                if key in seen:
                    continue
                seen.add(key)
                merged.append(ev)
        return tuple(merged)

    @staticmethod
    def _merge_budget(playbooks: List[Playbook]) -> BudgetSpec:
        if not playbooks:
            return BudgetSpec()
        max_req = min(pb.budget.max_requests for pb in playbooks)
        max_clock = min(pb.budget.max_wall_clock for pb in playbooks)
        min_int = max(pb.budget.min_interval_ms for pb in playbooks)
        return BudgetSpec(
            max_requests=max_req,
            max_wall_clock=max_clock,
            min_interval_ms=min_int,
        )

    @staticmethod
    def _merge_governance(playbooks: List[Playbook]) -> GovernanceSpec:
        if not playbooks:
            return GovernanceSpec()
        requires_approval = any(pb.governance.requires_approval for pb in playbooks)
        destructive_allowed = all(pb.governance.destructive_allowed for pb in playbooks)
        reproducible = all(pb.governance.require_reproducible_evidence for pb in playbooks)
        rank = max(_SCOPE_CLASS_RANK.get(pb.governance.scope_class, 1) for pb in playbooks)
        scope_class = {v: k for k, v in _SCOPE_CLASS_RANK.items()}[rank]
        notes_parts = [pb.governance.notes for pb in playbooks if pb.governance.notes]
        notes = " | ".join(notes_parts)
        return GovernanceSpec(
            requires_approval=requires_approval,
            scope_class=scope_class,
            require_reproducible_evidence=reproducible,
            destructive_allowed=destructive_allowed,
            notes=notes,
        )

    def compose(self, names: List[str], *, dedupe_payloads: bool = True) -> ComposedPlaybook:
        if not names:
            raise PlaybookValidationError("compose() requires at least one playbook name")
        playbooks = self._load_all_members(names)
        merged_payloads = self._merge_payloads(playbooks, dedupe_payloads)
        merged_evidence = self._merge_evidence(playbooks)
        total_budget = self._merge_budget(playbooks)
        governance = self._merge_governance(playbooks)
        composed_name = "+".join(names)
        return ComposedPlaybook(
            name=composed_name,
            playbooks=tuple(names),
            merged_payloads=merged_payloads,
            merged_evidence=merged_evidence,
            total_budget=total_budget,
            governance=governance,
        )

    def validate_compatibility(self, names: List[str]) -> List[str]:
        """Return a list of human-readable conflict messages.

        Empty list means the playbooks compose without conflict.
        """
        playbooks = self._load_all_members(names)
        return self.validate_compatibility_loaded(playbooks)

    @staticmethod
    def validate_compatibility_loaded(playbooks: List[Playbook]) -> List[str]:
        conflicts: List[str] = []

        scope_classes = {pb.governance.scope_class for pb in playbooks}
        if len(scope_classes) > 1:
            conflicts.append(
                f"conflicting scope_class values: {sorted(scope_classes)}"
            )

        # destructive_allowed: AND semantics, so a False anywhere is informative,
        # not a hard conflict; we still surface it so operators see the diff.
        destr_values = {pb.name: pb.governance.destructive_allowed for pb in playbooks}
        if len(set(destr_values.values())) > 1:
            conflicts.append(
                f"conflicting destructive_allowed values across playbooks: {destr_values}"
            )

        # Approval: OR semantics; only warn if one member requires and another
        # silently assumes no approval is needed.
        approvals = {pb.name: pb.governance.requires_approval for pb in playbooks}
        if any(approvals.values()) and not all(approvals.values()):
            conflicts.append(
                f"conflicting requires_approval values across playbooks: {approvals}"
            )

        # Budget: conflicting min_interval_ms when one playbook is supposed to
        # be faster than another. We only flag extreme divergence (>10x).
        if len(playbooks) >= 2:
            intervals = [pb.budget.min_interval_ms for pb in playbooks]
            lo, hi = min(intervals), max(intervals)
            if lo > 0 and hi / lo >= 10:
                conflicts.append(
                    f"min_interval_ms divergence: min={lo}, max={hi}"
                )

        return conflicts