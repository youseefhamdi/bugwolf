#!/usr/bin/env python3
"""Chain prediction from the Target Model (master plan §8.3, v1.19).

CyberStrike's chain engines correlate *findings*: something was found, then
something else, and a graph says they combine.  BugWolf's U7×U8 prediction
runs **before any probing**: a capability the target grants (U7 — what an
identity can do) crossed with a fragile assumption (U8 — what must hold for
that capability to be safe) predicts where a chain *will* exist.  Each
prediction names:

  * the class to dispatch (which lane owns the first hop),
  * the capability (role × object × impact) that becomes the impact story,
  * the assumption whose dispro plan is the first probe to fire,
  * the terminal escalation path (via ``deep_chain.EDGES``) the chain aims at,
  * a priority score ranked dollars → privilege → PII/ATO → business, with
    fragile assumptions and terminal reach pushing up.

Predictions become **high-priority dispatches**: the team engine staffs the
owning specialists pre-hunt, and the mission runner orders predicted
families first.  Deterministic tier — pure reads over stored artifacts, no
model ⇒ no predictions, and every consumer degrades to its pre-v1.19
behavior byte-for-byte.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.runtime.understanding.base import ModelStore

SCHEMA = "bugwolf-predicted-chains/v1"

# Priority weight of a capability's business impact (dollars first — the
# thesis: money paths are where criticals live).
_IMPACT_RANK = {"dollars": 4, "privilege": 3, "PII/ATO": 2, "ATO": 2,
                "business": 1}

# Which bug class OWNS the first hop for assumptions born at each stage —
# the dispatch vocabulary (COVERAGE_CLASSES), not the deep_chain graph's.
_CLASS_FROM_STAGE = {
    "U3": "business-logic",
    "U4": "authz-bypass",
    "U5": "mass-assignment",
    "U7": "authz-bypass",
}

# Only these stages' assumptions form prediction pairs: they state something
# testable about application logic, authority, or data handling (U1/U2/U6
# assumptions are observational context, not first-probe material).
ASSUMPTION_POOL_STAGES = ("U3", "U4", "U5", "U7")

# The agent registry indexes specialist ownership under its own (underscore)
# vocabulary; predicted classes resolve to the specialist that owns them
# through this map — staffing never guesses.
REGISTRY_CLASS = {
    "idor": "idor",
    "authz-bypass": "auth_bypass",
    "mass-assignment": "mass_assignment",
    "business-logic": "business_logic",
}


def registry_bug_class(bug_class: str) -> str:
    """Predicted class → the registry's ownership vocabulary."""
    return REGISTRY_CLASS.get(str(bug_class or "").strip().lower(),
                              str(bug_class or "").strip().lower())

_MAX_CAPABILITIES = 50
_MAX_PREDICTIONS = 20


@dataclass
class PredictedChain:
    """One predicted chain — a dispatch, not a finding."""

    bug_class: str
    capability: Dict[str, Any]
    assumption: Dict[str, Any]
    fragility: float
    priority: float
    terminal: bool = False
    chain: List[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "bug_class": self.bug_class,
            "capability": self.capability, "assumption": self.assumption,
            "fragility": self.fragility, "priority": self.priority,
            "terminal": self.terminal, "chain": list(self.chain),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PredictedChain":
        return cls(
            bug_class=str(d.get("bug_class", "")),
            capability=dict(d.get("capability") or {}),
            assumption=dict(d.get("assumption") or {}),
            fragility=float(d.get("fragility", 0.0)),
            priority=float(d.get("priority", 0.0)),
            terminal=bool(d.get("terminal", False)),
            chain=[str(c) for c in (d.get("chain") or [])],
            reason=str(d.get("reason", "")),
        )


class ChainPredictor:
    """U7 × U8 → ranked predicted chains (deterministic, no model ⇒ [])."""

    def __init__(self, store: ModelStore):
        self.store = store

    # -- prediction ----------------------------------------------------------

    def predict(self) -> Tuple[List[PredictedChain], List[str]]:
        """(predictions ranked by priority, brief lines) — both empty
        without a model, so no-model consumers are exact no-ops."""
        u7 = self.store.load("U7")
        if u7 is None:
            return [], []
        capabilities = [c for c in (u7.data or {}).get("capabilities", [])
                        if isinstance(c, dict)][: _MAX_CAPABILITIES]
        if not capabilities:
            return [], []

        # The ledger (U8) is the pair pool; fall back to per-stage artifacts
        # when U8 has not run yet (prediction stays available pre-synthesis).
        raw_assumptions = self._assumption_pool()
        if not raw_assumptions:
            return [], []

        predictions: List[PredictedChain] = []
        seen: set = set()
        for capability in capabilities:
            obj = str(capability.get("object", "")).strip().lower()
            if not obj:
                continue
            impact = str(capability.get("impact", "business"))
            impact_rank = _IMPACT_RANK.get(impact, 1)
            for assumption in raw_assumptions:
                if assumption.get("status") != "open":
                    continue
                statement = str(assumption.get("statement", "")).lower()
                # The pairing rule: the assumption must be ABOUT the
                # capability's object (its protection is what the capability
                # stresses).  Substring match over the object term.
                if obj not in statement:
                    continue
                try:
                    confidence = float(assumption.get("confidence", 0.4))
                except (TypeError, ValueError):
                    confidence = 0.4
                if not (0.05 <= confidence <= 0.9):
                    # Near-certain assumptions are not leads; zero-confidence
                    # ones are noise.  Fragility lives in the middle.
                    continue
                fragility = round(1.0 - confidence, 2)
                bug_class = _CLASS_FROM_STAGE.get(
                    str(assumption.get("stage", "")), "")
                if not bug_class:
                    continue
                key = (bug_class, capability.get("path", ""),
                       assumption.get("assumption_id", ""))
                if key in seen:
                    continue
                seen.add(key)

                terminal, chain = self._escalation_path(bug_class)
                priority = round(impact_rank + (2.0 - fragility)
                                 + (2.0 if terminal else 0.0), 2)
                predictions.append(PredictedChain(
                    bug_class=bug_class,
                    capability=capability,
                    assumption=assumption,
                    fragility=fragility,
                    priority=priority,
                    terminal=terminal,
                    chain=chain,
                    reason=(
                        f"{capability.get('role_label', '?')} can "
                        f"{capability.get('verb', 'modify')} "
                        f"'{capability.get('object', '?')}' "
                        f"({impact}) at {capability.get('path', '?')} while "
                        f"[{assumption.get('stage', '?')}] holds: "
                        f"\"{assumption.get('statement', '')}\" "
                        f"(fragility {fragility})"
                    ),
                ))
                if len(predictions) >= _MAX_PREDICTIONS:
                    break
            if len(predictions) >= _MAX_PREDICTIONS:
                break

        predictions.sort(key=lambda p: (-p.priority, p.bug_class,
                                        p.capability.get("path", "")))
        return predictions, self._brief_lines(predictions)

    # -- pieces ----------------------------------------------------------------

    def _assumption_pool(self) -> List[Dict[str, Any]]:
        """The pair pool: the U8 seed list itself (assumptions.jsonl is the
        plan's zero-day seed list — it round-trips every field prediction
        needs and honors operator annotations like status flips), falling
        back to per-stage artifacts when U8 has not run yet."""
        u8 = self.store.load("U8")
        if u8 is not None:
            return [a.to_dict() for a in u8.assumptions]
        pool: List[Dict[str, Any]] = []
        for stage in ASSUMPTION_POOL_STAGES:
            artifact = self.store.load(stage)
            if artifact is not None:
                pool.extend(a.to_dict() for a in artifact.assumptions)
        return [a for a in pool
                if str(a.get("stage", "")) in ASSUMPTION_POOL_STAGES]

    @staticmethod
    def _escalation_path(bug_class: str) -> Tuple[bool, List[str]]:
        """Chain head → nearest terminal class via deep_chain's graph.

        Import is deferred so the U-layer never hard-depends on deep_chain
        (and prediction still works if the graph moves).  No path ⇒ the
        prediction chains to itself only.
        """
        try:
            from tools.deep_chain import EDGES, TERMINAL
        except Exception:  # noqa: BLE001 - graph loss never blocks prediction
            return False, [bug_class]
        if bug_class in TERMINAL:
            return True, [bug_class]
        # BFS for the shortest path to any terminal class.
        frontier: List[List[str]] = [[bug_class]]
        visited = {bug_class}
        while frontier:
            path = frontier.pop(0)
            node = path[-1]
            for nxt in EDGES.get(node, []):
                if nxt in visited:
                    continue
                new_path = path + [nxt]
                if nxt in TERMINAL:
                    return True, new_path
                visited.add(nxt)
                frontier.append(new_path)
        return False, [bug_class]

    # -- persistence -------------------------------------------------------------

    def save(self, predictions: List[PredictedChain]) -> Path:
        path = self.store.dir / "predicted-chains.json"
        payload = {
            "schema": SCHEMA,
            "target": self.store.target,
            "predictions": [p.to_dict() for p in predictions],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def load(self) -> List[PredictedChain]:
        path = self.store.dir / "predicted-chains.json"
        if not path.is_file():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if payload.get("schema") != SCHEMA:
            return []
        return [PredictedChain.from_dict(d)
                for d in (payload.get("predictions") or [])
                if isinstance(d, dict)]

    # -- rendering -----------------------------------------------------------------

    @staticmethod
    def _brief_lines(predictions: List[PredictedChain]) -> List[str]:
        if not predictions:
            return []
        lines = ["", "## Predicted chains (U7 × U8 — dispatch first)", ""]
        for position, prediction in enumerate(predictions[:10], start=1):
            lines.append(
                f"{position}. **{prediction.bug_class}** → "
                f"{' → '.join(prediction.chain)} "
                f"[priority {prediction.priority}, fragility "
                f"{prediction.fragility}]"
            )
            lines.append(f"   {prediction.reason}")
            dispro = str(prediction.assumption.get("dispro_plan", ""))
            if dispro:
                lines.append(f"   First probe: {dispro}")
        lines.append("")
        lines.append("_Predicted ≠ confirmed: these are ranked dispatches; "
                     "the chain exists when the terminal impact is "
                     "EXECUTION-CONFIRMED._")
        return lines
