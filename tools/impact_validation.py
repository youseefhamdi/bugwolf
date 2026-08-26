#!/usr/bin/env python3
"""Phase 2 — Candidate evidence-state machine + impact validation.

A candidate may only advance through the evidence states in order:

    hypothesis -> signal -> candidate -> reproduced
    -> impact_verified -> human_confirmed -> reportable

Exits: signal -> refuted | candidate -> blocked | duplicate |
       needs_more_evidence.

No candidate may jump directly from model output, static rule, HTTP status,
or CVE resemblance to ``reportable``.  The state machine is a *reporting*
discipline — it never gates or reduces research depth.

Impact validation layers (all deterministic, all advisory):

  * transport   — recorded request/response with matching status/block state
  * behavior    — the relevant behavior repeats; a control does not
  * authorization — canary record owned by control Account A is returned to
                    Account B (disposable fixtures only)
  * integrity   — before/after invariant hashes prove the state mutation
  * confidentiality — a unique canary value is returned

Artifacts persist under ``state/impact/<target>/``.

Usage:
  python3 tools/impact_validation.py --target T --advance \
      --candidate-id C --to impact_verified --json
  python3 tools/impact_validation.py --target T --status --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf/impact-validation/v1"

# Ordered evidence states; reportable requires every prior state.
EVIDENCE_STATES = (
    "hypothesis", "signal", "candidate", "reproduced",
    "impact_verified", "human_confirmed", "reportable",
)
TERMINAL_EXITS = ("refuted", "blocked", "duplicate", "needs_more_evidence")

IMPACT_LAYERS = ("transport", "behavior", "authorization", "integrity",
                 "confidentiality")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir(project_root: Optional[str] = None, target: str = "") -> Path:
    root = workspace_root(project_root)
    if target:
        return root / "state" / "impact" / target_slug(target)
    return root / "state" / "impact"


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:24]


class StateError(ValueError):
    """Raised on illegal state transitions (reporting discipline)."""


@dataclass
class ImpactEvidence:
    layer: str
    passed: bool
    detail: str = ""
    artifact_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CandidateRecord:
    candidate_id: str
    target: str
    bug_class: str = ""
    state: str = "hypothesis"
    created_at: str = ""
    updated_at: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)
    impact: List[ImpactEvidence] = field(default_factory=list)

    def __post_init__(self):
        now = _now()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.history:
            self.history = [{"state": "hypothesis", "at": self.created_at,
                             "reason": "registered"}]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "candidate_id": self.candidate_id,
            "target": self.target,
            "bug_class": self.bug_class,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "history": self.history,
            "impact": [e.to_dict() for e in self.impact],
        }


class CandidateStateMachine:
    """Ordered, audited evidence-state transitions for one target."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target)
        self._candidates: Dict[str, CandidateRecord] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "candidates.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                rec["impact"] = [ImpactEvidence(**e) for e in rec.get("impact", [])]
                cand = CandidateRecord(**{k: v for k, v in rec.items()
                                          if k in CandidateRecord.__dataclass_fields__})
                self._candidates[cand.candidate_id] = cand
            except (TypeError, json.JSONDecodeError, KeyError):
                continue

    def _persist_all(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("w", encoding="utf-8") as stream:
            for cand in self._candidates.values():
                stream.write(json.dumps(cand.to_dict(), sort_keys=True) + "\n")

    def register(self, candidate_id: str, *, bug_class: str = "") -> CandidateRecord:
        if candidate_id in self._candidates:
            return self._candidates[candidate_id]
        cand = CandidateRecord(candidate_id=candidate_id, target=self.target,
                               bug_class=str(bug_class or ""))
        self._candidates[candidate_id] = cand
        self._persist_all()
        return cand

    def _rank(self, state: str) -> int:
        if state in EVIDENCE_STATES:
            return EVIDENCE_STATES.index(state)
        return -1  # terminal exits

    def advance(self, candidate_id: str, to_state: str, *,
                reason: str = "") -> CandidateRecord:
        """Advance one candidate through the evidence states (audited)."""
        cand = self._candidates.get(candidate_id)
        if not cand:
            raise StateError(f"unknown candidate: {candidate_id}")
        if to_state not in EVIDENCE_STATES and to_state not in TERMINAL_EXITS:
            raise StateError(f"unknown target state: {to_state}")
        current_rank = self._rank(cand.state)
        target_rank = self._rank(to_state)
        if current_rank < 0:
            raise StateError(f"candidate {candidate_id} is terminal "
                             f"({cand.state}); cannot advance")
        if target_rank < 0:
            # Terminal exit: allowed from any non-terminal state.
            cand.state = to_state
        else:
            # Advance exactly one ordered step: no skips, no reversals.
            if target_rank != current_rank + 1:
                raise StateError(
                    f"illegal transition {cand.state} -> {to_state} "
                    f"(evidence states must advance in order, one at a time)")
            cand.state = to_state
        cand.updated_at = _now()
        cand.history.append({"state": to_state, "at": cand.updated_at,
                             "reason": str(reason or "")})
        self._persist_all()
        return cand

    def record_impact(self, candidate_id: str, *, layer: str, passed: bool,
                      detail: str = "", artifact: Any = None) -> CandidateRecord:
        """Record one impact-validation layer (does not advance state)."""
        cand = self._candidates.get(candidate_id)
        if not cand:
            raise StateError(f"unknown candidate: {candidate_id}")
        if layer not in IMPACT_LAYERS:
            raise StateError(f"unknown impact layer: {layer}")
        evidence = ImpactEvidence(
            layer=layer, passed=bool(passed),
            detail=str(detail or "")[:300],
            artifact_hash=_sha256(artifact) if artifact is not None else "")
        cand.impact = [e for e in cand.impact if e.layer != layer] + [evidence]
        cand.updated_at = _now()
        self._persist_all()
        return cand

    def impact_verdict(self, candidate_id: str) -> Dict[str, Any]:
        """All layers passed -> impact_verified is eligible."""
        cand = self._candidates.get(candidate_id)
        if not cand:
            raise StateError(f"unknown candidate: {candidate_id}")
        by_layer = {e.layer: e for e in cand.impact}
        missing = [layer for layer in IMPACT_LAYERS if layer not in by_layer]
        failed = [layer for layer, e in by_layer.items() if not e.passed]
        return {
            "candidate_id": candidate_id,
            "state": cand.state,
            "all_layers_passed": not missing and not failed,
            "missing_layers": missing,
            "failed_layers": failed,
        }

    def candidates(self) -> List[CandidateRecord]:
        return sorted(self._candidates.values(), key=lambda c: c.candidate_id)

    def report(self) -> Dict[str, Any]:
        by_state: Dict[str, int] = {}
        for cand in self._candidates.values():
            by_state[cand.state] = by_state.get(cand.state, 0) + 1
        return {
            "schema": SCHEMA,
            "target": self.target,
            "candidates": len(self._candidates),
            "by_state": by_state,
            "states": [c.to_dict() for c in self.candidates()],
        }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf impact validation + candidate state machine")
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--status", action="store_true")
    actions.add_argument("--advance", action="store_true")
    actions.add_argument("--register", action="store_true")
    actions.add_argument("--record-impact", action="store_true")
    parser.add_argument("--candidate-id", default="")
    parser.add_argument("--bug-class", default="")
    parser.add_argument("--to", default="")
    parser.add_argument("--reason", default="")
    parser.add_argument("--layer", default="",
                        choices=sorted(IMPACT_LAYERS))
    parser.add_argument("--passed", action="store_true")
    parser.add_argument("--detail", default="")
    args = parser.parse_args(list(argv) if argv is not None else None)

    machine = CandidateStateMachine(args.target, args.project_root)
    try:
        if args.status:
            result = machine.report()
        elif args.register:
            result = machine.register(args.candidate_id or "cand-1",
                                      bug_class=args.bug_class).to_dict()
        elif args.advance:
            result = machine.advance(args.candidate_id, args.to,
                                     reason=args.reason).to_dict()
        else:
            result = machine.record_impact(
                args.candidate_id, layer=args.layer, passed=args.passed,
                detail=args.detail).to_dict()
        status = 0
    except StateError as exc:
        result = {"schema": SCHEMA, "error": str(exc)}
        status = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True)[:2000])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
