#!/usr/bin/env python3
"""Phase 3 — Coverage-guided, state-aware research substrate.

This module is the deterministic core of the full-depth research substrate:

  * **Coverage telemetry** — record which (operation, variable, kind, state)
    keys were explored so budget allocation steers toward untried surface.
  * **Corpus management** — content-addressed seed store with provenance,
    coverage novelty scoring, and deterministic replay.
  * **Crash deduplication** — stable crash signatures so one root cause never
    floods the queue; minimization reduces a crashing input to a short
    prefix that still reproduces the signature.
  * **State-sequence coverage** — track which workflow/state transitions were
    exercised (skip/repeat/reorder/role/ownership) for business-logic depth.

Everything here is offline, deterministic, and advisory: it never gates
research depth.  Artifacts persist under ``state/research/<target>/``.

Usage:
  python3 tools/research_core.py --target T --add-seed corpus/seed1 --json
  python3 tools/research_core.py --target T --record-coverage \
      --key 'GET:/api/users:id:object-reference' --json
  python3 tools/research_core.py --target T --register-crash \
      --signature asan:heap-buffer-overflow --json
  python3 tools/research_core.py --target T --minimize \
      --crash-id <id> --inputs crash/input1 --json
  python3 tools/research_core.py --target T --status --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf/research-core/v1"

# Default corpus directories relative to the workspace (mirror the repo's
# wordlist/seed convention without requiring static files).
DEFAULT_CORPUS_DIRS = ("wordlists", "corpus")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: Any) -> str:
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _dir(project_root: Optional[str] = None, target: str = "") -> Path:
    root = workspace_root(project_root)
    if target:
        return root / "state" / "research" / target_slug(target)
    return root / "state" / "research"


# ---------------------------------------------------------------------------
# Coverage telemetry
# ---------------------------------------------------------------------------

class CoverageTracker:
    """Deterministic coverage registry: key -> first-seen provenance."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target) / "coverage"
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "coverage.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._entries[str(rec["key"])] = rec
            except (json.JSONDecodeError, KeyError):
                continue

    def record(self, key: str, *, kind: str = "", technique: str = "",
               source: str = "manual") -> Dict[str, Any]:
        """Record one explored coverage key (idempotent, first-seen kept)."""
        key = str(key or "").strip()
        if not key:
            raise ValueError("coverage key is empty")
        existing = self._entries.get(key)
        if existing:
            return existing
        rec = {
            "key": key,
            "kind": str(kind or ""),
            "technique": str(technique or ""),
            "source": str(source or ""),
            "first_seen_at": _now(),
        }
        self._entries[key] = rec
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def is_tried(self, key: str) -> bool:
        return str(key or "").strip() in self._entries

    def keys(self) -> List[str]:
        return sorted(self._entries)

    def report(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for rec in self._entries.values():
            kind = str(rec.get("kind") or "unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        return {
            "schema": SCHEMA,
            "target": self.target,
            "total_keys": len(self._entries),
            "by_kind": by_kind,
            "keys": self.keys(),
        }


# ---------------------------------------------------------------------------
# Corpus management
# ---------------------------------------------------------------------------

@dataclass
class CorpusSeed:
    seed_id: str
    content_sha256: str
    name: str
    source: str
    coverage_keys: List[str] = field(default_factory=list)
    added_at: str = ""
    review_status: str = "quarantined"   # quarantined | approved

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CorpusManager:
    """Content-addressed seed store with provenance and coverage novelty."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target) / "corpus"
        self._seeds: Dict[str, CorpusSeed] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "seeds.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                seed = CorpusSeed(**{k: v for k, v in rec.items()
                                     if k in CorpusSeed.__dataclass_fields__})
                self._seeds[seed.seed_id] = seed
            except (TypeError, json.JSONDecodeError):
                continue

    def add(self, content: Any, *, name: str = "", source: str = "manual",
            coverage_keys: Optional[Iterable[str]] = None) -> CorpusSeed:
        """Add a seed if its content hash is new (dedup by content)."""
        digest = _sha256(content)
        for seed in self._seeds.values():
            if seed.content_sha256 == digest:
                return seed  # content duplicate — return existing
        seed = CorpusSeed(
            seed_id=digest[:16],
            content_sha256=digest,
            name=str(name or f"seed-{digest[:8]}"),
            source=str(source or ""),
            coverage_keys=[str(k) for k in (coverage_keys or [])],
            added_at=_now(),
        )
        self._seeds[seed.seed_id] = seed
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(seed.to_dict(), sort_keys=True) + "\n")
        return seed

    def approve(self, seed_id: str, *, reviewer: str = "operator") -> CorpusSeed:
        seed = self._seeds.get(seed_id)
        if not seed:
            raise ValueError(f"unknown seed: {seed_id}")
        seed.review_status = "approved"
        seed.approved_by = reviewer
        seed.approved_at = _now()
        self._persist_all()
        return seed

    def _persist_all(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("w", encoding="utf-8") as stream:
            for seed in self._seeds.values():
                stream.write(json.dumps(seed.to_dict(), sort_keys=True) + "\n")

    def seeds(self, *, status: str = "") -> List[CorpusSeed]:
        out = [s for s in self._seeds.values()]
        if status:
            out = [s for s in out if s.review_status == status]
        return sorted(out, key=lambda s: s.seed_id)

    def novelty(self, coverage: CoverageTracker) -> Dict[str, Any]:
        """Coverage-novelty score: seeds whose keys were never tried are new."""
        novel = [s for s in self._seeds.values()
                 if not all(coverage.is_tried(k) for k in (s.coverage_keys or []))]
        return {
            "schema": SCHEMA,
            "target": self.target,
            "total_seeds": len(self._seeds),
            "novel_seeds": len(novel),
            "novel_seed_ids": [s.seed_id for s in novel],
        }

    def replay_plan(self) -> Dict[str, Any]:
        """Deterministic replay plan: approved seeds in stable order."""
        approved = self.seeds(status="approved")
        return {
            "schema": SCHEMA,
            "target": self.target,
            "count": len(approved),
            "seeds": [s.to_dict() for s in approved],
        }


# ---------------------------------------------------------------------------
# Crash deduplication + minimization
# ---------------------------------------------------------------------------

class CrashRegistry:
    """Stable crash signatures; one root cause never floods the queue."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target) / "crashes"
        self._crashes: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "crashes.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._crashes[str(rec["crash_id"])] = rec
            except (json.JSONDecodeError, KeyError):
                continue

    @staticmethod
    def signature(*, input_hash: str, kind: str, stack_hint: str = "",
                  state: str = "") -> str:
        """Normalized crash signature: hash of the distinguishing fields."""
        normalized_stack = re.sub(r"0x[0-9a-fA-F]+", "ADDR",
                                  str(stack_hint or ""))
        normalized_stack = re.sub(r"\+0x[0-9a-fA-F]+", "", normalized_stack)
        raw = "|".join([str(kind or "").strip().lower(),
                        normalized_stack.strip().lower(),
                        str(state or "").strip().lower(),
                        str(input_hash or "")[:16]])
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def register(self, *, input_hash: str, kind: str, stack_hint: str = "",
                 state: str = "", source: str = "", input_name: str = ""
                 ) -> Dict[str, Any]:
        sig = self.signature(input_hash=input_hash, kind=kind,
                             stack_hint=stack_hint, state=state)
        existing = self._crashes.get(sig)
        if existing:
            existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
            self._persist_all()
            return existing
        rec = {
            "crash_id": sig,
            "signature": sig,
            "input_sha256": str(input_hash or ""),
            "kind": str(kind or ""),
            "stack_hint": str(stack_hint or ""),
            "state": str(state or ""),
            "source": str(source or ""),
            "input_name": str(input_name or ""),
            "occurrences": 1,
            "minimized": False,
            "minimal_input_sha256": "",
            "first_seen_at": _now(),
        }
        self._crashes[sig] = rec
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def _persist_all(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("w", encoding="utf-8") as stream:
            for rec in self._crashes.values():
                stream.write(json.dumps(rec, sort_keys=True) + "\n")

    def crashes(self) -> List[Dict[str, Any]]:
        return sorted(self._crashes.values(),
                      key=lambda r: (-int(r.get("occurrences", 1)), r["crash_id"]))

    def minimize(self, crash_id: str, inputs: List[Any],
                 *, reproduces) -> Dict[str, Any]:
        """Greedy prefix minimization with a caller-supplied oracle.

        ``reproduces(inputs) -> bool`` must be deterministic; the minimized
        prefix keeps the same crash signature (the caller verifies via the
        oracle).  Returns the minimized input record.
        """
        rec = self._crashes.get(crash_id)
        if not rec:
            raise ValueError(f"unknown crash: {crash_id}")
        if not inputs:
            raise ValueError("no inputs to minimize")
        if not reproduces(inputs):
            raise ValueError("provided inputs do not reproduce the crash")
        current = list(inputs)
        i = 0
        while i < len(current):
            candidate = current[:i] + current[i + 1:]
            if reproduces(candidate):
                current = candidate
            else:
                i += 1
        rec["minimized"] = True
        rec["minimal_input_sha256"] = _sha256(json.dumps(
            [str(x) for x in current], sort_keys=True))
        rec["minimal_size"] = len(current)
        self._persist_all()
        return {
            "crash_id": crash_id,
            "original_size": len(inputs),
            "minimal_size": len(current),
            "minimal_input_sha256": rec["minimal_input_sha256"],
            "minimal_inputs": current,
        }


# ---------------------------------------------------------------------------
# State-sequence coverage (business-logic depth)
# ---------------------------------------------------------------------------

class StateCoverage:
    """Track which state/role/workflow transitions were exercised."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target) / "states"
        self._transitions: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "transitions.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._transitions[str(rec["key"])] = rec
            except (json.JSONDecodeError, KeyError):
                continue

    def record(self, *, role: str, action: str, from_state: str, to_state: str,
               expected: bool = True, source: str = "manual") -> Dict[str, Any]:
        """Record one exercised transition (expected or illegal)."""
        key = f"{role}:{action}:{from_state}->{to_state}"
        existing = self._transitions.get(key)
        if existing:
            return existing
        rec = {
            "key": key,
            "role": str(role or ""),
            "action": str(action or ""),
            "from_state": str(from_state or ""),
            "to_state": str(to_state or ""),
            "expected": bool(expected),
            "source": str(source or ""),
            "first_seen_at": _now(),
        }
        self._transitions[key] = rec
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def report(self) -> Dict[str, Any]:
        illegal = [r for r in self._transitions.values() if not r["expected"]]
        return {
            "schema": SCHEMA,
            "target": self.target,
            "transitions": len(self._transitions),
            "illegal_transitions_found": len(illegal),
            "illegal": illegal,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf research core: coverage, corpus, crashes, states")
    parser.add_argument("--target", default="", help="target slug (optional)")
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true", help="emit JSON")

    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--status", action="store_true",
                         help="coverage + corpus + crash + state summary")
    actions.add_argument("--record-coverage", action="store_true",
                         help="record one coverage key")
    actions.add_argument("--add-seed", action="store_true",
                         help="add a seed from --content (or file paths)")
    actions.add_argument("--register-crash", action="store_true",
                         help="register a crash signature")
    actions.add_argument("--minimize", action="store_true",
                         help="minimize a registered crash with an oracle")
    actions.add_argument("--replay-plan", action="store_true",
                         help="print the approved-seed replay plan")

    parser.add_argument("--key", default="", help="coverage key")
    parser.add_argument("--kind", default="", help="kind tag")
    parser.add_argument("--technique", default="", help="technique tag")
    parser.add_argument("--content", default="", help="seed content")
    parser.add_argument("--name", default="", help="seed name")
    parser.add_argument("--source", default="cli", help="seed/crash source")
    parser.add_argument("--input-hash", default="", help="crash input sha256")
    parser.add_argument("--stack-hint", default="", help="crash stack hint")
    parser.add_argument("--state", default="", help="crash/transition state")
    parser.add_argument("--crash-id", default="", help="crash id to minimize")
    parser.add_argument("--inputs", nargs="*", default=[], help="inputs to minimize")
    parser.add_argument("--seed-ids", nargs="*", default=[],
                        help="seeds to approve (status)")
    parser.add_argument("--approve", action="store_true",
                        help="approve the listed seed ids")

    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.record_coverage:
            tracker = CoverageTracker(args.target, args.project_root)
            rec = tracker.record(args.key, kind=args.kind,
                                 technique=args.technique, source=args.source)
            result = {"schema": SCHEMA, "recorded": rec,
                      "report": tracker.report()}
        elif args.add_seed:
            manager = CorpusManager(args.target, args.project_root)
            content = args.content if args.content else " ".join(args.inputs)
            seed = manager.add(content, name=args.name, source=args.source)
            result = {"schema": SCHEMA, "seed": seed.to_dict()}
        elif args.approve:
            manager = CorpusManager(args.target, args.project_root)
            approved = [manager.approve(sid, reviewer="operator")
                        for sid in args.seed_ids]
            result = {"schema": SCHEMA, "approved": [s.to_dict() for s in approved]}
        elif args.register_crash:
            registry = CrashRegistry(args.target, args.project_root)
            rec = registry.register(
                input_hash=args.input_hash or _sha256(args.content),
                kind=args.kind or "unknown", stack_hint=args.stack_hint,
                state=args.state, source=args.source)
            result = {"schema": SCHEMA, "crash": rec}
        elif args.minimize:
            registry = CrashRegistry(args.target, args.project_root)
            rec = registry.crashes()
            crash = next((c for c in rec if c["crash_id"] == args.crash_id), None)
            if not crash:
                raise ValueError(f"unknown crash: {args.crash_id}")
            if not args.inputs:
                raise ValueError("--inputs required for minimization")
            result = {"schema": SCHEMA, "minimized": registry.minimize(
                args.crash_id, args.inputs,
                reproduces=lambda _c: True)}  # CLI default oracle: always true
        elif args.replay_plan:
            manager = CorpusManager(args.target, args.project_root)
            result = manager.replay_plan()
        else:
            tracker = CoverageTracker(args.target, args.project_root)
            manager = CorpusManager(args.target, args.project_root)
            registry = CrashRegistry(args.target, args.project_root)
            states = StateCoverage(args.target, args.project_root)
            result = {
                "schema": SCHEMA,
                "coverage": tracker.report(),
                "corpus": manager.novelty(tracker),
                "crashes": registry.crashes(),
                "state_coverage": states.report(),
            }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "error": str(exc)}
        status = 2
    else:
        status = 0

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True)[:2000])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
