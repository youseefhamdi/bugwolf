#!/usr/bin/env python3
"""Closed-loop discovery scheduler for BugWolf's Web/API discovery core.

Turns a surface model + its mutations into an ordered, coverage-aware search
plan and - when a transport is supplied - runs mutations one at a time through
the oracle, records observations, and emits the deterministic next step for
every ambiguous result (the same one-variable discipline as the lead ledger).

The scheduler owns *ordering, coverage, and the observation loop*. It never
performs HTTP itself: a transport callable executes each mutation (already
authorized through the execution controller) and returns an oracle-validated
:class:`tools.observation.ObservationRecord`.

Usage:
  python3 tools/discovery_scheduler.py --target T --recon-dir recon/T --output-dir recon/T/discovery --budget 200 --min-focus medium --json
  python3 tools/discovery_scheduler.py --target T --recon-dir recon/T --art --json
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from tools.impact_focus import CriticalityRouter
    from tools.mutator import Mutator, Mutation, RiskClass
    from tools.observation import ObservationRecord, ObservationState
    from tools.surface_model import SurfaceModel, load_surface
except ImportError:  # direct script execution
    from impact_focus import CriticalityRouter
    from mutator import Mutator, Mutation, RiskClass
    from observation import ObservationRecord, ObservationState
    from surface_model import SurfaceModel, load_surface

try:
    from tools.core.medium_safety import open_text
except Exception:  # pragma: no cover - tools.* not always importable
    def open_text(path, mode="r", **kw):  # type: ignore[no-redef]
        return open(path, mode, encoding=kw.get("encoding", "utf-8"),
                     errors=kw.get("errors", "replace"))

try:
    from tools.leads import create_lead
except ImportError:
    create_lead = None

try:
    from tools.art_selector import (
        DEFAULT_FIXED_SIZE, art_allocate, adaptive_select, feature_vector,
        nearest_neighbor_score, PayloadSpace,
    )
except ImportError:  # pragma: no cover - direct script execution
    from art_selector import (
        DEFAULT_FIXED_SIZE, art_allocate, adaptive_select, feature_vector,
        nearest_neighbor_score, PayloadSpace,
    )

SCHEMA_VERSION = "bugwolf-discovery-v1"

# Mutation-kind ordering: divergence and state first (highest novel-bug yield),
# then structure, then injection payloads (covered separately by hunt.py).
KIND_PRIORITY = {
    "sibling_differential": 0,
    "header_trust": 1,
    "state": 2,
    "required_tamper": 3,
    "mass_assignment": 4,
    "boundary": 5,
    "pollution": 6,
    "injection": 7,
    "blind_sqli": 8,
}


class CoverageTracker:
    """Which semantic (operation x variable x kind) mutations have been tried.

    Coverage is value-independent so budget allocation steers toward untested
    *surfaces*, while value-level anti-repeat lives in the lead ledger.
    """

    def __init__(self) -> None:
        self.tried: set = set()
        self.observed: set = set()      # keys that produced a SIGNAL

    def mark_tried(self, key: str) -> None:
        self.tried.add(key)

    def mark_observed(self, key: str) -> None:
        self.observed.add(key)

    def is_tried(self, key: str) -> bool:
        return key in self.tried

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tried": sorted(self.tried),
            "observed": sorted(self.observed),
            "tried_count": len(self.tried),
            "observed_count": len(self.observed),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CoverageTracker":
        c = cls()
        c.tried = set(data.get("tried", []))
        c.observed = set(data.get("observed", []))
        return c


@dataclass
class FollowUpStep:
    """The deterministic next experiment for one ambiguous observation."""
    observation_id: str
    kind: str
    purpose: str
    requests: List[Dict[str, Any]]
    acceptance: List[str]


@dataclass
class RunSummary:
    run_id: str = ""
    target: str = ""
    mutations_run: int = 0
    signals: int = 0
    unknowns: int = 0
    refuted: int = 0
    errors: int = 0
    follow_ups: List[FollowUpStep] = field(default_factory=list)
    signal_records: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = ""

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


class DiscoveryScheduler:
    """Order mutations by impact focus + coverage and run the observation loop."""

    def __init__(self, target: str, *, mutator: Optional[Mutator] = None,
                 router: Optional[CriticalityRouter] = None,
                 art_fixed_size: int = DEFAULT_FIXED_SIZE):
        self.target = target
        self.mutator = mutator or Mutator()
        self.router = router or CriticalityRouter()
        # ART4SQLi FSCS candidate-set size (paper §IV-D suggests 10).
        self.art_fixed_size = max(0, art_fixed_size)

    # -- ranking ------------------------------------------------------------

    def _focus(self, model: SurfaceModel) -> Dict[str, Any]:
        surfaces = [{
            "id": op.operation_id,
            "endpoint": op.path,
            "method": op.method,
            "title": op.summary,
        } for op in model.operations]
        scored = self.router.route(surfaces)
        return {s.surface_id: s for s in scored}

    def rank(self, model: SurfaceModel,
             coverage: Optional[CoverageTracker] = None) -> List[Mutation]:
        """Generate and order mutations: focus tier, then untried, then kind."""
        coverage = coverage or CoverageTracker()
        focus = self._focus(model)
        focus_rank = CriticalityRouter.FOCUS_RANK
        mutations = self.mutator.mutations(model)

        def sort_key(m: Mutation) -> tuple:
            fs = focus.get(m.operation_id)
            tier_rank = focus_rank.get(fs.focus, 3) if fs else 3
            untried = 0 if not coverage.is_tried(m.key()) else 1
            kind_rank = KIND_PRIORITY.get(m.kind, 99)
            return (tier_rank, untried, kind_rank, m.path, m.variable)
        return sorted(mutations, key=sort_key)

    def allocate(self, model: SurfaceModel, coverage: CoverageTracker,
                 budget: int, *, art: bool = False) -> List[Mutation]:
        """Select the next budget-worth of mutations, preferring untried.

        When ``art`` is True the selection is built via
        :func:`tools.art_selector.art_allocate`, which implements the
        ART4SQLi method (Zhang et al., IEEE Trans. Reliability):
        payload-bearing mutations (injection/blind_sqli) are embedded into a
        TF-IDF token space and spread by the ``1/cosine`` distance, while
        non-payload mutations use the structural feature vector (kind, method,
        bug_class, risk, variable-bucket, path-bucket); the next budget is
        picked with FSCS farthest-nearest-candidate selection over a
        ``art_fixed_size``-sized candidate set. The legacy rank-then-prefix
        logic remains the default so existing callers and tests are unchanged.
        """
        budget = max(0, budget)
        ranked = self.rank(model, coverage)
        if not art or budget == 0:
            untried = [m for m in ranked if not coverage.is_tried(m.key())]
            if len(untried) >= budget:
                return untried[:budget]
            # Refill with already-tried mutations only when nothing untried remains.
            picked = list(untried)
            for m in ranked:
                if len(picked) >= budget:
                    break
                if coverage.is_tried(m.key()) and m not in picked:
                    picked.append(m)
            return picked[:budget]

        # ART4SQLi mode (see tools/art_selector.py for the method).
        untried = [m for m in ranked if not coverage.is_tried(m.key())]
        tried = [m for m in ranked if coverage.is_tried(m.key())]
        return art_allocate(untried, tried, budget,
                            fixed_size=self.art_fixed_size or None)

    # -- observation loop ---------------------------------------------------

    @staticmethod
    def follow_up_step(record: ObservationRecord) -> Optional[FollowUpStep]:
        fu = record.follow_up
        if record.state != ObservationState.UNKNOWN or fu is None:
            return None
        return FollowUpStep(
            observation_id=record.observation_id,
            kind=fu.kind.value,
            purpose=fu.purpose,
            requests=[asdict(r) for r in fu.requests],
            acceptance=list(fu.acceptance),
        )

    def run(self, mutations: List[Mutation],
            transport: Callable[[Mutation], ObservationRecord],
            coverage: CoverageTracker,
            on_signal: Optional[Callable[[Mutation, ObservationRecord], None]] = None,
            ) -> RunSummary:
        """Execute mutations through the transport and drive the oracle loop.

        The transport is responsible for authorization (execution controller)
        and for returning an oracle-validated record. This method records
        coverage, classifies the outcome, and - for UNKNOWN observations -
        captures the deterministic follow-up as the next step.
        """
        summary = RunSummary(target=self.target)
        for mutation in mutations:
            key = mutation.key()
            coverage.mark_tried(key)
            record = transport(mutation)
            summary.mutations_run += 1
            if record.state == ObservationState.SIGNAL:
                summary.signals += 1
                coverage.mark_observed(key)
                summary.signal_records.append({
                    "mutation": mutation.to_dict(),
                    "observation_id": record.observation_id,
                    "state": record.state.value,
                    "decisive_rule": record.decisive_rule,
                })
                if on_signal is not None:
                    on_signal(mutation, record)
            elif record.state == ObservationState.UNKNOWN:
                summary.unknowns += 1
                step = self.follow_up_step(record)
                if step is not None:
                    summary.follow_ups.append(step)
            elif record.state == ObservationState.REFUTED:
                summary.refuted += 1
            else:
                summary.errors += 1
        return summary

    def register_signal_lead(self, mutation: Mutation,
                             record: ObservationRecord) -> Optional[Dict[str, Any]]:
        """Turn a SIGNAL observation into a persistent lead (if leads available).

        The lead is created with the two-half framing (trigger/impact) so the
        existing lead ledger owns the one-variable mutation discipline and the
        chain pool. Safe when ``create_lead`` is unavailable (returns None).
        """
        if create_lead is None:
            return None
        try:
            lead = create_lead(
                self.target,
                f"{mutation.bug_class} signal on {mutation.method} {mutation.path}",
                q_trigger=(f"{mutation.method} {mutation.path} with "
                           f"{mutation.variable or mutation.kind} "
                           f"mutated to {mutation.mutated!r}"),
                q_impact=f"observation {record.observation_id} "
                         f"({record.decisive_rule}) - trace victim harm",
                payload=json.dumps(mutation.to_dict(), default=str),
            )
            return {"lead_id": lead.lead_id, "state": lead.state}
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": str(exc)[:300]}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_coverage(path: str) -> CoverageTracker:
    p = Path(path)
    if p.exists():
        try:
            return CoverageTracker.from_dict(json.loads(p.read_text()))
        except (json.JSONDecodeError, TypeError):
            pass
    return CoverageTracker()


def main() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="BugWolf Web/API discovery scheduler")
    parser.add_argument("--target", required=True)
    parser.add_argument("--openapi", help="OpenAPI/Swagger JSON file")
    parser.add_argument("--graphql", help="GraphQL introspection JSON file")
    parser.add_argument("--urls-file", help="Recon URL list")
    parser.add_argument("--surface-file", help="Previously saved surface model")
    parser.add_argument("--recon-dir", help="Auto-discover schemas from a recon output directory")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--output-dir", default="discovery",
                        help="Where to write plan/coverage/results")
    parser.add_argument("--budget", type=int, default=200,
                        help="Max mutations to emit/allocate")
    parser.add_argument("--min-focus", default="medium",
                        choices=["critical", "high", "medium", "low"],
                        help="Minimum impact-focus tier to emit")
    parser.add_argument("--art", action="store_true",
                        help="Use ART4SQLi Adaptive Random Testing selection "
                             "for the budget (payload TF-IDF + FSCS)")
    parser.add_argument("--art-fixed-size", type=int, default=DEFAULT_FIXED_SIZE,
                        help="ART4SQLi FSCS candidate-set size (paper suggests 10; "
                             "0 = max-min over all candidates)")
    parser.add_argument("--json", action="store_true",
                        help="Print structured JSON to stdout")
    args = parser.parse_args()

    try:
        if args.recon_dir:
            from tools.schema_extractor import build_surface
            model = build_surface(args.target, args.recon_dir)
        else:
            model = load_surface(target=args.target, openapi_file=args.openapi,
                                 graphql_file=args.graphql, urls_file=args.urls_file,
                                 surface_file=args.surface_file, base_url=args.base_url)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage = _load_coverage(str(out_dir / "coverage.json"))

    scheduler = DiscoveryScheduler(
        args.target, router=CriticalityRouter(min_focus=args.min_focus),
        art_fixed_size=args.art_fixed_size)
    ranked = scheduler.rank(model, coverage)
    allocation = scheduler.allocate(model, coverage, args.budget, art=args.art)

    (out_dir / "surface-model.json").write_text(model.to_json() + "\n")
    (out_dir / "coverage.json").write_text(json.dumps(coverage.to_dict(), indent=2) + "\n")
    with open_text(out_dir / "plan.jsonl", "w") as stream:
        for m in allocation:
            stream.write(json.dumps(m.to_dict(), default=str) + "\n")

    if args.art:
        payloads = [m.mutated for m in allocation
                    if isinstance(m.mutated, str) and m.mutated
                    and m.kind in ("injection", "blind_sqli")]
        space = PayloadSpace.fit(payloads) if payloads else None
        diversity = nearest_neighbor_score(allocation, space=space)
        with open_text(out_dir / "art-report.json", "w") as stream:
            json.dump({
                "schema": "bugwolf-art-report-v2",
                "budget": args.budget,
                "selection_size": len(allocation),
                "fixed_size": args.art_fixed_size or None,
                "diversity_score": diversity,
                "payload_vocab_size": space.dimension if space else 0,
                "payload_bearing_selected": len(payloads),
            }, stream, indent=2)
            stream.write("\n")

    if args.json:
        print(json.dumps({
            "schema": SCHEMA_VERSION,
            "target": args.target,
            "surface_fingerprint": model.fingerprint(),
            "operations": len(model.operations),
            "siblings": len(model.siblings),
            "transitions": len(model.transitions),
            "mutations_ranked": len(ranked),
            "mutations_allocated": len(allocation),
            "selection_mode": "art" if args.art else "rank",
            "coverage": coverage.to_dict(),
            "plan": [m.to_dict() for m in allocation],
        }, indent=2, default=str))
    else:
        print(f"[*] Discovery plan for {args.target}")
        print(f"    operations: {len(model.operations)}  "
              f"siblings: {len(model.siblings)}  transitions: {len(model.transitions)}")
        print(f"    mutations ranked: {len(ranked)}  allocated: {len(allocation)}  "
              f"mode: {'ART' if args.art else 'rank'}"
              + (f" (fixed-size {args.art_fixed_size})" if args.art else ""))
        print(f"    coverage: {coverage.to_dict()['tried_count']} tried / "
              f"{coverage.to_dict()['observed_count']} observed")
        for m in allocation[:20]:
            print(f"    [{m.risk.value}] {m.kind} {m.method} {m.path} "
                  f"{m.variable or ''}")
        print(f"    plan written to {out_dir / 'plan.jsonl'}")
        if args.art:
            print(f"    ART diversity report written to {out_dir / 'art-report.json'}")


if __name__ == "__main__":
    main()
