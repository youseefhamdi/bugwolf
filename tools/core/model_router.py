#!/usr/bin/env python3
"""BugWolf Intelligent Model Router (U5).

Routes each research task to the cheapest model tier that can do it well:

  * ``deterministic`` — no model needed (wordlist generation, payload
    rendering, artifact verification, fingerprint parsing, plan generation).
  * ``local_slm`` — bounded probing/fuzzing decisions where a small local
    model suffices.
  * ``frontier`` — open-ended reasoning (chain synthesis, adversarial
    refutation, exploit construction, novel-hypothesis generation) where a
    Frontier model earns its cost.

BugWolf never calls a model itself — the harness (Claude Code / Freebuff /
Codex) executes research units.  This router therefore emits an *advisory*
``model_preference`` hint into the unit context; the harness decides which
model to run.  Routing is deterministic, and it can never gate execution:
an unavailable Frontier model degrades to ``local_slm`` (the unit still
runs), mirroring the search-provider fallback chain.

Usage:
  from tools.core.model_router import route, route_unit, attach_hint
  decision = route_unit(unit)          # unit from build_research_unit()
  attach_hint(unit)                    # adds context["model_preference"] (advisory)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Tier names (stable identifiers for unit context and tests).
TIER_DETERMINISTIC = "deterministic"
TIER_LOCAL = "local_slm"
TIER_FRONTIER = "frontier"

# Model preference strings the harness can interpret.
MODEL_NONE = "none"
MODEL_SLM = "slm-fast"
MODEL_FRONTIER = "frontier-reasoning"

# Complexity band thresholds (0..1).
_FRONTIER_THRESHOLD = 0.65
_LOCAL_THRESHOLD = 0.35

# Tasks that are pure deterministic computation — no model needed.  Note the
# phrasing: *generating* a payload family is deterministic; *sending* a probe
# is not, so plain "payload"/"probe" are deliberately absent.
DETERMINISTIC_HINTS = (
    "wordlist", "generate payload", "payload family", "payload set",
    "render payload", "artifact", "verify_sequence", "fingerprint",
    "parse", "render", "generate plan", "probe plan", "decode", "hash",
    "recon", "enumerate endpoint", "map", "template", "matrix", "policy check",
)

# Reasoning-heavy tasks that warrant a Frontier model.
REASONING_HINTS = (
    "chain", "synthesize", "synthesis", "refute", "adversarial", "exploit",
    "novel", "hypothesis", "decompose", "decomposition", "zero-day",
    "attack graph", "escalat", "account takeover", "pivot", "root cause",
)

# Bug classes whose exploitation path is open-ended reasoning.
COMPLEX_BUG_CLASSES = {
    "chain", "auth_bypass", "rce", "command_injection", "ssrf",
    "account_takeover", "deserialization", "zero_day", "jwt_attack",
    "business_logic",
}

# Bug classes where deterministic detection is the bulk of the work.
SIMPLE_BUG_CLASSES = {
    "xss", "sqli", "sql_injection", "csrf", "open_redirect", "clickjacking",
    "rate_limiting", "graphql_introspection", "graphql_dos",
    "information_disclosure", "misconfiguration", "public_bucket_access",
    "dns_misconfig", "session_fixation", "cache_poisoning", "email_spoofing",
    "parameter_pollution",
}


@dataclass
class RoutingDecision:
    task_id: str
    tier: str
    model_preference: str
    complexity: float
    rationale: str
    fallback: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _text(values: List[Any]) -> str:
    return " ".join(str(value or "") for value in values).lower()


def _complexity_score(objective: str, bug_class: str, *,
                      max_iterations: int, available_tools: List[str],
                      context: Dict[str, Any]) -> float:
    """Deterministic 0..1 complexity estimate from the unit's own fields."""
    text = f"{objective} {bug_class} {_text(available_tools)} " \
           f"{_text([context.get('current_state', ''), context.get('what_we_need', '')])}"
    score = 0.5
    if any(hint in text for hint in REASONING_HINTS):
        score += 0.15
    if bug_class and bug_class.strip().lower() in COMPLEX_BUG_CLASSES:
        score += 0.15
    if any(hint in text for hint in DETERMINISTIC_HINTS):
        score -= 0.20
    if bug_class and bug_class.strip().lower() in SIMPLE_BUG_CLASSES:
        score -= 0.10
    if int(max_iterations or 0) >= 30:
        score += 0.05
    if len(objective or "") >= 120:
        score += 0.05
    return round(max(0.0, min(1.0, score)), 3)


def classify(complexity: float) -> str:
    """Map a complexity score to a tier (deterministic banding)."""
    if complexity >= _FRONTIER_THRESHOLD:
        return TIER_FRONTIER
    if complexity >= _LOCAL_THRESHOLD:
        return TIER_LOCAL
    return TIER_DETERMINISTIC


def _preference(tier: str) -> str:
    return {TIER_DETERMINISTIC: MODEL_NONE,
            TIER_LOCAL: MODEL_SLM,
            TIER_FRONTIER: MODEL_FRONTIER}[tier]


def _fallback_for(tier: str) -> str:
    """What to run when the preferred tier's model is unavailable.

    Never blocks: the task still executes on a lesser tier.
    """
    return {
        TIER_FRONTIER: "frontier model unavailable; degrade to local_slm",
        TIER_LOCAL: "local model unavailable; degrade to deterministic core",
        TIER_DETERMINISTIC: "no model required; deterministic core executes",
    }[tier]


def route(objective: str, *, bug_class: str = "", task_id: str = "task",
          max_iterations: int = 50,
          available_tools: Optional[List[str]] = None,
          context: Optional[Dict[str, Any]] = None) -> RoutingDecision:
    """Classify one task spec into a deterministic routing decision."""
    complexity = _complexity_score(
        objective or "", bug_class or "", max_iterations=max_iterations,
        available_tools=list(available_tools or []), context=context or {})
    tier = classify(complexity)
    return RoutingDecision(
        task_id=task_id or "task",
        tier=tier,
        model_preference=_preference(tier),
        complexity=complexity,
        rationale=(f"complexity {complexity:.3f} -> {tier} "
                   f"(bug_class={bug_class or 'none'})"),
        fallback=_fallback_for(tier),
    )


def route_unit(unit: Dict[str, Any]) -> RoutingDecision:
    """Route a standard build_research_unit() dict.  Never raises."""
    if not isinstance(unit, dict):
        return route("malformed unit", task_id="malformed")
    context = unit.get("context") or {}
    if not isinstance(context, dict):
        context = {}
    return route(
        str(unit.get("objective", "")),
        bug_class=str(unit.get("bug_class", "")),
        task_id=str(unit.get("unit_id") or unit.get("id")
                    or unit.get("objective", "task"))[:80],
        max_iterations=int(unit.get("max_iterations", 50) or 50),
        available_tools=list(unit.get("available_tools") or []),
        context=context,
    )


def attach_hint(unit: Dict[str, Any]) -> Dict[str, Any]:
    """Add advisory routing hints to a unit's context (never gates)."""
    decision = route_unit(unit)
    if not isinstance(unit, dict):
        return unit
    context = unit.setdefault("context", {})
    if not isinstance(context, dict):
        context = {}
        unit["context"] = context
    context["model_preference"] = decision.model_preference
    context["model_tier"] = decision.tier
    context["model_fallback"] = decision.fallback
    context["model_routing"] = decision.to_dict()
    return unit


def main() -> int:
    import argparse
    import json
    parser = argparse.ArgumentParser(
        description="BugWolf model router (deterministic tier classification)")
    parser.add_argument("--objective", required=True,
                        help="task objective text")
    parser.add_argument("--bug-class", default="",
                        help="bug class for the task")
    parser.add_argument("--max-iterations", type=int, default=50)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    decision = route(args.objective, bug_class=args.bug_class,
                     max_iterations=args.max_iterations)
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"[{decision.tier:12s}] complexity {decision.complexity:.3f} "
              f"-> {decision.model_preference}")
        print(f"    {decision.rationale}")
        print(f"    fallback: {decision.fallback}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
