#!/usr/bin/env python3
"""Aggregate model/campaign outcomes into deterministic pass@k metrics."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

SCHEMA = "bugwolf/passk-metrics/v1"


@dataclass
class Attempt:
    case_id: str
    run_id: str
    found: bool
    confirmed: bool = False


def pass_at_k(attempts: Iterable[Attempt], k: int) -> float:
    """Return the fraction of cases with a successful attempt among first k runs."""
    if k < 1:
        raise ValueError("k must be positive")
    grouped: Dict[str, List[Attempt]] = {}
    for attempt in attempts:
        grouped.setdefault(attempt.case_id, []).append(attempt)
    if not grouped:
        return 0.0
    successes = sum(any(a.found for a in sorted(values, key=lambda a: a.run_id)[:k])
                    for values in grouped.values())
    return round(successes / len(grouped), 4)


def aggregate(attempts: Iterable[Attempt], *, budget_units: int = 0) -> Dict[str, Any]:
    values = list(attempts)
    cases = sorted({a.case_id for a in values})
    runs = sorted({a.run_id for a in values})
    found = sum(a.found for a in values)
    confirmed = sum(a.confirmed for a in values)
    return {
        "schema": SCHEMA,
        "cases": len(cases),
        "runs": len(runs),
        "attempts": len(values),
        "found": found,
        "confirmed": confirmed,
        "pass_at_1": pass_at_k(values, 1),
        "pass_at_3": pass_at_k(values, 3),
        "pass_at_k": {str(k): pass_at_k(values, k) for k in range(1, max(1, len(runs)) + 1)},
        "coverage_per_budget": round(len(cases) / budget_units, 4) if budget_units else 0.0,
    }


def from_records(records: Iterable[Mapping[str, Any]], *, budget_units: int = 0) -> Dict[str, Any]:
    return aggregate([Attempt(str(r["case_id"]), str(r["run_id"]),
                              bool(r.get("found")), bool(r.get("confirmed")))
                      for r in records], budget_units=budget_units)
