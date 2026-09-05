# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-scoring-init-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Scoring package — re-exports the three scorers."""

SCHEMA = "bugwolf-benchmarks-scoring-init-v1"

from bugwolf.benchmarks.scoring import chain_scorer, coverage_scorer, f05_scorer  # noqa: F401

__all__ = [
    "f05_scorer",
    "chain_scorer",
    "coverage_scorer",
    "SCHEMA",
]