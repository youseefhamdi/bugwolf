#!/usr/bin/env python3
"""Understanding Layer — U1..U9 (master plan Part VIII / 8.x).

The thesis, enforced by construction: **you cannot hunt what you haven't
modeled.**  The layer runs as a STRICT sequence — each stage's artifact is
the next stage's mandatory input — and ends in the coverage gate + Hunting
Brief.  Bug classes with no model support are PARKED WITH REASON, not
sprayed blindly.

Layout (``state/targets/<target-slug>/model/``):

    u1-business.json      U2-census.json   U3-logic.json    U4-identity.json
    u5-data.json          u6-trust.json    u7-capabilities.json
    u8-assumptions.jsonl  (the zero-day seed list)
    u9-target-model.json  (versioned, hash-chained)  +  hunting-brief.md

Deterministic tier: every engine here is pure code over captured facts
(fetched pages, crawl artifacts, the session store).  The plan's bounded
LLM reasoning passes are operator-side; the artifacts carry ``challenge``
fields ready for them.  No model calls in this package.
"""

from tools.runtime.understanding.base import (
    SCHEMA as MODEL_SCHEMA,
    Assumption,
    ModelStore,
    UArtifact,
    ASSUMPTION_ORIGINS,
)
from tools.runtime.understanding.pipeline import UnderstandingPipeline

__all__ = [
    "MODEL_SCHEMA", "Assumption", "ModelStore", "UArtifact",
    "ASSUMPTION_ORIGINS", "UnderstandingPipeline",
]
