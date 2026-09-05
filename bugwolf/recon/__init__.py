"""BugWolf Phase 2.5 — Recon Orchestration.

Additive package — does NOT modify any pre-existing module.

Provides:

  * ``ReconOrchestrator``   — multi-target job queue (concurrent, DAG-aware)
  * ``cli``                 — Cobra-style CLI (``bugwolf recon ...``)
  * ``api``                 — FastAPI control plane on :8811 (token-gated)
  * ``passive``             — 50+ passive intel modules (crtsh, shodan, ...)
  * ``workflows``           — 20+ YAML recon workflows (full_recon,
                               passive_recon, takeover, ...)

All modules declare ``SCHEMA = "bugwolf-recon-v1"``.  No third-party deps.
"""

from __future__ import annotations

SCHEMA = "bugwolf-recon-v1"

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PassiveFinding:
    """A single piece of intel harvested by a passive module.

    Frozen — immutable once produced.  ``seen_at`` is RFC 3339 UTC.
    """
    kind: str        # "subdomain" | "ip" | "email" | "credential" | "endpoint"
    value: str
    source: str      # which passive module produced it
    confidence: float
    seen_at: str
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReconJob:
    """A single recon job in the orchestrator DAG."""
    job_id: str
    target: str
    workflow: str
    phase: str
    tools: List[str]
    budget_requests: int
    budget_seconds: int
    scope_verb: str    # "passive" | "active" | "destructive"
    state: str         # PENDING | RUNNING | COMPLETED | FAILED | SKIPPED
    depends_on: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    reason: str = ""
    findings_count: int = 0


@dataclass(frozen=True)
class ReconReport:
    """Aggregated report returned by ``ReconOrchestrator.run()``."""
    target: str
    workflows: List[str]
    started_at: str
    finished_at: str
    jobs: List[ReconJob]
    findings: List[PassiveFinding] = field(default_factory=list)


# State machine constants — kept as plain strings for JSON-friendliness.
STATE_PENDING = "PENDING"
STATE_RUNNING = "RUNNING"
STATE_COMPLETED = "COMPLETED"
STATE_FAILED = "FAILED"
STATE_SKIPPED = "SKIPPED"

VALID_STATES = {
    STATE_PENDING, STATE_RUNNING, STATE_COMPLETED, STATE_FAILED, STATE_SKIPPED,
}

SCOPE_PASSIVE = "passive"
SCOPE_ACTIVE = "active"
SCOPE_DESTRUCTIVE = "destructive"

VALID_SCOPE_VERBS = {SCOPE_PASSIVE, SCOPE_ACTIVE, SCOPE_DESTRUCTIVE}

# Re-export the orchestrator at package level so callers can
# ``from bugwolf.recon import ReconOrchestrator``.
from .orchestrator import ReconOrchestrator  # noqa: E402

__all__ = [
    "SCHEMA",
    "PassiveFinding",
    "ReconJob",
    "ReconReport",
    "ReconOrchestrator",
    "STATE_PENDING",
    "STATE_RUNNING",
    "STATE_COMPLETED",
    "STATE_FAILED",
    "STATE_SKIPPED",
    "VALID_STATES",
    "SCOPE_PASSIVE",
    "SCOPE_ACTIVE",
    "SCOPE_DESTRUCTIVE",
    "VALID_SCOPE_VERBS",
]