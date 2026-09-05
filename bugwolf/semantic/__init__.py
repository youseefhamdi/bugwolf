"""BugWolf Phase 3.3 — Semantic Bug Detection.

Pure-stdlib, STUB-SAFE analyzers that turn low-level observations
(transport responses, JWT strings, workflow definitions, finding dicts)
into structured :class:`IDORFinding` / :class:`JWTIssue` / etc.
records an operator can triage.  The package composes well with the
rest of BugWolf: every public class accepts an injected transport
callable, and the LLM judge degrades to a deterministic structural
rubric when no backend is available.

Modules:
  * :mod:`bugwolf.semantic.idor_detector`   — multi-user session replay
  * :mod:`bugwolf.semantic.jwt_logic`       — JWT logic analyzer
  * :mod:`bugwolf.semantic.business_logic`  — race / workflow bypass / TOCTOU
  * :mod:`bugwolf.semantic.auth_flow`       — broken function-level auth
  * :mod:`bugwolf.semantic.llm_judge`       — LLM-as-judge + structural fallback
  * :mod:`bugwolf.semantic.diff_analyzer`   — success/fail response diffing
  * :mod:`bugwolf.semantic.stateful_workflow` — multi-step workflow checks
  * :mod:`bugwolf.semantic.semantic_search` — TF-IDF pattern matching

## Source:  bugwolf/semantic/__init__.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

from bugwolf.semantic.idor_detector import (
    Endpoint,
    IDORDetector,
    IDORFinding,
    Session,
)
from bugwolf.semantic.jwt_logic import (
    JWTIssue,
    JWTLogicAnalyzer,
)
from bugwolf.semantic.business_logic import (
    BusinessLogicDetector,
    RaceFinding,
    TOCTOUFinding,
    WorkflowBypassFinding,
    WorkflowStep as BLWorkflowStep,
)
from bugwolf.semantic.auth_flow import (
    AuthFinding,
    AuthFlowChecker,
)
from bugwolf.semantic.llm_judge import (
    JudgeResult,
    LLMJudge,
)
from bugwolf.semantic.diff_analyzer import (
    DiffAnalyzer,
    DiffResult,
    HttpObservation,
)
from bugwolf.semantic.stateful_workflow import (
    StatefulWorkflowAnalyzer,
    WorkflowFinding,
    WorkflowStep as SWWorkflowStep,
)
from bugwolf.semantic.semantic_search import (
    SemanticMatch,
    SemanticSearch,
)


# Re-export WorkflowStep from stateful_workflow as the canonical
# one; the business_logic module has its own (intentionally smaller)
# WorkflowStep that doesn't carry the CSRF / stateful flags.
WorkflowStep = SWWorkflowStep


__all__ = [
    "IDORDetector", "IDORFinding", "Session", "Endpoint",
    "JWTLogicAnalyzer", "JWTIssue",
    "BusinessLogicDetector", "RaceFinding", "WorkflowBypassFinding",
    "TOCTOUFinding", "BLWorkflowStep",
    "AuthFlowChecker", "AuthFinding",
    "LLMJudge", "JudgeResult",
    "DiffAnalyzer", "DiffResult", "HttpObservation",
    "StatefulWorkflowAnalyzer", "WorkflowFinding", "WorkflowStep",
    "SemanticSearch", "SemanticMatch",
]
