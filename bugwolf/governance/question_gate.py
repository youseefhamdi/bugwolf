"""7-Question Gate — semantic judgment of candidate findings (Phase 1.4).

The gate asks SEVEN questions about every candidate finding:

    1. Is the signal reproducible from the recorded evidence block?
    2. Is the impact described concrete and traceable to the recorded behavior?
    3. Is the endpoint in the scope contract?
    4. Does the action class match the scope contract's allowed_actions?
    5. Is there a recorded request/response pair (or equivalent captured state)?
    6. Does the chain-of-custody hash chain verify?
    7. Is the finding free of destructive default (no DELETE/STATE_CHANGE
       without operator opt-in)?

Each question returns ``(bool, str)`` — pass requires all True AND a
free-text reasoning note ≥ ``min_reasoning_chars`` (default 30).

The gate accepts an optional ``judge_backend`` callable.  When supplied,
the gate delegates the SEMANTIC side of every question to the backend
and only enforces the structural predicates locally.  When omitted,
the gate falls back to the 7 STRUCTURAL predicates (the bare-bones
"is the evidence here" checks) and returns :data:`GateVerdict.NEEDS_HUMAN_REVIEW`
when the structural checks pass but no semantic verdict is available.

The gate NEVER raises — every error path produces a verdict.

No external deps; stdlib only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"

DESTRUCTIVE_TOKENS = (
    "delete", "put", "patch", "post", "remove", "destroy", "drop",
    "kill", "shutdown", "reset", "purge",
)


class GateVerdict(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


@dataclass
class GateEvaluation:
    """Detailed result of a single 7-Question Gate run."""

    schema: str
    verdict: GateVerdict
    question_results: List[Dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    reasons: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    judge_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "verdict": self.verdict.value,
            "question_results": list(self.question_results),
            "reasoning": self.reasoning,
            "reasons": list(self.reasons),
            "evidence_refs": list(self.evidence_refs),
            "judge_used": self.judge_used,
        }


@dataclass
class FindingVerdict:
    """Lightweight verdict type the shim re-exports.

    Carries the :class:`GateVerdict` plus a short reason list so callers
    can render the verdict in logs without parsing the full evaluation.
    """

    schema: str
    verdict: GateVerdict
    reasons: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "evidence_refs": list(self.evidence_refs),
        }


JudgeBackend = Callable[[int, Mapping[str, Any]],
                        Tuple[bool, str, Dict[str, Any]]]


class QuestionGate:
    """Semantic 7-Question Gate.  NEVER raises."""

    schema = _SCHEMA

    def __init__(
        self,
        *,
        judge_backend: Optional[JudgeBackend] = None,
        min_reasoning_chars: int = 30,
    ) -> None:
        if min_reasoning_chars < 0:
            raise ValueError("min_reasoning_chars must be >= 0")
        self._judge_backend = judge_backend
        self._min_reasoning_chars = int(min_reasoning_chars)

    # -- public API ---------------------------------------------------------

    @property
    def judge_backend(self) -> Optional[JudgeBackend]:
        return self._judge_backend

    def evaluate(
        self,
        finding: Mapping[str, Any],
        *,
        evidence_block: Optional[Mapping[str, Any]] = None,
        scope_contract: Optional[Mapping[str, Any]] = None,
    ) -> GateEvaluation:
        """Run the 7-question gate on ``finding``.

        ``evidence_block`` is the canonical evidence (request/response
        pairs, captured state).  ``scope_contract`` is the active scope
        contract (target, allowed_actions, endpoints).

        The gate never raises; every failure path returns REJECTED with the
        specific question that failed.
        """
        try:
            return self._evaluate_internal(
                finding=finding or {},
                evidence_block=evidence_block or {},
                scope_contract=scope_contract or {},
            )
        except Exception as exc:  # noqa: BLE001 — fail-closed
            return GateEvaluation(
                schema=self.schema,
                verdict=GateVerdict.REJECTED,
                reasoning=f"internal error: {exc!r}",
                reasons=[f"internal_error: {exc!r}"],
            )

    def evaluate_verdict(
        self,
        finding: Mapping[str, Any],
        *,
        evidence_block: Optional[Mapping[str, Any]] = None,
        scope_contract: Optional[Mapping[str, Any]] = None,
    ) -> FindingVerdict:
        """Run :meth:`evaluate` and project to :class:`FindingVerdict`."""
        evaluation = self.evaluate(
            finding=finding or {},
            evidence_block=evidence_block,
            scope_contract=scope_contract,
        )
        return FindingVerdict(
            schema=self.schema,
            verdict=evaluation.verdict,
            reasons=list(evaluation.reasons),
            evidence_refs=list(evaluation.evidence_refs),
        )

    # -- internals ----------------------------------------------------------

    def _evaluate_internal(
        self,
        *,
        finding: Mapping[str, Any],
        evidence_block: Mapping[str, Any],
        scope_contract: Mapping[str, Any],
    ) -> GateEvaluation:
        questions = self._questions()
        results: List[Dict[str, Any]] = []
        rejected_reasons: List[str] = []
        evidence_refs: List[str] = []
        judge_used = False
        structural_only = self._judge_backend is None

        for index, question in enumerate(questions, start=1):
            passed, detail = self._run_question(
                index=index,
                question=question,
                finding=finding,
                evidence_block=evidence_block,
                scope_contract=scope_contract,
            )
            if self._judge_backend is not None:
                judge_used = True
                try:
                    judge_passed, judge_reason, judge_meta = self._judge_backend(
                        index,
                        {
                            "question": question,
                            "finding": dict(finding),
                            "evidence": dict(evidence_block),
                            "scope": dict(scope_contract),
                        },
                    )
                except Exception as exc:  # noqa: BLE001 — judge fails CLOSED
                    judge_passed = False
                    judge_reason = f"judge error: {exc!r}"
                    judge_meta = {}
                if not judge_passed:
                    passed = False
                detail = _merge_detail(detail, judge_reason, judge_meta)
            results.append({
                "index": index,
                "question": question,
                "passed": bool(passed),
                "detail": detail,
            })
            if not passed:
                rejected_reasons.append(
                    f"Q{index}: {question} — {detail.get('reason', 'failed')}")
            for ref in detail.get("evidence_refs", []) or []:
                if ref and ref not in evidence_refs:
                    evidence_refs.append(str(ref))

        all_passed = all(r["passed"] for r in results)
        if not all_passed:
            return GateEvaluation(
                schema=self.schema,
                verdict=GateVerdict.REJECTED,
                question_results=results,
                reasoning="; ".join(rejected_reasons),
                reasons=rejected_reasons,
                evidence_refs=evidence_refs,
                judge_used=judge_used,
            )

        # All structural checks pass.
        if structural_only:
            return GateEvaluation(
                schema=self.schema,
                verdict=GateVerdict.NEEDS_HUMAN_REVIEW,
                question_results=results,
                reasoning=(
                    "structural checks passed; no judge_backend available "
                    "for semantic verdict — escalate to human reviewer"),
                reasons=["no_judge_backend"],
                evidence_refs=evidence_refs,
                judge_used=False,
            )

        reasoning = _collect_reasoning(finding)
        if len(reasoning) < self._min_reasoning_chars:
            return GateEvaluation(
                schema=self.schema,
                verdict=GateVerdict.REJECTED,
                question_results=results,
                reasoning=(
                    f"reasoning note too short ({len(reasoning)} chars; "
                    f"need >= {self._min_reasoning_chars})"),
                reasons=["reasoning_too_short"],
                evidence_refs=evidence_refs,
                judge_used=judge_used,
            )

        return GateEvaluation(
            schema=self.schema,
            verdict=GateVerdict.ACCEPTED,
            question_results=results,
            reasoning=reasoning,
            reasons=[],
            evidence_refs=evidence_refs,
            judge_used=judge_used,
        )

    def _questions(self) -> List[str]:
        return [
            "Is the signal reproducible from the recorded evidence block?",
            "Is the impact described concrete and traceable to the recorded behavior?",
            "Is the endpoint in the scope contract?",
            "Does the action class match the scope contract's allowed_actions?",
            "Is there a recorded request/response pair (or equivalent captured state)?",
            "Does the chain-of-custody hash chain verify?",
            "Is the finding free of destructive default (no DELETE/STATE_CHANGE without operator opt-in)?",
        ]

    def _run_question(
        self,
        *,
        index: int,
        question: str,
        finding: Mapping[str, Any],
        evidence_block: Mapping[str, Any],
        scope_contract: Mapping[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        if index == 1:
            return self._q1_reproducible(finding, evidence_block)
        if index == 2:
            return self._q2_impact_traceable(finding, evidence_block)
        if index == 3:
            return self._q3_endpoint_in_scope(finding, scope_contract)
        if index == 4:
            return self._q4_action_in_scope(finding, scope_contract)
        if index == 5:
            return self._q5_recorded_state(evidence_block)
        if index == 6:
            return self._q6_chain_verifies(evidence_block)
        if index == 7:
            return self._q7_no_destructive_default(finding)
        return False, {"reason": f"unknown question index {index}"}

    def _q1_reproducible(self, finding: Mapping[str, Any],
                         evidence_block: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        signal = _get_path(finding, ("signal", "reproduction", "trigger"))
        evidence_steps = _get_path(evidence_block, ("steps", "transcript"))
        if signal and evidence_steps:
            return True, {"reason": "signal and evidence steps present",
                          "evidence_refs": _list_refs(evidence_block)}
        if signal:
            return False, {"reason": "signal recorded but no evidence steps"}
        return False, {"reason": "no reproduction signal recorded"}

    def _q2_impact_traceable(self, finding: Mapping[str, Any],
                             evidence_block: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        impact = _get_path(finding, ("impact", "consequence", "outcome"))
        observed = _get_path(evidence_block, ("observed", "response", "captured"))
        if impact and observed:
            return True, {"reason": "impact and observed behavior recorded",
                          "evidence_refs": _list_refs(evidence_block)}
        if impact and not observed:
            return False, {"reason": "impact claimed without observed behavior"}
        return False, {"reason": "no impact recorded"}

    def _q3_endpoint_in_scope(self, finding: Mapping[str, Any],
                              scope_contract: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        endpoint = _get_path(finding, ("endpoint", "url", "target_url"))
        scope_endpoints = scope_contract.get("endpoints") or []
        scope_target = scope_contract.get("target") or scope_contract.get("mission_target")
        if not endpoint:
            return False, {"reason": "finding missing endpoint/url"}
        if not scope_endpoints and not scope_target:
            return True, {"reason": "no scope contract endpoints declared",
                          "evidence_refs": []}
        host = _extract_host(endpoint)
        if scope_target and _host_matches(host, scope_target):
            return True, {"reason": "endpoint inside mission target"}
        if scope_endpoints and any(
                _endpoint_matches(endpoint, ep) for ep in scope_endpoints):
            return True, {"reason": "endpoint matches scope contract entry"}
        if scope_target and host and host == scope_target:
            return True, {"reason": "endpoint host matches mission target"}
        return False, {"reason": "endpoint not in scope contract"}

    def _q4_action_in_scope(self, finding: Mapping[str, Any],
                             scope_contract: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        action = _get_path(finding, ("action_class", "method", "action"))
        allowed = scope_contract.get("allowed_actions") or []
        if not action:
            return False, {"reason": "finding missing action_class"}
        if not allowed:
            return True, {"reason": "scope contract has no allowed_actions "
                                     "restriction"}
        normalized = str(action).upper()
        if any(str(a).upper() == normalized for a in allowed):
            return True, {"reason": "action class matches allowed_actions"}
        return False, {"reason": "action class not in allowed_actions"}

    def _q5_recorded_state(self, evidence_block: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        request = evidence_block.get("request") or evidence_block.get("captured_request")
        response = evidence_block.get("response") or evidence_block.get("captured_response")
        transcript = evidence_block.get("transcript")
        if (request and response) or transcript:
            return True, {"reason": "request/response (or transcript) present",
                          "evidence_refs": _list_refs(evidence_block)}
        return False, {"reason": "no recorded request/response or transcript"}

    def _q6_chain_verifies(self, evidence_block: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        chain_ok = evidence_block.get("chain_verifies")
        chain_hash = evidence_block.get("chain_hash") or evidence_block.get("entry_hash")
        if chain_ok is True:
            return True, {"reason": "chain-of-custody verifies",
                          "evidence_refs": _list_refs(evidence_block)}
        if chain_hash:
            return True, {"reason": "chain hash present",
                          "evidence_refs": _list_refs(evidence_block)}
        return False, {"reason": "no chain-of-custody verification"}

    def _q7_no_destructive_default(self, finding: Mapping[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        method = _get_path(finding, ("method", "action", "action_class"))
        opt_in = bool(finding.get("operator_opt_in") or finding.get("destructive_opt_in"))
        if not method:
            return True, {"reason": "no method declared; no destructive default"}
        normalized = str(method).lower()
        if any(token in normalized for token in DESTRUCTIVE_TOKENS):
            if opt_in:
                return True, {"reason": "destructive action with operator opt-in"}
            return False, {"reason": "destructive action without operator opt-in"}
        return True, {"reason": "non-destructive action"}


def _merge_detail(base: Dict[str, Any],
                  reason: str,
                  meta: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    if reason:
        merged["judge_reason"] = reason
    if isinstance(meta, dict):
        for k, v in meta.items():
            merged.setdefault(str(k), v)
    return merged


def _collect_reasoning(finding: Mapping[str, Any]) -> str:
    parts: List[str] = []
    for key in ("reasoning", "rationale", "justification", "summary"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    if not parts:
        desc = finding.get("description")
        if isinstance(desc, str) and desc.strip():
            parts.append(desc.strip())
    return "\n".join(parts).strip()


def _endpoint_matches(endpoint: str, scope_entry: Any) -> bool:
    if not scope_entry:
        return False
    ep = str(endpoint)
    se = str(scope_entry)
    if ep == se:
        return True
    if "*" in se:
        pattern = "^" + re.escape(se).replace("\\*", ".*") + "$"
        return bool(re.match(pattern, ep))
    host_ep = _extract_host(ep)
    host_se = _extract_host(se)
    if host_se and host_ep and host_ep == host_se:
        return True
    return ep.startswith(se)


def _extract_host(value: str) -> str:
    if not value:
        return ""
    s = str(value).strip()
    if "://" not in s:
        s = "//" + s
    try:
        from urllib.parse import urlparse
        return (urlparse(s).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _host_matches(host: str, scope_target: Any) -> bool:
    if not host or not scope_target:
        return False
    target = str(scope_target).lower().rstrip(".")
    return host == target or host.endswith("." + target)


def _get_path(mapping: Mapping[str, Any], keys: tuple) -> Any:
    for key in keys:
        if not isinstance(mapping, Mapping):
            return None
        if key in mapping:
            value = mapping[key]
            if value:
                return value
            continue
    return None


def _list_refs(evidence_block: Mapping[str, Any]) -> List[str]:
    refs: List[str] = []
    for key in ("evidence_ref", "evidence_refs", "ref", "artifact_ref"):
        value = evidence_block.get(key)
        if isinstance(value, str) and value:
            refs.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    refs.append(item)
    return refs


__all__ = [
    "SCHEMA",
    "GateVerdict",
    "GateEvaluation",
    "FindingVerdict",
    "QuestionGate",
    "GateVerdict2",
    "QuestionResult",
    "GateResult",
    "SevenQuestionGate",
]


# =============================================================================
# Appendix B — SevenQuestionGate (finding submission validator)
# =============================================================================
#
# The shallow :class:`QuestionGate` above judges candidate findings against
# a *scope contract* + *evidence block*.  The plan's Appendix B asks for a
# STRUCTURALLY DIFFERENT gate used at FINDING SUBMISSION TIME:
#
#   * Different enum (PASS / FAIL / NEEDS_MORE_EVIDENCE) so the caller
#     can read the verdict without confusing it with the ACCEPTED /
#     REJECTED / NEEDS_HUMAN_REVIEW triplet above.
#   * Different question set — the 7 canonical "is this report valid?"
#     questions a triage reviewer asks BEFORE writing a HackerOne-style
#     report.
#   * LLM-as-judge via ``bugwolf.runtime.backends.BaseBackend.complete``
#     (NOT the callable backend pattern used by ``QuestionGate``).  When
#     no backend is supplied, deterministic dry-run stubs return PASS
#     for findings that already carry an evidence block, FAIL otherwise.
#   * NEVER raises — every failure path produces a :class:`GateResult`.
# -----------------------------------------------------------------------------


class GateVerdict2(str, Enum):
    """Finding-submission verdict (Appendix B).

    Aliased to a different class name (``GateVerdict2``) to avoid clashing
    with the :class:`GateVerdict` (ACCEPTED / REJECTED / NEEDS_HUMAN_REVIEW)
    that the structural :class:`QuestionGate` uses.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


@dataclass
class QuestionResult:
    """Per-question output produced by :class:`SevenQuestionGate`."""

    question_id: int
    question: str
    verdict: GateVerdict2
    reasoning: str
    confidence: float
    evidence_cited: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "question_id": int(self.question_id),
            "question": self.question,
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "confidence": float(self.confidence),
            "evidence_cited": list(self.evidence_cited),
        }


@dataclass
class GateResult:
    """Aggregated output for a single finding."""

    finding_id: str
    results: List[QuestionResult]
    overall_verdict: GateVerdict2
    summary: str
    judge_used: bool = False
    backend_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "overall_verdict": self.overall_verdict.value,
            "summary": self.summary,
            "judge_used": bool(self.judge_used),
            "backend_name": self.backend_name,
            "results": [r.to_dict() for r in self.results],
        }


class SevenQuestionGate:
    """Finding-submission validator (Appendix B).

    The 7 canonical triage questions:

      1. Is the vulnerability class correctly identified?
      2. Is the attack surface reachable from the internet?
      3. Is the impact demonstrated (not just claimed)?
      4. Is the evidence reproducible from the report alone?
      5. Is the vulnerability in-scope per the program's policy?
      6. Is the severity correctly assessed (CVSS 3.1)?
      7. Is the finding distinct from duplicates/already-reported?

    Use ``backend.complete(prompt, ...)`` to delegate the semantic
    verdict; on any exception we fall back to the deterministic stub so
    the gate NEVER raises.
    """

    QUESTIONS: Tuple[str, ...] = (
        "Is the vulnerability class correctly identified?",
        "Is the attack surface reachable from the internet?",
        "Is the impact demonstrated (not just claimed)?",
        "Is the evidence reproducible from the report alone?",
        "Is the vulnerability in-scope per the program's policy?",
        "Is the severity correctly assessed (CVSS 3.1)?",
        "Is the finding distinct from duplicates/already-reported?",
    )

    def __init__(
        self,
        llm_backend: Any = None,
        *,
        timeout: float = 30.0,
        evidence_key: str = "recorded_evidence_block",
    ) -> None:
        self._backend = llm_backend
        self._timeout = float(timeout)
        self._evidence_key = str(evidence_key)

    @property
    def llm_backend(self) -> Any:
        return self._backend

    @property
    def backend_name(self) -> str:
        if self._backend is None:
            return ""
        return str(getattr(self._backend, "name", "") or "")

    def evaluate(self, finding: Mapping[str, Any]) -> GateResult:
        """Run all 7 questions; return a :class:`GateResult` (never raise)."""
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        try:
            results: List[QuestionResult] = []
            for idx, question in enumerate(self.QUESTIONS, start=1):
                results.append(self._evaluate_question(idx, question, finding))
            overall = self._aggregate(results)
            judge_used = self._backend is not None
            summary = _summarise(results, overall)
            return GateResult(
                finding_id=finding_id,
                results=results,
                overall_verdict=overall,
                summary=summary,
                judge_used=judge_used,
                backend_name=self.backend_name,
            )
        except Exception as exc:  # noqa: BLE001 — gate NEVER raises
            return GateResult(
                finding_id=finding_id,
                results=[],
                overall_verdict=GateVerdict2.FAIL,
                summary=f"internal error: {exc!r}",
                judge_used=False,
                backend_name=self.backend_name,
            )

    # -- internals ----------------------------------------------------------

    def _evaluate_question(
        self,
        qid: int,
        question: str,
        finding: Mapping[str, Any],
    ) -> QuestionResult:
        if self._backend is None:
            return self._dry_run(qid, question, finding)
        try:
            prompt = _build_judge_prompt(qid, question, finding)
            response = self._backend.complete(
                prompt, timeout=self._timeout,
            )
            text = getattr(response, "text", "") or ""
            return _parse_judge_response(qid, question, finding, text)
        except Exception as exc:  # noqa: BLE001 — fail closed to NEEDS_MORE_EVIDENCE
            return QuestionResult(
                question_id=qid,
                question=question,
                verdict=GateVerdict2.NEEDS_MORE_EVIDENCE,
                reasoning=f"judge error: {exc!r}",
                confidence=0.0,
                evidence_cited=_evidence_cited(finding),
            )

    def _dry_run(
        self,
        qid: int,
        question: str,
        finding: Mapping[str, Any],
    ) -> QuestionResult:
        """Deterministic stub used when no ``llm_backend`` is provided.

        Returns PASS for findings that already carry an evidence block,
        FAIL for findings without one.  This is the "evidence-aware"
        behaviour the plan's Gate 1 requires.
        """
        evidence_present = self._has_evidence(finding)
        cited = _evidence_cited(finding)
        if qid in (1, 2, 5, 7):
            # Static questions — evidence-aware binary verdict.
            verdict = GateVerdict2.PASS if evidence_present else GateVerdict2.FAIL
            confidence = 0.8 if evidence_present else 0.5
            reasoning = (
                "evidence block present" if evidence_present
                else "no evidence block attached"
            )
        elif qid == 3:
            impact = finding.get("impact") or finding.get("consequence")
            if isinstance(impact, str) and impact.strip() and evidence_present:
                verdict = GateVerdict2.PASS
                confidence = 0.8
                reasoning = "impact description + evidence block present"
            elif evidence_present:
                verdict = GateVerdict2.NEEDS_MORE_EVIDENCE
                confidence = 0.6
                reasoning = "evidence present but impact description is empty"
            else:
                verdict = GateVerdict2.FAIL
                confidence = 0.5
                reasoning = "no evidence and no impact description"
        elif qid == 4:
            steps = finding.get("reproduction_steps") or finding.get("steps")
            transcript = finding.get("transcript") or finding.get("request")
            if evidence_present and (steps or transcript):
                verdict = GateVerdict2.PASS
                confidence = 0.8
                reasoning = "reproduction steps + evidence block present"
            elif evidence_present:
                verdict = GateVerdict2.NEEDS_MORE_EVIDENCE
                confidence = 0.6
                reasoning = "evidence present but reproduction steps missing"
            else:
                verdict = GateVerdict2.FAIL
                confidence = 0.5
                reasoning = "no evidence and no reproduction steps"
        elif qid == 6:
            severity = finding.get("severity") or finding.get("cvss_score")
            if isinstance(severity, (int, float)) and 0.0 <= float(severity) <= 10.0:
                verdict = GateVerdict2.PASS
                confidence = 0.8
                reasoning = "numeric severity/CVSS present in range"
            else:
                verdict = GateVerdict2.NEEDS_MORE_EVIDENCE
                confidence = 0.5
                reasoning = "no numeric severity / CVSS 3.1 score"
        else:
            verdict = GateVerdict2.NEEDS_MORE_EVIDENCE
            confidence = 0.5
            reasoning = "unknown question"
        return QuestionResult(
            question_id=qid,
            question=question,
            verdict=verdict,
            reasoning=reasoning,
            confidence=float(confidence),
            evidence_cited=cited,
        )

    def _has_evidence(self, finding: Mapping[str, Any]) -> bool:
        block = finding.get(self._evidence_key)
        if not block:
            return False
        if isinstance(block, Mapping):
            return any(bool(v) for v in block.values())
        if isinstance(block, (list, tuple)):
            return any(bool(v) for v in block)
        if isinstance(block, str):
            return bool(block.strip())
        return True

    def _aggregate(self, results: List[QuestionResult]) -> GateVerdict2:
        """Combine 7 verdicts into the overall verdict.

        Any FAIL ⇒ FAIL.  All PASS ⇒ PASS.  Otherwise NEEDS_MORE_EVIDENCE.
        """
        if any(r.verdict == GateVerdict2.FAIL for r in results):
            return GateVerdict2.FAIL
        if results and all(r.verdict == GateVerdict2.PASS for r in results):
            return GateVerdict2.PASS
        return GateVerdict2.NEEDS_MORE_EVIDENCE


# -----------------------------------------------------------------------------
# Helpers — kept private.  All stdlib.
# -----------------------------------------------------------------------------


def _evidence_cited(finding: Mapping[str, Any]) -> List[str]:
    refs: List[str] = []
    block = finding.get("recorded_evidence_block") or {}
    if isinstance(block, Mapping):
        for key in ("evidence_ref", "evidence_refs", "ref", "artifact_ref"):
            val = block.get(key)
            if isinstance(val, str) and val:
                refs.append(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item:
                        refs.append(item)
    for key in ("evidence_ref", "evidence_refs", "ref"):
        val = finding.get(key)
        if isinstance(val, str) and val:
            refs.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item:
                    refs.append(item)
    # de-dup, preserve order
    seen: set = set()
    out: List[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _summarise(results: List[QuestionResult],
               overall: GateVerdict2) -> str:
    if not results:
        return "no questions evaluated"
    failed = [r for r in results if r.verdict == GateVerdict2.FAIL]
    pending = [r for r in results if r.verdict == GateVerdict2.NEEDS_MORE_EVIDENCE]
    parts: List[str] = [f"overall={overall.value}"]
    if failed:
        parts.append("failed: " + "; ".join(r.question for r in failed))
    if pending:
        parts.append("pending: " + "; ".join(r.question for r in pending))
    avg = sum(r.confidence for r in results) / float(len(results))
    parts.append(f"avg_confidence={avg:.2f}")
    return " | ".join(parts)


def _build_judge_prompt(qid: int, question: str,
                        finding: Mapping[str, Any]) -> str:
    """Build the LLM-as-judge prompt for question ``qid``."""
    import json as _json
    safe = {k: v for k, v in dict(finding).items()
            if not str(k).startswith("_")}
    payload = _json.dumps(safe, default=str, sort_keys=True)
    return (
        f"You are a triage reviewer answering question {qid} of 7.\n"
        f"Question: {question}\n"
        f"Finding (JSON):\n{payload}\n\n"
        f"Reply with EXACTLY one line, no markdown fences:\n"
        f"VERDICT: <PASS|FAIL|NEEDS_MORE_EVIDENCE> "
        f"CONFIDENCE: <0.0-1.0> REASONING: <one sentence>"
    )


def _parse_judge_response(qid: int, question: str,
                          finding: Mapping[str, Any],
                          text: str) -> QuestionResult:
    """Parse the LLM response line into a :class:`QuestionResult`."""
    verdict = GateVerdict2.NEEDS_MORE_EVIDENCE
    confidence = 0.5
    reasoning = (text or "").strip() or "no judge output"
    upper = reasoning.upper()
    if "VERDICT: PASS" in upper or upper.endswith("PASS"):
        verdict = GateVerdict2.PASS
    elif "VERDICT: FAIL" in upper or upper.endswith("FAIL"):
        verdict = GateVerdict2.FAIL
    # crude confidence parse
    import re as _re
    m = _re.search(r"CONFIDENCE:\s*([0-9]*\.?[0-9]+)", upper)
    if m:
        try:
            confidence = max(0.0, min(1.0, float(m.group(1))))
        except ValueError:
            confidence = 0.5
    m = _re.search(r"REASONING:\s*(.+)$", reasoning, flags=_re.DOTALL)
    if m:
        reasoning = m.group(1).strip()
    return QuestionResult(
        question_id=qid,
        question=question,
        verdict=verdict,
        reasoning=reasoning,
        confidence=float(confidence),
        evidence_cited=_evidence_cited(finding),
    )