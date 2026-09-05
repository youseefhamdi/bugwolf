"""LLM-as-a-judge for semantic validation of bug findings (Phase 3.3).

Wraps a :class:`bugwolf.runtime.backends.BaseBackend` to perform a
*second opinion* on a finding: is the severity right, is the evidence
concrete, is the remediation applicable?  When no backend is supplied
(or the backend raises), we fall back to a deterministic structural
check that scores a finding on the basis of the evidence / endpoint /
severity / payload-coverage fields.

NEVER RAISES: a backend failure returns
``JudgeResult(passed=False, confidence=0.0, reasoning=<why>)``.

The result is the BUGWOLF semantic one, NOT
``bugwolf.runtime.backends.base.JudgeResult`` — they live in different
layers and we don't want a base-runtime import to surface a Judge
result type with a different shape.

## Source:  bugwolf/semantic/llm_judge.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JudgeResult:
    """Result of a semantic validation pass on one finding.

    Fields:
        passed: True if the finding is judged valid (semantic).
        confidence: 0.0–1.0 score (we always clamp).
        reasoning: short human-readable explanation.
        backend: which path produced the verdict ("llm:<name>" or
                 "structural").
        model: model name (or "n/a" for the structural path).
        rubric: optional dict with the criteria used.
    """

    passed: bool
    confidence: float
    reasoning: str
    backend: str = "structural"
    model: str = "n/a"
    rubric: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "passed": bool(self.passed),
            "confidence": round(float(self.confidence), 4),
            "reasoning": self.reasoning,
            "backend": self.backend,
            "model": self.model,
            "rubric": dict(self.rubric),
        }


# ---------------------------------------------------------------------------
# Structural (no-backend) rubric
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Tokens that, when present in the evidence, suggest the finding has
# concrete repro material — strong signal for a "pass" verdict.
_STRONG_EVIDENCE_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"\bstatus\s*[=:]\s*\d{3}\b", re.IGNORECASE),
    re.compile(r"\bHTTP/\d\.\d\s+\d{3}\b"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._\-]{8,}\b", re.IGNORECASE),
    re.compile(r"\b(set-cookie|authorization|x-api-key)\b\s*:", re.IGNORECASE),
    re.compile(r"\b(sqli|xss|ssrf|idor|rce|ssti)\b", re.IGNORECASE),
    re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+/\S+", re.IGNORECASE),
    re.compile(r"https?://\S+\.\S+"),
    re.compile(r"\b(sha1|sha256|md5|hmac|ecdsa|rsa|jwt)\b", re.IGNORECASE),
    re.compile(r"\b(traceback|stacktrace)\b", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# LLMJudge
# ---------------------------------------------------------------------------

class LLMJudge:
    """Frontier-model semantic judge for bug findings.

    Construction is cheap; the actual LLM call is the expensive part
    and only happens in :meth:`judge_finding` (one prompt per call).
    """

    PROMPT_VERSION: str = "bugwolf-semantic-judge-v1"

    def __init__(self, backend: Optional[Any] = None) -> None:
        # We accept any object that exposes ``.complete(prompt)`` and
        # ``.judge(prompt, rubric=...)``.  Concrete type is
        # ``BaseBackend`` from bugwolf.runtime.backends.
        self.backend: Optional[Any] = backend
        self._backend_name: str = (
            getattr(backend, "name", "unknown") if backend is not None
            else "none"
        )

    # ------------------------------------------------------------------ api

    def judge_finding(self, finding: Dict[str, Any]) -> JudgeResult:
        """Run a semantic validation pass on ``finding``.

        ``finding`` is expected to be a dict with at least ``title`` /
        ``evidence`` / ``endpoint`` / ``severity``.  Any other keys are
        forwarded into the LLM prompt verbatim.

        NEVER RAISES: backend errors are caught and translated into a
        low-confidence, ``passed=False`` result with a structural
        fallback.
        """
        try:
            return self._judge_safe(finding)
        except Exception as exc:  # noqa: BLE001
            log.warning("LLMJudge swallowed: %r", exc)
            return JudgeResult(
                passed=False,
                confidence=0.0,
                reasoning=f"judge-error: {exc!r}",
                backend=f"llm:{self._backend_name}",
                model="n/a",
                rubric={"structural": False},
            )

    def judge_many(
        self, findings: List[Dict[str, Any]]
    ) -> List[JudgeResult]:
        """Validate a batch of findings.  Order preserved."""
        out: List[JudgeResult] = []
        for f in findings or ():
            out.append(self.judge_finding(f))
        return out

    # ------------------------------------------------------------------ impl

    def _judge_safe(self, finding: Dict[str, Any]) -> JudgeResult:
        finding = finding or {}
        # If we have a backend, defer to it.  Backend failure here
        # yields a judge-error result (NOT the structural fallback),
        # because the operator deliberately asked for an LLM verdict
        # and that path failed -- silently downgrading to a
        # structural verdict would mask the failure.
        if self.backend is not None:
            try:
                return self._call_backend(finding)
            except Exception as exc:  # noqa: BLE001
                log.warning("LLMJudge backend failure: %r", exc)
                return JudgeResult(
                    passed=False,
                    confidence=0.0,
                    reasoning=f"judge-error: backend raised {exc!r}",
                    backend=f"llm:{self._backend_name}",
                    model="n/a",
                    rubric={"structural": False,
                            "reason": "backend-failed"},
                )
        # No backend: deterministic structural heuristic.
        return self._structural(finding)

    def _call_backend(self, finding: Dict[str, Any]) -> JudgeResult:
        prompt = self._build_prompt(finding)
        rubric = {
            "schema": SCHEMA,
            "criteria": [
                "evidence_observable",
                "endpoint_reachable",
                "severity_appropriate",
                "remediation_concrete",
            ],
        }
        # Use judge() if the backend implements it; otherwise fall back
        # to complete() and parse the response heuristically.
        if hasattr(self.backend, "judge") and callable(self.backend.judge):
            try:
                jr = self.backend.judge(prompt, rubric=rubric)
            except Exception as exc:  # noqa: BLE001
                log.debug("backend.judge failed: %r", exc)
                jr = None
        else:
            jr = None
        if jr is None and hasattr(self.backend, "complete") \
                and callable(self.backend.complete):
            cr = self.backend.complete(prompt)
            jr = self._coerce_complete_to_judge(cr, finding)
        if jr is None:
            return self._structural(finding)
        return JudgeResult(
            passed=bool(getattr(jr, "passed", False)),
            confidence=float(getattr(jr, "score", 0.5)
                             or getattr(jr, "confidence", 0.5) or 0.5),
            reasoning=str(getattr(jr, "rationale", "")
                          or getattr(jr, "reasoning", "") or ""),
            backend=f"llm:{self._backend_name}",
            model=str(getattr(jr, "model", "n/a") or "n/a"),
            rubric=rubric,
        )

    def _coerce_complete_to_judge(self, cr: Any, finding: Dict[str, Any]) \
            -> Any:
        """Best-effort: parse a free-form complete() response into a
        JudgeResult-shaped object.  We only do this when the backend
        doesn't expose ``judge()``."""
        text = str(getattr(cr, "text", "") or "")
        passed, conf = self._parse_verdict(text)
        # A tiny ad-hoc class; downstream uses getattr.
        class _AdHoc:
            def __init__(self) -> None:
                self.passed = passed
                self.score = conf
                self.confidence = conf
                self.rationale = text[:280]
                self.reasoning = text[:280]
                self.model = str(getattr(cr, "model", "n/a") or "n/a")
        return _AdHoc()

    @staticmethod
    def _parse_verdict(text: str) -> tuple:
        """Look for a ``VERDICT: PASS/FAIL`` + ``CONFIDENCE: 0.x`` line."""
        if not text:
            return False, 0.0
        m_pass = re.search(r"\bverdict\s*[:=]\s*(pass|fail|yes|no|true|false)\b",
                           text, re.IGNORECASE)
        m_conf = re.search(r"\bconfidence\s*[:=]\s*([01]?\.\d+|\d+)",
                           text, re.IGNORECASE)
        passed = False
        if m_pass:
            tag = m_pass.group(1).lower()
            passed = tag in ("pass", "yes", "true")
        else:
            # Soft fallback: positive words in the first 600 chars.
            head = text[:600].lower()
            passed = ("pass" in head or "valid" in head or "confirmed"
                      in head) and "fail" not in head
        conf = 0.5
        if m_conf:
            try:
                conf = float(m_conf.group(1))
            except (TypeError, ValueError):
                conf = 0.5
        return passed, max(0.0, min(1.0, conf))

    # ------------------------------------------------------------------ structural

    def _structural(self, finding: Dict[str, Any]) -> JudgeResult:
        evidence = str(finding.get("evidence", "")
                       or finding.get("detail", "") or "")
        endpoint = str(finding.get("endpoint", "")
                       or finding.get("url", "") or "")
        severity = str(finding.get("severity", "")
                       or finding.get("priority", "") or "medium").lower()
        fix = str(finding.get("fix", "")
                  or finding.get("remediation", "") or "")
        title = str(finding.get("title", "")
                    or finding.get("name", "") or "")
        payload = str(finding.get("payload", "")
                      or finding.get("reproducer", "")
                      or finding.get("exploit", "")
                      or finding.get("signature", ""))

        evidence_score = self._score_evidence(evidence, payload)
        endpoint_score = 1.0 if endpoint else 0.0
        severity_score = self._score_severity(severity, finding)
        fix_score = 1.0 if fix and len(fix) > 10 else 0.0
        title_score = 1.0 if title and len(title) > 3 else 0.0

        # Weighted average; bias towards evidence because that is the
        # primary signal for "is this a real bug or a false positive".
        confidence = (
            0.45 * evidence_score
            + 0.20 * endpoint_score
            + 0.15 * severity_score
            + 0.10 * fix_score
            + 0.10 * title_score
        )
        confidence = max(0.0, min(1.0, confidence))
        passed = confidence >= 0.45
        reasoning = self._format_reasoning(
            evidence_score, endpoint_score, severity_score,
            fix_score, title_score, evidence, endpoint,
        )
        return JudgeResult(
            passed=passed,
            confidence=confidence,
            reasoning=reasoning,
            backend="structural",
            model="structural-rubric-v1",
            rubric={
                "schema": SCHEMA,
                "criteria": {
                    "evidence_observable": round(evidence_score, 3),
                    "endpoint_reachable": round(endpoint_score, 3),
                    "severity_appropriate": round(severity_score, 3),
                    "remediation_concrete": round(fix_score, 3),
                    "title_present": round(title_score, 3),
                },
            },
        )

    def _score_evidence(self, evidence: str, payload: str) -> float:
        text = f"{evidence}\n{payload}"
        if not text.strip():
            return 0.05
        hits = sum(1 for p in _STRONG_EVIDENCE_PATTERNS if p.search(text))
        length_bonus = min(1.0, len(text) / 200.0)
        return min(1.0, 0.25 * hits + 0.5 * length_bonus)

    def _score_severity(self, severity: str, finding: Dict[str, Any]) -> float:
        rank = _SEVERITY_RANK.get(severity.lower(), -1)
        if rank < 0:
            return 0.3
        # A real evidence string is required for a high severity to
        # count as appropriate; an empty evidence with "critical" is
        # a smell.
        if rank >= 3 and not finding.get("evidence"):
            return 0.4
        return 1.0

    @staticmethod
    def _format_reasoning(
        ev: float, ep: float, sev: float, fix: float, title: float,
        evidence: str, endpoint: str,
    ) -> str:
        parts: List[str] = []
        if ev < 0.2:
            parts.append("evidence is thin or absent — re-run probe with concrete repro")
        elif ev < 0.5:
            parts.append("evidence is partial — strengthen with response/status markers")
        else:
            parts.append("evidence includes concrete response signals")
        if ep < 0.5:
            parts.append("endpoint missing — attach target URL")
        if sev < 0.5:
            parts.append("severity may be inflated for the available evidence")
        if fix < 0.5:
            parts.append("remediation is missing or too generic — describe the fix")
        if title < 0.5:
            parts.append("title is missing — name the bug class")
        if not parts:
            parts.append("all rubric criteria pass")
        snippet = (evidence or "").strip().replace("\n", " ")
        if snippet:
            parts.append(f"evidence: {snippet[:120]!r}")
        if endpoint:
            parts.append(f"target: {endpoint}")
        return "; ".join(parts)

    # ------------------------------------------------------------------ prompt

    @staticmethod
    def _build_prompt(finding: Dict[str, Any]) -> str:
        return (
            "You are a security finding judge. Reply in the form "
            "'VERDICT: PASS|FAIL' then a line 'CONFIDENCE: 0.x' then a "
            "single short rationale paragraph.\n\n"
            "Finding:\n"
            f"{json.dumps(finding, default=str, ensure_ascii=False)[:4000]}\n"
        )


__all__ = ["SCHEMA", "JudgeResult", "LLMJudge"]
