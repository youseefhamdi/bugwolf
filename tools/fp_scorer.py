#!/usr/bin/env python3
"""
## Source: bugwolf M-4 audit finding (5xx-as-sqli FP) -- internal remediation spec
## Source: gobypass403 core/engine/result.go (false-positive heuristic constants)
## Source: NoMoreForbidden nomoreforbidden/core/scorer.py (12-signal weighted score)
## License: MIT (gobypass403, NoMoreForbidden) + bugwolf-internal spec
## Port: 2026-09-05

12-signal weighted false-positive scorer.

Closes the M-4 audit finding: probes that return a generic 5xx with no
SQL error signature were previously auto-tagged as ``sqli`` -- the
scorer fixes that by giving a *strong negative* weight to the presence
of a known error signature and a *strong positive* weight to a 5xx
with no signature (i.e. likely a transport error, not an injection).

Weight summary (from the plan, Appendix H + M-4 fix):

  +30   status_delta_neutral       (5xx with no body signature)
  -25   body_signature_present     (presence of SQL error signature)
  +10   time_baseline_match        (response time matches baseline)
   +8   header_anomaly             (CF/IIS-set cookies, etc.)
   +5   content_length_delta_neutral
  -10   method_allowed             (method is on the allowlist)
  -15   scope_allow                (URL inside operator scope)
  +20   waf_detected               (response carries WAF markers)
  +25   duplicate_endpoint         (same endpoint already flagged)
  -30   payload_in_response_echo   (payload bytes echoed back)
  +10   response_diff_neutral      (body is identical to baseline)
  -50   operator_confirmed         (operator manually confirmed)

Score >= 40  -> false positive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class FPEvalInput:
    """Single-call evaluation bundle.

    Each field corresponds to one signal in :attr:`FPScorer.WEIGHTS`.
    Missing fields default to ``None`` (treated as 0 contribution).
    """

    status: int = 0
    baseline_status: Optional[int] = None
    body_signature_match: bool = False
    time_baseline_match: bool = False
    header_anomaly: bool = False
    content_length_delta_neutral: bool = False
    method_allowed: bool = False
    scope_allow: bool = False
    waf_detected: bool = False
    duplicate_endpoint: bool = False
    payload_in_response_echo: bool = False
    response_diff_neutral: bool = False
    operator_confirmed: bool = False


class FPScorer:
    """Weighted false-positive scorer (12 signals)."""

    WEIGHTS: dict = {
        "status_delta_neutral": 30,
        "body_signature_present": -25,
        "time_baseline_match": 10,
        "header_anomaly": 8,
        "content_length_delta_neutral": 5,
        "method_allowed": -10,
        "scope_allow": -15,
        "waf_detected": 20,
        "duplicate_endpoint": 25,
        "payload_in_response_echo": -30,
        "response_diff_neutral": 10,
        "operator_confirmed": -50,
    }

    FP_THRESHOLD: int = 40

    def score(self, *, eval_input: FPEvalInput) -> float:
        """Compute the weighted FP score (0..n, can exceed 100 in theory).

        The 0..100 normalization is the caller's responsibility -- we
        return the raw sum so callers can choose their own threshold.
        """
        s = 0
        if (
            eval_input.status >= 500
            and eval_input.baseline_status is not None
            and eval_input.status == eval_input.baseline_status
            and not eval_input.body_signature_match
        ):
            s += self.WEIGHTS["status_delta_neutral"]
        if eval_input.body_signature_match:
            s += self.WEIGHTS["body_signature_present"]
        if eval_input.time_baseline_match:
            s += self.WEIGHTS["time_baseline_match"]
        if eval_input.header_anomaly:
            s += self.WEIGHTS["header_anomaly"]
        if eval_input.content_length_delta_neutral:
            s += self.WEIGHTS["content_length_delta_neutral"]
        if eval_input.method_allowed:
            s += self.WEIGHTS["method_allowed"]
        if eval_input.scope_allow:
            s += self.WEIGHTS["scope_allow"]
        if eval_input.waf_detected:
            s += self.WEIGHTS["waf_detected"]
        if eval_input.duplicate_endpoint:
            s += self.WEIGHTS["duplicate_endpoint"]
        if eval_input.payload_in_response_echo:
            s += self.WEIGHTS["payload_in_response_echo"]
        if eval_input.response_diff_neutral:
            s += self.WEIGHTS["response_diff_neutral"]
        if eval_input.operator_confirmed:
            s += self.WEIGHTS["operator_confirmed"]
        return float(s)

    def score_from_kwargs(self, **kwargs) -> float:
        """Convenience wrapper around :meth:`score` accepting keyword args.

        Unknown keys raise ``TypeError`` (no silent acceptance).
        """
        valid = {f.name for f in FPEvalInput.__dataclass_fields__.values()}
        unknown = set(kwargs) - valid
        if unknown:
            raise TypeError(
                f"score_from_kwargs() got unexpected keyword arguments: "
                f"{sorted(unknown)}"
            )
        eval_input = FPEvalInput(**kwargs)
        return self.score(eval_input=eval_input)

    def is_false_positive(self, score: float) -> bool:
        """Return True if ``score >= FP_THRESHOLD``."""
        try:
            return float(score) >= float(self.FP_THRESHOLD)
        except (TypeError, ValueError):
            return False

    def classify(self, eval_input: FPEvalInput) -> dict:
        """Return ``{"score": float, "is_fp": bool, "threshold": int}``."""
        s = self.score(eval_input=eval_input)
        return {
            "score": s,
            "is_fp": self.is_false_positive(s),
            "threshold": self.FP_THRESHOLD,
        }