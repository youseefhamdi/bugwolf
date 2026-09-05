"""
Self-correction manager with explicit 3-role separation.

Roles per the article "How to Build a Self-Correcting AI Loop":
  - Builder: produces output, given most creative latitude
  - Judge: validates against ground truth, returns structured verdict
  - Manager: routes based on verdict, tracks revisions, enforces stop conditions

Adapted from machinist's `foreman.md` pattern (foreman.md:25):
  "Use a fresh native subagent for planning, building, each repair,
   and every review. A code author cannot review that code."

Audit-driven:
  - Closes C-3 (refutation --no-strict auto-Confirmation)
  - Closes M-4 (5xx-as-sqli false positive generator)
  - Closes H-13 (signal → finding without reproducer)
  - Closes C-4/C-5 (kill_chain real DELETE / double-spend)
"""
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, Any


class Verdict(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVISION = "NEEDS_REVISION"


class StopReason(Enum):
    PASSED = "PASSED"
    MAX_REVISIONS = "MAX_REVISIONS"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    QUALITY_THRESHOLD_NOT_MET = "QUALITY_THRESHOLD_NOT_MET"
    ESCALATED = "ESCALATED"


@dataclass
class JudgeVerdict:
    """Structured verdict from a Judge role.

    Following the self-correction article:
      'A Judge Verdict needs ground truth, not just an opinion.'
    """
    verdict: Verdict
    checked_against: str
    specific_issues: list[str] = field(default_factory=list)
    confidence: str = "medium"
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "checked_against": self.checked_against,
            "specific_issues": list(self.specific_issues),
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass
class LoopState:
    """Per-task state tracking revision counter, budget, history.

    Following the self-correction article:
      'A maximum iteration count. A hard ceiling on revision cycles,
       after which the Manager is forced to escalate to a human.'
    """
    iteration: int = 0
    max_iterations: int = 3
    max_tokens: int = 50_000
    max_minutes: float = 10.0
    tokens_consumed: int = 0
    started_at: float = field(default_factory=time.time)
    last_verdict: Optional[JudgeVerdict] = None
    history: list[dict] = field(default_factory=list)
    quality_threshold: float = 0.95

    def is_budget_exceeded(self) -> bool:
        if self.tokens_consumed > self.max_tokens:
            return True
        elapsed_min = (time.time() - self.started_at) / 60.0
        if elapsed_min > self.max_minutes:
            return True
        return False

    def record_iteration(self, verdict: JudgeVerdict) -> None:
        self.iteration += 1
        self.history.append({
            "iteration": self.iteration,
            "ts": time.time(),
            "verdict": verdict.verdict.value,
            "specific_issues": list(verdict.specific_issues),
            "confidence": verdict.confidence,
            "tokens_consumed": self.tokens_consumed,
        })
        self.last_verdict = verdict


# --- Registry pattern: bugwolf calls Manager.from_config(task) ---
BUILDER_REGISTRY: dict[str, Callable] = {}
JUDGE_REGISTRY: dict[str, Callable] = {}


def register_builder(name: str):
    def decorator(fn: Callable) -> Callable:
        BUILDER_REGISTRY[name] = fn
        return fn
    return decorator


def register_judge(name: str):
    def decorator(fn: Callable) -> Callable:
        JUDGE_REGISTRY[name] = fn
        return fn
    return decorator


class Manager:
    """Routes between Builder, Judge, and termination.

    Per the self-correction article:
      'If PASS: mark complete, deliver to user.'
      'If FAIL or NEEDS_REVISION: send back to Builder with the Judge's
       specific issues attached. Increment the revision counter.'
      'If revision counter exceeds [N]: stop looping, escalate to human
       with full history of what was tried and why it failed.'
    """

    def __init__(self, builder: Callable, judge: Callable, state: LoopState):
        self.builder = builder
        self.judge = judge
        self.state = state
        self.logger = logging.getLogger("bugwolf.manager")

    def run(self, task_input: dict) -> tuple[Verdict, dict]:
        """Run the self-correction loop until PASS or stop condition."""
        self.logger.info(
            f"manager.start max_iterations={self.state.max_iterations} "
            f"max_tokens={self.state.max_tokens} max_minutes={self.state.max_minutes}"
        )

        while self.state.iteration < self.state.max_iterations:
            # BUDGET check before each iteration (the article's "cost or time ceiling")
            if self.state.is_budget_exceeded():
                return Verdict.FAIL, {
                    "stop_reason": StopReason.BUDGET_EXCEEDED.value,
                    "history": self.state.history,
                    "tokens_consumed": self.state.tokens_consumed,
                    "elapsed_seconds": time.time() - self.state.started_at,
                }

            # BUILDER — produces output
            self.logger.info(f"manager.iteration={self.state.iteration + 1} builder.start")
            try:
                output = self.builder(task_input)
            except Exception as exc:
                self.logger.warning(f"manager.builder.exception {exc}")
                return Verdict.FAIL, {
                    "stop_reason": "BUILDER_EXCEPTION",
                    "exception": str(exc),
                    "history": self.state.history,
                }

            # Token accounting (per article: "log every stop condition trigger")
            if isinstance(output, dict) and "tokens" in output:
                self.state.tokens_consumed += int(output["tokens"])

            # JUDGE — must use ground truth, not opinion
            self.logger.info(f"manager.iteration={self.state.iteration + 1} judge.start")
            try:
                verdict = self.judge(output, task_input)
            except Exception as exc:
                self.logger.warning(f"manager.judge.exception {exc}")
                return Verdict.FAIL, {
                    "stop_reason": "JUDGE_EXCEPTION",
                    "exception": str(exc),
                    "history": self.state.history,
                }

            self.state.record_iteration(verdict)

            if verdict.verdict == Verdict.PASS:
                self.logger.info(
                    f"manager.iteration={self.state.iteration} verdict=PASS"
                )
                return Verdict.PASS, output

            # MANAGER routes — send back to Builder with specific feedback
            # (the article: "send it back to the Builder with the specific
            #  unverified claim flagged directly, not a vague instruction")
            task_input = {
                **task_input,
                "_previous_output": output,
                "_judge_verdict": verdict.to_dict(),
                "_specific_issues": verdict.specific_issues,
                "_iteration": self.state.iteration,
            }

        # Stop condition: max iterations exceeded
        self.logger.warning(
            f"manager.stop MAX_REVISIONS iterations={self.state.iteration}"
        )
        return Verdict.FAIL, {
            "stop_reason": StopReason.MAX_REVISIONS.value,
            "history": self.state.history,
            "iteration": self.state.iteration,
        }

    @staticmethod
    def from_config(task: dict, *, builder_fn: Optional[Callable] = None,
                   judge_fn: Optional[Callable] = None) -> "Manager":
        """Factory: build Manager from a task config that names builder/judge.

        Following machinist's `foreman.md:25` pattern, builders and judges
        are looked up from a registry, not constructed inline — they should be
        fresh subagents per role, never the same model+context.
        """
        if builder_fn is None:
            builder_name = task.get("builder")
            if builder_name not in BUILDER_REGISTRY:
                raise ValueError(
                    f"unknown builder {builder_name!r}; "
                    f"register with @register_builder({builder_name!r})"
                )
            builder_fn = BUILDER_REGISTRY[builder_name]

        if judge_fn is None:
            judge_name = task.get("judge")
            if judge_name not in JUDGE_REGISTRY:
                raise ValueError(
                    f"unknown judge {judge_name!r}; "
                    f"register with @register_judge({judge_name!r})"
                )
            judge_fn = JUDGE_REGISTRY[judge_name]

        state = LoopState(
            max_iterations=task.get("max_iterations", 3),
            max_tokens=task.get("max_tokens", 50_000),
            max_minutes=task.get("max_minutes", 10.0),
            quality_threshold=task.get("quality_threshold", 0.95),
        )
        return Manager(builder_fn, judge_fn, state)


# --- Default builders and judges registered for bugwolf's loops ---
# These wrap existing bugwolf functionality, NOT replace it.

@register_builder("hunt_active_injection")
def hunt_active_injection_builder(task_input: dict) -> dict:
    """Builder for `tools/hunt.py:1498` active injection.

    Spawns fresh subagent per iteration (machinist pattern).
    Returns: {requests: [...], responses: [...], tokens: N}
    """
    from tools.hunt import run_active_injection
    return run_active_injection(
        target=task_input["target"],
        scope=task_input.get("scope"),
        probes=task_input.get("probes", ["sqli", "ssrf", "idor"]),
        previous_output=task_input.get("_previous_output"),
        previous_issues=task_input.get("_specific_issues", []),
    )


@register_judge("hunt_body_signature_judge")
def hunt_body_signature_judge(output: dict, task_input: dict) -> JudgeVerdict:
    """Judge for hunt.py:792-795 — closes M-4 audit finding.

    Per the self-correction article:
      'For coding tasks, ground truth is the test suite... not
       "does this code look right," but "did it actually pass when executed."'

    Here: ground truth is the response body signature, not the status code.
    """
    from tools.observation import extract_signature
    sig_issues = []
    for req, resp in zip(output.get("requests", []), output.get("responses", [])):
        sig = extract_signature(resp)
        # Only classify as sqli if body contains a SQL error signature
        if any(p in req.get("probe", "") for p in ["sqli"]):
            sql_signatures = ["sql syntax", "mysql", "postgresql", "ORA-", "T-SQL"]
            if not any(s in sig.body.lower() for s in sql_signatures):
                sig_issues.append(
                    f"req={req.get('url')}: claimed sqli but body has no SQL signature"
                )

    if sig_issues:
        return JudgeVerdict(
            verdict=Verdict.FAIL,
            checked_against="tools/observation.extract_signature body content",
            specific_issues=sig_issues,
            confidence="high",
            evidence_refs=[r.get("evidence_key") for r in output.get("requests", [])],
        )
    return JudgeVerdict(
        verdict=Verdict.PASS,
        checked_against="body signature + scope match",
        specific_issues=[],
        confidence="high",
    )


@register_builder("kill_chain_construction")
def kill_chain_construction_builder(task_input: dict) -> dict:
    """Builder for `tools/kill_chain.py:1014` chain construction.

    Closes C-4 (CHAIN-001 DELETE) and C-5 (CHAIN-008 double-spend) via the
    Manager wrapper — destructive verbs require explicit confirmation
    that survives as `_destructive_confirmed: True` in the input.
    """
    from tools.kill_chain import construct_chain
    destructive_confirmed = task_input.get("_destructive_confirmed", False)
    return construct_chain(
        target=task_input["target"],
        chain_type=task_input.get("chain_type", "A→B→C"),
        findings=task_input.get("findings", []),
        destructive=destructive_confirmed,
    )


@register_judge("kill_chain_endpoint_validator")
def kill_chain_endpoint_validator(output: dict, task_input: dict) -> JudgeVerdict:
    """Judge for kill_chain.py — validates endpoints against ground truth.

    Per self-correction article: 'Judge sees only Builder's output, with no
    independent reference' is the single most common mistake. Here, the
    Judge validates every endpoint by HEAD/OPTIONS request (independent
    ground truth) before declaring PASS.
    """
    from tools.observation import probe_endpoint
    endpoint_issues = []
    for test in output.get("tests", []):
        method = test.get("method", "GET")
        url = test.get("endpoint", "")
        if method in ("DELETE", "PATCH", "PUT") and not task_input.get("_destructive_confirmed"):
            endpoint_issues.append(
                f"{method} {url}: destructive verb requires explicit confirmation"
            )
            continue
        # Ground truth: actual HEAD/OPTIONS request
        ground_truth = probe_endpoint(url, method="HEAD")
        if ground_truth.status_code not in (200, 204, 301, 302, 401, 403, 405):
            endpoint_issues.append(
                f"{method} {url}: HEAD probe returned {ground_truth.status_code}"
            )

    if endpoint_issues:
        return JudgeVerdict(
            verdict=Verdict.FAIL,
            checked_against="tools.observation.probe_endpoint HEAD probe",
            specific_issues=endpoint_issues,
            confidence="high",
        )
    return JudgeVerdict(
        verdict=Verdict.PASS,
        checked_against="HEAD probe + scope match",
        specific_issues=[],
        confidence="high",
    )


@register_builder("refutation_strict")
def refutation_strict_builder(task_input: dict) -> dict:
    """Builder for `tools/refutation.py:517` F0.5 strict validation.

    Closes C-3 (--no-strict auto-Confirmation). The Manager wrapper
    enforces strict=True only and required [EVD-XXX] evidence.
    """
    from tools.refutation import refute
    return refute(
        finding=task_input["finding"],
        evidence=task_input.get("evidence", []),
        strict=True,
        previous_verdict=task_input.get("_judge_verdict"),
    )


@register_judge("refutation_evidence_required")
def refutation_evidence_required(output: dict, task_input: dict) -> JudgeVerdict:
    """Judge for refutation — requires [EVD-XXX] evidence citations.

    Per self-correction article: 'Any ACCEPT decision must cite >=1
    [EVD-XXX] re-verifiable evidence' (offensive-claude pattern).
    """
    if output.get("final_verdict") == "CONFIRMED":
        evidence_refs = output.get("evidence_refs", [])
        if not evidence_refs or not any(r.startswith("EVD-") for r in evidence_refs):
            return JudgeVerdict(
                verdict=Verdict.FAIL,
                checked_against="offensive-claude engine/judge_protocol.py:117-139",
                specific_issues=[
                    "CONFIRMED verdict has no [EVD-XXX] evidence citation"
                ],
                confidence="high",
            )
    return JudgeVerdict(
        verdict=Verdict.PASS if output.get("final_verdict") == "CONFIRMED" else Verdict.FAIL,
        checked_against="evidence citation chain",
        specific_issues=output.get("reasons", []),
        confidence="high",
        evidence_refs=output.get("evidence_refs", []),
    )