"""
Stress tests for tools/manager.py — the 4 tests from
"How to Build a Self-Correcting AI Loop" article.

1. test_unsolvable_task_escalates — given impossible task, Manager must hit
   iteration ceiling + escalate (NOT spin forever)
2. test_confidently_wrong_caught — given known-wrong output, Judge with
   ground truth must catch it (NOT pass through)
3. test_same_model_blind_spot — Judge using same model+context as Builder
   must NOT catch the model's characteristic blind spots
4. test_cost_runaway — worst-case path must not exceed budget ceiling
"""
import pytest
from tools.manager import (
    Manager, JudgeVerdict, LoopState, Verdict, StopReason,
    register_builder, register_judge, BUILDER_REGISTRY, JUDGE_REGISTRY,
)


# --- Test 1: Unsolvable task test ---

@register_builder("fail_always")
def fail_always_builder(task_input: dict) -> dict:
    """Always returns output that the Judge must reject."""
    return {"output": "always wrong", "tokens": 100}


@register_judge("always_strict")
def always_strict_judge(output: dict, task_input: dict) -> JudgeVerdict:
    return JudgeVerdict(
        verdict=Verdict.FAIL,
        checked_against="test",
        specific_issues=["always fails"],
        confidence="high",
    )


def test_unsolvable_task_escalates():
    """Given an impossible task, Manager must hit iteration ceiling + escalate.

    Per article: 'The unsolvable task test. Deliberately give the Builder a
    task it cannot complete to the Judge's standard, on purpose. Does the
    Manager correctly hit the iteration ceiling and escalate to a human,
    or does it spin indefinitely, burning cost on a task that was never
    going to succeed.'
    """
    manager = Manager(
        builder=fail_always_builder,
        judge=always_strict_judge,
        state=LoopState(max_iterations=3),
    )
    verdict, output = manager.run({"task": "prove P=NP"})

    assert verdict == Verdict.FAIL, "Manager must return FAIL on unsolvable task"
    assert output["stop_reason"] == StopReason.MAX_REVISIONS.value, (
        "Manager must hit MAX_REVISIONS, not spin indefinitely"
    )
    assert output["iteration"] == 3, "Manager must stop at max_iterations"
    assert len(output["history"]) == 3, "Manager must record 3 failed iterations"


def test_unsolvable_task_respects_max_iterations_override():
    """Custom max_iterations is respected."""
    manager = Manager(
        builder=fail_always_builder,
        judge=always_strict_judge,
        state=LoopState(max_iterations=5),
    )
    _, output = manager.run({"task": "anything"})
    assert output["iteration"] == 5


# --- Test 2: Confidently wrong test ---

@register_builder("returns_wrong_answer")
def returns_wrong_answer_builder(task_input: dict) -> dict:
    """Returns a confidently-wrong answer (well-formatted but factually wrong)."""
    return {
        "answer": "Paris",
        "question": task_input.get("question"),
        "formatting": "good",
    }


@register_judge("ground_truth_capital")
def ground_truth_capital_judge(output: dict, task_input: dict) -> JudgeVerdict:
    """Judge with INDEPENDENT ground truth (correct capital of Germany)."""
    correct = "Berlin"
    if output.get("answer") == correct:
        return JudgeVerdict(
            verdict=Verdict.PASS,
            checked_against="ground truth: capital of Germany = Berlin",
            specific_issues=[],
            confidence="high",
        )
    return JudgeVerdict(
        verdict=Verdict.FAIL,
        checked_against="ground truth: capital of Germany = Berlin",
        specific_issues=[f"claimed {output.get('answer')!r}, ground truth is {correct!r}"],
        confidence="high",
    )


def test_confidently_wrong_caught():
    """Given known-wrong output, Judge with ground truth MUST catch it.

    Per article: 'The confidently wrong test. Feed the Judge an output you
    already know is subtly wrong... Does the Judge, with its ground truth
    reference, correctly catch it.'
    """
    manager = Manager(
        builder=returns_wrong_answer_builder,
        judge=ground_truth_capital_judge,
        state=LoopState(max_iterations=3),
    )
    verdict, _ = manager.run({"question": "capital of Germany"})
    assert verdict == Verdict.FAIL, "Judge must catch confidently-wrong answer"


def test_coherence_without_ground_truth_fails_to_catch():
    """A Judge WITHOUT ground truth (coherence check only) will pass wrong answer.
    This proves why ground truth is mandatory.
    """
    @register_judge("coherence_only")
    def coherence_only_judge(output: dict, task_input: dict) -> JudgeVerdict:
        # Checks only "does it look well-formatted?" — NO ground truth
        if output.get("formatting") == "good":
            return JudgeVerdict(
                verdict=Verdict.PASS,
                checked_against="coherence only (formatting check)",
                specific_issues=[],
                confidence="low",
            )
        return JudgeVerdict(
            verdict=Verdict.FAIL,
            checked_against="coherence only",
            specific_issues=["formatting bad"],
            confidence="low",
        )

    manager = Manager(
        builder=returns_wrong_answer_builder,
        judge=coherence_only_judge,
        state=LoopState(max_iterations=3),
    )
    verdict, _ = manager.run({"question": "capital of Germany"})
    assert verdict == Verdict.PASS, (
        "Coherence-only Judge passes wrong answer (anti-pattern). "
        "This is why ground truth is MANDATORY."
    )


# --- Test 3: Same-model blind spot test ---

@register_builder("returns_dangerous_code")
def returns_dangerous_code_builder(task_input: dict) -> dict:
    """Returns code containing a known dangerous pattern (rm -rf /)."""
    return {
        "code": "import os\nos.system('rm -rf /')\n",
        "language": "python",
    }


@register_judge("same_model_naive_judge")
def same_model_naive_judge(output: dict, task_input: dict) -> JudgeVerdict:
    """Naive Judge that just checks syntax (does NOT check for dangerous patterns).

    Per article: 'The same-model blind spot test. If your Builder and Judge
    run on the same underlying model, this is worth checking directly.
    Feed the Judge an output containing exactly the kind of mistake that
    model characteristically tends to make. If the Judge waves it through,
    you have built a loop that shares its blind spots between roles.'
    """
    code = output.get("code", "")
    # Naive: just check syntax compiles (not whether it does damage)
    if "import os" in code:
        return JudgeVerdict(
            verdict=Verdict.PASS,
            checked_against="syntax check only",
            specific_issues=[],
            confidence="low",
        )
    return JudgeVerdict(
        verdict=Verdict.FAIL,
        checked_against="syntax check only",
        specific_issues=["no import"],
        confidence="low",
    )


@register_judge("ground_truth_safety_judge")
def ground_truth_safety_judge(output: dict, task_input: dict) -> JudgeVerdict:
    """Strict Judge with EXPLICIT safety ground truth (no dangerous patterns)."""
    code = output.get("code", "")
    dangerous_patterns = ["rm -rf /", "os.system(", "subprocess.call(", "shell=True"]
    issues = [
        f"contains {pat!r}"
        for pat in dangerous_patterns
        if pat in code
    ]
    if issues:
        return JudgeVerdict(
            verdict=Verdict.FAIL,
            checked_against="safety ground truth: no dangerous patterns",
            specific_issues=issues,
            confidence="high",
        )
    return JudgeVerdict(
        verdict=Verdict.PASS,
        checked_against="safety ground truth",
        specific_issues=[],
        confidence="high",
    )


def test_same_model_blind_spot_passes_dangerous_code():
    """Same-model (naive) Judge passes dangerous code — demonstrates the blind spot."""
    manager = Manager(
        builder=returns_dangerous_code_builder,
        judge=same_model_naive_judge,
        state=LoopState(max_iterations=3),
    )
    verdict, _ = manager.run({"task": "delete cache"})
    # This SHOULD fail to demonstrate the blind spot.
    # If a different Judge (with ground truth) catches it, the article is correct.
    assert verdict == Verdict.PASS, (
        "Naive Judge passes dangerous code — the blind spot exists. "
        "This is why we need a Judge with GROUND TRUTH."
    )


def test_ground_truth_judge_catches_dangerous_code():
    """Different Judge with ground truth CATCHES dangerous code."""
    manager = Manager(
        builder=returns_dangerous_code_builder,
        judge=ground_truth_safety_judge,
        state=LoopState(max_iterations=3),
    )
    verdict, _ = manager.run({"task": "delete cache"})
    assert verdict == Verdict.FAIL, (
        "Ground-truth Judge must catch dangerous code"
    )


# --- Test 4: Cost runaway test ---

@register_builder("expensive_call")
def expensive_call_builder(task_input: dict) -> dict:
    """Builder that consumes a lot of 'tokens' per call."""
    return {"tokens": 100_000, "output": "expensive"}


@register_judge("never_passes")
def never_passes_judge(output: dict, task_input: dict) -> JudgeVerdict:
    return JudgeVerdict(
        verdict=Verdict.FAIL,
        checked_against="test",
        specific_issues=["never passes"],
        confidence="high",
    )


def test_cost_runaway_budget_ceiling_fires():
    """Worst-case path must not exceed budget ceiling.

    Per article: 'The cost runaway test. Calculate the worst case path
    through your system, maximum revisions, most expensive model calls
    involved, longest reasonable content length, and work out what that
    actually costs in real dollars and real time. If that number would
    alarm you appearing on an actual invoice, your stop conditions are
    not tight enough yet.'
    """
    manager = Manager(
        builder=expensive_call_builder,
        judge=never_passes_judge,
        state=LoopState(max_iterations=100, max_tokens=150_000),
    )
    verdict, output = manager.run({"task": "infinite loop"})
    # Budget ceiling fires after first iteration (100k > 150k? no — 100k < 150k)
    # Wait — let me set it tight
    manager.state.max_tokens = 50_000  # Tight budget
    verdict, output = manager.run({"task": "infinite loop"})
    assert "BUDGET_EXCEEDED" in str(output.get("stop_reason")), (
        "Budget ceiling must fire BEFORE max iterations when budget is tight"
    )


def test_cost_runway_max_iterations_fires_when_budget_adequate():
    """When budget is generous, max_iterations fires first."""
    manager = Manager(
        builder=expensive_call_builder,
        judge=never_passes_judge,
        state=LoopState(max_iterations=3, max_tokens=10_000_000),
    )
    _, output = manager.run({"task": "infinite loop"})
    assert output["stop_reason"] == StopReason.MAX_REVISIONS.value


# --- Test 5: Manager factory from_config ---

def test_manager_factory_uses_registered_builders_and_judges():
    """Manager.from_config() looks up builders/judges by name."""
    task = {
        "builder": "hunt_active_injection",
        "judge": "hunt_body_signature_judge",
        "max_iterations": 5,
        "max_tokens": 25_000,
    }
    manager = Manager.from_config(task)
    assert manager.builder is BUILDER_REGISTRY["hunt_active_injection"]
    assert manager.judge is JUDGE_REGISTRY["hunt_body_signature_judge"]
    assert manager.state.max_iterations == 5
    assert manager.state.max_tokens == 25_000


def test_manager_factory_raises_on_unknown_builder():
    """Manager.from_config() fails loudly on unknown builder."""
    with pytest.raises(ValueError, match="unknown builder"):
        Manager.from_config({"builder": "nonexistent", "judge": "hunt_body_signature_judge"})


def test_manager_factory_raises_on_unknown_judge():
    with pytest.raises(ValueError, match="unknown judge"):
        Manager.from_config({"builder": "hunt_active_injection", "judge": "nonexistent"})