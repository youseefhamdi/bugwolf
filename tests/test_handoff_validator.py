"""
Tests for tools/handoff_validator.py

Per machinist foreman.md:76:
  'Verify every handoff against the worktree, Git, and GitHub.'

Per self-correction article:
  'The Judge needs ground truth, not just an opinion.'
"""
import pytest
from tools.handoff_validator import (
    HandoffValidator, HandoffValidationError, HANDOFF_SCHEMAS,
    git_branch_ground_truth,
)


def test_valid_build_handoff_passes():
    """A complete build handoff with all required fields passes schema check."""
    validator = HandoffValidator()
    handoff = {
        "branch": "feature/test",
        "worktree": "/tmp/test-worktree",
        "base_sha": "abc123",
        "head_sha": "def456",
        "commits": ["commit1", "commit2"],
        "changed_files": ["file1.py", "file2.py"],
        "checks": {"tests": "passing"},
    }
    errors = validator.validate("build", handoff)
    assert errors == []


def test_missing_required_field_fails():
    """Missing required field → validation error."""
    validator = HandoffValidator()
    handoff = {
        "branch": "feature/test",
        "worktree": "/tmp/test",
        "base_sha": "abc",
        "head_sha": "def",
        # missing commits
        "changed_files": [],
        "checks": {},
    }
    errors = validator.validate("build", handoff)
    assert any("commits" in e for e in errors)


def test_empty_required_field_fails():
    """Empty required field → validation error (the article's "no vague")."""
    validator = HandoffValidator()
    handoff = {
        "branch": "feature/test",
        "worktree": "/tmp/test",
        "base_sha": "abc",
        "head_sha": "def",
        "commits": [],          # EMPTY (article: "no vague")
        "changed_files": [],     # EMPTY
        "checks": {},            # EMPTY
    }
    errors = validator.validate("build", handoff)
    assert len(errors) == 3


def test_ground_truth_mismatch_fails():
    """When handoff claims one value but ground truth says another → fail.

    Per the article: 'A Judge that only sees the Builder's output, with no
    independent reference to check against, can only evaluate internal
    consistency, whether the output seems coherent and well formatted. It
    cannot evaluate correctness.'
    """
    validator = HandoffValidator()

    # Mock ground-truth provider that disagrees with handoff
    def mock_gt(field_name):
        if field_name == "branch":
            return "main"  # Handoff claims "feature/test", ground truth is "main"
        if field_name == "head_sha":
            return "actual_sha_123"
        return None

    handoff = {
        "branch": "feature/test",
        "worktree": "/tmp/test",
        "base_sha": "abc",
        "head_sha": "claimed_sha_456",  # Wrong — ground truth is "actual_sha_123"
        "commits": ["c1"],
        "changed_files": ["f1"],
        "checks": {"t": "p"},
    }
    errors = validator.validate("build", handoff, ground_truth_provider=mock_gt)
    assert any("branch" in e and "ground truth mismatch" in e for e in errors)
    assert any("head_sha" in e and "ground truth mismatch" in e for e in errors)


def test_require_pass_raises_on_validation_error():
    """require_pass() is the strict variant — raises HandoffValidationError."""
    validator = HandoffValidator()
    with pytest.raises(HandoffValidationError) as exc_info:
        validator.require_pass("build", {"branch": "x"})  # missing everything else
    assert "build" in str(exc_info.value)
    assert len(exc_info.value.errors) > 0


def test_unknown_handoff_type_fails():
    """Unknown handoff type → clear error message."""
    validator = HandoffValidator()
    errors = validator.validate("nonexistent_type", {})
    assert any("unknown handoff_type" in e for e in errors)


def test_review_handoff_requires_verdict_field():
    """Review handoff MUST have verdict (the article's structured output)."""
    validator = HandoffValidator()
    errors = validator.validate("review", {
        "reviewed_head": "abc",
        "reviewed_base": "def",
        "criterion_evidence": [],
        "checks": {},
        "current_findings": [],
        # missing verdict
    })
    assert any("verdict" in e for e in errors)


def test_judge_verdict_handoff_requires_three_fields():
    """Judge verdict handoff MUST have verdict, checked_against, specific_issues, confidence.

    Per self-correction article: JUDGE VERDICT FORMAT.
    """
    validator = HandoffValidator()
    errors = validator.validate("judge_verdict", {})
    assert any("verdict" in e for e in errors)
    assert any("checked_against" in e for e in errors)
    assert any("specific_issues" in e for e in errors)
    assert any("confidence" in e for e in errors)


def test_handoff_with_no_ground_truth_provider_still_validates_schema():
    """When no ground truth provider given, only schema is validated.

    Per the article: this is the "coherence check only" mode — useful but
    INSECURE. The test passes but flags this as anti-pattern.
    """
    validator = HandoffValidator()
    handoff = {
        "branch": "any-branch",  # Any value is OK without ground truth
        "worktree": "/tmp",
        "base_sha": "x",
        "head_sha": "y",
        "commits": ["c"],
        "changed_files": ["f"],
        "checks": {"t": "p"},
    }
    errors = validator.validate("build", handoff)  # No ground_truth_provider
    assert errors == []  # Schema passes


# --- Integration: git_branch_ground_truth ---

def test_git_branch_ground_truth_returns_branch():
    """git_branch_ground_truth returns actual git branch name."""
    import os
    import subprocess
    # Use a known repo (current test directory should be in a git repo)
    cwd = os.getcwd()
    if not os.path.exists(os.path.join(cwd, ".git")):
        pytest.skip("not in a git repository")

    branch = git_branch_ground_truth("branch")
    assert isinstance(branch, str)
    # Branch name should not be empty
    assert len(branch) > 0


def test_git_branch_ground_truth_raises_on_unknown_field():
    """Unknown field name raises KeyError."""
    with pytest.raises(KeyError):
        git_branch_ground_truth("nonexistent_field")