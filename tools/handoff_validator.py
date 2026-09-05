"""
Handoff schema validation against ground truth.

Per machinist's `foreman.md:76`:
  'Verify every handoff against the worktree, Git, and GitHub.'

Per the self-correction article:
  'The Judge needs ground truth, not just an opinion.'
  'A Judge Verdict needs a defined format, so the receiving role is not
   parsing loose prose and guessing at what matters.'
"""
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class HandoffSchema:
    """Schema definition for a structured handoff.

    Following the self-correction article's recommended structure:
      BUILDER OUTPUT FORMAT:
        Deliverable: [the actual output]
        Confidence: [high / medium / low]
        Known uncertainties: [anything you are unsure about]
        Assumptions made: [anything you assumed without being told]

      JUDGE VERDICT FORMAT:
        Verdict: [PASS / FAIL / NEEDS REVISION]
        Checked against: [the specific standard used]
        Specific issues found: [exact problems, not general impression]
        Confidence: [high / medium / low]
    """
    name: str
    required_fields: list[str] = field(default_factory=list)
    ground_truth_fields: list[str] = field(default_factory=list)


HANDOFF_SCHEMAS = {
    "build": HandoffSchema(
        name="## Build handoff",
        required_fields=[
            "branch", "worktree", "base_sha", "head_sha",
            "commits", "changed_files", "checks",
        ],
        ground_truth_fields=["branch", "base_sha", "head_sha"],
    ),
    "review": HandoffSchema(
        name="## Review handoff",
        required_fields=[
            "verdict", "reviewed_head", "reviewed_base",
            "criterion_evidence", "checks", "current_findings",
        ],
        ground_truth_fields=["reviewed_head", "verdict"],
    ),
    "repair": HandoffSchema(
        name="## Repair handoff",
        required_fields=[
            "attempt", "prior_head", "new_head", "repair_commit",
            "findings_disposition", "changed_files", "checks",
        ],
        ground_truth_fields=["prior_head", "new_head"],
    ),
    "planning": HandoffSchema(
        name="## Planning handoff",
        required_fields=[
            "updated_title", "required_sections", "issue_update_time",
            "unresolved_decisions",
        ],
        ground_truth_fields=["issue_update_time"],
    ),
    "judge_verdict": HandoffSchema(
        name="Judge verdict",
        required_fields=[
            "verdict", "checked_against", "specific_issues", "confidence",
        ],
        ground_truth_fields=["verdict"],
    ),
    "engagement_state": HandoffSchema(
        name="Engagement state (STATE.md per machinist foreman.md:40-44)",
        required_fields=[
            "stage", "branch", "worktree", "base_sha", "head_sha",
            "locally_approved_sha", "pull_request_url", "checks",
            "review_verdict", "repair_count",
        ],
        ground_truth_fields=["branch", "base_sha", "head_sha"],
    ),
}


class HandoffValidator:
    """Validates structured handoffs against their schema + ground truth.

    Per the self-correction article:
      'Letting the Judge see only the Builder's output, with no independent
       reference. This is the single most common mistake, and it silently
       turns your system from a correctness check into a coherence check.'
    """

    def __init__(self):
        self.logger = logging.getLogger("bugwolf.handoff")

    def validate(
        self,
        handoff_type: str,
        handoff: dict,
        ground_truth_provider: Optional[Callable] = None,
    ) -> list[str]:
        """Returns list of validation errors (empty if valid).

        Args:
            handoff_type: One of HANDOFF_SCHEMAS keys.
            handoff: The handoff dict to validate.
            ground_truth_provider: callable(field_name) -> actual_value.
                If None, only schema validation runs (no ground-truth check).
        """
        errors = []
        schema = HANDOFF_SCHEMAS.get(handoff_type)
        if schema is None:
            return [f"unknown handoff_type {handoff_type!r}"]

        # Schema check (per the self-correction article: "defined format")
        for field_name in schema.required_fields:
            if field_name not in handoff:
                errors.append(f"missing required field: {field_name}")
                continue
            value = handoff[field_name]
            if value is None:
                errors.append(f"required field is None: {field_name}")
            elif isinstance(value, (list, dict)) and len(value) == 0:
                errors.append(f"required field is empty: {field_name}")

        # Ground-truth check (per the article: "independent reference")
        if ground_truth_provider is not None:
            for field_name in schema.ground_truth_fields:
                claimed = handoff.get(field_name)
                if claimed is None:
                    continue  # Already reported by schema check
                try:
                    actual = ground_truth_provider(field_name)
                except Exception as exc:
                    errors.append(
                        f"ground-truth provider failed for {field_name}: {exc}"
                    )
                    continue
                if claimed != actual:
                    errors.append(
                        f"ground truth mismatch on {field_name}: "
                        f"handoff claims {claimed!r}, ground truth is {actual!r}"
                    )

        self.logger.info(
            f"handoff.validate type={handoff_type} errors={len(errors)}"
        )
        return errors

    def require_pass(
        self,
        handoff_type: str,
        handoff: dict,
        ground_truth_provider: Optional[Callable] = None,
    ) -> None:
        """Validate and raise HandoffValidationError if any errors."""
        errors = self.validate(handoff_type, handoff, ground_truth_provider)
        if errors:
            raise HandoffValidationError(
                handoff_type=handoff_type,
                handoff=handoff,
                errors=errors,
            )


class HandoffValidationError(Exception):
    """Raised when a handoff fails schema + ground-truth validation."""

    def __init__(self, handoff_type: str, handoff: dict, errors: list[str]):
        self.handoff_type = handoff_type
        self.handoff = handoff
        self.errors = errors
        super().__init__(
            f"handoff {handoff_type!r} failed validation: {'; '.join(errors)}"
        )


# --- Default ground-truth providers for bugwolf's existing files ---

def git_branch_ground_truth(field_name: str) -> str:
    """Ground truth: actual git branch state.

    Per machinist foreman.md:76:
      'Verify every handoff against the worktree, Git, and GitHub.'
    """
    import subprocess
    if field_name == "branch":
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=False,
        )
        return result.stdout.strip()
    if field_name in ("base_sha", "head_sha"):
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
        )
        return result.stdout.strip()
    raise KeyError(f"no git ground truth for {field_name!r}")


def scope_ground_truth(field_name: str) -> str:
    """Ground truth: actual scope state from tools/runtime/scope.py."""
    from tools.runtime.scope import current_target
    if field_name == "scope":
        return current_target()
    raise KeyError(f"no scope ground truth for {field_name!r}")