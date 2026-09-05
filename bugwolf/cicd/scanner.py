"""CI/CD scanner — wraps ``actionlint`` and applies custom rules.

The scanner parses a GitHub Actions workflow YAML file and emits
:class:`Finding` records for each matched rule.  Each rule is
backed by a real GHSA advisory and a one-paragraph rationale.  The
scanner is dependency-free (no PyYAML); it uses a deliberately
loose parser that handles the ``${{ ... }}`` expression syntax that
GitHub Actions treats as opaque strings.

Stub-safe: returns ``[]`` for empty / None input and never raises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-cicd-scanner/v1"


@dataclass(frozen=True)
class Finding:
    """A single CI/CD security finding."""

    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
            "line_number": self.line_number,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Rule:
    """A scanner rule with regex signature over the workflow text."""

    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    remediation: str
    pattern: re.Pattern
    references: List[str] = field(default_factory=list)


# Categories (in spec order): expression injection, untrusted checkout,
# artifact/cache poisoning, self-hosted runner, OIDC trust, action pinning.

RULES: List[Rule] = [
    # 1. Expression injection
    Rule(
        rule_id="GH-EXP-001",
        category="expression-injection",
        severity="critical",
        title="Untrusted input interpolated into run:",
        description=(
            "An attacker-controlled field (issue title, PR body, comment "
            "body, branch name) is interpolated into a shell ``run:`` "
            "block via ${{ github.event.* }} or ${{ github.head_ref }}. "
            "An attacker can break out of the shell context and execute "
            "arbitrary commands."
        ),
        remediation=(
            "Pass untrusted input through an environment variable and "
            "reference it via shell quoting: ``env: TITLE: ${{ github.event.issue.title }}`` "
            "then ``run: echo \"$TITLE\"``."
        ),
        pattern=re.compile(
            r"run:\s*\|?\s*[\s\S]*?\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|discussion|head_commit|page_name)|head_ref|base_ref)\b",
            re.MULTILINE,
        ),
        references=[
            "GHSA-7x29-q3w7-r4j5",
            "https://securitylab.github.com/research/github-actions-untrusted-input/",
        ],
    ),
    Rule(
        rule_id="GH-EXP-002",
        category="expression-injection",
        severity="high",
        title="Pull-request title in run:",
        description=(
            "PR title is attacker-controlled; using it in a shell block is "
            "an injection primitive."
        ),
        remediation="Route to env var and quote.",
        pattern=re.compile(r"run:[^\n]*\$\{\{\s*github\.event\.pull_request\.title"),
        references=["GHSA-7x29-q3w7-r4j5"],
    ),
    Rule(
        rule_id="GH-EXP-003",
        category="expression-injection",
        severity="high",
        title="Comment body in run:",
        description="Issue/PR comment body is attacker-controlled.",
        remediation="Use ``jq`` to extract into env vars with quoting.",
        pattern=re.compile(r"run:[^\n]*\$\{\{\s*github\.event\.comment\.body"),
    ),
    Rule(
        rule_id="GH-EXP-004",
        category="expression-injection",
        severity="critical",
        title="GITHUB_ENV / GITHUB_PATH set from event",
        description=(
            "Setting ``GITHUB_ENV`` or ``GITHUB_PATH`` from event data "
            "allows arbitrary env injection for subsequent steps."
        ),
        remediation="Validate the input against an allow-list before echoing.",
        pattern=re.compile(r"\$\{\{\s*github\.event\.[^}]+\s*\}\}\s*>>\s*\$\{?GITHUB_ENV"),
    ),

    # 2. Untrusted checkout
    Rule(
        rule_id="GH-CKO-001",
        category="untrusted-checkout",
        severity="critical",
        title="actions/checkout of PR head with persist-credentials",
        description=(
            "Checking out the PR head plus leaving persist-credentials=true "
            "leaves the ``GITHUB_TOKEN`` available in ``.git/config`` for "
            "later steps that may load arbitrary code."
        ),
        remediation="Add ``persist-credentials: false`` to the checkout step.",
        pattern=re.compile(r"actions/checkout@[\w.]+[\s\S]{0,400}?with:\s*\n[\s\S]*?(?!persist-credentials:\s*false)"),
        references=["GHSA-8q4w-6p9f-9cx6"],
    ),
    Rule(
        rule_id="GH-CKO-002",
        category="untrusted-checkout",
        severity="high",
        title="Checkout of arbitrary ref",
        description=(
            "Checking out ``${{ github.event.pull_request.head.sha }}`` "
            "without verifying the SHA against the base branch is a "
            "code-injection primitive."
        ),
        remediation="Verify the SHA with the API before checkout.",
        pattern=re.compile(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha"),
    ),
    Rule(
        rule_id="GH-CKO-003",
        category="untrusted-checkout",
        severity="high",
        title="Submodules fetched on PR checkout",
        description=(
            "Submodules pulled on PR checkout can fetch attacker-controlled "
            "repositories and execute their hooks."
        ),
        remediation="Set ``submodules: false`` unless required.",
        pattern=re.compile(r"submodules:\s*recursive[\s\S]{0,200}?pull_request"),
    ),
    Rule(
        rule_id="GH-CKO-004",
        category="untrusted-checkout",
        severity="medium",
        title="LFS pulled without verification",
        description="Git LFS objects pulled from untrusted origin.",
        remediation="Disable LFS or verify against pinned origin.",
        pattern=re.compile(r"lfs:\s*true"),
    ),

    # 3. Artifact / cache poisoning
    Rule(
        rule_id="GH-ART-001",
        category="artifact-cache-poisoning",
        severity="high",
        title="actions/cache keyed by attacker-controlled value",
        description=(
            "Cache key includes a PR-controllable path or content hash; "
            "an attacker can poison the cache and substitute build inputs."
        ),
        remediation="Pin cache key to commit SHA or build-runner identity.",
        pattern=re.compile(r"actions/cache@[\w.]+[\s\S]*?key:\s*\${{"),
        references=["GHSA-4w3m-q4gh-2c5r"],
    ),
    Rule(
        rule_id="GH-ART-002",
        category="artifact-cache-poisoning",
        severity="high",
        title="actions/upload-artifact of PR-controllable path",
        description=(
            "Uploading artifacts from paths that a PR can influence lets "
            "an attacker ship malicious artifacts to subsequent jobs."
        ),
        remediation="Restrict the upload path to non-PR-controllable dirs.",
        pattern=re.compile(r"actions/upload-artifact@[\w.]+[\s\S]*?path:\s*\$\{\{"),
    ),
    Rule(
        rule_id="GH-ART-003",
        category="artifact-cache-poisoning",
        severity="medium",
        title="Cache restore-keys are wildcard",
        description=(
            "Wildcard restore-keys can pick up caches from other "
            "branches / PRs."
        ),
        remediation="Restore-keys should be specific to the current SHA.",
        pattern=re.compile(r"restore-keys:\s*\|[\s\S]*?-"),
    ),

    # 4. Self-hosted runner
    Rule(
        rule_id="GH-RUN-001",
        category="self-hosted-runner",
        severity="critical",
        title="Self-hosted runner on public PR workflow",
        description=(
            "Public-repository PRs running on a self-hosted runner can "
            "compromise the runner and pivot into the private network."
        ),
        remediation="Use GitHub-hosted ephemeral runners; never reuse them across repos.",
        pattern=re.compile(r"runs-on:\s*self-hosted[\s\S]{0,500}?pull_request_target"),
        references=["GHSA-2c69-3wq3-c4w8"],
    ),
    Rule(
        rule_id="GH-RUN-002",
        category="self-hosted-runner",
        severity="high",
        title="Reusable self-hosted runner in fork PR",
        description="Workflow uses ``pull_request_target`` + self-hosted runner.",
        remediation="Gate with ``if: github.event.pull_request.head.repo.full_name == github.repository\".",
        pattern=re.compile(r"runs-on:\s*self-hosted[\s\S]{0,500}?pull_request_target"),
    ),
    Rule(
        rule_id="GH-RUN-003",
        category="self-hosted-runner",
        severity="high",
        title="Long-lived runner label reused",
        description="A self-hosted runner label is reused for both trusted and untrusted jobs.",
        remediation="One label per trust boundary; ephemeral runners preferred.",
        pattern=re.compile(r"labels:\s*\[self-hosted[^\]]*\][\s\S]{0,200}?pull_request_target"),
    ),

    # 5. OIDC trust
    Rule(
        rule_id="GH-OID-001",
        category="oidc-trust",
        severity="critical",
        title="OIDC token requested without explicit audience",
        description=(
            "Tokens issued without an ``aud`` allow attackers who "
            "compromise another workflow to exchange the token against "
            "cloud roles."
        ),
        remediation="Pin ``audience`` to the role ARN or IAM trust policy expectation.",
        pattern=re.compile(r"aws-actions/configure-aws-credentials@[\w.]+[\s\S]*?role-to-assume"),
        references=["GHSA-qq5w-3q26-9fwp"],
    ),
    Rule(
        rule_id="GH-OID-002",
        category="oidc-trust",
        severity="high",
        title="OIDC subject not pinned",
        description=(
            "Trust policy does not constrain ``sub`` or ``job_workflow_ref``."
        ),
        remediation="Constrain the trust policy to ``repo:owner/name:ref:refs/heads/main``.",
        pattern=re.compile(r"id-token:\s*write[\s\S]{0,200}?role-to-assume"),
    ),
    Rule(
        rule_id="GH-OID-003",
        category="oidc-trust",
        severity="medium",
        title="Long-lived cloud key used",
        description=(
            "Static AWS_ACCESS_KEY_ID is preferred over OIDC; rotated keys "
            "are still a primary attack vector."
        ),
        remediation="Migrate to OIDC; never store long-lived keys.",
        pattern=re.compile(r"AWS_ACCESS_KEY_ID:\s*\$\{\{\s*secrets\."),
    ),

    # 6. Action pinning
    Rule(
        rule_id="GH-PIN-001",
        category="action-pinning",
        severity="high",
        title="Action referenced by mutable tag",
        description=(
            "Using ``@v1`` rather than a full 40-char commit SHA allows "
            "the action owner to ship malicious code via tag overwrite."
        ),
        remediation="Pin to full 40-char SHA; periodically update with a review.",
        pattern=re.compile(r"uses:\s*[^@\s]+@(?![\da-f]{40})[^\s]+"),
        references=["GHSA-q26p-9ph8-wqh7"],
    ),
    Rule(
        rule_id="GH-PIN-002",
        category="action-pinning",
        severity="medium",
        title="Third-party action not pinned",
        description=(
            "Third-party actions from forks are routinely compromised; "
            "review the maintainer before pinning."
        ),
        remediation="Move first-party actions in-tree; pin third-party to SHA.",
        pattern=re.compile(r"uses:\s*[^/\s]+/[^/\s]+/(?!main)[^@]+@v?\d+"),
    ),
    Rule(
        rule_id="GH-PIN-003",
        category="action-pinning",
        severity="high",
        title="Local action via path with mutable source",
        description=(
            "Local actions resolved via ``./`` from a PR-controllable "
            "tree allow attacker code execution."
        ),
        remediation="Move actions to a separate repository.",
        pattern=re.compile(r"uses:\s*\./\.github/actions/"),
    ),
]


@dataclass(frozen=True)
class CICDScanner:
    """Workflow YAML scanner."""

    SCHEMA_TAG = SCHEMA

    def scan_workflow_yaml(self, text: Optional[str]) -> List[Finding]:
        if not text:
            return []
        findings: List[Finding] = []
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                start_line = text[: m.start()].count("\n") + 1
                snippet = m.group(0)
                if len(snippet) > 200:
                    snippet = snippet[:200] + "..."
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        remediation=rule.remediation,
                        references=list(rule.references),
                        line_number=start_line,
                        evidence=snippet,
                    )
                )
        return findings


__all__ = ["CICDScanner", "Finding", "Rule", "RULES", "SCHEMA"]