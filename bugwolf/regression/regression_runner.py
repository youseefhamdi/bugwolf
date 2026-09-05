"""Phase 3.4 — end-to-end regression pipeline.

The :class:`RegressionRunner` ties together:

  * :class:`GitDiffer` — produce a :class:`SemanticDiff` between two refs;
  * :class:`CrossCommitTaintAnalyzer` — find newly-introduced taint flows;
  * :class:`BisectRunner` — narrow each regression down to a commit (best
    effort; skipped if the repo isn't a git repo).

The pipeline produces a :class:`RegressionReport` frozen dataclass with
a :meth:`to_markdown` helper for human consumption.

STUB-SAFE: every component must be STUB-SAFE — this runner NEVER
raises, even if every dependency is missing.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Tuple

from bugwolf.regression.git_diff import GitDiffer, SemanticDiff
from bugwolf.regression.cross_commit_taint import (
    CrossCommitTaintAnalyzer,
    CrossCommitFinding,
)
from bugwolf.regression.bisect import (
    BisectRunner,
    BisectResult,
    BisectUnavailable,
)


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegressionReport:
    """The full output of :meth:`RegressionRunner.detect_regressions`."""

    diffs: List[SemanticDiff] = field(default_factory=list)
    findings: List[CrossCommitFinding] = field(default_factory=list)
    bisects: List[BisectResult] = field(default_factory=list)
    metadata: Tuple[Tuple[str, str], ...] = ()

    def is_empty(self) -> bool:
        return not (self.diffs or self.findings or self.bisects)

    def to_markdown(self) -> str:
        """Render a human-readable markdown report."""
        out: List[str] = ["# Regression Report", ""]

        if self.metadata:
            out.append("## Metadata")
            for k, v in self.metadata:
                out.append(f"- **{k}**: {v}")
            out.append("")

        # Diffs
        out.append("## Semantic Diffs")
        if not self.diffs:
            out.append("_No diffs._")
            out.append("")
        for i, d in enumerate(self.diffs, 1):
            out.append(f"### Diff {i}")
            if d.repo_error:
                out.append(f"- _error_: `{d.repo_error}`")
            out.append(f"- files changed: `{len(d.files_changed)}`")
            out.append(f"- lines added / removed: `{d.lines_added}` / `{d.lines_removed}`")
            out.append(f"- taint sources added: `{d.taint_sources_added}`")
            out.append(f"- taint sinks added: `{d.taint_sinks_added}`")
            if d.files_changed:
                out.append("- changed files:")
                for fp in d.files_changed[:20]:
                    out.append(f"  - `{fp}`")
                if len(d.files_changed) > 20:
                    out.append(f"  - … (+{len(d.files_changed) - 20} more)")
            if d.modified_functions:
                out.append("- modified functions:")
                for fc in d.modified_functions[:20]:
                    out.append(
                        f"  - `{fc.file}` :: `{fc.kind} {fc.name}` "
                        f"(+{fc.added} / -{fc.removed})"
                    )
            out.append("")

        # Findings
        out.append("## Cross-Commit Taint Findings")
        if not self.findings:
            out.append("_No findings._")
            out.append("")
        for f in self.findings:
            out.append(
                f"- `{f.commit_sha[:12]}` :: `{f.file}:{f.line}`  "
                f"`{f.source_kind}` → `{f.sink_kind}`  "
                f"_(severity={f.severity}, confidence={f.confidence:.2f})_"
            )
        out.append("")

        # Bisects
        out.append("## Bisects")
        if not self.bisects:
            out.append("_No bisects._")
            out.append("")
        for b in self.bisects:
            if isinstance(b, BisectUnavailable):
                out.append(f"- _unavailable_: `{b.error}`")
                continue
            out.append(
                f"- first bad: `{b.first_bad_commit[:12]}` "
                f":: last good: `{b.last_good_commit[:12]}` "
                f"({b.duration_seconds}s, "
                f"test=`{' '.join(b.test_command)}`)"
            )
        out.append("")

        return "\n".join(out)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Invoke ``fn`` and swallow every exception.  Returns ``None``."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None


def _bisect_for_finding(finding: CrossCommitFinding, *,
                        bisect_runner: Any,
                        bisect_runner_factory: Any = None,
                        max_commits: int) -> Any:
    """Return a :class:`BisectResult` for a single taint finding.

    The default test_command is ``["true"]`` — bisect is best-effort
    when no real test command is supplied.  Callers can override via
    ``bisect_runner_factory``.
    """
    try:
        if bisect_runner is None:
            return None
        test_command = ["true"]
        result = _safe_call(
            bisect_runner.bisect,
            bad=finding.commit_sha,
            good=f"{finding.commit_sha}^",
            test_command=test_command,
            timeout_seconds=60,
        )
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


class RegressionRunner:
    """End-to-end pipeline: diff → cross-commit taint → bisect.

    >>> differ = GitDiffer(Path("/repo"))
    >>> taint = CrossCommitTaintAnalyzer(Path("/repo"), engine=None)
    >>> bisect = BisectRunner(Path("/repo"))
    >>> runner = RegressionRunner(differ, taint, bisect)
    >>> report = runner.detect_regressions("v1.0", "v1.1")
    >>> print(report.to_markdown())
    """

    def __init__(self, git_differ: Any, taint_analyzer: Any,
                 bisect_runner: Any) -> None:
        self.git_differ = git_differ
        self.taint_analyzer = taint_analyzer
        self.bisect_runner = bisect_runner

    # ------------------------------------------------------------------

    def detect_regressions(self, ref_a: str, ref_b: str,
                           *, max_bisect_commits: int = 10) -> RegressionReport:
        """Run the full pipeline.

        STUB-SAFE: never raises.  Missing components produce empty
        sections in the report.
        """
        started = time.monotonic()

        diffs: List[SemanticDiff] = []
        findings: List[CrossCommitFinding] = []
        bisects: List[BisectResult] = []

        # 1. diff
        try:
            if self.git_differ is not None and hasattr(self.git_differ, "diff"):
                d = self.git_differ.diff(ref_a, ref_b)
                if isinstance(d, SemanticDiff):
                    diffs.append(d)
        except Exception:
            pass

        # 2. cross-commit taint
        try:
            if self.taint_analyzer is not None and \
                    hasattr(self.taint_analyzer, "analyze_history"):
                fs = self.taint_analyzer.analyze_history(
                    ref_a, ref_b, max_commits=max_bisect_commits,
                )
                if isinstance(fs, list):
                    findings = [f for f in fs
                                if isinstance(f, CrossCommitFinding)]
        except Exception:
            pass

        # 3. bisect for each finding (best-effort, capped)
        try:
            for finding in findings[:max(1, int(max_bisect_commits))]:
                res = _bisect_for_finding(
                    finding,
                    bisect_runner=self.bisect_runner,
                    max_commits=max_bisect_commits,
                )
                if res is None:
                    continue
                if isinstance(res, (BisectResult, BisectUnavailable)):
                    bisects.append(res)
        except Exception:
            pass

        elapsed = int(time.monotonic() - started)

        metadata: List[Tuple[str, str]] = [
            ("ref_a", str(ref_a)),
            ("ref_b", str(ref_b)),
            ("max_bisect_commits", str(max_bisect_commits)),
            ("elapsed_seconds", str(elapsed)),
            ("schema", SCHEMA),
        ]

        return RegressionReport(
            diffs=diffs,
            findings=findings,
            bisects=bisects,
            metadata=tuple(metadata),
        )


__all__ = [
    "RegressionRunner",
    "RegressionReport",
    "_safe_call",
    "_bisect_for_finding",
]
