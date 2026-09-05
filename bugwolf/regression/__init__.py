"""BugWolf Phase 3.4 — Code-Diff Regression Scanner.

This package adds a ``regression`` sub-package that ties together:

  * a semantic git diff engine (``git_diff.GitDiffer``);
  * a CVE extractor for NVD + GHSA advisories (``cve_extractor.CVEExtractor``);
  * a cross-commit taint analyser (``cross_commit_taint.CrossCommitTaintAnalyzer``);
  * a thin re-export shim wrapping ``tools.patch_gap`` (``patch_gap``);
  * a ``git bisect run`` wrapper (``bisect.BisectRunner``);
  * an end-to-end pipeline (``regression_runner.RegressionRunner``).

Every public symbol is STUB-SAFE: if a dependency (git repo, taint engine,
test command, network, …) is missing, the call returns an "unavailable"
frozen dataclass instead of raising.  No third-party deps; stdlib only.

Schemas / conventions:
  SCHEMA = "bugwolf-regression-v1" — declared at the top of every file.
  All HTTP/CLI work uses argv-array subprocess (no ``shell=True``).
  All dataclasses are ``frozen=True``.

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

from bugwolf.regression.git_diff import (
    GitDiffer,
    SemanticDiff,
    FunctionChange,
    _EMPTY_DIFF,
)
from bugwolf.regression.cve_extractor import (
    CVEExtractor,
    CVEEntry,
)
from bugwolf.regression.cross_commit_taint import (
    CrossCommitTaintAnalyzer,
    CrossCommitFinding,
)
from bugwolf.regression.patch_gap import (
    RegressionPatchGap,
    RegressionPatchGapReport,
)
from bugwolf.regression.bisect import (
    BisectRunner,
    BisectResult,
    BisectUnavailable,
)
from bugwolf.regression.regression_runner import (
    RegressionRunner,
    RegressionReport,
)


__all__ = [
    "GitDiffer",
    "SemanticDiff",
    "FunctionChange",
    "_EMPTY_DIFF",
    "CVEExtractor",
    "CVEEntry",
    "CrossCommitTaintAnalyzer",
    "CrossCommitFinding",
    "RegressionPatchGap",
    "RegressionPatchGapReport",
    "BisectRunner",
    "BisectResult",
    "BisectUnavailable",
    "RegressionRunner",
    "RegressionReport",
]
