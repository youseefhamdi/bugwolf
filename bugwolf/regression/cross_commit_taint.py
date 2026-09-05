"""Phase 3.4 — cross-commit taint analysis.

The :class:`CrossCommitTaintAnalyzer` walks a commit range and compares
each commit's *changed files* against the previous commit.  For every
commit it asks the injected ``taint_engine`` (anything with an
``analyze(path, ref)`` method, or an ``analyze(path, text)`` callable)
to compute the taint flows that newly appear in the changed files.

Findings are emitted as :class:`CrossCommitFinding` frozen dataclasses.

STUB-SAFE: any error from git, the engine, or the file system becomes
an empty list — we never raise.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


_SEVERITIES = {"low", "medium", "high", "critical"}


def _coerce_severity(value: Any, default: str = "medium") -> str:
    if isinstance(value, str) and value.lower() in _SEVERITIES:
        return value.lower()
    return default


def _coerce_confidence(value: Any) -> float:
    try:
        c = float(value)
    except (TypeError, ValueError):
        return 0.5
    if c < 0.0:
        return 0.0
    if c > 1.0:
        return 1.0
    return c


@dataclass(frozen=True)
class CrossCommitFinding:
    """A single taint flow that newly appears in a commit."""

    commit_sha: str
    file: str
    line: int
    source_kind: str
    sink_kind: str
    severity: str
    confidence: float


# ---------------------------------------------------------------------------
# Git plumbing
# ---------------------------------------------------------------------------


def _is_git_repo(repo_path: Path) -> bool:
    try:
        if not repo_path.exists() or not repo_path.is_dir():
            return False
        if (repo_path / ".git").exists():
            return True
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _rev_list(repo_path: Path, ref_a: str, ref_b: str,
              *, max_commits: int) -> List[str]:
    """Return the SHAs in ``ref_a..ref_b`` newest-first, capped."""
    try:
        rng = f"{ref_a}..{ref_b}"
        result = subprocess.run(
            ["git", "rev-list", "--max-count", str(max_commits), rng],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        if result.returncode != 0:
            return []
        return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def _changed_files(repo_path: Path, commit: str) -> List[str]:
    """Return the list of files changed in ``commit`` vs its parent."""
    try:
        result = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        if result.returncode != 0:
            return []
        return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def _show_file(repo_path: Path, commit: str, file_path: str) -> str:
    """Return the contents of ``file_path`` at ``commit`` (empty on miss)."""
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:{file_path}"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Engine adapter
# ---------------------------------------------------------------------------


class _EngineAdapter:
    """Normalise various engine signatures into ``analyze(path, text)``."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    def analyze(self, file_path: str, text: str, *, ref: str = "") -> List[Dict[str, Any]]:
        """Call the engine; return a list of flow dicts.

        Accepted engine shapes:
          * ``engine.analyze(path, text)`` returning ``[dict, ...]``
          * ``engine.analyze(path, text, ref=ref)``
          * ``engine.analyze_file(path, ref)`` returning ``[dict, ...]``
          * ``engine(path, text)`` (callable)
          * ``engine.scan(text)`` — falls back to scanning the raw text

        Returns ``[]`` on any problem.
        """
        if self.engine is None:
            return []
        try:
            # Method form: analyze(path, text)
            if hasattr(self.engine, "analyze"):
                fn = self.engine.analyze  # type: ignore[attr-defined]
                try:
                    res = fn(file_path, text, ref=ref)
                except TypeError:
                    res = fn(file_path, text)
                return list(res or [])
            # Method form: analyze_file(path, ref)
            if hasattr(self.engine, "analyze_file"):
                fn = self.engine.analyze_file  # type: ignore[attr-defined]
                res = fn(file_path, ref or "")
                return list(res or [])
            # Callable
            if callable(self.engine):
                res = self.engine(file_path, text)  # type: ignore[call-arg]
                return list(res or [])
        except Exception:
            return []
        return []


# ---------------------------------------------------------------------------
# Diff key helpers
# ---------------------------------------------------------------------------


def _flow_key(flow: Dict[str, Any]) -> Tuple[str, str, int, str]:
    """Stable identity for a taint flow across commits."""
    return (
        str(flow.get("source_kind", flow.get("source", ""))),
        str(flow.get("sink_kind", flow.get("sink", ""))),
        int(flow.get("line", 0) or 0),
        str(flow.get("file", "")),
    )


def _flows_to_keys(flows: Iterable[Dict[str, Any]]) -> set:
    return {_flow_key(f) for f in flows if isinstance(f, dict)}


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


class CrossCommitTaintAnalyzer:
    """Walk a commit range and emit taint findings that newly appear.

    >>> engine = MyTaintEngine()
    >>> cca = CrossCommitTaintAnalyzer(Path("/repo"), engine)
    >>> findings = cca.analyze_history("v1.0", "v1.1", max_commits=20)
    """

    def __init__(self, repo_path: Path, taint_engine: Any) -> None:
        self.repo_path = Path(repo_path)
        self._adapter = _EngineAdapter(taint_engine)

    # ------------------------------------------------------------------

    def analyze_history(self, ref_a: str, ref_b: str,
                        *, max_commits: int = 50) -> List[CrossCommitFinding]:
        """Compare taint flows in each commit vs its parent.

        STUB-SAFE: returns ``[]`` on any failure (bad refs, missing repo,
        engine error, …).
        """
        try:
            if not _is_git_repo(self.repo_path):
                return []
            shas = _rev_list(self.repo_path, ref_a, ref_b, max_commits=max_commits)
            if not shas:
                return []

            findings: List[CrossCommitFinding] = []
            for sha in shas:
                files = _changed_files(self.repo_path, sha)
                if not files:
                    continue
                # parent sha
                parent = self._parent_sha(sha)
                for f in files:
                    new_text = _show_file(self.repo_path, sha, f)
                    old_text = _show_file(self.repo_path, parent, f) if parent else ""
                    new_flows = self._adapter.analyze(f, new_text, ref=sha)
                    old_flows = (
                        self._adapter.analyze(f, old_text, ref=parent)
                        if parent else []
                    )
                    diff_keys = _flows_to_keys(new_flows) - _flows_to_keys(old_flows)
                    for flow in new_flows:
                        if not isinstance(flow, dict):
                            continue
                        if _flow_key(flow) not in diff_keys:
                            continue
                        findings.append(CrossCommitFinding(
                            commit_sha=sha,
                            file=f,
                            line=int(flow.get("line", 0) or 0),
                            source_kind=str(flow.get("source_kind", flow.get("source", ""))),
                            sink_kind=str(flow.get("sink_kind", flow.get("sink", ""))),
                            severity=_coerce_severity(flow.get("severity")),
                            confidence=_coerce_confidence(flow.get("confidence")),
                        ))
            return findings
        except Exception:
            return []

    # ------------------------------------------------------------------

    def _parent_sha(self, sha: str) -> str:
        try:
            result = subprocess.run(
                ["git", "rev-parse", f"{sha}^"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if result.returncode != 0:
                return ""
            return (result.stdout or "").strip()
        except Exception:
            return ""


__all__ = [
    "CrossCommitFinding",
    "CrossCommitTaintAnalyzer",
    "_EngineAdapter",
]
