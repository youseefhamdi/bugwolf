"""Phase 3.4 — ``git bisect run`` wrapper.

The :class:`BisectRunner` wraps ``git bisect run`` in argv-array form
(no ``shell=True``) and returns a :class:`BisectResult` frozen dataclass
with the first-bad / last-good SHAs plus the bisect log.

STUB-SAFE: on a non-git path it returns a :class:`BisectUnavailable`
frozen dataclass instead of raising.  When git bisect fails or the test
command exits non-zero, the result still carries the log so the caller
can introspect.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BisectResult:
    """Result of a successful ``git bisect run``.

    ``test_command`` is stored as a tuple so the dataclass stays hashable
    and frozen.
    """

    first_bad_commit: str
    last_good_commit: str
    bisect_log: Tuple[str, ...]
    duration_seconds: int
    test_command: Tuple[str, ...]
    ok: bool = True
    error: str = ""


@dataclass(frozen=True)
class BisectUnavailable:
    """Returned when ``git bisect`` is not possible (non-git repo, etc.)."""

    first_bad_commit: str = ""
    last_good_commit: str = ""
    bisect_log: Tuple[str, ...] = ()
    duration_seconds: int = 0
    test_command: Tuple[str, ...] = ()
    ok: bool = False
    error: str = "bisect unavailable"

    def __bool__(self) -> bool:  # explicit False-y
        return False


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


def _git(repo_path: Path, args: List[str], *,
         timeout: int = 30) -> Tuple[int, str, str]:
    """Run a ``git`` argv-array command and return (rc, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return (result.returncode, result.stdout or "", result.stderr or "")
    except subprocess.TimeoutExpired:
        return (124, "", "git timeout")
    except Exception as e:
        return (1, "", f"git error: {e}")


def _resolve_ref(repo_path: Path, ref: str) -> str:
    """Resolve a ref to a full SHA (empty string on failure)."""
    rc, out, _ = _git(repo_path, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    if rc != 0:
        return ""
    return out.strip()


# ---------------------------------------------------------------------------
# Bisect log parsing
# ---------------------------------------------------------------------------


_BAD_RE = re.compile(r"^([0-9a-f]{7,40})\s+is the first bad commit", re.IGNORECASE)
_GOOD_RE = re.compile(r"^([0-9a-f]{7,40})\s+is the first (?:good|new) commit",
                      re.IGNORECASE)


def _parse_bisect_log(log: str) -> Tuple[str, str]:
    """Extract the first-bad / last-good SHAs from ``git bisect`` output."""
    bad = ""
    good = ""
    for line in log.splitlines():
        if not bad:
            m = _BAD_RE.match(line)
            if m:
                bad = m.group(1)
                continue
        if not good:
            m = _GOOD_RE.match(line)
            if m:
                good = m.group(1)
                continue
    return bad, good


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


class BisectRunner:
    """Wrap ``git bisect run`` with argv-array subprocesses.

    >>> br = BisectRunner(Path("/repo"))
    >>> res = br.bisect(bad="HEAD", good="v1.0", test_command=["pytest", "-q"])
    """

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = Path(repo_path)

    # ------------------------------------------------------------------

    def bisect(self, *, bad: str, good: str,
               test_command: List[str],
               timeout_seconds: int = 300) -> BisectResult | BisectUnavailable:
        """Run ``git bisect run <test_command>`` between ``good`` and ``bad``.

        STUB-SAFE: returns :class:`BisectUnavailable` when the path is
        not a git repo or git bisect fails before producing a verdict.

        The test command is run via argv-array (no shell), inside the
        repo, with a hard timeout.  ``timeout_seconds`` also bounds the
        overall bisect.
        """
        if not isinstance(test_command, list) or not test_command:
            return BisectUnavailable(error="test_command must be a non-empty list")

        if not _is_git_repo(self.repo_path):
            return BisectUnavailable(error="not a git repository")

        # Best-effort cleanup before we start — we don't *require* it to
        # succeed, but it's polite.
        _git(self.repo_path, ["bisect", "reset"], timeout=10)

        # Resolve starting refs
        bad_sha = _resolve_ref(self.repo_path, bad)
        good_sha = _resolve_ref(self.repo_path, good)
        if not bad_sha or not good_sha:
            return BisectUnavailable(error=f"unresolved refs (bad={bad_sha!r}, good={good_sha!r})")

        # git bisect start
        rc, _, err = _git(self.repo_path, ["bisect", "start"], timeout=10)
        if rc != 0:
            return BisectUnavailable(error=f"bisect start failed: {err.strip()}")

        # git bisect bad <ref>
        rc, _, err = _git(self.repo_path, ["bisect", "bad", bad], timeout=10)
        if rc != 0:
            _git(self.repo_path, ["bisect", "reset"], timeout=10)
            return BisectUnavailable(error=f"bisect bad failed: {err.strip()}")

        # git bisect good <ref>
        rc, _, err = _git(self.repo_path, ["bisect", "good", good], timeout=10)
        if rc != 0:
            _git(self.repo_path, ["bisect", "reset"], timeout=10)
            return BisectUnavailable(error=f"bisect good failed: {err.strip()}")

        # git bisect run <test_command>
        start = time.monotonic()
        try:
            proc = subprocess.run(
                ["git", "bisect", "run", *test_command],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_seconds)),
                shell=False,
            )
            duration = int(time.monotonic() - start)
            log_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
            log_lines = tuple(ln for ln in log_text.splitlines() if ln.strip())
            first_bad, last_good = _parse_bisect_log(log_text)
            # Reset on the way out so the repo is left clean.
            _git(self.repo_path, ["bisect", "reset"], timeout=10)
            if not first_bad:
                return BisectUnavailable(
                    bisect_log=log_lines,
                    duration_seconds=duration,
                    test_command=tuple(test_command),
                    error="bisect run did not identify a first-bad commit",
                )
            return BisectResult(
                first_bad_commit=first_bad,
                last_good_commit=last_good,
                bisect_log=log_lines,
                duration_seconds=duration,
                test_command=tuple(test_command),
                ok=True,
                error="",
            )
        except subprocess.TimeoutExpired:
            _git(self.repo_path, ["bisect", "reset"], timeout=10)
            return BisectUnavailable(
                duration_seconds=int(timeout_seconds),
                test_command=tuple(test_command),
                error="bisect run timed out",
            )
        except Exception as e:
            _git(self.repo_path, ["bisect", "reset"], timeout=10)
            return BisectUnavailable(
                test_command=tuple(test_command),
                error=f"bisect run crashed: {e}",
            )


__all__ = [
    "BisectRunner",
    "BisectResult",
    "BisectUnavailable",
    "_is_git_repo",
    "_parse_bisect_log",
]
