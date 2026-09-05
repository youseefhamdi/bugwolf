"""Phase 3.4 — semantic git diff for the regression pipeline.

The :class:`GitDiffer` wraps ``git diff <a> <b>`` and produces a
:class:`SemanticDiff` frozen dataclass that captures:

  * which files changed;
  * aggregate lines added / removed;
  * added / removed import lines per file (regex-based; language-agnostic);
  * per-function changes (heuristic — looks for ``def name(``,
    ``function name(`` and ``class Name`` markers before/after);
  * counts of newly-added taint *sources* / *sinks* (regex hints — never
    parsed as actual code; this is a coarse pre-filter).

The differ is STUB-SAFE: when invoked against a non-git path it returns
an *empty* :class:`SemanticDiff` carrying ``repo_error="not a git
repository"`` rather than raising.  All subprocess calls use argv-arrays
(``shell=False``) — CI gate A-1.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Tuple


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FunctionChange:
    """A coarse-grained per-function change detected between two refs.

    The diff is heuristic: it pairs the first ``def name(`` / ``class Name``
    / ``function name(`` markers that appear in the ``-`` / ``+`` hunks.
    It is *not* a real AST diff — for STUB-SAFE behaviour we keep it
    regex-driven and never raise.
    """

    file: str
    name: str
    kind: str  # "def" | "class" | "function"
    before_lines: Tuple[str, ...]
    after_lines: Tuple[str, ...]
    added: int = 0
    removed: int = 0


@dataclass(frozen=True)
class SemanticDiff:
    """The semantic representation of a ``git diff <a> <b>``.

    All tuple/dict fields are immutable so the dataclass can be hashed
    and shared across threads.  ``repo_error`` is ``""`` on success and a
    short reason on failure (e.g. ``"not a git repository"``).
    """

    files_changed: Tuple[str, ...] = ()
    lines_added: int = 0
    lines_removed: int = 0
    added_imports: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    removed_imports: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    modified_functions: Tuple[FunctionChange, ...] = ()
    taint_sources_added: int = 0
    taint_sinks_added: int = 0
    repo_error: str = ""

    def is_empty(self) -> bool:
        return (
            not self.files_changed
            and self.lines_added == 0
            and self.lines_removed == 0
            and self.repo_error != ""
        ) or (
            self.repo_error != ""
        )

    def ok(self) -> bool:
        return self.repo_error == ""


def _empty_diff(repo_error: str = "not a git repository") -> SemanticDiff:
    return SemanticDiff(repo_error=repo_error)


_EMPTY_DIFF = _empty_diff()


# ---------------------------------------------------------------------------
# Regex hints
# ---------------------------------------------------------------------------


# import foo.bar     (Python)
# import "foo/bar"   (Go / JS)
# #include <foo/bar.h>   (C/C++)
# use foo::bar;     (Rust)
_IMPORT_RE = re.compile(
    r"""^\+
        \s*
        (?:
            import\s+["']?([\w./\\:-]+)["']?       # py / go / js
          | from\s+["']?([\w./\\:-]+)["']?\s+import  # py
          | \#\s*include\s+[<"]([\w./\\-]+)[>"]      # c/c++
          | use\s+([\w:]+)\s*;                       # rust
          | require\s+["']([\w./\\:-]+)["']           # js/ruby
        )
    """,
    re.VERBOSE,
)

# removed import line — same regex but for ``-`` prefix
_REMOVED_IMPORT_RE = re.compile(
    r"""^\-
        \s*
        (?:
            import\s+["']?([\w./\\:-]+)["']?
          | from\s+["']?([\w./\\:-]+)["']?\s+import
          | \#\s*include\s+[<"]([\w./\\-]+)[>"]
          | use\s+([\w:]+)\s*;
          | require\s+["']([\w./\\:-]+)["']
        )
    """,
    re.VERBOSE,
)

# taint source / sink hints — heuristic, never authoritative
_TAINT_SOURCE_RE = re.compile(
    r"""^\+
        (?:
            \s*request\.(?:GET|POST|args|form|json|body|headers|cookies|params)
          | \s*sys\.argv\[
          | \s*getenv\(
          | \s*os\.environ\[
          | \s*input\(
          | \s*sys\.stdin
          | \s*document\.location
          | \s*window\.location
          | \s*location\.search
          | \s*location\.hash
        )
    """,
    re.VERBOSE,
)

_TAINT_SINK_RE = re.compile(
    r"""^\+
        (?:
            \s*subprocess\.(?:call|run|Popen|check_output|check_call)
          | \s*os\.system\(
          | \s*os\.popen\(
          | \s*eval\(
          | \s*exec\(
          | \s*\.execute\(        # cursor.execute, db.execute
          | \s*innerHTML\s*=
          | \s*outerHTML\s*=
          | \s*document\.write\(
          | \s*render_template_string\(
          | \s*pickle\.loads?\(
          | \s*yaml\.load\(
          | \s*open\(.+['"]w['"]
        )
    """,
    re.VERBOSE,
)

# function / class signatures — heuristic, language agnostic
_DEF_RE = re.compile(r"^\+\s*(?:async\s+)?(?:def|function)\s+([A-Za-z_][\w]*)")
_CLASS_RE = re.compile(r"^\+\s*class\s+([A-Za-z_][\w]*)")
# corresponding "before" versions
_DEF_RE_MINUS = re.compile(r"^\-\s*(?:async\s+)?(?:def|function)\s+([A-Za-z_][\w]*)")
_CLASS_RE_MINUS = re.compile(r"^\-\s*class\s+([A-Za-z_][\w]*)")


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------


def _is_git_repo(repo_path: Path) -> bool:
    """Return True iff ``repo_path`` exists and contains a ``.git`` dir.

    STUB-SAFE: any I/O / non-existent-path problem returns False.
    """
    try:
        if not repo_path.exists() or not repo_path.is_dir():
            return False
        if (repo_path / ".git").exists():
            return True
        # Sub-directory of a git repo?  Quick check via `git rev-parse`.
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


def _run_git_diff(repo_path: Path, ref_a: str, ref_b: str) -> str:
    """Run ``git diff <a> <b>`` returning the raw unified-diff text.

    STUB-SAFE: any error returns ``""``.  Uses argv-array (no shell).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--no-color", "--unified=3",
             "--diff-filter=ACMRT", ref_a, ref_b],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout or ""
    except Exception:
        return ""


def _split_files(diff_text: str) -> List[Tuple[str, List[str]]]:
    """Split a unified diff into ``(file_path, lines)`` chunks.

    Lines preserve their leading ``+`` / ``-`` / `` `` prefix.  The
    per-file chunk includes the ``diff --git`` and ``+++`` / ``---``
    headers for downstream introspection.
    """
    files: List[Tuple[str, List[str]]] = []
    current_file: str = ""
    current_lines: List[str] = []
    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            if current_file or current_lines:
                files.append((current_file, current_lines))
            # `diff --git a/foo b/foo`
            parts = raw.split()
            b_path = parts[-1] if len(parts) >= 2 else ""
            if b_path.startswith("b/"):
                b_path = b_path[2:]
            current_file = b_path
            current_lines = [raw]
        else:
            if current_lines or raw.startswith("diff --git "):
                current_lines.append(raw)
    if current_lines or current_file:
        files.append((current_file, current_lines))
    return files


def _line_kind(line: str) -> str:
    """Return ``"+"`` / ``"-"`` / ``" "`` / ``"other"`` for a diff line."""
    if not line:
        return "other"
    head = line[0]
    if head in "+- ":
        return head
    return "other"


def _added_removed_counts(lines: List[str]) -> Tuple[int, int]:
    a = 0
    r = 0
    for line in lines:
        kind = _line_kind(line)
        if kind == "+":
            a += 1
        elif kind == "-":
            r += 1
    return a, r


def _extract_added_imports(lines: List[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for line in lines:
        m = _IMPORT_RE.match(line)
        if m:
            for grp in m.groups():
                if grp:
                    out.append(grp)
                    break
    return tuple(sorted(set(out)))


def _extract_removed_imports(lines: List[str]) -> Tuple[str, ...]:
    out: List[str] = []
    for line in lines:
        m = _REMOVED_IMPORT_RE.match(line)
        if m:
            for grp in m.groups():
                if grp:
                    out.append(grp)
                    break
    return tuple(sorted(set(out)))


def _count_added_taint(lines: List[str]) -> Tuple[int, int]:
    """Return ``(sources, sinks)`` for newly-added ``+`` lines."""
    s = 0
    k = 0
    for line in lines:
        if not line.startswith("+"):
            continue
        if _TAINT_SOURCE_RE.match(line):
            s += 1
        if _TAINT_SINK_RE.match(line):
            k += 1
    return s, k


def _function_changes_for(file_path: str, lines: List[str]) -> Tuple[FunctionChange, ...]:
    """Pair up ``def`` / ``class`` / ``function`` markers before/after.

    Heuristic only: we collect per-name ``-`` and ``+`` blocks (until the
    next blank line / next marker), then emit a :class:`FunctionChange`.
    """
    # index of "before" definitions by name
    before: Dict[str, List[str]] = {}
    after: Dict[str, List[str]] = {}
    # walk through the per-file lines grouping +/- blocks
    current_kind: str = ""  # "+" / "-"
    current_name: str = ""
    block: List[str] = []

    def _flush() -> None:
        nonlocal current_kind, current_name, block
        if current_name and current_kind:
            target = after if current_kind == "+" else before
            target.setdefault(current_name, []).extend(block)
        current_kind = ""
        current_name = ""
        block = []

    for line in lines:
        if line.startswith("+") and not line.startswith("+++"):
            m1 = _DEF_RE.match(line)
            m2 = _CLASS_RE.match(line)
            if m1:
                _flush()
                current_kind = "+"
                current_name = m1.group(1)
                block = [line]
                continue
            if m2:
                _flush()
                current_kind = "+"
                current_name = m2.group(1)
                block = [line]
                continue
            if current_kind == "+" and current_name:
                block.append(line)
            continue
        if line.startswith("-") and not line.startswith("---"):
            m1 = _DEF_RE_MINUS.match(line)
            m2 = _CLASS_RE_MINUS.match(line)
            if m1:
                _flush()
                current_kind = "-"
                current_name = m1.group(1)
                block = [line]
                continue
            if m2:
                _flush()
                current_kind = "-"
                current_name = m2.group(1)
                block = [line]
                continue
            if current_kind == "-" and current_name:
                block.append(line)
            continue
        # context line or header — flush current block
        _flush()
    _flush()

    changes: List[FunctionChange] = []
    all_names = sorted(set(before) | set(after))
    for name in all_names:
        b = tuple(before.get(name, ()))
        a = tuple(after.get(name, ()))
        if not b and not a:
            continue
        kind = "def"
        # crude kind detection — if the after signature contains "class"
        if a and any("class " in ln for ln in a[:1]):
            kind = "class"
        elif a and any("function " in ln for ln in a[:1]):
            kind = "function"
        changes.append(FunctionChange(
            file=file_path,
            name=name,
            kind=kind,
            before_lines=b,
            after_lines=a,
            added=sum(1 for x in a if x.startswith("+") and not x.startswith("+++")),
            removed=sum(1 for x in b if x.startswith("-") and not x.startswith("---")),
        ))
    return tuple(changes)


class GitDiffer:
    """Semantic git diff between two refs.

    >>> differ = GitDiffer(Path("/tmp/some-repo"))
    >>> diff = differ.diff("HEAD~1", "HEAD")
    >>> diff.ok()
    True   # or False if not a git repo
    """

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = Path(repo_path)

    def diff(self, ref_a: str, ref_b: str) -> SemanticDiff:
        """Return a :class:`SemanticDiff` for ``ref_a..ref_b``.

        STUB-SAFE: returns an empty diff with ``repo_error`` set if the
        path is not a git repo or ``git diff`` fails.
        """
        try:
            if not _is_git_repo(self.repo_path):
                return _empty_diff("not a git repository")
            raw = _run_git_diff(self.repo_path, ref_a, ref_b)
            if not raw:
                # No diff is not an error — return a real (empty) diff.
                return SemanticDiff()
            return self._parse(raw)
        except Exception as e:
            return _empty_diff(f"diff failed: {e}")

    # ------------------------------------------------------------------

    def _parse(self, raw: str) -> SemanticDiff:
        files = _split_files(raw)
        file_paths: List[str] = []
        added_imports: Dict[str, Tuple[str, ...]] = {}
        removed_imports: Dict[str, Tuple[str, ...]] = {}
        all_function_changes: List[FunctionChange] = []
        total_added = 0
        total_removed = 0
        total_sources = 0
        total_sinks = 0

        for file_path, lines in files:
            if not file_path:
                continue
            file_paths.append(file_path)
            a, r = _added_removed_counts(lines)
            total_added += a
            total_removed += r
            added = _extract_added_imports(lines)
            removed = _extract_removed_imports(lines)
            if added:
                added_imports[file_path] = added
            if removed:
                removed_imports[file_path] = removed
            src, snk = _count_added_taint(lines)
            total_sources += src
            total_sinks += snk
            all_function_changes.extend(_function_changes_for(file_path, lines))

        return SemanticDiff(
            files_changed=tuple(sorted(set(file_paths))),
            lines_added=total_added,
            lines_removed=total_removed,
            added_imports=added_imports,
            removed_imports=removed_imports,
            modified_functions=tuple(all_function_changes),
            taint_sources_added=total_sources,
            taint_sinks_added=total_sinks,
            repo_error="",
        )


__all__ = [
    "GitDiffer",
    "SemanticDiff",
    "FunctionChange",
    "_EMPTY_DIFF",
    "_empty_diff",
    "_is_git_repo",
    "_run_git_diff",
]
