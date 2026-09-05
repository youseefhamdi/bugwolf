## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: AFL++ docs (https://github.com/AFLplusplus/AFLplusplus) — CLI flag surface
## License: bugwolf-MIT + AFL++ Apache-2.0 (CLI shape)
## Schema: bugwolf-fuzz-v1

"""AFL++ subprocess wrapper for the BugWolf fuzzing substrate.

:class:`AFLRunner` is the in-process coordinator. It owns the
``argv``-array subprocess contract (never the legacy shell-string
form), records the standard AFL++ outcome counters and packages the
run into the frozen :class:`FuzzResult` dataclass.

The runner is **stub-safe**: when the ``afl-fuzz`` binary is absent the
runner returns :class:`FuzzRunnerUnavailable` rather than raising so
the orchestrator can degrade gracefully.
"""
from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-fuzz-afl-v1"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FuzzResult:
    """Outcome of a coverage-guided fuzzing run.

    Attributes
    ----------
    target:
        Path to the binary that was fuzzed.
    duration_seconds:
        Wall-clock time consumed by the run.
    total_executions:
        Estimated number of target executions (from AFL fuzzer_stats).
    coverage_edges:
        Unique edges observed in the bitmap.
    new_edges_found:
        Edges discovered during this run.
    crashes:
        Tuple of crash artefact paths.
    hangs:
        Tuple of hang artefact paths.
    unique_crashes:
        Tuple of triaged crash dicts (one per unique signature).
    corpus_size:
        Final corpus size in files.
    runner_name:
        Lower-case runner identifier (``"afl++"``, ``"libfuzzer"``...).
    seed_count:
        Number of seeds supplied at run start.
    """

    target: str
    duration_seconds: int
    total_executions: int
    coverage_edges: int
    new_edges_found: int
    crashes: Tuple[str, ...]
    hangs: Tuple[str, ...]
    unique_crashes: Tuple[Dict[str, Any], ...]
    corpus_size: int
    runner_name: str
    seed_count: int


@dataclass(frozen=True)
class FuzzRunnerUnavailable:
    """Returned by a runner when its binary is missing.

    Mirrors :class:`FuzzResult` so callers can pattern-match on the
    field bag without catching exceptions.
    """

    runner_name: str
    reason: str
    target: str = ""
    duration_seconds: int = 0
    total_executions: int = 0
    coverage_edges: int = 0
    new_edges_found: int = 0
    crashes: Tuple[str, ...] = field(default_factory=tuple)
    hangs: Tuple[str, ...] = field(default_factory=tuple)
    unique_crashes: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    corpus_size: int = 0
    seed_count: int = 0


# ---------------------------------------------------------------------------
# AFLRunner
# ---------------------------------------------------------------------------


class AFLRunner:
    """Wrap an AFL++ ``afl-fuzz`` invocation.

    Parameters
    ----------
    afl_path:
        Filesystem path to the ``afl-fuzz`` binary.  When ``None`` the
        runner resolves it via :func:`shutil.which`.
    timeout_seconds:
        Wall-clock budget for one fuzzer invocation.
    cores:
        Number of AFL cores (``-M`` / ``-S``).
    extra_args:
        Extra argv passed verbatim to ``afl-fuzz``.
    """

    name = "afl++"
    SCHEMA = SCHEMA

    def __init__(
        self,
        *,
        afl_path: Optional[str] = "/usr/bin/afl-fuzz",
        timeout_seconds: int = 3600,
        cores: int = 1,
        extra_args: Optional[Sequence[str]] = None,
    ) -> None:
        self.afl_path = afl_path or "/usr/bin/afl-fuzz"
        self.timeout_seconds = int(max(1, timeout_seconds))
        self.cores = int(max(1, cores))
        self.extra_args: Tuple[str, ...] = tuple(extra_args or ())

    # ------------------------------------------------------------------ utils

    def _resolved(self) -> Optional[str]:
        """Return a usable path to ``afl-fuzz`` or ``None``."""
        candidate = self.afl_path
        if candidate and os.path.isabs(candidate) and os.path.exists(candidate):
            return candidate
        found = shutil.which(str(candidate or "afl-fuzz"))
        return found

    def is_available(self) -> bool:
        """Return ``True`` iff ``afl-fuzz`` is on disk."""
        return self._resolved() is not None

    # ------------------------------------------------------------------ run

    def run(
        self,
        target_binary: str,
        input_corpus: Path,
        output_dir: Path,
        *,
        dictionary: Optional[Path] = None,
        llm_seed_gen: Optional[Any] = None,
        timeout_seconds: Optional[int] = None,
    ) -> Any:
        """Execute a single AFL++ campaign.

        Returns
        -------
        :class:`FuzzResult` on success or :class:`FuzzRunnerUnavailable`
        when the binary is missing.  Never raises.
        """
        binary = self._resolved()
        if binary is None:
            return FuzzRunnerUnavailable(
                runner_name=self.name,
                reason=f"afl-fuzz not on PATH ({self.afl_path!r})",
                target=str(target_binary),
                seed_count=_count_seed_files(input_corpus),
            )

        try:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            seeds = _count_seed_files(input_corpus)
            argv = self._build_argv(binary, target_binary, input_corpus, out, dictionary)
            started = time.time()
            try:
                result = _safe_spawn_argv(
                    argv,
                    cwd=str(out),
                    timeout=float(timeout_seconds or self.timeout_seconds),
                )
            except Exception as exc:  # noqa: BLE001 - never raise
                return FuzzRunnerUnavailable(
                    runner_name=self.name,
                    reason=f"spawn failed: {exc!r}",
                    target=str(target_binary),
                    seed_count=seeds,
                )
            duration = int(time.time() - started)
            stats = _parse_afl_stats(out / "fuzzer_stats")
            crashes, hangs, unique = _collect_crashes(out)
            return FuzzResult(
                target=str(target_binary),
                duration_seconds=duration,
                total_executions=int(stats.get("execs_done", 0)),
                coverage_edges=int(stats.get("edges_found", 0)),
                new_edges_found=int(stats.get("new_edges", 0)),
                crashes=crashes,
                hangs=hangs,
                unique_crashes=unique,
                corpus_size=int(stats.get("corpus_count", seeds)),
                runner_name=self.name,
                seed_count=seeds,
            )
        except Exception as exc:  # noqa: BLE001 - never raise
            return FuzzRunnerUnavailable(
                runner_name=self.name,
                reason=f"run failed: {exc!r}",
                target=str(target_binary),
            )

    # ------------------------------------------------------------------ argv

    def _build_argv(
        self,
        binary: str,
        target_binary: str,
        input_corpus: Path,
        output_dir: Path,
        dictionary: Optional[Path],
    ) -> List[str]:
        argv: List[str] = [binary]
        argv.extend(["-i", str(input_corpus)])
        argv.extend(["-o", str(output_dir)])
        if self.cores > 1:
            argv.extend(["-M", f"main-{os.getpid()}"])
        if dictionary is not None:
            argv.extend(["-x", str(dictionary)])
        argv.extend(list(self.extra_args))
        argv.append("--")
        argv.append(str(target_binary))
        return argv

    # ----------------------------------------------------------------- repr

    def __repr__(self) -> str:
        return (
            f"AFLRunner(afl_path={self.afl_path!r}, "
            f"timeout_seconds={self.timeout_seconds}, cores={self.cores})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_spawn_argv(argv: List[str], *, cwd: str, timeout: float) -> Any:
    """Spawn ``argv`` via ``safe_subprocess.spawn_argv`` if available.

    Falls back to :func:`subprocess.run` with ``shell`` set to
    ``False`` when the wrapper is not importable (e.g. running tests
    in isolation).  Either way, the legacy shell-string form is
    NEVER used.
    """
    try:
        from tools.cross_project.safe_subprocess_lib import spawn_argv

        return spawn_argv(argv, cwd=cwd, timeout=timeout, check=False)
    except Exception:
        import subprocess

        proc = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout)),
            check=False,
            shell=False,
        )
        return proc


def _count_seed_files(corpus: Path) -> int:
    """Return the number of files under ``corpus`` (recursively)."""
    try:
        p = Path(corpus)
        if not p.exists():
            return 0
        return sum(1 for _ in p.rglob("*") if _.is_file())
    except Exception:
        return 0


def _parse_afl_stats(path: Path) -> Dict[str, int]:
    """Parse AFL's ``fuzzer_stats`` file into a flat dict of ints.

    Missing values default to 0.  Parsing NEVER raises.
    """
    out: Dict[str, int] = {}
    try:
        if not path.exists():
            return out
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            k = key.strip().lower()
            v = value.strip()
            try:
                out[k] = int(v.split()[0])
            except (ValueError, IndexError):
                continue
    except Exception:
        return out
    return out


def _collect_crashes(output_dir: Path) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[Dict[str, Any], ...]]:
    """Walk AFL's output dirs and bucket crashes/hangs."""
    crashes: List[str] = []
    hangs: List[str] = []
    unique: List[Dict[str, Any]] = []
    try:
        default_dir = output_dir / "default"
        if default_dir.exists():
            crash_dir = default_dir / "crashes"
            hang_dir = default_dir / "hangs"
            if crash_dir.exists():
                for f in sorted(crash_dir.iterdir()):
                    if f.is_file() and f.name != "README.txt":
                        crashes.append(str(f))
            if hang_dir.exists():
                for f in sorted(hang_dir.iterdir()):
                    if f.is_file() and f.name != "README.txt":
                        hangs.append(str(f))
            for c in crashes[:8]:
                unique.append({"path": c, "signature": _crash_signature(Path(c))})
    except Exception:
        pass
    return tuple(crashes), tuple(hangs), tuple(unique)


def _crash_signature(path: Path) -> str:
    """Compute a tiny signature for a crash artefact (sha256 prefix)."""
    try:
        import hashlib

        data = path.read_bytes() if path.exists() else b""
        return hashlib.sha256(data).hexdigest()[:12]
    except Exception:
        return "unknown"
