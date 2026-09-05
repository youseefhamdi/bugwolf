## Source: bugwolf Phase 3.1 (Coverage-Guided Fuzzing Substrate) — net-new
## Source: libFuzzer docs (https://llvm.org/docs/LibFuzzer.html) — flags and corpus format
## License: bugwolf-MIT + LLVM Apache-2.0 (CLI shape)
## Schema: bugwolf-fuzz-v1

"""libFuzzer subprocess wrapper for the BugWolf fuzzing substrate.

:class:`LibFuzzerRunner` wraps a single libFuzzer binary and packages
its outcome into the frozen :class:`FuzzResult` dataclass.  Like
:class:`AFLRunner` it is stub-safe: when the binary is missing the
runner returns :class:`FuzzRunnerUnavailable` rather than raising.
"""
from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

from bugwolf.fuzz.afl_runner import (
    FuzzResult,
    FuzzRunnerUnavailable,
    _count_seed_files,
    _safe_spawn_argv,
)


SCHEMA = "bugwolf-fuzz-libfuzzer-v1"


# libFuzzer writes a small ``artifacts/`` directory with crash files
# named ``crash-<sha>.bin`` and hangs named ``timeout-<sha>.bin``.
_LF_CRASH_PREFIX = "crash-"
_LF_HANG_PREFIX = "timeout-"


@dataclass(frozen=True)
class LibFuzzerOptions:
    """Sub-call configuration carried alongside the runner.

    Mirrors the libFuzzer flags that BugWolf exposes — kept as a
    small frozen dataclass so callers can construct one option bag and
    pass it through without keyword juggling.
    """

    max_total_time: int = 60           # -max_total_time
    max_len: int = 4096                # -max_len
    timeout: int = 10                  # -timeout (per-input)
    jobs: int = 1                      # -jobs
    workers: int = 1                   # -workers
    dict: Optional[str] = None         # -dict=<path>
    artifact_prefix: str = "./"        # -artifact_prefix
    extra: Tuple[str, ...] = ()        # any other -flag value pairs


class LibFuzzerRunner:
    """Wrap a libFuzzer binary.

    Parameters
    ----------
    target_binary:
        Filesystem path to the libFuzzer-instrumented binary.  The
        runner treats the binary as the libFuzzer entry point — there
        is no separate ``libFuzzer`` binary to spawn.
    timeout_seconds:
        Wall-clock budget for the whole run.
    options:
        Optional :class:`LibFuzzerOptions` carrying the per-call flags.
    """

    name = "libfuzzer"
    SCHEMA = SCHEMA

    def __init__(
        self,
        *,
        target_binary: Optional[str] = None,
        timeout_seconds: int = 3600,
        options: Optional[LibFuzzerOptions] = None,
    ) -> None:
        self.target_binary = target_binary
        self.timeout_seconds = int(max(1, timeout_seconds))
        self.options: LibFuzzerOptions = options or LibFuzzerOptions()

    # ------------------------------------------------------------------ utils

    def _resolved(self) -> Optional[str]:
        """Return a usable path to the libFuzzer target binary."""
        if not self.target_binary:
            return None
        if os.path.isabs(self.target_binary) and os.path.exists(self.target_binary):
            return self.target_binary
        return shutil.which(self.target_binary) or (
            self.target_binary if os.path.exists(self.target_binary) else None
        )

    def is_available(self) -> bool:
        """Return ``True`` iff the libFuzzer binary is on disk."""
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
        """Execute a single libFuzzer campaign.

        Returns a :class:`FuzzResult` on success or a
        :class:`FuzzRunnerUnavailable` when the target binary is
        missing.  Never raises.
        """
        binary = self._resolved()
        if binary is None:
            return FuzzRunnerUnavailable(
                runner_name=self.name,
                reason=f"libfuzzer binary not on PATH ({target_binary!r})",
                target=str(target_binary),
                seed_count=_count_seed_files(input_corpus),
            )

        try:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            seeds = _count_seed_files(input_corpus)
            argv = self._build_argv(binary, input_corpus, out, dictionary)
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
            stats = _parse_lf_summary(result)
            crashes, hangs, unique = _collect_lf_crashes(out)
            return FuzzResult(
                target=str(target_binary),
                duration_seconds=duration,
                total_executions=int(stats.get("execs", 0)),
                coverage_edges=int(stats.get("edges", 0)),
                new_edges_found=int(stats.get("new_edges", 0)),
                crashes=crashes,
                hangs=hangs,
                unique_crashes=unique,
                corpus_size=int(stats.get("corpus", seeds)),
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
        input_corpus: Path,
        output_dir: Path,
        dictionary: Optional[Path],
    ) -> List[str]:
        opt = self.options
        argv: List[str] = [binary]
        argv.extend([str(input_corpus), str(output_dir)])
        argv.extend(["-max_total_time", str(opt.max_total_time)])
        argv.extend(["-max_len", str(opt.max_len)])
        argv.extend(["-timeout", str(opt.timeout)])
        if opt.jobs > 1:
            argv.extend(["-jobs", str(opt.jobs)])
            argv.extend(["-workers", str(opt.workers)])
        dict_path = dictionary or (Path(opt.dict) if opt.dict else None)
        if dict_path is not None:
            argv.extend(["-dict", str(dict_path)])
        if opt.artifact_prefix:
            argv.extend(["-artifact_prefix", str(opt.artifact_prefix)])
        argv.extend(list(opt.extra))
        return argv

    # ----------------------------------------------------------------- repr

    def __repr__(self) -> str:
        return (
            f"LibFuzzerRunner(target={self.target_binary!r}, "
            f"timeout_seconds={self.timeout_seconds})"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_lf_summary(result: Any) -> dict:
    """Extract a tiny counter dict from a libFuzzer run.

    libFuzzer does not emit a structured stats file by default; we
    parse its ``STATS`` lines instead.  Never raises.
    """
    out = {"execs": 0, "edges": 0, "new_edges": 0, "corpus": 0}
    try:
        text = (getattr(result, "stdout", "") or "") + "\n" + (getattr(result, "stderr", "") or "")
    except Exception:
        return out
    for line in text.splitlines():
        upper = line.strip()
        if upper.startswith("#") and "STATS" not in upper:
            continue
        if "cov:" in line:
            try:
                out["edges"] = max(out["edges"], int(line.rsplit("cov:", 1)[1].strip().split()[0]))
            except Exception:
                pass
        if "exec/s:" in line:
            pass
        if "corp:" in line:
            try:
                out["corpus"] = int(line.rsplit("corp:", 1)[1].strip().split()[0])
            except Exception:
                pass
        if "execs:" in line:
            try:
                out["execs"] = int(line.rsplit("execs:", 1)[1].strip().split()[0])
            except Exception:
                pass
    return out


def _collect_lf_crashes(output_dir: Path) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[dict, ...]]:
    """Walk the libFuzzer output directory for crash/timeout artefacts."""
    crashes: List[str] = []
    hangs: List[str] = []
    unique: List[dict] = []
    try:
        for f in sorted(Path(output_dir).iterdir()):
            if not f.is_file():
                continue
            name = f.name
            if name.startswith(_LF_CRASH_PREFIX):
                crashes.append(str(f))
            elif name.startswith(_LF_HANG_PREFIX):
                hangs.append(str(f))
        for c in crashes[:8]:
            unique.append({"path": c, "signature": Path(c).stem[-12:]})
    except Exception:
        pass
    return tuple(crashes), tuple(hangs), tuple(unique)
