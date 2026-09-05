"""Mythril symbolic-execution runner wrapper.

Mythril is ConsenSys' EVM bytecode symbolic-execution engine.  This
wrapper speaks the same ``RunnerResult`` / ``RunnerUnavailable`` contract
as :mod:`bugwolf.web3.slither_runner` — if Mythril is not on PATH the
runner returns ``RunnerUnavailable(exit_code=127)`` and never raises.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from bugwolf.web3.slither_runner import RunnerResult, RunnerUnavailable


SCHEMA = "bugwolf-web3-mythril-runner/v1"


@dataclass(frozen=True)
class MythrilRunner:
    """Wrapper around the ``myth`` CLI.

    Stub-safe: returns :class:`RunnerUnavailable` when ``myth`` is not
    on PATH; never raises.
    """

    RUNNER = "myth"
    timeout_seconds: int = 1800

    def is_available(self) -> bool:
        return shutil.which(self.RUNNER) is not None

    def run(
        self,
        target: str,
        *,
        solver_timeout: Optional[int] = None,
        max_depth: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
    ):
        if not self.is_available():
            return RunnerUnavailable(
                runner=self.RUNNER,
                reason=f"{self.RUNNER} not on PATH",
            )

        cmd: List[str] = [
            self.RUNNER,
            "analyze",
            target,
            "-o",
            "json",
        ]
        if solver_timeout is not None:
            cmd += ["--solver-timeout", str(solver_timeout)]
        if max_depth is not None:
            cmd += ["--max-depth", str(max_depth)]
        if extra_args:
            cmd += list(extra_args)

        start = time.time()
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start) * 1000)
            return RunnerUnavailable(
                runner=self.RUNNER,
                reason=f"{self.RUNNER} timed out after {self.timeout_seconds}s",
                stderr="timeout",
                command=cmd,
                duration_ms=duration_ms,
            )

        duration_ms = int((time.time() - start) * 1000)
        findings: List[Dict[str, Any]] = []
        if completed.stdout:
            try:
                parsed = json.loads(completed.stdout)
                issues = parsed.get("issues", [])
                for issue in issues:
                    findings.append(
                        {
                            "title": issue.get("title"),
                            "swc_id": issue.get("swc-id"),
                            "severity": issue.get("severity"),
                            "description": (issue.get("description") or "")[:512],
                            "address": issue.get("address"),
                        }
                    )
            except json.JSONDecodeError:
                findings = []

        return RunnerResult(
            runner=self.RUNNER,
            command=cmd,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=duration_ms,
            findings=findings,
        )


__all__ = ["MythrilRunner", "RunnerResult", "RunnerUnavailable", "SCHEMA"]