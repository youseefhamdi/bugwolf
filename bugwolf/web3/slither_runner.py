"""Slither static-analysis runner wrapper.

Slither is Trail-of-Bits' Solidity static analyzer.  This module wraps
the ``slither`` CLI in a stub-safe runner: if ``slither`` is not on
PATH, the runner returns a :class:`RunnerUnavailable` result with
``exit_code=127`` rather than raising.

The runner deliberately speaks through dataclasses (``RunnerResult``)
so that callers can serialize the result onto the bugwolf event bus
without dependency on third-party types.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-web3-slither-runner/v1"


@dataclass(frozen=True)
class RunnerUnavailable:
    """Returned when a wrapped CLI tool is not on PATH."""

    runner: str
    reason: str
    exit_code: int = 127
    stderr: str = ""
    command: List[str] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def available(self) -> bool:
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": False,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "stderr": self.stderr,
            "command": list(self.command),
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class RunnerResult:
    """A successful run of an external CLI tool."""

    runner: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": True,
            "exit_code": self.exit_code,
            "command": list(self.command),
            "stdout_hash": hash(self.stdout) & 0xFFFFFFFF,
            "stderr_hash": hash(self.stderr) & 0xFFFFFFFF,
            "duration_ms": self.duration_ms,
            "findings": self.findings,
        }


class SlitherRunner:
    """Wrapper around the ``slither`` CLI.

    Stub-safe: ``run()`` returns a :class:`RunnerUnavailable` when the
    binary is missing, and never raises.
    """

    RUNNER = "slither"

    def __init__(self, timeout_seconds: int = 600) -> None:
        self.timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        return shutil.which(self.RUNNER) is not None

    def run(
        self,
        target: str,
        *,
        json_output: bool = True,
        detectors: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ):
        """Run Slither against ``target`` (a file or directory).

        Returns a :class:`RunnerResult` on success or a
        :class:`RunnerUnavailable` if Slither is missing.  Never raises.
        """
        if not self.is_available():
            return RunnerUnavailable(
                runner=self.RUNNER,
                reason=f"{self.RUNNER} not on PATH",
            )

        cmd: List[str] = [self.RUNNER, target]
        if json_output:
            cmd += ["--json", "-"]
        if detectors:
            cmd += ["--detect", detectors]
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
        if json_output and completed.stdout:
            try:
                parsed = json.loads(completed.stdout)
                detectors = parsed.get("results", {}).get("detectors", [])
                for d in detectors:
                    findings.append(
                        {
                            "check": d.get("check"),
                            "impact": d.get("impact"),
                            "confidence": d.get("confidence"),
                            "description": (d.get("description") or "")[:512],
                            "file": (d.get("elements") or [{}])[0].get(
                                "source_mapping", {}
                            ).get("filename_relative"),
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


__all__ = ["SlitherRunner", "RunnerResult", "RunnerUnavailable", "SCHEMA"]