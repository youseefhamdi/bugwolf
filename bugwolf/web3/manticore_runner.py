"""Manticore concolic-execution runner wrapper.

Manticore is Trail-of-Bits' concolic-execution engine; it accepts
EVM bytecode and explores reachable states. This wrapper follows the
same stub-safe contract as the Slither and Mythril runners.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from bugwolf.web3.slither_runner import RunnerResult, RunnerUnavailable


SCHEMA = "bugwolf-web3-manticore-runner/v1"


@dataclass(frozen=True)
class ManticoreRunner:
    """Wrapper around the ``manticore`` CLI.

    Stub-safe: returns :class:`RunnerUnavailable` when ``manticore`` is
    not on PATH; never raises.
    """

    RUNNER = "manticore"
    timeout_seconds: int = 1800

    def is_available(self) -> bool:
        return shutil.which(self.RUNNER) is not None

    def run(
        self,
        bytecode_or_solidity: str,
        *,
        contract_name: Optional[str] = None,
        explore_priority: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ):
        if not self.is_available():
            return RunnerUnavailable(
                runner=self.RUNNER,
                reason=f"{self.RUNNER} not on PATH",
            )

        cmd: List[str] = [self.RUNNER, bytecode_or_solidity]
        if contract_name:
            cmd += ["--contract", contract_name]
        if explore_priority:
            cmd += ["--explore-priority", explore_priority]
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
        # Manticore emits ndjson-like summaries; we parse best-effort.
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("type") == "finding":
                findings.append(
                    {
                        "kind": obj.get("kind"),
                        "address": obj.get("address"),
                        "pc": obj.get("pc"),
                        "description": (obj.get("description") or "")[:512],
                    }
                )

        return RunnerResult(
            runner=self.RUNNER,
            command=cmd,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=duration_ms,
            findings=findings,
        )


__all__ = ["ManticoreRunner", "RunnerResult", "RunnerUnavailable", "SCHEMA"]