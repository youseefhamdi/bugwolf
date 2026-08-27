#!/usr/bin/env python3
"""Bounded Web3 fixture runner for local Foundry/Hardhat/Echidna-style tools."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.reliability import run_bounded_subprocess

TOOL_PRIORITY = ("slither", "aderyn", "foundry", "echidna", "medusa", "mythril", "halmos")


@dataclass
class ToolRunResult:
    tool: str
    command: List[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    output_sha256: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["schema"] = "bugwolf/tool-run/v1"
        return value


class Web3FixtureRunner:
    """Plan and execute local Web3 tools with strict operational bounds."""

    def __init__(self, target: str, *, project_root: Optional[str] = None,
                 timeout: float = 300.0, max_output_bytes: int = 10_000_000):
        self.target = str(target)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def plan_tools(self, tools: Iterable[str], *, budget: int = 4) -> List[str]:
        """Return the planned tools in deterministic priority order, bounded.

        The plan lists what to run even when a tool is not installed; runtime
        availability is reported separately by ``available()`` so the plan is
        stable and reviewable before execution.
        """
        wanted = [t for t in tools if t in TOOL_PRIORITY]
        wanted = sorted(set(wanted), key=lambda t: TOOL_PRIORITY.index(t))
        return wanted[:max(1, budget)]

    def run_tool(self, tool: str, *, cwd: str | Path, args: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None,
                 timeout: Optional[float] = None) -> ToolRunResult:
        """Execute one tool with timeout, output cap, and process cleanup."""
        import time
        command = [tool] + list(args or [])
        started = time.monotonic()
        try:
            completed = run_bounded_subprocess(
                command, cwd=cwd, timeout=timeout or self.timeout,
                max_output_bytes=self.max_output_bytes, env=env)
            stdout = completed.stdout.decode("utf-8", errors="replace")
            stderr = completed.stderr.decode("utf-8", errors="replace")
            return ToolRunResult(
                tool=tool, command=command, exit_code=completed.returncode,
                stdout=stdout[:self.max_output_bytes],
                stderr=stderr[:self.max_output_bytes],
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                output_sha256=hashlib.sha256(stdout.encode()).hexdigest()[:16],
            )
        except Exception as exc:
            return ToolRunResult(
                tool=tool, command=command, exit_code=-1,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                error=f"{type(exc).__name__}: {str(exc)[:300]}",
            )