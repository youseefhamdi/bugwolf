#!/usr/bin/env python3
"""Bounded red-team runner integration (PyRIT / Garak / Promptfoo).

Plans and executes local red-team CLI commands with strict timeouts and
output caps, then normalizes their output through the existing AI tool
adapters. Missing tools are reported gracefully; nothing runs without the
operator providing the local sandbox.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.ai_tool_adapters import AIToolAdapters
from tools.reliability import run_bounded_subprocess

_COMMAND_TEMPLATES = {
    "pyrit": lambda target, out: ["pyrit", "attack", "--target", str(target),
                                  "--output", str(out)],
    "garak": lambda target, out: ["garak", "--model_type", "rest",
                                  "--model_name", str(target),
                                  "--report_prefix", str(out)],
    "promptfoo": lambda target, out: ["promptfoo", "eval", "--config",
                                      str(target), "--output", str(out)],
}


class RedTeamRunner:
    def __init__(self, target: str, *, timeout: float = 300.0,
                 max_output_bytes: int = 10_000_000):
        self.target = str(target)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def plan_commands(self, tool: str, *, target: str = "",
                      output_dir: str = "") -> List[Dict[str, Any]]:
        """Return the deterministic command plan (even when the tool is absent)."""
        if tool not in _COMMAND_TEMPLATES:
            return []
        out = Path(output_dir or ".").expanduser().resolve()
        command = _COMMAND_TEMPLATES[tool](target or self.target, out)
        return [{"tool": tool, "command": command,
                 "available": self.available(tool)}]

    def run_command(self, tool: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
        import time
        if not self.available(tool):
            return {"ok": False, "tool": tool, "error": f"{tool} not installed"}
        command = [tool] + list(args or [])
        started = time.monotonic()
        try:
            completed = run_bounded_subprocess(
                command, cwd=str(Path.cwd()), timeout=self.timeout,
                max_output_bytes=self.max_output_bytes)
            stdout = completed.stdout.decode("utf-8", errors="replace")
            return {
                "ok": completed.returncode == 0, "tool": tool,
                "exit_code": completed.returncode,
                "stdout_preview": stdout[-4000:],
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "tool": tool, "error": "timeout"}
        except Exception as exc:
            return {"ok": False, "tool": tool,
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}"}

    def normalize(self, tool: str, output: Dict[str, Any],
                  *, project_root: Optional[str] = None) -> List[Any]:
        """Normalize tool output through the shared AI adapters."""
        adapters = AIToolAdapters(self.target, project_root=project_root)
        if tool == "pyrit":
            return adapters.from_pyrit(output)
        if tool == "garak":
            return adapters.from_garak(output)
        if tool == "promptfoo":
            return adapters.from_promptfoo(output)
        return []

    def run_and_normalize(self, tool: str, *, output: Dict[str, Any],
                          project_root: Optional[str] = None) -> Dict[str, Any]:
        candidates = self.normalize(tool, output, project_root=project_root)
        added = 0
        if candidates:
            adapters = AIToolAdapters(self.target, project_root=project_root)
            added = sum(1 for _ in candidates if adapters.register([candidates[0]]))
        return {"tool": tool, "candidates": len(candidates), "registered": added}