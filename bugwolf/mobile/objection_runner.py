"""Objection runtime wrapper.

``objection`` is a Frida-powered exploration toolkit for iOS and
Android.  This wrapper provides a stub-safe runner: if ``objection``
is not on PATH, the methods return ``ObjectionUnavailable`` rather
than raising.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-mobile-objection/v1"


@dataclass(frozen=True)
class ObjectionUnavailable:
    runner: str = "objection"
    reason: str = "objection not on PATH"
    available: bool = False
    command: List[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": False,
            "reason": self.reason,
            "command": list(self.command),
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class ObjectionResult:
    runner: str = "objection"
    command: List[str] = field(default_factory=list)
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    available: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": True,
            "exit_code": self.exit_code,
            "stdout_hash": hash(self.stdout) & 0xFFFFFFFF,
            "stderr_hash": hash(self.stderr) & 0xFFFFFFFF,
            "duration_ms": self.duration_ms,
            "command": list(self.command),
        }


class ObjectionRunner:
    """Stub-safe runner for the ``objection`` CLI."""

    RUNNER = "objection"

    def is_available(self) -> bool:
        return shutil.which(self.RUNNER) is not None

    def explore(
        self,
        bundle_id: str,
        *,
        commands: Optional[List[str]] = None,
        timeout_seconds: int = 600,
    ):
        """Run a series of ``objection`` commands against ``bundle_id``.

        Returns an :class:`ObjectionResult` or
        :class:`ObjectionUnavailable`.  Never raises.
        """
        if not self.is_available():
            return ObjectionUnavailable()

        cmd: List[str] = [self.RUNNER, "explore", "-g", bundle_id]
        start = time.time()
        if commands:
            cmd += ["-c", "; ".join(commands)]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start) * 1000)
            return ObjectionUnavailable(
                reason=f"objection timed out after {timeout_seconds}s",
                command=cmd,
                duration_ms=duration_ms,
            )

        duration_ms = int((time.time() - start) * 1000)
        return ObjectionResult(
            command=cmd,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=duration_ms,
        )


__all__ = ["ObjectionRunner", "ObjectionResult", "ObjectionUnavailable", "SCHEMA"]