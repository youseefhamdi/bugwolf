# bugwolf/distributed — Redis-backed master/worker pool
# SCHEMA: bugwolf-distributed-ipc-v1
# ## Source: original work for Phase 4.2
# ## License: BugWolf internal
# ## Capability tier: C2 (active scanner) / C3 (exploit) — opt-in only

"""IPC bridge to bugwolf-rs.

Invokes ``bugwolf-rs/target/debug/{healthcheck,bench}`` as argv-array
subprocesses via ``tools.cross_project.safe_subprocess_lib.spawn_argv``.
STUB-SAFE: any error returns ``"unavailable"`` / ``{status:
"unavailable"}``.  Never raises.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from tools.cross_project.safe_subprocess_lib import spawn_argv
except Exception:  # pragma: no cover - tools.* not always importable
    spawn_argv = None  # type: ignore[assignment]


SCHEMA = "bugwolf-distributed-ipc-v1"


_DEFAULT_BIN_DIR = Path(__file__).resolve().parents[2] / "bugwolf-rs" / "target" / "debug"


def _resolve_binary(binary_name: str, binary_path: Optional[str]) -> Optional[str]:
    if binary_path:
        return binary_path
    candidate = _DEFAULT_BIN_DIR / binary_name
    if candidate.exists():
        return str(candidate)
    found = shutil.which(binary_name)
    return found


def is_rust_binary_available(binary_name: str = "healthcheck") -> bool:
    """Return True if the ``bugwolf-rs`` binary is on disk."""
    resolved = _resolve_binary(binary_name, None)
    return bool(resolved) and Path(resolved).exists()


def _run(argv: list, timeout: float = 5.0) -> Dict[str, Any]:
    """Run an argv-array subprocess via ``spawn_argv``; never raise."""
    started = time.time()
    try:
        if spawn_argv is None:
            import subprocess
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
            duration_ms = int((time.time() - started) * 1000)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "exit_code": int(proc.returncode),
                "stdout": str(proc.stdout or ""),
                "stderr": str(proc.stderr or ""),
                "duration_ms": duration_ms,
            }
        result = spawn_argv(list(argv), timeout=timeout)
        return {
            "status": "ok" if result.exit_code == 0 else "error",
            "exit_code": int(result.exit_code),
            "stdout": str(result.stdout),
            "stderr": str(result.stderr),
            "duration_ms": int(result.duration_ms),
            "timed_out": bool(result.timed_out),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "unavailable", "error": f"{type(exc).__name__}: {exc}"}


def run_rust_healthcheck(binary_path: Optional[str] = None) -> str:
    """Invoke the ``healthcheck`` binary.  Returns ``"unavailable"`` on failure."""
    resolved = _resolve_binary("healthcheck", binary_path)
    if not resolved:
        return "unavailable"
    if not Path(resolved).exists():
        return "unavailable"
    res = _run([resolved], timeout=5.0)
    if res.get("status") == "unavailable":
        return "unavailable"
    if res.get("status") != "ok":
        return "unavailable"
    return res.get("stdout", "").strip() or "ok"


def run_rust_bench(
    iterations: int = 1000,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Invoke the ``bench`` binary (if present) with ``--iter N``.

    Falls back to ``{status: "unavailable"}`` on any error.
    """
    resolved = _resolve_binary("bench", binary_path)
    if not resolved or not Path(resolved).exists():
        return {"status": "unavailable", "iterations": int(iterations)}
    argv = [resolved, "--iter", str(int(iterations))]
    res = _run(argv, timeout=10.0)
    if res.get("status") == "unavailable":
        return {"status": "unavailable", "iterations": int(iterations)}
    return {
        "iterations": int(iterations),
        "stdout": res.get("stdout", ""),
        "stderr": res.get("stderr", ""),
        "status": res.get("status", "ok"),
        "duration_ms": res.get("duration_ms", 0),
    }


__all__ = [
    "SCHEMA",
    "is_rust_binary_available",
    "run_rust_healthcheck",
    "run_rust_bench",
]
