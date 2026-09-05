#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter safe_subprocess.py:1-820 (1.5.n)
## Source: BugWolf runtime/scope.py + tools/opsec.py (Phase 0 in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

safe_subprocess + action_guard + redact_headers + http_creds.

Four tightly-coupled primitives every bugwolf tool depends on:

  * :func:`safe_subprocess.spawn_argv` — argv-array subprocess wrapper
  * :func:`action_guard.check_argv`    — returns blocking issues
  * :func:`redact_headers`             — strips Authorization/Cookie/etc
  * :func:`http_creds.extract_from_url` — captures userinfo in URLs

The :class:`Issue` dataclass describes the kind of block.  Every
issue is structured so the orchestrator can apply uniform policy.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit


SCHEMA = "bugwolf-safe-subprocess/v1"


# ---------------------------------------------------------------------------
# Issue taxonomy
# ---------------------------------------------------------------------------

class IssueSeverity(str, Enum):
    """How serious an action_guard issue is."""
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class Issue:
    """A single action_guard finding."""

    code: str
    message: str
    severity: str = "block"  # block | warn | info
    arg_index: int = -1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "arg_index": self.arg_index,
        }


# ---------------------------------------------------------------------------
# safe_subprocess — argv-array wrapper
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SpawnResult:
    """Outcome of one :func:`spawn_argv` invocation."""

    argv: Tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": bool(self.timed_out),
        }


def spawn_argv(argv: Sequence[str], *,
               cwd: Optional[str] = None,
               timeout: float = 30.0,
               env: Optional[Mapping[str, str]] = None,
               check: bool = False) -> SpawnResult:
    """Spawn ``argv`` as an argv-array subprocess.

    NEVER uses shell-string form. ``timeout`` is in seconds; sub-second
    values are rounded up to one.

    Raises :class:`ShellInjectionRefused` if any argv element contains
    shell metacharacters (the same check :func:`action_guard.check_argv`
    runs).
    """
    issues = action_guard.check_argv(list(argv))
    blocking = [i for i in issues if i.severity == "block"]
    if blocking:
        raise ShellInjectionRefused(
            f"argv refused by action_guard: {[i.code for i in blocking]}")
    merged_env: Dict[str, str] = dict(env if env is not None else os.environ)
    started = time.time()
    try:
        proc = subprocess.run(
            list(argv),
            cwd=cwd,
            env=merged_env,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout)) if timeout >= 1 else 1,
            check=False,
        )
        duration = int((time.time() - started) * 1000)
        return SpawnResult(
            argv=tuple(argv),
            exit_code=int(proc.returncode),
            stdout=str(proc.stdout or ""),
            stderr=str(proc.stderr or ""),
            duration_ms=duration,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = int((time.time() - started) * 1000)
        return SpawnResult(
            argv=tuple(argv),
            exit_code=124,
            stdout=str(exc.stdout or ""),
            stderr=str(exc.stderr or ""),
            duration_ms=duration,
            timed_out=True,
        )


class ShellInjectionRefused(Exception):
    """Raised when action_guard refuses an argv."""


# ---------------------------------------------------------------------------
# action_guard — pre-spawn validator
# ---------------------------------------------------------------------------

# Shell metacharacters we NEVER allow in argv.
_META_RE = re.compile(r"[;&|`$<>\n\r\\]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")

# Binaries that are dangerous to spawn directly.
_DANGEROUS_BINARIES = frozenset({
    "rm", "dd", "mkfs", "mkfs.ext4", "shutdown", "reboot", "halt",
    "poweroff", "userdel", "groupdel", "iptables", "nft", "fdisk",
    "parted", "wipefs",
})


def action_guard_check_argv(argv: Sequence[str]) -> List[Issue]:
    """Public name of the action_guard check."""
    return check_argv(argv)


def check_argv(argv: Sequence[str]) -> List[Issue]:
    """Return the list of :class:`Issue` records for ``argv``."""
    issues: List[Issue] = []
    for idx, arg in enumerate(argv):
        if not isinstance(arg, str):
            issues.append(Issue(
                code="argv_type", message=f"arg[{idx}] is not str",
                severity="block", arg_index=idx))
            continue
        if _META_RE.search(arg):
            issues.append(Issue(
                code="shell_metachar",
                message=f"arg[{idx}] contains shell metacharacter",
                severity="block", arg_index=idx))
    if argv:
        binary = argv[0].rsplit("/", 1)[-1]
        if binary in _DANGEROUS_BINARIES:
            issues.append(Issue(
                code="dangerous_binary",
                message=f"binary {binary!r} is on the block list",
                severity="block", arg_index=0))
    if len(argv) > 4096:
        issues.append(Issue(
            code="argv_too_long",
            message=f"argv has {len(argv)} elements; limit is 4096",
            severity="warn"))
    return issues


# Backwards-compatible alias
action_guard = __import__("types").SimpleNamespace(
    check_argv=check_argv,
)


# ---------------------------------------------------------------------------
# redact_headers — strip credentials before logging / persistence
# ---------------------------------------------------------------------------

_REDACT_HEADER_NAMES = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-amz-security-token", "x-shopify-access-token",
    "x-hub-signature", "proxy-authorization", "www-authenticate",
})


def redact_headers(headers: Mapping[str, str],
                   *,
                   replacement: str = "<redacted>") -> Dict[str, str]:
    """Return a copy of ``headers`` with credential-shaped values stripped."""
    out: Dict[str, str] = {}
    for key, val in headers.items():
        if str(key).strip().lower() in _REDACT_HEADER_NAMES:
            out[str(key)] = replacement
        else:
            out[str(key)] = str(val)
    return out


# ---------------------------------------------------------------------------
# http_creds — extract userinfo from URLs (evidence capture)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HttpCreds:
    """Userinfo extracted from a URL."""

    url: str
    username: str
    password: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "url": self.url,
            "username": self.username,
            "password": "<redacted>",  # never log passwords
        }


def extract_from_url(url: str) -> Dict[str, str]:
    """Return ``{username, password}`` if userinfo is present in ``url``.

    The function NEVER raises; on malformed URLs it returns an empty
    dict.
    """
    if not url:
        return {"username": "", "password": ""}
    try:
        parts = urlsplit(url)
    except ValueError:
        return {"username": "", "password": ""}
    userinfo = parts.username or ""
    password = parts.password or ""
    return {"username": userinfo, "password": password}


def extract_http_creds(url: str) -> HttpCreds:
    """Convenience wrapper returning an :class:`HttpCreds` object."""
    creds = extract_from_url(url)
    return HttpCreds(url=url, username=creds["username"], password=creds["password"])


# Re-export module name expected by the spec
class _SafeSubprocessModule:
    spawn_argv = staticmethod(spawn_argv)


safe_subprocess = _SafeSubprocessModule()


__all__ = [
    "SCHEMA", "Issue", "IssueSeverity",
    "SpawnResult", "ShellInjectionRefused",
    "safe_subprocess", "spawn_argv",
    "action_guard", "check_argv", "action_guard_check_argv",
    "redact_headers",
    "extract_from_url", "extract_http_creds", "HttpCreds",
]