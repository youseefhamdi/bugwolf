#!/usr/bin/env python3
"""
## Source: bugwolf Phase 1.3 (new module — bridge adapter contract)
## License: bugwolf-MIT
## Port: 2026-09-05

Adapter contract for Python<->TypeScript harness bridges.

Every TypeScript bridge in :mod:`bugwolf.runtime.bridges` implements the
same surface so the Python orchestrator can dispatch to it without
special-casing each harness.  The contract is intentionally small:

  * :attr:`BridgeContract.name`            — short key (e.g. ``"claude_code"``)
  * :attr:`BridgeContract.command`         — argv-array entrypoint
  * :attr:`BridgeContract.env_overrides`   — env vars always set for the bridge
  * :attr:`BridgeContract.playbook_loader` — translates YAML playbook -> argv
  * :attr:`BridgeContract.result_parser`   — normalizes harness JSONL events
  * :attr:`BridgeContract.error_handler`   — maps subprocess errors -> enums
  * :meth:`BridgeContract.smoke_test`      — non-network invocation check

This module contains ONLY the contract types.  Each bridge module is
responsible for instantiating its own CONTRACT.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence


SCHEMA = "bugwolf-bridge-contract/v1"


class BridgeErrorKind(str, Enum):
    """Normalised bridge error taxonomy.

    The same subprocess failure mode should resolve to the same kind across
    every bridge so the orchestrator can apply uniform retry / quarantine
    policy.
    """

    SUBPROCESS_NOT_FOUND = "subprocess_not_found"
    SUBPROCESS_TIMEOUT = "subprocess_timeout"
    SUBPROCESS_NONZERO_EXIT = "subprocess_nonzero_exit"
    INVOCATION_REJECTED = "invocation_rejected"
    AUTH_MISSING = "auth_missing"
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


class BridgeError(Exception):
    """Raised by :meth:`ErrorHandler.to_exception` when a fault is fatal."""

    def __init__(self, kind: BridgeErrorKind, message: str, *,
                 bridge: str, stdout: str = "", stderr: str = "",
                 exit_code: Optional[int] = None):
        self.kind = kind
        self.bridge = bridge
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        super().__init__(f"[{bridge}] {kind.value}: {message}")


@dataclass(frozen=True)
class SpawnResult:
    """Outcome of a bridge subprocess invocation (typed wrapper)."""

    argv: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class BridgeSmokeResult:
    """Outcome of a bridge smoke test (no network, no LLM call)."""

    name: str
    ok: bool
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ok": bool(self.ok),
            "reason": self.reason,
            "details": dict(self.details),
        }


# ---------------------------------------------------------------------------
# Functional hook signatures
# ---------------------------------------------------------------------------

PlaybookLoader = Callable[[Mapping[str, Any], str], List[str]]
"""Translate ``(playbook, target)`` into an argv list for the bridge.

The loader MUST NOT shell-interpolate — it returns an argv array that the
adapter passes to :func:`safe_subprocess.spawn_argv`.
"""

ResultParser = Callable[[str], List[Dict[str, Any]]]
"""Parse the bridge's stdout (JSONL) into a list of normalised events.

Each event is a dict with at minimum ``{"kind": str, ...}``.  The adapter
does NOT trust event content for security decisions — only the parser
output's ``kind`` enum is consumed by downstream tooling.
"""

ErrorHandlerFn = Callable[["SpawnResult"], Optional[BridgeError]]
"""Map a :class:`SpawnResult` to a :class:`BridgeError` (or None if OK)."""


# ---------------------------------------------------------------------------
# Bridge contract
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BridgeContract:
    """The full bridge contract.

    Instances are constructed by each ``*.ts`` Python-spec module.  The
    orchestrator treats them as immutable registries.
    """

    name: str
    command: List[str]
    env_overrides: Dict[str, str]
    playbook_loader: PlaybookLoader
    result_parser: ResultParser
    error_handler: ErrorHandlerFn
    description: str = ""
    version: str = "1.0.0"
    schema: str = SCHEMA
    capabilities: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    smoke_test: Optional[Callable[[], BridgeSmokeResult]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "command": list(self.command),
            "env_overrides": dict(self.env_overrides),
            "capabilities": list(self.capabilities),
            "requires": list(self.requires),
        }


# ---------------------------------------------------------------------------
# Default loaders / parsers / handlers
# ---------------------------------------------------------------------------

def default_playbook_loader(playbook: Mapping[str, Any],
                            target: str) -> List[str]:
    """Generic loader that prepends ``--target`` and serialises the playbook.

    Each bridge may override this for harness-specific flags (e.g. Claude
    Code's ``--tool``, OpenCode's ``--mode``).  The default is suitable for
    bridges that consume a single YAML payload on stdin.
    """
    argv: List[str] = ["--target", target]
    flags = playbook.get("flags") or {}
    if isinstance(flags, Mapping):
        for key, val in flags.items():
            argv.extend([f"--{key}", str(val)])
    return argv


def jsonl_result_parser(stdout: str) -> List[Dict[str, Any]]:
    """Parse JSONL events, ignoring blank lines and unparseable tokens."""
    events: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def default_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    """Translate subprocess failures to :class:`BridgeError` (or None)."""
    if result.timed_out:
        return BridgeError(
            BridgeErrorKind.SUBPROCESS_TIMEOUT,
            "subprocess exceeded timeout",
            bridge="<unknown>", stderr=result.stderr,
            exit_code=result.exit_code,
        )
    if result.exit_code != 0:
        return BridgeError(
            BridgeErrorKind.SUBPROCESS_NONZERO_EXIT,
            f"exit_code={result.exit_code}",
            bridge="<unknown>",
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return None


def safe_join_argv(argv: Sequence[str]) -> str:
    """Return a shell-safe printable form of ``argv`` (for logging only)."""
    return " ".join(shlex.quote(part) for part in argv)


def env_with_overrides(base: Optional[Mapping[str, str]],
                       overrides: Mapping[str, str]) -> Dict[str, str]:
    """Return ``os.environ``-style dict with overrides applied.

    Used by the orchestrator before :func:`safe_subprocess.spawn_argv`.  We
    never store secrets in plain env unless they are already in the base
    environment — the contract is additive.
    """
    merged: Dict[str, str] = {}
    for key, val in (base or {}).items():
        merged[str(key)] = str(val)
    for key, val in overrides.items():
        merged[str(key)] = str(val)
    return merged


def make_env_from_current(overrides: Mapping[str, str]) -> Dict[str, str]:
    """Build env dict from :data:`os.environ` + ``overrides``."""
    return env_with_overrides(os.environ, overrides)


__all__ = [
    "SCHEMA",
    "BridgeErrorKind", "BridgeError",
    "SpawnResult", "BridgeSmokeResult",
    "PlaybookLoader", "ResultParser", "ErrorHandlerFn",
    "BridgeContract",
    "default_playbook_loader", "jsonl_result_parser", "default_error_handler",
    "safe_join_argv", "env_with_overrides", "make_env_from_current",
]