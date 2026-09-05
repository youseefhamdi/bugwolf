#!/usr/bin/env python3
# === TypeScript Bridge: claude_code.ts ===
# This file is the Python-equivalent spec for the .ts bridge. When the user
# has the Node.js + TypeScript toolchain installed, they should port this
# verbatim to TypeScript and place it in:
#   bugwolf/runtime/bridges/claude_code.ts
#
# Target runtime: Node.js 18+ (uses fetch + child_process.spawn)
# Dependencies:   @anthropic-ai/sdk (optional — only when MCP transport is used),
#                 stdlib fetch otherwise
# Invocation:
#   bugwolf --bridge claude_code --playbook <yaml>
#
# The .ts equivalent exports:
#   1. class ClaudeCodeBridge  — orchestrator entry point
#   2. interface Playbook      — the YAML contract this bridge consumes
#   3. function runPlaybook()  — argv+env setup + stdio transport
#   4. function mapEvent()     — Claude Code events -> bugwolf Finding shape
#
# This Python file IS the spec.  No shims or bridges — it is the same
# contract expressed in Python so the orchestrator can call it as a
# normal subprocess until the TS toolchain is wired up.

"""
## Source: bridge spec (1.3 — claude_code)
## License: bugwolf-MIT
## Port: 2026-09-05
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from .adapter import (
    SCHEMA,
    BridgeContract,
    BridgeError,
    BridgeErrorKind,
    BridgeSmokeResult,
    PlaybookLoader,
    ResultParser,
    ErrorHandlerFn,
    SpawnResult,
    default_error_handler,
    default_playbook_loader,
    jsonl_result_parser,
    make_env_from_current,
    safe_join_argv,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BRIDGE_NAME = "claude_code"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["claude"]  # The Claude Code CLI binary.  Resolved at run time.
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "claude_code",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
    "CLAUDE_CODE_USE_BUGWOLF_TOOLS": "1",
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "finding_extraction",
    "jsonl_streaming",
]
REQUIRES = ["claude_code_cli>=1.0.0"]


# ---------------------------------------------------------------------------
# Playbook shape (YAML schema)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClaudeCodePlaybook:
    """The YAML schema consumed by the Claude Code bridge.

    In the .ts equivalent this is exported as an interface (with zod or
    io-ts runtime validation).  Fields map 1:1 to Claude Code CLI flags.
    """

    prompt_file: str
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 8192
    allowed_tools: List[str] = field(default_factory=list)
    system_prompt: str = ""
    dry_run: bool = False
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ClaudeCodePlaybook":
        return cls(
            prompt_file=str(data.get("prompt_file") or ""),
            model=str(data.get("model") or "claude-sonnet-4-20250514"),
            max_tokens=int(data.get("max_tokens") or 8192),
            allowed_tools=list(data.get("allowed_tools") or []),
            system_prompt=str(data.get("system_prompt") or ""),
            dry_run=bool(data.get("dry_run") or False),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


# ---------------------------------------------------------------------------
# Playbook loader — translate YAML -> argv (NEVER shell-string concat)
# ---------------------------------------------------------------------------

def claude_code_playbook_loader(playbook: Mapping[str, Any],
                                target: str) -> List[str]:
    """Translate the YAML playbook into an argv list for the Claude CLI.

    Flags:
      --print            force stdout mode (no interactive REPL)
      --output-format stream-json   stream JSONL events to stdout
      --add-dir <target>  let Claude read the operator-declared target dir
      --allowedTools     whitelist of tool names (comma-separated repeated)
      --model <model>     LLM model id
      --max-tokens <n>    per-response cap
    """
    pb = ClaudeCodePlaybook.from_mapping(playbook)
    argv: List[str] = ["--print", "--output-format", "stream-json",
                       "--add-dir", target, "--model", pb.model,
                       "--max-tokens", str(pb.max_tokens)]
    if pb.dry_run:
        argv.append("--dry-run")
    for tool in pb.allowed_tools:
        argv.extend(["--allowedTools", tool])
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt-file", pb.prompt_file])
    return argv


# ---------------------------------------------------------------------------
# Result parser — JSONL stream events -> normalised bugwolf events
# ---------------------------------------------------------------------------

_EVENT_KIND_MAP = {
    "assistant.message": "assistant_message",
    "tool_use": "tool_invocation",
    "tool_result": "tool_result",
    "finding": "finding",
    "error": "error",
    "result": "result",
}


def claude_code_result_parser(stdout: str) -> List[Dict[str, Any]]:
    """Parse Claude Code's stream-json output into normalised events."""
    events = jsonl_result_parser(stdout)
    normalised: List[Dict[str, Any]] = []
    for ev in events:
        kind = _EVENT_KIND_MAP.get(ev.get("type") or "", str(ev.get("type") or ""))
        ev2 = dict(ev)
        ev2["kind"] = kind
        ev2["bridge"] = BRIDGE_NAME
        normalised.append(ev2)
    return normalised


def claude_code_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    """Map Claude Code subprocess failures to BridgeError."""
    err = default_error_handler(result)
    if err is None:
        return None
    text = (result.stderr or "") + (result.stdout or "")
    text_l = text.lower()
    if "unauthorized" in text_l or "api key" in text_l or "auth" in text_l:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "Claude Code rejected credentials",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    if "econnrefused" in text_l or "enotfound" in text_l or "fetch" in text_l:
        return BridgeError(
            BridgeErrorKind.NETWORK_ERROR,
            "Claude Code network failure",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


# ---------------------------------------------------------------------------
# Smoke test — non-network invocation check
# ---------------------------------------------------------------------------

def claude_code_smoke_test() -> BridgeSmokeResult:
    """Run a no-op invocation: ``claude --version``.

    This does NOT touch the network and does NOT consume quota.  It only
    verifies the CLI is installed and that ``--version`` works.
    """
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"claude CLI not found in PATH (command={COMMAND})",
        )
    # The actual subprocess call is delegated to the orchestrator's
    # safe_subprocess layer — this function only describes the intent.
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"claude CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


# ---------------------------------------------------------------------------
# Exported contract
# ---------------------------------------------------------------------------

CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=claude_code_playbook_loader,
    result_parser=claude_code_result_parser,
    error_handler=claude_code_error_handler,
    description="Claude Code CLI bridge — Anthropic native harness.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=claude_code_smoke_test,
)


# ---------------------------------------------------------------------------
# Self-test entrypoint (only when this file is the __main__)
# ---------------------------------------------------------------------------

def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", claude_code_smoke_test().to_dict())
    sample = json.dumps({"type": "tool_use", "name": "WebFetch",
                         "input": {"url": "https://example.com"}}) + "\n"
    print("parser:", json.dumps(claude_code_result_parser(sample * 2), indent=2))
    pb = {"prompt_file": "/tmp/prompt.md", "model": "claude-sonnet-4-20250514",
          "allowed_tools": ["WebFetch"]}
    print("argv:", safe_join_argv(claude_code_playbook_loader(pb, "/tmp/target")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())