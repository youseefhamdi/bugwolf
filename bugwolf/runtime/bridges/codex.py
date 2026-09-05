#!/usr/bin/env python3
# === TypeScript Bridge: codex.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/codex.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+ (fetch + child_process.spawn)
# Dependencies:   openai (optional, only when proxy mode is used), stdlib fetch
# Invocation:
#   bugwolf --bridge codex --playbook <yaml>

"""
## Source: bridge spec (1.3 — codex)
## License: bugwolf-MIT
## Port: 2026-09-05
"""

from __future__ import annotations

import dataclasses
import json
import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .adapter import (
    BridgeContract,
    BridgeError,
    BridgeErrorKind,
    BridgeSmokeResult,
    SpawnResult,
    default_error_handler,
    jsonl_result_parser,
    safe_join_argv,
)


BRIDGE_NAME = "codex"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["codex"]  # OpenAI Codex CLI binary
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "codex",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "jsonl_streaming",
    "findings_extraction",
]
REQUIRES = ["codex_cli>=0.1.0"]


@dataclass(frozen=True)
class CodexPlaybook:
    """YAML schema for the OpenAI Codex CLI bridge.

    Mirrors the CLI surface used by the OpenAI research preview CLI:
    ``codex exec --model gpt-5 --json --prompt-file <path>``.
    """

    prompt_file: str
    model: str = "gpt-5"
    sandbox: str = "read-only"
    full_auto: bool = False
    json_output: bool = True
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CodexPlaybook":
        return cls(
            prompt_file=str(data.get("prompt_file") or ""),
            model=str(data.get("model") or "gpt-5"),
            sandbox=str(data.get("sandbox") or "read-only"),
            full_auto=bool(data.get("full_auto") or False),
            json_output=bool(data.get("json_output", True)),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def codex_playbook_loader(playbook: Mapping[str, Any],
                          target: str) -> List[str]:
    """Translate YAML playbook -> argv for the codex CLI.

    Flags:
      exec               subcommand
      --model <model>     LLM model id
      --sandbox <kind>    read-only | workspace-write | danger-full-access
      --full-auto         enable YOLO-ish execution (off by default)
      --json              force JSONL output
      --cd <target>       CWD for the sandboxed exec
      <prompt_file>       positional: prompt file path
    """
    pb = CodexPlaybook.from_mapping(playbook)
    argv: List[str] = ["exec", "--model", pb.model,
                       "--sandbox", pb.sandbox,
                       "--cd", target]
    if pb.full_auto:
        argv.append("--full-auto")
    if pb.json_output:
        argv.append("--json")
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.append(pb.prompt_file)
    return argv


def codex_result_parser(stdout: str) -> List[Dict[str, Any]]:
    """Parse codex JSONL events."""
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("event") or ev.get("type") or "event"))
    return events


def codex_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    """Map codex subprocess failures to BridgeError."""
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "401" in text or "api key" in text or "unauthorized" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "codex rejected credentials",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    if "rate limit" in text or "429" in text:
        return BridgeError(
            BridgeErrorKind.NETWORK_ERROR,
            "codex rate limit hit",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def codex_smoke_test() -> BridgeSmokeResult:
    """Run ``codex --version``."""
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"codex CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"codex CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=codex_playbook_loader,
    result_parser=codex_result_parser,
    error_handler=codex_error_handler,
    description="OpenAI Codex CLI bridge.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=codex_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", codex_smoke_test().to_dict())
    pb = {"prompt_file": "/tmp/p.md", "model": "gpt-5", "sandbox": "read-only"}
    print("argv:", safe_join_argv(codex_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())