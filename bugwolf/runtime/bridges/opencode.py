#!/usr/bin/env python3
# === TypeScript Bridge: opencode.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/opencode.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+ (fetch + child_process.spawn)
# Dependencies:   stdlib fetch
# Invocation:
#   bugwolf --bridge opencode --playbook <yaml>

"""
## Source: bridge spec (1.3 — opencode)
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


BRIDGE_NAME = "opencode"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["opencode"]  # OpenCode CLI
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "opencode",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "findings_extraction",
    "jsonl_streaming",
]
REQUIRES = ["opencode_cli>=0.5.0"]


@dataclass(frozen=True)
class OpenCodePlaybook:
    """YAML schema for the OpenCode CLI bridge."""

    prompt: str
    model: str = "auto"
    mode: str = "agent"
    tools: List[str] = field(default_factory=list)
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "OpenCodePlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            model=str(data.get("model") or "auto"),
            mode=str(data.get("mode") or "agent"),
            tools=list(data.get("tools") or []),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def opencode_playbook_loader(playbook: Mapping[str, Any],
                             target: str) -> List[str]:
    """Translate YAML -> argv for the opencode CLI."""
    pb = OpenCodePlaybook.from_mapping(playbook)
    argv: List[str] = ["run", "--model", pb.model,
                       "--mode", pb.mode,
                       "--target", target]
    for tool in pb.tools:
        argv.extend(["--tool", tool])
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def opencode_result_parser(stdout: str) -> List[Dict[str, Any]]:
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def opencode_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "auth" in text or "apikey" in text or "unauthorized" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "opencode rejected credentials",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def opencode_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"opencode CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"opencode CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=opencode_playbook_loader,
    result_parser=opencode_result_parser,
    error_handler=opencode_error_handler,
    description="OpenCode CLI bridge.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=opencode_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", opencode_smoke_test().to_dict())
    pb = {"prompt": "scan", "model": "auto", "mode": "agent"}
    print("argv:", safe_join_argv(opencode_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())