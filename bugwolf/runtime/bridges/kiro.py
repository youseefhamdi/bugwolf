#!/usr/bin/env python3
# === TypeScript Bridge: kiro.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/kiro.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+
# Invocation:
#   bugwolf --bridge kiro --playbook <yaml>

"""
## Source: bridge spec (1.3 — kiro)
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


BRIDGE_NAME = "kiro"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["kiro"]  # Kiro CLI
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "kiro",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "findings_extraction",
    "jsonl_streaming",
]
REQUIRES = ["kiro_cli>=0.1.0"]


@dataclass(frozen=True)
class KiroPlaybook:
    """YAML schema for the Kiro CLI bridge."""

    prompt: str
    mode: str = "assistant"
    model: str = "auto"
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "KiroPlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            mode=str(data.get("mode") or "assistant"),
            model=str(data.get("model") or "auto"),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def kiro_playbook_loader(playbook: Mapping[str, Any],
                         target: str) -> List[str]:
    pb = KiroPlaybook.from_mapping(playbook)
    argv: List[str] = ["exec", "--mode", pb.mode,
                       "--model", pb.model,
                       "--target", target]
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def kiro_result_parser(stdout: str) -> List[Dict[str, Any]]:
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def kiro_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "auth" in text or "login" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "kiro requires authentication",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def kiro_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"kiro CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"kiro CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=kiro_playbook_loader,
    result_parser=kiro_result_parser,
    error_handler=kiro_error_handler,
    description="Kiro CLI bridge.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=kiro_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", kiro_smoke_test().to_dict())
    pb = {"prompt": "scan", "mode": "assistant", "model": "auto"}
    print("argv:", safe_join_argv(kiro_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())