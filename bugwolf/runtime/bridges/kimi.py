#!/usr/bin/env python3
# === TypeScript Bridge: kimi.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/kimi.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+
# Invocation:
#   bugwolf --bridge kimi --playbook <yaml>

"""
## Source: bridge spec (1.3 — kimi)
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


BRIDGE_NAME = "kimi"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["kimi"]  # Moonshot Kimi CLI
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "kimi",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "findings_extraction",
    "jsonl_streaming",
    "long_context",
]
REQUIRES = ["kimi_cli>=0.1.0"]


@dataclass(frozen=True)
class KimiPlaybook:
    """YAML schema for the Moonshot Kimi CLI bridge."""

    prompt: str
    model: str = "kimi-k2-0905-preview"
    max_context: int = 200000
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "KimiPlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            model=str(data.get("model") or "kimi-k2-0905-preview"),
            max_context=int(data.get("max_context") or 200000),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def kimi_playbook_loader(playbook: Mapping[str, Any],
                         target: str) -> List[str]:
    pb = KimiPlaybook.from_mapping(playbook)
    argv: List[str] = ["run", "--model", pb.model,
                       "--max-context", str(pb.max_context),
                       "--target", target,
                       "--output-format", "stream-json"]
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def kimi_result_parser(stdout: str) -> List[Dict[str, Any]]:
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def kimi_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "auth" in text or "apikey" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "kimi missing credentials",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def kimi_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"kimi CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"kimi CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=kimi_playbook_loader,
    result_parser=kimi_result_parser,
    error_handler=kimi_error_handler,
    description="Moonshot Kimi CLI bridge.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=kimi_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", kimi_smoke_test().to_dict())
    pb = {"prompt": "scan", "model": "kimi-k2-0905-preview"}
    print("argv:", safe_join_argv(kimi_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())