#!/usr/bin/env python3
# === TypeScript Bridge: gemini.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/gemini.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+
# Invocation:
#   bugwolf --bridge gemini --playbook <yaml>

"""
## Source: bridge spec (1.3 — gemini)
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


BRIDGE_NAME = "gemini"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["gemini"]  # Google Gemini CLI
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "gemini",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "findings_extraction",
    "jsonl_streaming",
    "google_search_grounding",
]
REQUIRES = ["gemini_cli>=0.1.0"]


@dataclass(frozen=True)
class GeminiPlaybook:
    """YAML schema for the Google Gemini CLI bridge."""

    prompt: str
    model: str = "gemini-2.5-pro"
    sandbox: bool = False
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "GeminiPlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            model=str(data.get("model") or "gemini-2.5-pro"),
            sandbox=bool(data.get("sandbox") or False),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def gemini_playbook_loader(playbook: Mapping[str, Any],
                           target: str) -> List[str]:
    pb = GeminiPlaybook.from_mapping(playbook)
    argv: List[str] = ["--model", pb.model,
                       "--target", target,
                       "--output-format", "stream-json"]
    if pb.sandbox:
        argv.append("--sandbox")
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def gemini_result_parser(stdout: str) -> List[Dict[str, Any]]:
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def gemini_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "quota" in text or "429" in text or "rate" in text:
        return BridgeError(
            BridgeErrorKind.NETWORK_ERROR,
            "gemini rate limit",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    if "credentials" in text or "api key" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "gemini missing credentials",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def gemini_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"gemini CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"gemini CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=gemini_playbook_loader,
    result_parser=gemini_result_parser,
    error_handler=gemini_error_handler,
    description="Google Gemini CLI bridge.",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=gemini_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", gemini_smoke_test().to_dict())
    pb = {"prompt": "scan", "model": "gemini-2.5-pro"}
    print("argv:", safe_join_argv(gemini_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())