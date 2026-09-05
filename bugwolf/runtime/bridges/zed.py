#!/usr/bin/env python3
# === TypeScript Bridge: zed.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/zed.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+
# Invocation:
#   bugwolf --bridge zed --playbook <yaml>

"""
## Source: bridge spec (1.3 — zed)
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


BRIDGE_NAME = "zed"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["zed"]  # Zed editor CLI
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "zed",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "tool_invocation",
    "findings_extraction",
    "jsonl_streaming",
    "editor_integration",
]
REQUIRES = ["zed>=0.150.0"]


@dataclass(frozen=True)
class ZedPlaybook:
    """YAML schema for the Zed editor bridge."""

    prompt: str
    workspace: str = "."
    model: str = "auto"
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ZedPlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            workspace=str(data.get("workspace") or "."),
            model=str(data.get("model") or "auto"),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def zed_playbook_loader(playbook: Mapping[str, Any],
                        target: str) -> List[str]:
    pb = ZedPlaybook.from_mapping(playbook)
    argv: List[str] = ["agent", "--workspace", pb.workspace or target,
                       "--model", pb.model,
                       "--target", target,
                       "--output-format", "stream-json"]
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def zed_result_parser(stdout: str) -> List[Dict[str, Any]]:
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def zed_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "auth" in text or "credential" in text or "login" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "zed requires authentication",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def zed_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"zed CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"zed CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=zed_playbook_loader,
    result_parser=zed_result_parser,
    error_handler=zed_error_handler,
    description="Zed editor bridge (headless agent mode).",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=zed_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", zed_smoke_test().to_dict())
    pb = {"prompt": "scan", "workspace": "/tmp/t", "model": "auto"}
    print("argv:", safe_join_argv(zed_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())