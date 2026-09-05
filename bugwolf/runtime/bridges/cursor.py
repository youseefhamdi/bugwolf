#!/usr/bin/env python3
# === TypeScript Bridge: cursor.ts ===
# This file is the Python-equivalent spec for the .ts bridge.  Port verbatim
# to bugwolf/runtime/bridges/cursor.ts when the .ts toolchain is available.
#
# Target runtime: Node.js 18+ (fetch + child_process.spawn)
# Dependencies:   stdlib fetch; Cursor is editor-native — invocation goes
#                 through the ``cursor`` shell helper or the ``cursor-agent``
#                 CLI shipped with Cursor 0.40+.
# Invocation:
#   bugwolf --bridge cursor --playbook <yaml>

"""
## Source: bridge spec (1.3 — cursor)
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


BRIDGE_NAME = "cursor"
BRIDGE_VERSION = "1.0.0"
COMMAND = ["cursor-agent"]  # Cursor editor CLI helper
ENV_OVERRIDES: Dict[str, str] = {
    "BUGWOLF_BRIDGE": "cursor",
    "BUGWOLF_BRIDGE_VERSION": BRIDGE_VERSION,
}
CAPABILITIES = [
    "playbook_execution",
    "editor_command_palette",
    "findings_extraction",
    "jsonl_streaming",
]
REQUIRES = ["cursor>=0.40.0"]


@dataclass(frozen=True)
class CursorPlaybook:
    """YAML schema for the Cursor editor bridge.

    Cursor's agent mode accepts a prompt and an optional model id.  The
    bridge here delegates to ``cursor-agent`` so we can stay headless.
    """

    prompt: str
    model: str = "auto"
    workspace: str = "."
    headless: bool = True
    extra_flags: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CursorPlaybook":
        return cls(
            prompt=str(data.get("prompt") or ""),
            model=str(data.get("model") or "auto"),
            workspace=str(data.get("workspace") or "."),
            headless=bool(data.get("headless", True)),
            extra_flags=dict(data.get("extra_flags") or {}),
        )


def cursor_playbook_loader(playbook: Mapping[str, Any],
                           target: str) -> List[str]:
    """Translate the YAML playbook into argv for the cursor-agent CLI."""
    pb = CursorPlaybook.from_mapping(playbook)
    argv: List[str] = ["run", "--model", pb.model,
                       "--workspace", pb.workspace or target,
                       "--headless" if pb.headless else "--interactive"]
    for key, val in pb.extra_flags.items():
        argv.extend([f"--{key}", str(val)])
    argv.extend(["--prompt", pb.prompt])
    return argv


def cursor_result_parser(stdout: str) -> List[Dict[str, Any]]:
    """Parse Cursor's JSONL output."""
    events = jsonl_result_parser(stdout)
    for ev in events:
        ev.setdefault("bridge", BRIDGE_NAME)
        ev.setdefault("kind", str(ev.get("type") or "event"))
    return events


def cursor_error_handler(result: SpawnResult) -> Optional[BridgeError]:
    """Map Cursor subprocess failures to BridgeError."""
    err = default_error_handler(result)
    if err is None:
        return None
    text = ((result.stderr or "") + (result.stdout or "")).lower()
    if "auth" in text or "login" in text or "credential" in text:
        return BridgeError(
            BridgeErrorKind.AUTH_MISSING,
            "Cursor requires an authenticated session",
            bridge=BRIDGE_NAME,
            stdout=result.stdout, stderr=result.stderr,
            exit_code=result.exit_code,
        )
    return dataclasses.replace(err, bridge=BRIDGE_NAME)


def cursor_smoke_test() -> BridgeSmokeResult:
    cli = shutil.which(COMMAND[0]) if COMMAND else None
    if not cli:
        return BridgeSmokeResult(
            name=BRIDGE_NAME, ok=False,
            reason=f"cursor-agent CLI not in PATH (command={COMMAND})",
        )
    return BridgeSmokeResult(
        name=BRIDGE_NAME, ok=True,
        reason=f"cursor-agent CLI resolved at {cli}",
        details={"binary": cli, "version_flag": "--version"},
    )


CONTRACT = BridgeContract(
    name=BRIDGE_NAME,
    command=list(COMMAND),
    env_overrides=dict(ENV_OVERRIDES),
    playbook_loader=cursor_playbook_loader,
    result_parser=cursor_result_parser,
    error_handler=cursor_error_handler,
    description="Cursor editor bridge (headless cursor-agent).",
    version=BRIDGE_VERSION,
    capabilities=list(CAPABILITIES),
    requires=list(REQUIRES),
    smoke_test=cursor_smoke_test,
)


def _self_test() -> int:
    print(json.dumps(CONTRACT.to_dict(), indent=2))
    print("smoke:", cursor_smoke_test().to_dict())
    pb = {"prompt": "scan", "model": "auto", "workspace": "/tmp/t"}
    print("argv:", safe_join_argv(cursor_playbook_loader(pb, "/tmp/t")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())