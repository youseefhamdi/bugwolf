#!/usr/bin/env python3
"""Provider-neutral runtime adapter contracts for Claude Code lab workflows."""
from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

SCHEMA = "bugwolf/lab-runtime-adapters/v1"
RUNTIME_KINDS = ("browser", "emulator", "chain_node", "model", "mcp", "cloud")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RuntimeDiagnostic:
    runtime: str
    available: bool
    diagnostic: str
    adapter: str = ""
    version: str = ""
    capabilities: list[str] = field(default_factory=list)
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    checked_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}


class RuntimeAdapter:
    """Base adapter: availability is explicit; no output is fabricated."""

    runtime = "generic"

    def __init__(self, *, name: str = "unconfigured", version: str = ""):
        self.name = name
        self.version = version

    def diagnose(self) -> RuntimeDiagnostic:
        available = bool(self.name and self.name != "unconfigured" and shutil.which(self.name))
        if available:
            return RuntimeDiagnostic(runtime=self.runtime, available=True,
                                     diagnostic="runtime executable detected",
                                     adapter=self.name, version=self.version)
        return RuntimeDiagnostic(
            runtime=self.runtime,
            available=False,
            diagnostic="runtime not supplied by lab; adapter is unconfigured",
            adapter=self.name,
            version=self.version,
        )

    def execute(self, _action: Mapping[str, Any]) -> Dict[str, Any]:
        diagnostic = self.diagnose()
        return {"schema": SCHEMA, "ok": False, "executed": False,
                "diagnostic": diagnostic.to_dict()}


class BrowserAdapter(RuntimeAdapter):
    runtime = "browser"


class EmulatorAdapter(RuntimeAdapter):
    runtime = "emulator"


class ChainNodeAdapter(RuntimeAdapter):
    runtime = "chain_node"


class ModelAdapter(RuntimeAdapter):
    runtime = "model"


class McpAdapter(RuntimeAdapter):
    runtime = "mcp"


class CloudAdapter(RuntimeAdapter):
    runtime = "cloud"


_ADAPTERS = {
    "browser": BrowserAdapter,
    "emulator": EmulatorAdapter,
    "chain_node": ChainNodeAdapter,
    "model": ModelAdapter,
    "mcp": McpAdapter,
    "cloud": CloudAdapter,
}


def diagnostics(config: Optional[Mapping[str, Mapping[str, Any]]] = None) -> Dict[str, Any]:
    """Return diagnostics for every optional runtime, never fake observations."""
    config = config or {}
    result = []
    for kind in RUNTIME_KINDS:
        settings = dict(config.get(kind) or {})
        adapter = _ADAPTERS[kind](name=str(settings.get("adapter", "unconfigured")),
                                  version=str(settings.get("version", "")))
        result.append(adapter.diagnose().to_dict())
    return {"schema": SCHEMA, "runtimes": result,
            "available": [item["runtime"] for item in result if item["available"]],
            "unavailable": [item["runtime"] for item in result if not item["available"]]}


def main() -> int:
    print(json.dumps(diagnostics(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
