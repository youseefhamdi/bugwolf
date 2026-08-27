#!/usr/bin/env python3
"""Report readiness of local BugWolf runtime dependencies."""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.lab_runtime_adapters import RUNTIME_KINDS, diagnostics


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def doctor() -> Dict[str, Any]:
    result = diagnostics({})
    checks: Dict[str, Dict[str, Any]] = {}
    checks["browser"] = {"available": bool(shutil.which("node")),
                          "fix": "python3 -m playwright install chromium"}
    checks["emulator"] = {"available": bool(shutil.which("adb") and shutil.which("emulator")),
                           "fix": "install Android SDK emulator or run: scripts/lab_setup.sh up emulator"}
    checks["chain_node"] = {"available": bool(shutil.which("anvil")) or _port_open("127.0.0.1", 8545),
                             "fix": "anvil --host 127.0.0.1 --port 8545"}
    model_ok = _port_open("127.0.0.1", 11434)
    checks["model"] = {"available": model_ok, "fix": "ollama serve && ollama pull <pinned-model>"}
    checks["mcp"] = {"available": os.path.isfile("lab/mcp/mcp_local_server.py"),
                      "fix": "provide lab/mcp/mcp_local_server.py and run it locally"}
    checks["cloud"] = {"available": _port_open("127.0.0.1", 4566),
                        "fix": "scripts/lab_setup.sh up cloud"}
    rows = []
    for kind in RUNTIME_KINDS:
        item = dict(checks[kind])
        item["runtime"] = kind
        if not item["available"]:
            item["diagnostic"] = "runtime not supplied by lab; fix: " + item["fix"]
        else:
            item["diagnostic"] = "runtime detected; run a domain-specific health check before campaign execution"
        rows.append(item)
    result["doctor"] = rows
    result["ready"] = all(item["available"] for item in rows)
    result["available"] = [item["runtime"] for item in rows if item["available"]]
    result["unavailable"] = [item["runtime"] for item in rows if not item["available"]]
    return result


def main(argv: Optional[Iterable[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf lab runtime doctor")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    result = doctor()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Runtime       Status   Diagnostic")
        for item in result["doctor"]:
            print(f"{item['runtime']:<13} {'READY' if item['available'] else 'MISSING':<8} {item['diagnostic']}")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
