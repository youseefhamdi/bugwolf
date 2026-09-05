#!/usr/bin/env python3
"""BugWolf mandatory pre-flight (orchestrator plan v2, section 4.5).

Non-skippable capability discovery before any mission work: no recon, no
dispatch, no traffic until pre-flight completes.  This is NOT a permission
gate -- nothing is restricted and nothing is blocked from running later.
It exists because agents cannot use tools they never discovered, and
discovering that mid-campaign burns lanes on degraded technique choices.

Order rule (enforced by the scheduler):
  PF1  machine tool inventory  - every hunting binary + BugWolf module
       fingerprinted into state/preflight/manifest.json
  PF2  MCP connection checks   - #1 browserMCP, #2 burpMCP, in that order;
       a down connection marks dependent work BLOCKED/DEGRADED -- never
       silently skipped
  PF3  memory                  - the manifest digest attaches to the
       MissionSpec (preflight_manifest_ref) and every lane context, so no
       agent has to "remember" what exists
  PF4  state machine           - per-connection
       UNKNOWN -> CHECKING -> CONNECTED | DEGRADED | BLOCKED, re-checked on
       demand / on dependent-task failure / every 60s; transitions publish
       MCP_CONNECTION_CHANGED so the scheduler can auto-reopen blocked work.

All probing is offline-safe and fail-open: a failed check is recorded, not
raised.  Binary probes use short timeouts and never touch a target.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import target_slug, workspace_root

try:  # contract status constants (single source of truth)
    from tools.runtime.contracts import (
        MCP_UNKNOWN, MCP_CHECKING, MCP_CONNECTED, MCP_DEGRADED, MCP_BLOCKED,
        ARTIFACT_PREFLIGHT,
    )
except ImportError:  # pragma: no cover - installed-skill fallback
    from contracts import (  # type: ignore
        MCP_UNKNOWN, MCP_CHECKING, MCP_CONNECTED, MCP_DEGRADED, MCP_BLOCKED,
        ARTIFACT_PREFLIGHT,
    )

SCHEMA = "bugwolf-preflight/v1"

BROWSER_MCP = "browser_mcp"
BURP_MCP = "burp_mcp"
MCP_CONNECTIONS = (BROWSER_MCP, BURP_MCP)  # check order is mandated (PF2)

# Re-check interval for cached connection state (PF4).
CONNECTION_TTL_SECONDS = 60.0

# PF1 inventory: hunting binaries with version probes.  Names follow the
# plan's pre-flight list plus batch-2/4 additions (chaos/dnsx/naabu/katana,
# gitleaks/trufflehog, exiftool) and the Web3 toolchain (forge/anvil/cast/
# solc/slither).  Status is ready/fallback/missing -- never a gate.
BINARY_CAPABILITIES: Dict[str, tuple] = {
    "httpx": ("--version", "-version"),
    "subfinder": ("-version",),
    "amass": ("-version",),
    "nuclei": ("-version",),
    "ffuf": ("-V",),
    "gau": ("--version",),
    "waymore": ("--version",),
    "arjun": ("--version",),
    "sqlmap": ("--version",),
    "ghauri": ("--version",),
    "jwt_tool": ("",),
    "apktool": ("--version",),
    "jadx": ("--version",),
    "kiterunner": ("version",),
    "curl": ("--version",),
    "nmap": ("--version",),
    "chaos": ("-version",),
    "dnsx": ("-version",),
    "naabu": ("-version",),
    "katana": ("-version",),
    "gitleaks": ("version",),
    "trufflehog": ("--version",),
    "exiftool": ("-ver",),
    "forge": ("--version",),
    "anvil": ("--version",),
    "cast": ("--version",),
    "solc": ("--version",),
    "slither": ("--version",),
}

# BugWolf core modules whose importability lanes depend on.
MODULE_CAPABILITIES = (
    "tools.core.signal_bus",
    "tools.core.model_router",
    "tools.runtime.contracts",
    "tools.core.live_executor",
    "tools.recon.historical_asset_delta",
)

# Default MCP endpoints (overridable via environment; the pasted elite loop
# documents Burp Pro MCP on 127.0.0.1:9876).
MCP_DEFAULT_URLS = {
    BROWSER_MCP: "http://127.0.0.1:9222",
    BURP_MCP: "http://127.0.0.1:9876",
}

# BugWolf modules are always a fallback for raw-send work; browser work has
# no fallback (that is the plan's BLOCKED semantics).
MCP_FALLBACKS = {BROWSER_MCP: False, BURP_MCP: True}


# ---------------------------------------------------------------------------
# Connection state machine (PF4)
# ---------------------------------------------------------------------------


@dataclass
class ConnectionState:
    name: str
    status: str = MCP_UNKNOWN
    url: str = ""
    detail: str = ""
    latency_ms: int = 0
    checked_at: float = 0.0
    transitions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "status": self.status, "url": self.url,
            "detail": self.detail, "latency_ms": self.latency_ms,
            "transitions": self.transitions,
        }


class ConnectionRegistry:
    """Tracks MCP connection state; transitions are publishable events."""

    def __init__(self) -> None:
        self._states: Dict[str, ConnectionState] = {}

    def get(self, name: str) -> ConnectionState:
        if name not in self._states:
            self._states[name] = ConnectionState(name=name)
        return self._states[name]

    def update(self, name: str, status: str, *, url: str = "",
               detail: str = "", latency_ms: int = 0) -> tuple:
        """Transition state; returns (changed: bool, state)."""
        state = self.get(name)
        changed = state.status != status
        if changed:
            state.transitions += 1
        state.status = status
        state.url = url or state.url
        state.detail = detail
        state.latency_ms = latency_ms
        state.checked_at = time.time()
        return changed, state

    def fresh(self, name: str) -> bool:
        state = self.get(name)
        return (state.status not in (MCP_UNKNOWN, MCP_CHECKING)
                and (time.time() - state.checked_at) < CONNECTION_TTL_SECONDS)


# Module-level registry (process-wide state machine) + injectable HTTP probe
# so tests never need a live endpoint.
_REGISTRY = ConnectionRegistry()


def _probe_http(url: str, timeout: float = 2.0) -> tuple:
    """GET an MCP endpoint.  Returns (reachable: bool, detail, latency_ms)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "bugwolf-preflight"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = (resp.read(200) or b"").decode("utf-8", "replace")
            latency = int((time.monotonic() - start) * 1000)
            return True, f"HTTP {resp.status}: {body[:80]!r}", latency
    except urllib.error.HTTPError as exc:
        latency = int((time.monotonic() - start) * 1000)
        return True, f"HTTP {exc.code} (server up)", latency
    except Exception as exc:  # noqa: BLE001 - fail-open by design
        latency = int((time.monotonic() - start) * 1000)
        return False, f"{type(exc).__name__}: {exc}", latency


def mcp_url(name: str) -> str:
    env_key = "BUGWOLF_" + name.upper() + "_URL"
    return os.environ.get(env_key) or MCP_DEFAULT_URLS.get(name, "")


def check_connection(name: str, *, force: bool = False,
                     registry: Optional[ConnectionRegistry] = None) -> ConnectionState:
    """Check one MCP connection (PF2); cached for CONNECTION_TTL_SECONDS."""
    reg = registry or _REGISTRY
    if name not in MCP_CONNECTIONS:
        raise ValueError(f"unknown MCP connection {name!r}")
    if not force and reg.fresh(name):
        return reg.get(name)
    url = mcp_url(name)
    reg.update(name, MCP_CHECKING, url=url)
    reachable, detail, latency = _probe_http(url)
    if reachable:
        status = MCP_CONNECTED
    elif MCP_FALLBACKS.get(name, False):
        status = MCP_DEGRADED  # raw sends fall back; history mining re-queued
    else:
        status = MCP_BLOCKED    # dependent lane blocked, never silently skipped
    changed, state = reg.update(name, status, url=url, detail=detail,
                                latency_ms=latency)
    if changed:
        _publish_connection_change(state)
    return state


def _publish_connection_change(state: ConnectionState) -> None:
    """Publish MCP_CONNECTION_CHANGED (best-effort; never raises)."""
    try:
        from tools.core.signal_bus import MCP_CONNECTION_CHANGED, SignalBus
        SignalBus("orchestrator").publish(
            MCP_CONNECTION_CHANGED, "preflight",
            {"connection": state.to_dict()})
    except Exception:  # noqa: BLE001 - bus is advisory
        pass


def connection_snapshot() -> Dict[str, Dict[str, Any]]:
    return {name: _REGISTRY.get(name).to_dict() for name in MCP_CONNECTIONS}


# ---------------------------------------------------------------------------
# PF1 inventory
# ---------------------------------------------------------------------------


def _fingerprint_binary(name: str, flags: tuple) -> Dict[str, Any]:
    invoke = shutil.which(name)
    if not invoke:
        return {"name": name, "kind": "binary", "status": "missing",
                "version": "", "invoke_path": "", "latency_ms": 0,
                "detail": "not found on PATH"}
    from tools.runtime.sandbox import sandboxed_run, SandboxViolation
    for flag in flags:
        cmd = [invoke] + ([flag] if flag else [])
        start = time.monotonic()
        try:
            # Sandboxed spawn (readiness R3): allowlisted by construction
            # (the probe IS the inventory), scrubbed env, bounded output.
            proc = sandboxed_run(cmd, cwd=workspace_root(), timeout=5,
                                 max_output_bytes=65536, purpose="preflight")
            latency = int((time.monotonic() - start) * 1000)
        except (OSError, subprocess.SubprocessError, SandboxViolation):
            continue
        out = ((proc.stdout or b"") + (proc.stderr or b"")).decode(
            "utf-8", "replace").strip()
        version = out.splitlines()[0][:120] if out else ""
        if proc.returncode == 0 or version:
            return {"name": name, "kind": "binary", "status": "ready",
                    "version": version, "invoke_path": invoke,
                    "latency_ms": latency, "detail": f"probe {' '.join(cmd)!r}"}
    return {"name": name, "kind": "binary", "status": "ready",
            "version": "", "invoke_path": invoke, "latency_ms": 0,
            "detail": "present on PATH; version probe inconclusive"}


def _module_status(module: str) -> Dict[str, Any]:
    try:
        __import__(module)
        return {"name": module, "kind": "module", "status": "ready",
                "version": "", "invoke_path": module, "latency_ms": 0,
                "detail": "importable"}
    except Exception as exc:  # noqa: BLE001
        return {"name": module, "kind": "module", "status": "missing",
                "version": "", "invoke_path": module, "latency_ms": 0,
                "detail": f"{type(exc).__name__}: {exc}"}


def _mcp_entry(state: ConnectionState) -> Dict[str, Any]:
    return {"name": state.name, "kind": "mcp", "status": state.status,
            "version": "", "invoke_path": state.url,
            "latency_ms": state.latency_ms, "detail": state.detail}


def inventory(*, probe_binaries: bool = True) -> List[Dict[str, Any]]:
    """PF1: enumerate and fingerprint every hunting capability."""
    caps: List[Dict[str, Any]] = []
    if probe_binaries:
        for name, flags in BINARY_CAPABILITIES.items():
            caps.append(_fingerprint_binary(name, flags))
    else:
        caps.extend({"name": name, "kind": "binary", "status": "ready",
                     "version": "", "invoke_path": name, "latency_ms": 0,
                     "detail": "unprobed (offline mode)"}
                    for name in BINARY_CAPABILITIES)
    for module in MODULE_CAPABILITIES:
        caps.append(_module_status(module))
    for name in MCP_CONNECTIONS:  # PF2 order preserved in the manifest
        caps.append(_mcp_entry(check_connection(name)))
    return caps


# ---------------------------------------------------------------------------
# Manifest + persistence (PF3)
# ---------------------------------------------------------------------------


def manifest_path(*, project_root: Optional[str] = None) -> Path:
    return workspace_root(project_root) / "state" / "preflight" / "manifest.json"


def capability_digest(caps: List[Dict[str, Any]]) -> str:
    """Short human-readable digest for lane contexts (PF3)."""
    ready = [c["name"] for c in caps if c["status"] == "ready"]
    blocked = [c["name"] for c in caps if c["status"] in (MCP_BLOCKED, "missing")]
    degraded = [c["name"] for c in caps if c["status"] == MCP_DEGRADED]
    return (f"capabilities: {len(ready)} ready"
            + (f"; degraded: {', '.join(degraded)}" if degraded else "")
            + (f"; blocked/missing: {', '.join(blocked)}" if blocked else ""))


def run_preflight(target: str, *, project_root: Optional[str] = None,
                  probe_binaries: bool = True,
                  mission_id: str = "",
                  operation_profile: str = "governed",
                  scope_digest: str = "") -> Dict[str, Any]:
    """Run the full pre-flight, persist the manifest, publish the event.

    Returns the manifest dict.  Never raises for probe failures; only a
    truly unwritable state dir can raise OSError.
    """
    started = time.time()
    caps = inventory(probe_binaries=probe_binaries)
    summary = {
        "ready": sum(1 for c in caps if c["status"] == "ready"),
        "degraded": sum(1 for c in caps if c["status"] == MCP_DEGRADED),
        "blocked": sum(1 for c in caps if c["status"] == MCP_BLOCKED),
        "missing": sum(1 for c in caps if c["status"] == "missing"),
    }
    manifest = {
        "schema": SCHEMA,
        "target": target,
        "target_slug": target_slug(target),
        "mission_id": mission_id,
        "operation_profile": operation_profile,
        "scope_digest": scope_digest,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "capabilities": caps,
        "connections": connection_snapshot(),
        "summary": summary,
        "digest": capability_digest(caps),
    }
    manifest["sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    path = manifest_path(project_root=project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True,
                               default=str), encoding="utf-8")
    # Append-only history line (plan lever P5).
    with open(path.parent / "preflight.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": manifest["started_at"],
                             "sha256": manifest["sha256"],
                             "summary": summary}, sort_keys=True) + "\n")

    try:
        from tools.core.signal_bus import PREFLIGHT_COMPLETE, SignalBus
        SignalBus(target).publish(PREFLIGHT_COMPLETE, "preflight",
                                  {"sha256": manifest["sha256"],
                                   "summary": summary,
                                   "digest": manifest["digest"]})
    except Exception:  # noqa: BLE001 - bus is advisory
        pass
    return manifest


def validate_manifest_for_mission(manifest: Dict[str, Any], *, target: str,
                                   mission_id: str = "",
                                   operation_profile: str = "governed",
                                   scope_digest: str = "") -> List[str]:
    """Validate that a preflight receipt belongs to the active mission.

    The receipt hash is computed over the manifest without its hash field,
    matching ``run_preflight``.  A valid-looking digest is not enough: a
    changed target, profile, scope, or capability list must invalidate it.
    """
    issues: List[str] = []
    if manifest.get("schema") != SCHEMA:
        issues.append("preflight schema mismatch")
    if str(manifest.get("target") or "") != str(target):
        issues.append("preflight target mismatch")
    if mission_id and str(manifest.get("mission_id") or "") != mission_id:
        issues.append("preflight mission_id mismatch")
    if str(manifest.get("operation_profile") or "governed") != operation_profile:
        issues.append("preflight operation profile mismatch")
    if scope_digest and str(manifest.get("scope_digest") or "") != scope_digest:
        issues.append("preflight scope digest mismatch")
    recorded_hash = str(manifest.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", recorded_hash):
        issues.append("preflight receipt missing valid sha256")
    else:
        unsigned = dict(manifest)
        unsigned.pop("sha256", None)
        calculated = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        if calculated != recorded_hash:
            issues.append("preflight receipt sha256 does not match contents")
    return issues


def artifact_ref(manifest: Dict[str, Any], *, project_root: Optional[str] = None) -> Dict[str, Any]:
    """ArtifactRef-shaped dict for MissionSpec.preflight_manifest_ref (PF3)."""
    return {
        "artifact_id": "preflight-" + manifest.get("sha256", "")[:12],
        "path": str(manifest_path(project_root=project_root)),
        "kind": ARTIFACT_PREFLIGHT,
        "producer_task": "preflight",
        "sha256": manifest.get("sha256", ""),
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf mandatory pre-flight (capability discovery)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--offline", action="store_true",
                        help="skip binary version probes (paths only)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest = run_preflight(args.target, probe_binaries=not args.offline)
    if args.json:
        print(json.dumps(manifest, indent=2, default=str))
    else:
        print(f"[preflight] {manifest['digest']}")
        print(f"  manifest: {manifest_path()}")
        for conn in manifest["connections"].values():
            print(f"  {conn['name']:12s} {conn['status']:10s} {conn['url']}"
                  f"  ({conn['latency_ms']} ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
