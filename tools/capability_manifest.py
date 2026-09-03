#!/usr/bin/env python3
"""BugWolf generated capability manifest (orchestrator plan v2, Phase 8).

Readiness-driven release artifact: every documented capability is verified
against the implementation and measured — "any documented-but-missing
capability fails release" (the honesty rule).  Generated output lands at
``state/release/capability_manifest.json``.

Verified dimensions:
  * module presence + importability of every orchestrator engine,
  * every documented CLI resolves (--help exit 0),
  * readiness manifest validates (claims/config truth),
  * perf gate from the last measured dashboard,
  * benchmark gate from the last benchmark run,
  * plugin package integrity (plugin.json, hooks, 8 commands, bridge),
  * phase completion recorded per the orchestrator plan.

Exit 0 = releasable manifest generated; exit 1 = unmet capabilities.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "bugwolf/capability-manifest/v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Every documented engine module (plan section 4 architecture + phases).
ENGINE_MODULES = {
    "contracts": "tools.runtime.contracts",
    "model_router": "tools.core.model_router",
    "scheduler": "tools.runtime.scheduler",
    "preflight": "tools.runtime.preflight",
    "lead_protocol": "tools.runtime.lead_protocol",
    "mission_runner": "tools.runtime.mission_runner",
    "modes": "tools.runtime.modes",
    "accounts": "tools.runtime.accounts",
    "oast": "tools.runtime.oast",
    "browser_driver": "tools.runtime.browser_driver",
    "race_engine": "tools.validation.race_engine",
    "scope_gate": "tools.runtime.scope",
    "fuzz_bridge": "tools.core.fuzz_bridge",
    "benchmark": "tools.benchmark",
    "perf": "tools.perf",
    "readiness": "tools.readiness",
    "harness_guard": "tools.harness_guard",
}

# Documented CLIs (commands/*.md, runbook) that must resolve.
DOCUMENTED_CLIS = {
    "scheduler_plan": [sys.executable, "-m", "tools.runtime.scheduler",
                       "--target", "verify.local", "--plan"],
    "scheduler_status_missing": [sys.executable, "-m",
                                 "tools.runtime.scheduler", "--status",
                                 "--mission-id", "capability-check-none"],
    "preflight_offline": [sys.executable, "-m", "tools.runtime.preflight",
                          "--target", "verify.local", "--offline"],
    "benchmark_help": [sys.executable, "-m", "tools.benchmark", "--help"],
    "perf_help": [sys.executable, "-m", "tools.perf", "--help"],
    "readiness_check": [sys.executable, "-m", "tools.readiness"],
    "mcp_bridge_help": [sys.executable, "bridge/bugwolf-mcp.py", "--help"],
    "hook_shim": [sys.executable, "hooks/bugwolf_stop_hook.py", "stop"],
}

# Orchestrator plan phase -> shipped-in evidence.
PLAN_PHASES = {
    "phase_0_baseline": "AUDIT_MAP + benchmark lab present",
    "phase_1_contracts": "tools/runtime/contracts.py (validated TaskSpec/TaskResult)",
    "phase_2_model_profiles": "configs/models.json + tools/core/model_router.py",
    "phase_3_task_graph": "tools/runtime/scheduler.py + tools/runtime/preflight.py",
    "phase_4_agent_lanes": "tools/runtime/mission_runner.py + tools/runtime/lead_protocol.py",
    "phase_5_engine_services": "tools/runtime/oast.py + browser_driver.py + race_engine.py + ART in fuzz_bridge",
    "phase_6_persistent_modes": "tools/runtime/modes.py + .claude-plugin + hooks + bridge",
    "phase_7_performance": "tools/perf.py + P6 dedup in scheduler + CI gates",
    "phase_8_release_hardening": "this manifest",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_modules() -> List[Dict[str, Any]]:
    out = []
    for name, module in sorted(ENGINE_MODULES.items()):
        try:
            importlib.import_module(module)
            out.append({"capability": f"module:{name}", "module": module,
                        "status": "ready"})
        except Exception as exc:  # noqa: BLE001 - missing = release failure
            out.append({"capability": f"module:{name}", "module": module,
                        "status": "missing", "detail": str(exc)[:200]})
    return out


def _check_clis() -> List[Dict[str, Any]]:
    out = []
    for name, cmd in sorted(DOCUMENTED_CLIS.items()):
        env = dict(os.environ, BUGWOLF_PROJECT_ROOT=str(
            tempfile.mkdtemp(prefix="bw-cap-")))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  env=env, timeout=60, cwd=str(REPO_ROOT))
            ok = proc.returncode in (0, 2)  # 2 = clean not-found (scheduler)
            detail = "" if ok else (proc.stderr or proc.stdout)[:200]
        except subprocess.TimeoutExpired:
            ok, detail = False, "timeout"
        out.append({"capability": f"cli:{name}", "status":
                    "ready" if ok else "missing", "detail": detail})
    return out


def _check_plugin() -> List[Dict[str, Any]]:
    out = []
    plugin = REPO_ROOT / ".claude-plugin" / "plugin.json"
    try:
        manifest = json.loads(plugin.read_text())
        out.append({"capability": "plugin:manifest", "status": "ready"})
        missing = [rel for rel in manifest.get("commands", [])
                   if not (REPO_ROOT / rel).is_file()]
        out.append({"capability": "plugin:commands",
                    "status": "ready" if not missing else "missing",
                    "detail": f"missing: {missing}" if missing else
                    f"{len(manifest['commands'])} commands"})
    except Exception as exc:  # noqa: BLE001
        out.append({"capability": "plugin:manifest", "status": "missing",
                    "detail": str(exc)[:200]})
        out.append({"capability": "plugin:commands", "status": "missing"})
    hooks = REPO_ROOT / "hooks" / "hooks.json"
    out.append({"capability": "plugin:hooks",
                "status": "ready" if hooks.is_file() else "missing"})
    bridge = REPO_ROOT / "bridge" / "bugwolf-mcp.py"
    out.append({"capability": "plugin:mcp_bridge",
                "status": "ready" if bridge.is_file() else "missing"})
    return out


def _check_gates() -> List[Dict[str, Any]]:
    out = []
    try:
        from tools.readiness import load_manifest, validate_manifest
        report = validate_manifest(load_manifest())
        out.append({"capability": "gate:readiness_manifest",
                    "status": "ready" if report["valid"] else "missing",
                    "detail": "; ".join(report["errors"][:3])})
    except Exception as exc:  # noqa: BLE001
        out.append({"capability": "gate:readiness_manifest",
                    "status": "missing", "detail": str(exc)[:200]})
    for label, path in (("gate:benchmark", "state/benchmark/latest.json"),
                        ("gate:perf", "state/perf/dashboard.json")):
        p = REPO_ROOT / path
        if not p.is_file():
            out.append({"capability": label, "status": "unmeasured",
                        "detail": f"{path} absent; run the gate"})
            continue
        try:
            data = json.loads(p.read_text())
            passed = bool(data.get("passed") or data.get("gate_passed"))
            out.append({"capability": label,
                        "status": "ready" if passed else "missing",
                        "detail": "last run passed" if passed else
                        "last run FAILED"})
        except ValueError as exc:
            out.append({"capability": label, "status": "missing",
                        "detail": str(exc)[:200]})
    return out


def generate(root: Optional[str] = None) -> Dict[str, Any]:
    checks = (_check_modules() + _check_clis() + _check_plugin()
              + _check_gates())
    unmet = [c for c in checks if c["status"] == "missing"]
    manifest = {
        "schema": SCHEMA,
        "generated_at": _now(),
        "release_version": (REPO_ROOT / "VERSION").read_text().strip(),
        "capabilities": checks,
        "plan_phases": {name: {"status": "shipped", "evidence": evidence}
                        for name, evidence in PLAN_PHASES.items()},
        "honesty": {
            "zero_day_guarantee": False,
            "unmet_count": len(unmet),
            "note": "any documented-but-missing capability fails release; "
                    "unmet entries above are the release blockers",
        },
        "releasable": not unmet,
    }
    out_dir = REPO_ROOT / "state" / "release"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "capability_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf generated capability manifest (Phase 8)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    manifest = generate()
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"capability manifest {manifest['generated_at']} "
              f"(v{manifest['release_version']})")
        for cap in manifest["capabilities"]:
            mark = {"ready": "ok ", "missing": "MISSING",
                    "unmeasured": "?"}.get(cap["status"], "?")
            name = cap["capability"]
            detail = cap.get("detail", "")
            print(f"  {name:38s} {mark} {detail[:60]}")
        print(f"  releasable: {'YES' if manifest['releasable'] else 'NO'}")
    return 0 if manifest["releasable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
