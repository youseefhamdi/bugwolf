#!/usr/bin/env python3
"""Phase 8 — Release and supply-chain operational checks.

Offline release discipline for the plug-in itself:

  * **SBOM** — content-addressed inventory of the shipped Python modules
    (name, path, sha256, size) so a release is fully enumerated.
  * **Bundle integrity** — verify a release archive contains the required
    entries, no leaked bytecode/build artifacts, and no path-traversal
    entries.
  * **Dependency provenance** — reuse the Phase 5 lockfile verification so a
    release cannot ship with silently drifted dependencies.
  * **Clean-install smoke** — import every shipped module in a clean
    subprocess with the bytecode cache disabled, so the bundle has no
    import-time breakage.

All checks are read-only, offline, and advisory for research depth — they are
mandatory for *release* quality, never for research execution.

Usage:
  python3 tools/release_ops.py --sbom --json
  python3 tools/release_ops.py --bundle dist/bugwolf-v1.2.10.freebuff.zip \\
      --json
  python3 tools/release_ops.py --deps package-lock.json --json
  python3 tools/release_ops.py --smoke --json
  python3 tools/release_ops.py --all --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

SCHEMA = "bugwolf/release-ops/v1"
REQUIRED_BUNDLE_ENTRIES = (
    "SKILL.md", "VERSION", "README.md", "CHANGELOG.md",
    "configs/readiness.json", "tools/runtime_paths.py",
    "tools/readiness.py", "tools/engagement_context.py",
    "tools/research_core.py", "tools/benchmark.py",
    "tools/impact_validation.py", "tools/static_bridge.py",
    "tools/research_sources.py", "tools/reporting.py", "tools/release_ops.py",
)
FORBIDDEN_BUNDLE_PATTERNS = (".pyc", "__pycache__", ".tmp", ".DS_Store")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _module_files(root: Path) -> List[Path]:
    return sorted((root / "tools").rglob("*.py"))


def build_sbom(root: Optional[str] = None) -> Dict[str, Any]:
    base = workspace_root(root) if root else CODE_ROOT
    modules = _module_files(base)
    entries = []
    digest = hashlib.sha256()
    for path in modules:
        rel = path.relative_to(base).as_posix()
        data = path.read_bytes()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
        entries.append({
            "name": rel,
            "sha256": _sha256(data),
            "size": len(data),
        })
    return {
        "schema": SCHEMA,
        "generated_at": _now(),
        "module_count": len(entries),
        "sbom_sha256": digest.hexdigest(),
        "modules": entries,
    }


def check_bundle(bundle_path: str) -> Dict[str, Any]:
    """Verify a release archive: required entries, no artifacts, no traversal."""
    path = Path(bundle_path)
    if not path.is_file():
        raise ValueError(f"bundle not found: {path}")
    errors: List[str] = []
    prefix = ""
    names: List[str] = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if any(n.endswith(".agents/skills/bugwolf/SKILL.md") or
               "/.agents/skills/bugwolf/" in n for n in names):
            prefix = ".agents/skills/bugwolf/"
        rel = {n[len(prefix):] if n.startswith(prefix) else n for n in names}
        for required in REQUIRED_BUNDLE_ENTRIES:
            if required not in rel:
                errors.append(f"missing required entry: {required}")
        for name in names:
            if any(pattern in name for pattern in FORBIDDEN_BUNDLE_PATTERNS):
                errors.append(f"forbidden build artifact in bundle: {name}")
            if ".." in name.split("/"):
                errors.append(f"path-traversal entry in bundle: {name}")
    return {
        "schema": SCHEMA,
        "bundle": str(path),
        "entries": len(names),
        "errors": errors,
        "valid": not errors,
    }


def check_dependencies(lockfile: str,
                       expected: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    from tools.static_bridge import verify_dependencies

    return verify_dependencies(Path(lockfile), expected=expected)


def smoke_imports(root: Optional[str] = None) -> Dict[str, Any]:
    """Import every shipped module in a clean subprocess (no bytecode cache)."""
    base = workspace_root(root) if root else CODE_ROOT
    modules = _module_files(base)
    failed: List[str] = []
    for path in modules:
        rel = path.relative_to(base)
        if rel.name == "__init__.py":
            continue
        module = ".".join(rel.with_suffix("").parts)
        try:
            from tools.runtime.sandbox import sandboxed_run
            proc = sandboxed_run(
                [sys.executable, "-B", "-c",
                 f"import {module}"],
                cwd=str(base), timeout=30,
                allow_unlisted=True, purpose="release_import_check")
        except subprocess.TimeoutExpired:
            failed.append(f"{module}: import timed out")
            continue
        except Exception as exc:  # SandboxViolation: kill switch is data
            failed.append(f"{module}: {exc}")
            continue
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace")[-200:]
            failed.append(f"{module}: {stderr.splitlines()[-1] if stderr else 'import failed'}")
    return {
        "schema": SCHEMA,
        "modules_tested": len(modules),
        "failed": failed,
        "valid": not failed,
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf release and supply-chain checks (Phase 8)")
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--sbom", action="store_true")
    actions.add_argument("--bundle", metavar="ZIP")
    actions.add_argument("--deps", metavar="LOCKFILE")
    actions.add_argument("--smoke", action="store_true")
    actions.add_argument("--all", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        results: Dict[str, Any] = {"schema": SCHEMA, "generated_at": _now()}
        if args.sbom or args.all:
            results["sbom"] = build_sbom(args.project_root)
        if args.bundle or args.all:
            results["bundle"] = check_bundle(args.bundle or
                                             "dist/bugwolf-v1.2.10.freebuff.zip")
        if args.deps or args.all:
            results["dependencies"] = check_dependencies(args.deps or
                                                         "package-lock.json")
        if args.smoke or args.all:
            results["smoke"] = smoke_imports(args.project_root)
        status = 0
        if results.get("bundle") and not results["bundle"]["valid"]:
            status = 2
        if results.get("dependencies") and not results["dependencies"]["provenance_ok"]:
            status = 2
        if results.get("smoke") and not results["smoke"]["valid"]:
            status = 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        results = {"schema": SCHEMA, "error": str(exc)}
        status = 2
    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    else:
        print(json.dumps(results, sort_keys=True)[:2000])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
