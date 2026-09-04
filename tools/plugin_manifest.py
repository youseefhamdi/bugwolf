#!/usr/bin/env python3
"""Plugin manifest integrity for BugWolf (master plan Phase 0.4).

Offline, read-only checks that keep the plugin packaging truthful:

  * **version-sync** — VERSION, .claude-plugin/plugin.json,
    .claude-plugin/marketplace.json (metadata + plugins[0].version), and the
    latest CHANGELOG.md heading must all carry the same version.
  * **manifest shape** — plugin.json / marketplace.json parse, declare the
    same plugin name, and reference files that exist (commands, hooks,
    agents, skills).
  * **front-matter shape** — every generated agent definition declares a
    native ``model:`` field (sonnet|opus|haiku|inherit) and a Claude Code
    tool allowlist; the silently-ignored ``model-tier:`` key is forbidden.

Usage:
  python3 tools/plugin_manifest.py --check --json
  python3 tools/plugin_manifest.py --check-agents --json
  python3 tools/plugin_manifest.py --all --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

SCHEMA = "bugwolf/plugin-manifest/v1"

VERSION_FILE = "VERSION"
PLUGIN_JSON = ".claude-plugin/plugin.json"
MARKETPLACE_JSON = ".claude-plugin/marketplace.json"
CHANGELOG = "CHANGELOG.md"
AGENTS_DIR = "agents/bugwolf"

_VALID_MODELS = {"sonnet", "opus", "haiku", "inherit"}
_FORBIDDEN_AGENT_KEYS = ("model-tier",)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_CHANGELOG_HEADING_RE = re.compile(r"^##\s+v(\d+\.\d+\.\d+)\b", re.MULTILINE)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _root(explicit: Optional[str]) -> Path:
    return workspace_root(explicit) if explicit else CODE_ROOT


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def check_version_sync(root: Path) -> Dict[str, Any]:
    """Every version-bearing surface must agree on the release version."""
    failures: List[str] = []

    version = (root / VERSION_FILE).read_text(encoding="utf-8").strip()
    if not _SEMVER_RE.match(version):
        failures.append(f"{VERSION_FILE}: not semver ({version!r})")

    versions: Dict[str, str] = {VERSION_FILE: version}

    try:
        plugin = _load_json(root / PLUGIN_JSON)
        plugin_version = str(plugin.get("version", ""))
        versions[PLUGIN_JSON] = plugin_version
        if plugin_version != version:
            failures.append(
                f"{PLUGIN_JSON}: version {plugin_version!r} != {VERSION_FILE} {version!r}")
    except FileNotFoundError:
        failures.append(f"{PLUGIN_JSON}: missing")
    except json.JSONDecodeError as exc:
        failures.append(f"{PLUGIN_JSON}: invalid JSON ({exc})")

    try:
        marketplace = _load_json(root / MARKETPLACE_JSON)
        meta_version = str((marketplace.get("metadata") or {}).get("version", ""))
        plugin_entry_version = str(((marketplace.get("plugins") or [{}])[0]).get("version", ""))
        versions[MARKETPLACE_JSON + "#metadata"] = meta_version
        versions[MARKETPLACE_JSON + "#plugins[0]"] = plugin_entry_version
        if meta_version != version:
            failures.append(
                f"{MARKETPLACE_JSON} metadata.version {meta_version!r} != {VERSION_FILE} {version!r}")
        if plugin_entry_version != version:
            failures.append(
                f"{MARKETPLACE_JSON} plugins[0].version {plugin_entry_version!r} != {VERSION_FILE} {version!r}")
    except FileNotFoundError:
        failures.append(f"{MARKETPLACE_JSON}: missing")
    except (json.JSONDecodeError, IndexError) as exc:
        failures.append(f"{MARKETPLACE_JSON}: invalid ({exc})")

    try:
        changelog_text = (root / CHANGELOG).read_text(encoding="utf-8")
        match = _CHANGELOG_HEADING_RE.search(changelog_text)
        changelog_version = match.group(1) if match else ""
        versions[CHANGELOG] = changelog_version
        if not changelog_version:
            failures.append(f"{CHANGELOG}: no '## vX.Y.Z' heading found")
        elif changelog_version != version:
            failures.append(
                f"{CHANGELOG}: latest heading {changelog_version!r} != {VERSION_FILE} {version!r}")
    except FileNotFoundError:
        failures.append(f"{CHANGELOG}: missing")

    return {
        "check": "version_sync",
        "ok": not failures,
        "versions": versions,
        "failures": failures,
    }


def check_manifest_shape(root: Path) -> Dict[str, Any]:
    """Manifests parse, agree on the plugin name, and reference real files."""
    failures: List[str] = []
    warnings: List[str] = []

    try:
        plugin = _load_json(root / PLUGIN_JSON)
    except FileNotFoundError:
        return {"check": "manifest_shape", "ok": False,
                "failures": [f"{PLUGIN_JSON}: missing"], "warnings": []}
    except json.JSONDecodeError as exc:
        return {"check": "manifest_shape", "ok": False,
                "failures": [f"{PLUGIN_JSON}: invalid JSON ({exc})"], "warnings": []}

    name = str(plugin.get("name", ""))
    if not name:
        failures.append(f"{PLUGIN_JSON}: no plugin name")

    marketplace_name = ""
    try:
        marketplace = _load_json(root / MARKETPLACE_JSON)
        marketplace_name = str(marketplace.get("name", ""))
        entries = marketplace.get("plugins") or []
        if not entries:
            failures.append(f"{MARKETPLACE_JSON}: no plugins[] entries")
        elif str(entries[0].get("name", "")) != name:
            failures.append(
                f"{MARKETPLACE_JSON} plugins[0].name {entries[0].get('name')!r} != plugin.json name {name!r}")
    except FileNotFoundError:
        warnings.append(f"{MARKETPLACE_JSON}: missing (marketplace install unavailable)")
    except json.JSONDecodeError as exc:
        failures.append(f"{MARKETPLACE_JSON}: invalid JSON ({exc})")

    # Referenced files must exist (commands, hooks, skills, agents dir).
    for key in ("commands", "skills"):
        for rel in plugin.get(key) or []:
            if not (root / rel).is_file():
                failures.append(f"{PLUGIN_JSON} {key}: referenced file missing: {rel}")
    hooks = plugin.get("hooks")
    if hooks and not (root / hooks).is_file():
        failures.append(f"{PLUGIN_JSON} hooks: referenced file missing: {hooks}")
    agents = plugin.get("agents")
    if agents and not (root / agents).is_dir():
        failures.append(f"{PLUGIN_JSON} agents: referenced dir missing: {agents}")

    return {
        "check": "manifest_shape",
        "ok": not failures,
        "plugin": name,
        "marketplace": marketplace_name,
        "failures": failures,
        "warnings": warnings,
    }


def check_agent_frontmatter(root: Path) -> Dict[str, Any]:
    """Generated agent definitions carry native Claude Code front-matter."""
    failures: List[str] = []
    checked = 0

    agents_dir = root / AGENTS_DIR
    if not agents_dir.is_dir():
        return {"check": "agent_frontmatter", "ok": False, "checked": 0,
                "failures": [f"{AGENTS_DIR}: missing"], "warnings": []}

    for path in sorted(agents_dir.glob("*.md")):
        checked += 1
        text = path.read_text(encoding="utf-8")
        if not text.startswith("---\n"):
            failures.append(f"{path.name}: no front-matter block")
            continue
        front = text.split("---\n", 2)[1]

        model_match = re.search(r"^model:\s*(\S+)", front, re.MULTILINE)
        if not model_match:
            failures.append(f"{path.name}: missing native 'model:' field")
        elif model_match.group(1) not in _VALID_MODELS:
            failures.append(
                f"{path.name}: model {model_match.group(1)!r} not in {_VALID_MODELS}")

        tools_match = re.search(r"^tools:\s*(.+)$", front, re.MULTILINE)
        if not tools_match:
            failures.append(f"{path.name}: missing 'tools:' allowlist")
        elif not tools_match.group(1).strip():
            failures.append(f"{path.name}: empty 'tools:' allowlist")

        for key in _FORBIDDEN_AGENT_KEYS:
            if re.search(rf"^{key}:", front, re.MULTILINE):
                failures.append(f"{path.name}: forbidden legacy key '{key}:' "
                                "(use 'model:' + 'x-bugwolf-tier:')")

    return {
        "check": "agent_frontmatter",
        "ok": not failures,
        "checked": checked,
        "failures": failures,
        "warnings": [],
    }


def run_all(root: Optional[str] = None) -> Dict[str, Any]:
    base = _root(root)
    version = check_version_sync(base)
    shape = check_manifest_shape(base)
    agents = check_agent_frontmatter(base)
    ok = all(result["ok"] for result in (version, shape, agents))
    return {
        "schema": SCHEMA,
        "checked_at": _now(),
        "ok": ok,
        "checks": [version, shape, agents],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf plugin manifest integrity")
    parser.add_argument("--check", action="store_true",
                        help="version sync + manifest shape")
    parser.add_argument("--check-agents", action="store_true",
                        help="agent front-matter shape")
    parser.add_argument("--all", action="store_true", help="every check")
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    if not (args.check or args.check_agents or args.all):
        parser.error("choose --check, --check-agents, or --all")

    if args.all:
        report = run_all(args.project_root)
    elif args.check_agents:
        base = _root(args.project_root)
        report = {"schema": SCHEMA, "checked_at": _now(),
                  "ok": check_agent_frontmatter(base)["ok"],
                  "checks": [check_agent_frontmatter(base)]}
    else:
        base = _root(args.project_root)
        v = check_version_sync(base)
        s = check_manifest_shape(base)
        report = {"schema": SCHEMA, "checked_at": _now(),
                  "ok": v["ok"] and s["ok"], "checks": [v, s]}

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        status = "OK" if report["ok"] else "FAIL"
        print(f"plugin manifest: {status}")
        for check in report.get("checks", []):
            for failure in check.get("failures", []):
                print(f"  FAIL {failure}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
