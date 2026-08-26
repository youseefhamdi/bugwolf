#!/usr/bin/env python3
"""Regenerate AUDIT.md deterministically from the live repository state.

Run:  python3 scripts/generate_audit.py
Exit 0 on success. Writes AUDIT.md at the repository root.

The audit inventory is computed, never hand-maintained, so the document cannot
drift from the tree it describes.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent

SCHEMA = "bugwolf-audit/v1"


def git_head() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=False)
        return out.stdout.strip() or "no-git"
    except OSError:
        return "no-git"


def git_branch() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=False)
        return out.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def file_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    tools = (ROOT / "tools").rglob("*.py")
    for path in sorted(tools, key=lambda p: str(p)):
        lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        rows.append({
            "path": str(path.relative_to(ROOT)),
            "lines": lines,
            "kind": "module",
        })
    return rows


def module_stats() -> Dict[str, Any]:
    modules: List[Path] = []
    inits = 0
    cli = 0
    for path in (ROOT / "tools").rglob("*.py"):
        if path.name == "__init__.py":
            inits += 1
            continue
        modules.append(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        if "__main__" in text and ("def main" in text or "argparse" in text):
            cli += 1
    lines = sum(len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                for p in modules)
    return {"modules": len(modules), "init_markers": inits, "cli_modules": cli,
            "module_lines": lines}


def group_sizes() -> Dict[str, int]:
    result: Dict[str, int] = {}
    for sub in ("core", "domains", "intelligence", "recon", "validation"):
        result[sub] = len([p for p in (ROOT / "tools" / sub).rglob("*.py")
                           if p.name != "__init__.py"])
    return result


def test_stats() -> Dict[str, Any]:
    loader = __import__("unittest").TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
    files = [p for p in (ROOT / "tests").glob("test_*.py")]
    return {"test_files": len(files), "tests": suite.countTestCases()}


def reference_stats() -> Dict[str, Any]:
    refs = [p for p in (ROOT / "references").rglob("*.md")]
    attack = [p for p in (ROOT / "references" / "attack-vectors").glob("*.md")]
    agents = [p for p in (ROOT / "references" / "hacking-agents").glob("*.md")]
    return {"reference_md": len(refs), "attack_vector_md": len(attack),
            "hacking_agent_md": len(agents)}


def script_stats() -> Dict[str, int]:
    return {"scripts_sh": len(list((ROOT / "scripts").glob("*.sh")))}


def py_counts() -> Dict[str, int]:
    files = [p for p in (ROOT / "tests").rglob("*.py")]
    return {"python_files": len(files),
            "python_lines": sum(len(p.read_text(encoding="utf-8", errors="replace").splitlines())
                                for p in files)}


def readiness_lines() -> List[str]:
    out: List[str] = []
    manifest_path = ROOT / "configs" / "readiness.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            out.append(f"- readiness level: `{manifest.get('readiness_level')}`")
            out.append(f"- release status: `{manifest.get('release_status')}`")
        except (OSError, json.JSONDecodeError):
            out.append("- readiness manifest: unreadable")
    return out


def tool_map_rows() -> List[str]:
    rows: List[str] = []
    table: List[Dict[str, str]] = []
    modules = [p for p in (ROOT / "tools").rglob("*.py")
               if p.name != "__init__.py"]
    for path in sorted(modules, key=lambda p: -len(
            p.read_text(encoding="utf-8", errors="replace").splitlines())):
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = len(text.splitlines())
        first_doc = ""
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Module) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    first_doc = str(first.value.value).strip().splitlines()[0][:120]
                break
        table.append({"path": str(path.relative_to(ROOT)), "lines": lines,
                      "purpose": first_doc})
    rows.append("| Module | Lines | Purpose |")
    rows.append("|---|---|---|")
    for item in table[:40]:
        rows.append(f"| `{item['path']}` | {item['lines']} | {item['purpose']} |")
    return rows


def render() -> str:
    head = git_head()
    branch = git_branch()
    files = file_rows()
    modules = module_stats()
    groups = group_sizes()
    tests = test_stats()
    refs = reference_stats()
    scripts = script_stats()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines: List[str] = []
    lines.append("# BugWolf — Repository Audit & File Map (generated)")
    lines.append("")
    lines.append(f"> Generated on {now} from `{branch}@{head}` by "
                 "`scripts/generate_audit.py`. All counts are computed from the "
                 "live tree; do not edit them by hand.")
    lines.append("")
    lines.append("## 1. Scale")
    lines.append("")
    lines.append(f"- Python modules under `tools/`: **{modules['modules']}** "
                 f"({modules['module_lines']} lines) + **{modules['init_markers']}** "
                 "`__init__.py` package markers.")
    lines.append(f"- CLI-capable modules (argparse/`__main__`): "
                 f"**{modules['cli_modules']}**")
    lines.append(f"- Group sizes: core **{groups.get('core', 0)}**, "
                 f"domains **{groups.get('domains', 0)}**, "
                 f"intelligence **{groups.get('intelligence', 0)}**, "
                 f"recon **{groups.get('recon', 0)}**, "
                 f"validation **{groups.get('validation', 0)}**")
    lines.append("")
    lines.append("## 2. Test suite")
    lines.append("")
    lines.append(f"- Test files: **{tests['test_files']}**")
    lines.append(f"- Discovered tests: **{tests['tests']}**")
    lines.append("")
    lines.append("## 3. References")
    lines.append("")
    lines.append(f"- Reference docs: **{refs['reference_md']}** "
                 f"({refs['attack_vector_md']} attack-vector catalogs, "
                 f"{refs['hacking_agent_md']} hacking-agent guides)")
    lines.append("")
    lines.append("## 4. Scripts & configs")
    lines.append("")
    lines.append(f"- Shell scripts under `scripts/`: **{scripts['scripts_sh']}**")
    for item in readiness_lines():
        lines.append(item)
    lines.append("")
    lines.append("## 5. Tool map (largest modules)")
    lines.append("")
    lines.extend(tool_map_rows())
    lines.append("")
    lines.append("## 6. Verification notes")
    lines.append("")
    lines.append("Run the reproducible verification locally:")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 scripts/generate_audit.py")
    lines.append("python3 -m unittest discover -s tests -p 'test_*.py'")
    lines.append("python3 -m compileall -q tools tests lab")
    lines.append("bash -n tools/recon_engine.sh")
    lines.append("bash scripts/ci_bundle_check.sh")
    lines.append("```")
    lines.append("")
    lines.append("This document makes no claim about zero-day discovery "
                 "probability; it is an engineering inventory.")
    return "\n".join(lines)


def main() -> int:
    try:
        content = render()
    except Exception as exc:
        print(f"[!] audit generation failed: {exc}", file=sys.stderr)
        return 2
    out = ROOT / "AUDIT.md"
    out.write_text(content, encoding="utf-8")
    print(f"[*] Regenerated {out.relative_to(ROOT)} ({len(content.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
