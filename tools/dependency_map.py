#!/usr/bin/env python3
"""Generate a deterministic internal import graph for BugWolf tools."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "bugwolf-dependency-map/v1"


def module_name(path: Path, root: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    return ".".join(relative.parts)


def imports_for(path: Path, root: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return []
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
    known = {module_name(item, root) for item in root.rglob("*.py")}
    return sorted(name for name in imports if name in known or name.startswith("tools."))


def build(root: Path) -> dict[str, Any]:
    root = root.resolve()
    modules = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        name = module_name(path, root)
        modules.append({
            "module": name,
            "path": str(path.relative_to(root.parent)),
            "imports": imports_for(path, root),
            "lines": len(path.read_text(encoding="utf-8", errors="replace").splitlines()),
        })
    edges = [
        {"from": item["module"], "to": dependency}
        for item in modules for dependency in item["imports"]
    ]
    return {"schema": SCHEMA, "root": str(root), "modules": modules, "edges": edges}


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="tools")
    parser.add_argument("--output", default="state/dependency-map.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    result = build(Path(args.root))
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
