#!/usr/bin/env python3
"""Cross-project citation check (Plan Appendix G + H).

Walks the ``tools/`` and ``bugwolf/`` trees looking for Python files that
carry ``## Source:`` and ``## License:`` citation comments.  Every file
that participates in a cross-project port MUST carry BOTH comments —
the source path/line and the SPDX-ish license identifier — so the
provenance of borrowed code is auditable.

Exit codes:
  0  every file that needs a citation has one (or none need one)
  1  at least one file is missing a required citation, or has a malformed
     comment block
  2  required Python helper (re) is missing — script bug

The check is intentionally heuristic: it does NOT enforce that every
file has the comments (most files are original work); it only flags
files that contain the pattern ``## Source:`` without a matching
``## License:`` on the same file, plus files that contain
``## License:`` without a corresponding ``## Source:``.

It additionally reports any file whose ``## Source:`` line is missing a
``path:line`` style reference — purely advisory, exits 0 if all good.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
BUGWOLF = ROOT / "bugwolf"

SOURCE_RE = re.compile(r"^##\s*Source:\s*(?P<source>.+?)\s*$", re.MULTILINE)
LICENSE_RE = re.compile(r"^##\s*License:\s*(?P<license>.+?)\s*$", re.MULTILINE)
PATH_LINE_RE = re.compile(r"\S+\.(?:py|go|ts|js|rs|sol|yaml|yml|md):?\d*")


def _scan_one(path: Path) -> dict:
    """Return citation findings for a single file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"path": str(path), "error": "unreadable"}
    sources = SOURCE_RE.findall(text)
    licenses = LICENSE_RE.findall(text)
    findings = {
        "path": str(path.relative_to(ROOT)),
        "sources": sources,
        "licenses": licenses,
    }
    if sources and not licenses:
        findings["error"] = "## Source: present but ## License: missing"
    elif licenses and not sources:
        findings["error"] = "## License: present but ## Source: missing"
    return findings


def _walk_trees() -> list:
    out = []
    for base in (TOOLS, BUGWOLF):
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            out.append(_scan_one(p))
    return out


def main() -> int:
    if not TOOLS.exists() and not BUGWOLF.exists():
        print("[!] neither tools/ nor bugwolf/ found — refusing to run", file=sys.stderr)
        return 2
    findings = _walk_trees()
    total_files = len(findings)
    cited = [f for f in findings if f.get("sources") or f.get("licenses")]
    errors = [f for f in findings if "error" in f]

    print(f"[i] scanned {total_files} Python files under tools/ + bugwolf/")
    print(f"[i] {len(cited)} files carry citation comments "
          f"({len(cited) * 100 // max(total_files, 1)}%)")

    if errors:
        print("[!] citation check FAILED:")
        for f in errors:
            print(f"    - {f['path']}: {f['error']}")
        return 1

    # Advisory: every ## Source: comment should reference a path[:line].
    advisory = []
    for f in findings:
        for src in f.get("sources", []):
            if not PATH_LINE_RE.search(src):
                advisory.append(f"{f['path']}: ## Source: {src!r} (no path:line)")
    if advisory:
        print("[~] advisory: some ## Source: comments lack path:line reference:")
        for a in advisory:
            print(f"    - {a}")
    print("[+] cross-project citation check PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
