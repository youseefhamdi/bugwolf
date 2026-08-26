#!/usr/bin/env python3
"""Phase 5 — Static analysis, source reasoning, patch-gap research bridge.

Complements the existing static analyzers (chain_analyzer, tech_fingerprint,
patch_gap, paper_intel) with three deterministic, offline capabilities:

  * **Source fingerprinting** — line-hash provenance for static findings so
    a finding can be traced to exact source lines and re-verified after
    changes.
  * **Patch-diff reasoning** — extract security-relevant changes from a
    vulnerable->patched diff (CVE references, removed sink guards, changed
    validation) and emit regression hypotheses; never proof.
  * **Dependency provenance** — verify lockfile/SBOM consistency and flag
    pinned-but-drifted dependencies, missing provenance, or unreviewed
    artifacts.

Everything is advisory and offline: static findings are hypotheses until
runtime reproduction or human review.  Never gates research depth.

Artifacts persist under ``state/static/<target>/``.

Usage:
  python3 tools/static_bridge.py --target T --fingerprint src/ --json
  python3 tools/static_bridge.py --target T --diff before.patch after.patch \
      --json
  python3 tools/static_bridge.py --target T --deps package-lock.json --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf/static-bridge/v1"
SECURITY_MARKERS = (
    "CVE-", "auth", "authorize", "permission", "role", "admin", "token",
    "secret", "password", "csrf", "injection", "redirect", "upload",
    "deserialize", "eval(", "exec(", "shell", "ssti", "xss", "sqli", "ssrf",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir(project_root: Optional[str] = None, target: str = "") -> Path:
    root = workspace_root(project_root)
    if target:
        return root / "state" / "static" / target_slug(target)
    return root / "state" / "static"


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def fingerprint_path(path: Path) -> Dict[str, Any]:
    """Hash a source file into a stable, line-aware fingerprint."""
    path = Path(path)
    digest = hashlib.sha256()
    line_hashes: List[str] = []
    try:
        text = path.read_bytes()
        digest.update(text)
        for line in text.splitlines():
            line_hashes.append(hashlib.sha256(line).hexdigest()[:12])
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "lines": len(line_hashes),
        "line_hashes": line_hashes,
    }


@dataclass
class StaticFinding:
    finding_id: str
    source_path: str
    line: int
    sha256: str
    signal: str
    severity: str = "medium"
    kind: str = "static"
    line_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SourceFingerprinter:
    """Line-hash provenance store for static findings."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target)
        self._findings: Dict[str, StaticFinding] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "findings.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._findings[str(rec["finding_id"])] = StaticFinding(**{
                    k: v for k, v in rec.items()
                    if k in StaticFinding.__dataclass_fields__})
            except (TypeError, json.JSONDecodeError, KeyError):
                continue

    def register(self, finding_id: str, source_path: str, line: int,
                 sha256: str, signal: str, *, severity: str = "medium",
                 line_sha256: str = "") -> StaticFinding:
        if not line_sha256:
            # Derive the exact line hash at registration time so the finding
            # is traceable to the precise source line (independent of the
            # file-level hash).
            try:
                line_hashes = fingerprint_path(source_path)["line_hashes"]
                if 0 < int(line) <= len(line_hashes):
                    line_sha256 = line_hashes[int(line) - 1]
            except ValueError:
                line_sha256 = ""
        finding = StaticFinding(
            finding_id=finding_id, source_path=str(source_path),
            line=int(line), sha256=str(sha256), signal=str(signal),
            severity=str(severity), line_sha256=str(line_sha256))
        self._findings[finding_id] = finding
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(finding.to_dict(), sort_keys=True) + "\n")
        return finding

    def verify(self, finding_id: str,
               fingerprint: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """A finding is only traceable when the current on-disk line hash
        still matches the recorded line hash — drift marks it stale.

        When ``fingerprint`` is omitted, the source file is re-read from
        disk so the comparison is always against current reality.
        """
        finding = self._findings.get(finding_id)
        if not finding:
            raise ValueError(f"unknown static finding: {finding_id}")
        if fingerprint is None:
            try:
                fingerprint = fingerprint_path(finding.source_path)
            except ValueError:
                return {
                    "finding_id": finding_id,
                    "source_path": finding.source_path,
                    "line": finding.line,
                    "file_hash_matches": False,
                    "line_hash_matches": False,
                    "traceable": False,
                    "stale": True,
                    "error": "source file unreadable or missing",
                }
        current_sha = fingerprint.get("sha256")
        line_hashes = fingerprint.get("line_hashes") or []
        current_line_hash = line_hashes[finding.line - 1] \
            if 0 < finding.line <= len(line_hashes) else None
        line_matches = bool(current_line_hash
                            and current_line_hash == finding.line_sha256)
        return {
            "finding_id": finding_id,
            "source_path": finding.source_path,
            "line": finding.line,
            "file_hash_matches": current_sha == finding.sha256,
            "line_hash_matches": line_matches,
            "traceable": line_matches,
            "stale": bool(current_sha != finding.sha256),
        }

    def findings(self) -> List[StaticFinding]:
        return sorted(self._findings.values(), key=lambda f: f.finding_id)


# ---------------------------------------------------------------------------
# Patch-diff reasoning
# ---------------------------------------------------------------------------

def analyze_patch(diff_text: str, *, before_rev: str = "", after_rev: str = ""
                  ) -> Dict[str, Any]:
    """Extract security-relevant change hypotheses from a patch diff.

    Deterministic text analysis only: removed security keywords, added
    validation, changed files, and CVE references become *hypotheses* that
    require runtime or source-level proof before they can be reported.
    """
    diff = str(diff_text or "")
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", diff, re.I)))
    files_changed = sorted(set(
        re.findall(r"^\+\+\+\s+b/(\S+)", diff, re.M)))
    added = [ln for ln in diff.splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln for ln in diff.splitlines()
               if ln.startswith("-") and not ln.startswith("---")]
    removed_security = [ln for ln in removed
                        if any(m in ln.lower() for m in SECURITY_MARKERS)]
    added_validation = [ln for ln in added
                        if any(m in ln.lower() for m in
                               ("validate", "authorize", "reject", "deny",
                                "escape", "sanitize", "require",
                                "content-type", "allowlist"))]
    return {
        "schema": SCHEMA,
        "before_rev": str(before_rev or ""),
        "after_rev": str(after_rev or ""),
        "cve_references": cves,
        "files_changed": files_changed,
        "added_lines": len(added),
        "removed_lines": len(removed),
        "removed_security_lines": removed_security[:20],
        "added_validation_lines": added_validation[:20],
        "hypotheses": [
            {
                "kind": "removed-security-control",
                "reason": (f"{len(removed_security)} security-marker lines "
                           "removed"),
                "requires": "runtime reproduction or source-level proof",
            },
            {
                "kind": "validation-added",
                "reason": (f"{len(added_validation)} validation-marker lines "
                           "added"),
                "requires": "regression comparison on the vulnerable revision",
            },
            {
                "kind": "cve-referenced",
                "reason": f"{len(cves)} CVE references in patch",
                "requires": "version applicability + reproduction",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Dependency provenance
# ---------------------------------------------------------------------------

LOCKFILE_PATTERNS = {
    "package-lock.json": r'"([\w@./~-]+)":\s*\{\s*"version":\s*"([^"]+)"',
    "yarn.lock": r'^"?([\w@./~-]+)@[^:]+:\s*version\s+"?([^"\s]+)"?',
    "poetry.lock": r'^name\s*=\s*"([^"]+)"\s*^version\s*=\s*"([^"]+)"',
    "Cargo.lock": r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"',
    "requirements.txt": r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)\s*([^\s;#]+)",
}


def verify_dependencies(lockfile_path: Path, *, expected: Optional[Dict[str, str]] = None
                        ) -> Dict[str, Any]:
    """Verify a lockfile parses, count pins, and flag drift against a pinned
    expected set.  Never installs, never resolves the network."""
    path = Path(lockfile_path)
    if not path.is_file():
        raise ValueError(f"lockfile not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = next((pat for name, pat in LOCKFILE_PATTERNS.items()
                    if path.name == name), None)
    pinned: Dict[str, str] = {}
    if pattern:
        for match in re.finditer(pattern, text, re.M | re.I):
            name, version = match.group(1), match.group(2)
            pinned.setdefault(name.strip(), version.strip())
    issues: List[str] = []
    if expected:
        for name, version in (expected or {}).items():
            actual = pinned.get(name)
            if actual is None:
                issues.append(f"dependency {name} not found in lockfile")
            elif actual != version:
                issues.append(f"dependency {name} drifted: expected "
                              f"{version}, locked {actual}")
    return {
        "schema": SCHEMA,
        "lockfile": str(path),
        "dependencies": len(pinned),
        "exact_pins": sum(1 for v in pinned.values() if re.fullmatch(
            r"\d+\.\d+(\.\d+)?", v)),
        "pinned": dict(sorted(pinned.items())),
        "drift_issues": issues,
        "provenance_ok": not issues,
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf static-source / patch-gap / dependency bridge")
    parser.add_argument("--target", default="")
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--fingerprint", metavar="PATH",
                         help="fingerprint a source file")
    actions.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"),
                         help="analyze a patch diff file")
    actions.add_argument("--deps", metavar="LOCKFILE",
                         help="verify a lockfile")
    parser.add_argument("--finding-id", default="")
    parser.add_argument("--line", type=int, default=1)
    parser.add_argument("--signal", default="static-signal")
    parser.add_argument("--register", action="store_true",
                        help="register a static finding after fingerprinting")
    parser.add_argument("--before-rev", default="")
    parser.add_argument("--after-rev", default="")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.fingerprint:
            fp = fingerprint_path(args.fingerprint)
            result = {"schema": SCHEMA, "fingerprint": fp}
            if args.register:
                store = SourceFingerprinter(args.target, args.project_root)
                finding = store.register(
                    args.finding_id or f"static-{fp['sha256'][:12]}",
                    fp["path"], args.line, fp["sha256"], args.signal)
                result["finding"] = finding.to_dict()
                result["verify"] = store.verify(finding.finding_id)
        elif args.diff:
            before = Path(args.diff[0]).read_text(encoding="utf-8", errors="replace")
            after = Path(args.diff[1]).read_text(encoding="utf-8", errors="replace")
            result = analyze_patch(before + "\n" + after,
                                   before_rev=args.before_rev,
                                   after_rev=args.after_rev)
        else:
            result = verify_dependencies(args.deps)
        status = 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "error": str(exc)}
        status = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True)[:2000])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
