#!/usr/bin/env python3
"""BugWolf variant_hunt v1.24.1+ — HUNT-style variant generation.

Given ONE confirmed finding (or a CVE pattern), enumerate all sibling
variants across the codebase, the protocol surface, or the parameter
space. Mirrors the HUNT methodology from academic vulnerability research:

  1. Identify the ROOT CAUSE of a confirmed bug (one file, one function,
     one parameter, one encoding).
  2. For each candidate sibling (sister function in same file, same
     parameter name in sister files, alternate encoding of the same value,
     alternate HTTP method on the same route), emit a TEST_PLAN entry
     that the mission_runner can dispatch.
  3. Cluster siblings by root cause: copy-paste vs framework-misuse vs
     missing-input-validation. Cluster membership drives whether the
     remediation is one fix or many.

This module is OFFLINE + DETERMINISTIC. It does not call any model and
does not perform any network request. The mission_runner dispatches the
emitted test plans through the same governed replay engine as Phase 4
hunt lanes.

Usage:
  python3 tools/variant_hunt.py --finding <finding.json> --output <dir>
  python3 tools/variant_hunt.py --cve CVE-2024-12345 --target acme.com \
      --output <dir>
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


SCHEMA = "bugwolf-variant-hunt/v1"

# Root-cause clusters the HUNT methodology recognizes. Cluster membership
# determines whether the fix is one change or many.
CLUSTERS = (
    "copy_paste",            # same bug, sister function / sister file
    "framework_misuse",      # bug from misunderstanding the framework API
    "missing_input_validation",
    "authz_omission",        # auth check missing on sister endpoint
    "crypto_choice",         # same weak primitive, sister location
    "race_window",           # same TOCTOU shape, sister resource
    "deserialization_sink",  # same sink, sister gadget
    "ssrf_consumer",         # same SSRF consumer shape, sister URL param
)


@dataclass
class VariantPlan:
    id: str
    root_finding: str
    cluster: str
    surface: str
    technique: str
    payload: Optional[Dict[str, Any]] = None
    expected_response_diff: str = ""
    notes: str = ""


@dataclass
class VariantHunt:
    target: str
    root_cause: str
    root_evidence: str
    cluster: str
    plans: List[VariantPlan] = field(default_factory=list)
    total_siblings: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Root-cause derivation
# ---------------------------------------------------------------------------

def derive_root_cause(finding: Dict[str, Any]) -> str:
    """Extract a stable root-cause signature from a finding.

    The signature is a SHA-256 over the (class, sink, source) triple —
    the most stable representation of "what's actually wrong" that
    sibling-finding detection can cluster on.
    """
    canonical = {
        "class":  finding.get("bug_class", ""),
        "sink":   finding.get("sink", ""),
        "source": finding.get("source", ""),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def infer_cluster(finding: Dict[str, Any]) -> str:
    """Cluster a finding into one of the HUNT root-cause buckets."""
    bc = str(finding.get("bug_class", "")).lower()
    sink = str(finding.get("sink", "")).lower()
    if "reentran" in sink or bc == "reentrancy":
        return "copy_paste"
    if bc in ("auth_bypass", "bola", "bfla", "idor"):
        return "authz_omission"
    if "ssrf" in bc or "ssrf" in sink:
        return "ssrf_consumer"
    if "race" in bc or "toctou" in sink:
        return "race_window"
    if bc in ("sql_injection", "xss", "command_injection", "ssti",
             "xxe", "deserialization"):
        return "missing_input_validation"
    if "crypto" in bc or "jwt" in bc or "tls" in bc:
        return "crypto_choice"
    if "deser" in bc or "pickle" in sink or "unserialize" in sink:
        return "deserialization_sink"
    return "copy_paste"


# ---------------------------------------------------------------------------
# Sibling enumeration
# ---------------------------------------------------------------------------

def _id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{'-'.join(hashlib.sha256(''.join(parts).encode()).hexdigest()[:8] for _ in [None])}"  # noqa


def enumerate_siblings(finding: Dict[str, Any],
                       *,
                       endpoints: Optional[List[str]] = None,
                       source_files: Optional[List[str]] = None,
                       params: Optional[List[str]] = None) -> List[VariantPlan]:
    """Return a list of test plans for each sibling of the root finding.

    The sibling space is the union of:
      - endpoints sharing the root path prefix
      - source files that import the same module
      - parameter names in the same family
    Each sibling is recorded as a VariantPlan the mission_runner can
    dispatch through the replay engine.
    """
    root = finding
    root_path = str(root.get("path", ""))
    root_param = str(root.get("param", root.get("parameter", "")))
    root_method = str(root.get("method", "GET")).upper()
    cluster = infer_cluster(root)

    plans: List[VariantPlan] = []
    seen: Set[str] = set()

    def _add(surface: str, technique: str, payload: Optional[Dict] = None,
             expected: str = "", notes: str = "") -> None:
        key = f"{surface}|{technique}|{json.dumps(payload or {}, sort_keys=True)}"
        if key in seen:
            return
        seen.add(key)
        plan_id = f"VAR-{hashlib.sha256(key.encode()).hexdigest()[:12]}"
        plans.append(VariantPlan(
            id=plan_id,
            root_finding=str(root.get("id", "")),
            cluster=cluster,
            surface=surface,
            technique=technique,
            payload=payload,
            expected_response_diff=expected,
            notes=notes,
        ))

    # 1. Sibling endpoints (path prefix scan)
    if endpoints and root_path:
        prefix = root_path.rsplit("/", 1)[0]
        for ep in endpoints:
            if ep == root_path:
                continue
            if not ep.startswith(prefix):
                continue
            # Each sibling endpoint gets the same payload against the same
            # technique the root finding used.
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                if method == root_method:
                    continue
                _add(
                    surface=ep,
                    technique=f"http-method-swap-{method}",
                    payload={"method": method, "path": ep,
                            "param": root_param},
                    expected=("status flip on the same param" if root_param
                              else "method-allowed-200"),
                    notes=f"Method swap on sibling of {root_path}",
                )

    # 2. Sibling parameters (same family, different name)
    if params and root_param:
        family = _param_family(root_param)
        for p in params:
            if p == root_param:
                continue
            if _param_family(p) != family:
                continue
            _add(
                surface=root_path,
                technique="sibling-param-swap",
                payload={"path": root_path, "param": p,
                         "value": root.get("payload_value", "")},
                expected="same response shape with sibling param",
                notes=f"Param swap {root_param} -> {p} in {family}",
            )

    # 3. Sibling files (same module import) — only if the root has a
    #    source_file AND the operator supplied the sister-file list. The
    #    comparison strips the last `_xxx` segment so `import_service.py`
    #    matches `import_validator.py` (both are "import_*").
    if source_files and root.get("source_file"):
        root_module = _module_stem(str(root["source_file"]))
        for sf in source_files:
            if sf == root["source_file"]:
                continue
            if _module_stem(sf) != root_module:
                continue
            _add(
                surface=sf,
                technique="sister-file-same-module",
                payload={"file": sf, "replicates": root.get("sink", "")},
                expected="same vulnerability shape in sister file",
                notes=f"Sister file to {root['source_file']} sharing module",
            )

    # 4. Encoding variants of the same payload — only if the root has a
    #    concrete payload value to vary.
    if root.get("payload_value"):
        for codec in ("base64", "url", "double-url", "unicode", "hex"):
            _add(
                surface=root_path,
                technique=f"encoding-{codec}",
                payload={"path": root_path, "param": root_param,
                         "value": root["payload_value"],
                         "codec": codec},
                expected="same vulnerability under alternate encoding",
                notes="Encoding-resilience test for the same root cause",
            )

    return plans


def _param_family(name: str) -> str:
    """Bucket a parameter name into a family (id, amount, name, ...)."""
    n = name.lower()
    if re.search(r"^id$|_id$|uuid$|^uid$", n):
        return "id"
    if re.search(r"^amount$|^price$|^total$|^cost$|^qty$|^quantity$", n):
        return "amount"
    if re.search(r"^name$|^user(name)?$|^first_?name$|^last_?name$", n):
        return "name"
    if re.search(r"^email$|^mail$", n):
        return "email"
    if re.search(r"^url$|^uri$|^link$|^redirect(_uri)?$|^next$|^return_?to$", n):
        return "url"
    if re.search(r"^file$|^path$|^filename$|^attachment$", n):
        return "file"
    return "other"


def _module_stem(path: str) -> str:
    """Group a file path by its leading name token so sister files match.

    ``/app/services/import_service.py`` → ``import``
    ``/app/services/import_validator.py`` → ``import``
    Both share the same leading token and are treated as sister files.
    """
    name = Path(path).stem
    parts = name.split("_")
    return parts[0] if parts else name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hunt(finding: Dict[str, Any], *, target: str,
         endpoints: Optional[List[str]] = None,
         source_files: Optional[List[str]] = None,
         params: Optional[List[str]] = None) -> VariantHunt:
    """Run a HUNT-style variant hunt for the given finding."""
    root = derive_root_cause(finding)
    cluster = infer_cluster(finding)
    plans = enumerate_siblings(
        finding,
        endpoints=endpoints,
        source_files=source_files,
        params=params,
    )
    return VariantHunt(
        target=target,
        root_cause=root,
        root_evidence=str(finding.get("evidence_refs", [""])[0]
                          if finding.get("evidence_refs") else ""),
        cluster=cluster,
        plans=plans,
        total_siblings=len(plans),
    )


def write_hunt(hunt_result: VariantHunt, output_dir: Path) -> Path:
    """Persist the hunt result to ``output_dir/<target>-variants.json``."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{hunt_result.target}-variants.json"
    path.write_text(json.dumps(_to_dict(hunt_result), indent=2))
    return path


def _to_dict(h: VariantHunt) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "target": h.target,
        "root_cause": h.root_cause,
        "root_evidence": h.root_evidence,
        "cluster": h.cluster,
        "total_siblings": h.total_siblings,
        "generated_at": h.generated_at,
        "plans": [asdict(p) for p in h.plans],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf HUNT-style variant generator")
    p.add_argument("--finding", help="Path to a single finding JSON")
    p.add_argument("--findings-file", help="JSONL findings file")
    p.add_argument("--target", required=True, help="Target name")
    p.add_argument("--endpoints-file", help="Optional endpoints.txt (one per line)")
    p.add_argument("--output", required=True, help="Output directory")
    args = p.parse_args()

    findings: List[Dict[str, Any]] = []
    if args.finding:
        findings = [json.loads(Path(args.finding).read_text())]
    elif args.findings_file:
        findings = [json.loads(l) for l in Path(args.findings_file).read_text().splitlines() if l.strip()]
    if not findings:
        print("[!] no findings supplied", file=sys.stderr)
        return 2

    endpoints: Optional[List[str]] = None
    if args.endpoints_file:
        endpoints = [l.strip() for l in Path(args.endpoints_file).read_text().splitlines() if l.strip()]

    out_dir = Path(args.output)
    total = 0
    for f in findings:
        h = hunt(f, target=args.target, endpoints=endpoints)
        path = write_hunt(h, out_dir)
        total += h.total_siblings
        print(f"[+] {f.get('id', '?')}: {h.total_siblings} sibling plans "
              f"(cluster={h.cluster}, root_cause={h.root_cause}) -> {path}")
    print(f"[+] total sibling plans: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
