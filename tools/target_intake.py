#!/usr/bin/env python3
"""Operator-supplied target intake and reproducible academic exports.

The intake is the campaign boundary: no target is discovered or added by this
module.  It records the operator's attestation and exact scope in the campaign
and evidence lineage, then exposes the chosen live or replica/fork strategy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.campaign import CampaignManager
    from tools.evidence import EvidenceStore, redact
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:
    from campaign import CampaignManager
    from evidence import EvidenceStore, redact
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf-target-spec/v1"
VALID_DOMAINS = {"web/api", "web3", "mobile", "ai"}
VALID_AUTHORIZATION = {"own-asset", "bug-bounty scope URL", "contract", "academic approval"}
VALID_STRATEGIES = {"live", "replica/fork"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class TargetSpec:
    target_identifier: str
    domain: str
    authorization_basis: str
    scope_notes: Dict[str, Any] = field(default_factory=dict)
    roe_flags: Dict[str, Any] = field(default_factory=dict)
    validation_strategy: str = "live"
    operator: str = ""
    attestation: str = ""
    campaign_id: str = ""
    schema: str = SCHEMA
    recorded_at: str = ""

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.target_identifier.strip(): errors.append("target_identifier is required")
        if self.domain not in VALID_DOMAINS: errors.append(f"domain must be one of {sorted(VALID_DOMAINS)}")
        if self.authorization_basis not in VALID_AUTHORIZATION: errors.append("unsupported authorization_basis")
        if self.validation_strategy not in VALID_STRATEGIES: errors.append("validation_strategy must be live or replica/fork")
        if not self.operator.strip(): errors.append("operator is required")
        if not self.attestation.strip(): errors.append("attestation is required")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_spec(path: str | Path) -> TargetSpec:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    spec = TargetSpec(**data)
    errors = spec.validate()
    if errors:
        raise ValueError("invalid target spec: " + "; ".join(errors))
    return spec


def record_target_spec(spec: TargetSpec, *, project_root: Optional[str] = None) -> Dict[str, Any]:
    """Record the immutable intake record in campaign audit and evidence lineage."""
    errors = spec.validate()
    if errors: raise ValueError("invalid target spec: " + "; ".join(errors))
    root = workspace_root(project_root)
    mgr = CampaignManager(spec.target_identifier)
    if project_root:
        # CampaignManager follows the process workspace; make intake portable
        # for tests and exported project workspaces by persisting a parallel
        # target-spec record under the requested root.
        campaign_root = root / "state" / "campaigns" / target_slug(spec.target_identifier)
        campaign_root.mkdir(parents=True, exist_ok=True)
        campaign_spec_path = campaign_root / "target-spec.json"
    else:
        mgr.initialize()
        campaign_spec_path = mgr.root / "target-spec.json"
    campaign_spec_path.write_text(json.dumps(spec.to_dict(), indent=2) + "\n", encoding="utf-8")
    record = {"schema": SCHEMA, "kind": "target_intake", "recorded_at": spec.recorded_at or _now(),
              "target_spec": redact(spec.to_dict()), "scope_boundary": redact(spec.scope_notes),
              "roe_flags": redact(spec.roe_flags), "attestation": spec.attestation,
              "capability_policy": "maximum capability inside operator-supplied boundary",
              "discovery_policy": "no autonomous target discovery beyond supplied spec",
              "default_validation": "non-destructive unless operator explicitly flags fully-owned target",
              "spec_hash": _hash(spec.to_dict())}
    if project_root:
        audit_path = root / "state" / "campaigns" / target_slug(spec.target_identifier) / "audit.jsonl"
        with audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": "target_spec_attested", "data": record}, sort_keys=True) + "\n")
    else:
        mgr.log_event("target_spec_attested", record)
    evidence = EvidenceStore(spec.target_identifier)
    entry = evidence.add("target_spec_attestation", record, metadata={"spec_hash": record["spec_hash"]})
    output = dict(record)
    output["evidence_id"] = entry.evidence_id
    output["evidence_path"] = entry.path
    output["campaign_target"] = target_slug(spec.target_identifier)
    return output


def _git_revision(root: Path) -> str:
    try:
        from tools.runtime.sandbox import sandboxed_run
        proc = sandboxed_run(["git", "rev-parse", "HEAD"], cwd=root,
                             text=True, purpose="target_intake")
        return (proc.stdout or "").strip()
    except (OSError, subprocess.CalledProcessError, Exception):
        return "unknown"


def export_academic(*, target: str, output_dir: str, attempts: Iterable[Dict[str, Any]] = (),
                    methodology: str = "", technique_stats: Optional[Dict[str, Any]] = None,
                    project_root: Optional[str] = None) -> Dict[str, Any]:
    """Export reproducibility manifest, methodology, aggregate data, and appendix."""
    root = workspace_root(project_root)
    out = Path(output_dir)
    if not out.is_absolute(): out = root / out
    out.mkdir(parents=True, exist_ok=True)
    spec_path = root / "state" / "campaigns" / target_slug(target) / "target-spec.json"
    spec = json.loads(spec_path.read_text()) if spec_path.exists() else None
    records = [redact(dict(item)) for item in attempts]
    manifest = {"schema": "bugwolf/academic-reproducibility/v1", "target": target_slug(target),
                "generated_at": _now(), "seed": _hash(records)[:16],
                "tool_version": _git_revision(root), "environment_hash": _hash({"python": platform.python_version(), "platform": platform.platform()}),
                "target_spec_hash": _hash(spec) if spec else "missing", "pinned_versions": {"python": platform.python_version()},
                "validation_strategy": spec.get("validation_strategy") if spec else "unknown"}
    (out / "reproducibility.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "aggregate-dataset.json").write_text(json.dumps({"schema": "bugwolf/academic-dataset/v1", "records": records}, indent=2) + "\n")
    stats = technique_stats or {}
    (out / "baseline-vs-technique.json").write_text(json.dumps(stats, indent=2) + "\n")
    method = methodology or "# Methodology\n\nNo methodology text was supplied.\n"
    (out / "methodology.md").write_text(method)
    (out / "methodology.tex").write_text("\\section{Methodology}\n" + method.replace("%", "\\%"))
    appendix = "# Evidence Appendix\n\n" + "\n".join(f"- Attempt {r.get('run_id', i + 1)}: {r.get('case_id', 'unknown')}" for i, r in enumerate(records)) + "\n"
    (out / "evidence-appendix.md").write_text(appendix)
    return {"schema": manifest["schema"], "output_dir": str(out), "files": sorted(p.name for p in out.iterdir()), "manifest": manifest}


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="BugWolf operator target intake and academic export")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--record", metavar="SPEC.json")
    group.add_argument("--export-academic", action="store_true")
    parser.add_argument("--target", default="")
    parser.add_argument("--output-dir", default="research/academic")
    parser.add_argument("--attempts-file")
    parser.add_argument("--methodology-file")
    parser.add_argument("--project-root")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.record:
            spec = load_spec(args.record)
            result = record_target_spec(spec, project_root=args.project_root)
        else:
            attempts = json.loads(Path(args.attempts_file).read_text()) if args.attempts_file else []
            methodology = Path(args.methodology_file).read_text() if args.methodology_file else ""
            result = export_academic(target=args.target, output_dir=args.output_dir, attempts=attempts, methodology=methodology, project_root=args.project_root)
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)})); return 2

if __name__ == "__main__": raise SystemExit(main())
