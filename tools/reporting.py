#!/usr/bin/env python3
"""Phase 7 — Review, reporting, and coordinated disclosure.

The reporting gate is a *reporting* discipline — it never gates or reduces
research depth.  It ensures:

  * a report is only marked ``reportable`` when it carries the required
    evidence fields (reproduction, impact proof, affected versions,
    remediation, disclosure status) AND a human reviewer decision;
  * findings that are incomplete, unreviewed, or missing impact proof are
    refused with a clear reason;
  * disclosure is coordinated: vendor contact, response, patch version, and
    retest outcome are recorded and linked back to the original finding.

Artifacts persist under ``state/reports/<target>/``.

Usage:
  python3 tools/reporting.py --target T --check --finding-file F --json
  python3 tools/reporting.py --target T --review --finding-id F \
      --decision confirmed --json
  python3 tools/reporting.py --target T --disclose --finding-id F \
      --vendor vendor@example.com --json
  python3 tools/reporting.py --target T --status --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

SCHEMA = "bugwolf/reporting/v1"
REQUIRED_EVIDENCE_FIELDS = (
    "reproduction", "impact_proof", "affected_versions", "remediation",
)
VALID_REVIEW_DECISIONS = ("confirmed", "rejected", "needs_more_evidence")
DISCLOSURE_STATES = ("not_started", "contacted", "vendor_response",
                     "patched", "retested", "closed")

# ---------------------------------------------------------------------------
# Noise filter (INTEGRATION_PLAN Phase B, v1.25; source: ECC
# security-bounty-hunter skip-list, MIT, attributed).  Platform-rejected
# noise classes are HELD at the gate with advisory reasons — never
# silently deleted, and any finding carrying demonstrated impact BYPASSES
# its category match (impact always outranks the denylist).
# ---------------------------------------------------------------------------
NOISE_PATTERNS = (
    # (category, body/title substrings, why it is noise)
    ("self-xss",
     ("self-xss", "self xss"),
     "requires the victim to paste the payload manually"),
    ("headers-only",
     ("missing security header", "security headers"),
     "header absence alone is informational, not exploitable"),
    ("rate-limit-generic",
     ("rate limit", "rate limiting", "no rate limit"),
     "generic rate-limiting complaint without demonstrated impact"),
    ("local-only-deserialization",
     ("pickle.load", "torch.load", "yaml.load"),
     "local-only sink — needs a remotely reachable path to count"),
    ("cli-only-exec",
     ("eval(", "exec("),
     "CLI-only tooling sink with no remote trigger"),
    ("hardcoded-shell",
     ("shell=true", "shell=True"),
     "fully hardcoded command — no attacker-controlled input"),
    ("test-only",
     ("/tests/", "/fixtures/", "/examples/", "example.com"),
     "test, fixture, or demo surface — not a shippable target"),
)

# A finding whose impact text matches any of these is demonstrating real
# impact (ECC's in-scope table): the noise match is overridden.
_IMPACT_OVERRIDES = (
    "internal network", "metadata", "cloud metadata", "unauthorized access",
    "code execution", "rce", "data exfiltration", "session theft",
    "admin compromise", "authentication bypass", "auth bypass",
    "arbitrary file", "sql injection", "smuggled", "poisoned",
)


def noise_reasons(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """Advisory noise analysis for a finding dict.

    Returns (category, matched_on, why) triples.  Categories whose match is
    overridden by demonstrated impact text are EXCLUDED (impact outranks
    the denylist).  Pure function; never mutates or rejects.
    """
    title = str(finding.get("title") or "").lower()
    body = " ".join(str(finding.get(k) or "") for k in
                    ("reproduction", "trigger_trace", "notes", "summary",
                     "remediation", "affected_versions")).lower()
    impact = " ".join(str(finding.get(k) or "") for k in
                      ("impact_proof", "impact_trace",
                       "demonstrated_impact")).lower()
    if any(marker in impact for marker in _IMPACT_OVERRIDES):
        return []                    # demonstrated impact: nothing is noise
    reasons: List[Dict[str, str]] = []
    for category, markers, why in NOISE_PATTERNS:
        for marker in markers:
            haystack = title if category in ("self-xss", "headers-only",
                                             "rate-limit-generic") \
                else title + " " + body
            if marker.lower() in haystack:
                reasons.append({"category": category,
                                "matched_on": marker, "why": why})
                break
    return reasons


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir(project_root: Optional[str] = None, target: str = "") -> Path:
    root = workspace_root(project_root)
    if target:
        return root / "state" / "reports" / target_slug(target)
    return root / "state" / "reports"


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_refs(finding: Dict[str, Any]) -> List[Any]:
    """Return explicit durable-evidence references, if the finding supplies them."""
    refs: List[Any] = []
    for key in ("artifact_refs", "evidence_artifacts", "evidence_refs"):
        value = finding.get(key)
        if isinstance(value, (list, tuple)):
            refs.extend(value)
        elif value:
            refs.append(value)
    return refs


def validate_evidence_artifacts(finding: Dict[str, Any], *,
                                project_root: Optional[str] = None) -> Dict[str, Any]:
    """Verify explicit evidence references are durable and content-addressed.

    Narrative fields are intentionally not treated as files.  Once a caller
    supplies an explicit reference, however, every reference must resolve
    inside the workspace (or an explicitly absolute path), be readable, and
    match its declared SHA-256.  Missing symbolic IDs such as ``replay-L1``
    therefore cannot satisfy a confirmation gate.
    """
    refs = _evidence_refs(finding)
    if not refs:
        return {"required": False, "valid": True, "checked": 0, "errors": []}
    root = workspace_root(project_root)
    checked = 0
    errors: List[str] = []
    for index, ref in enumerate(refs):
        declared_hash = ""
        raw_path: Any = ref
        if isinstance(ref, dict):
            raw_path = ref.get("path") or ref.get("artifact_path") or ""
            declared_hash = str(ref.get("sha256") or "").lower()
            if declared_hash and not re.fullmatch(r"[0-9a-f]{64}", declared_hash):
                errors.append(f"evidence[{index}] has invalid sha256")
                continue
        path_text = str(raw_path or "").strip()
        if not path_text:
            errors.append(f"evidence[{index}] missing path")
            continue
        path = Path(path_text).expanduser()
        if not path.is_absolute():
            path = root / path
        try:
            resolved = path.resolve()
            # Relative references must remain in the invoking workspace.  An
            # absolute reference is accepted only when it is already inside
            # that workspace; this avoids turning report generation into an
            # arbitrary file reader.
            resolved.relative_to(root.resolve())
        except (OSError, ValueError):
            errors.append(f"evidence[{index}] path escapes workspace: {path_text}")
            continue
        if not resolved.is_file():
            errors.append(f"evidence[{index}] artifact not found: {path_text}")
            continue
        try:
            actual = _file_sha256(resolved)
        except OSError as exc:
            errors.append(f"evidence[{index}] unreadable: {exc}")
            continue
        checked += 1
        if not declared_hash:
            errors.append(f"evidence[{index}] missing sha256: {path_text}")
        elif actual != declared_hash:
            errors.append(f"evidence[{index}] sha256 mismatch: {path_text}")
    return {"required": True, "valid": not errors, "checked": checked,
            "references": len(refs), "errors": errors}


@dataclass
class DisclosureRecord:
    finding_id: str = ""
    state: str = "not_started"
    vendor_contact: str = ""
    vendor_response: str = ""
    patch_version: str = ""
    retest_outcome: str = ""
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReportRecord:
    finding_id: str
    title: str = ""
    target: str = ""
    severity: str = "info"
    evidence_fields: Dict[str, str] = field(default_factory=dict)
    reviewer: str = ""
    review_decision: str = ""
    review_note: str = ""
    disclosure: DisclosureRecord = field(default_factory=DisclosureRecord)
    evidence_integrity: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = _now()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.disclosure.finding_id:
            self.disclosure.finding_id = self.finding_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "severity": self.severity,
            "evidence_fields": self.evidence_fields,
            "reviewer": self.reviewer,
            "review_decision": self.review_decision,
            "review_note": self.review_note,
            "disclosure": self.disclosure.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "reportable": self.is_reportable(),
        }

    def is_reportable(self) -> bool:
        """A report is only reportable with complete evidence + review."""
        if self.review_decision != "confirmed":
            return False
        if not all(str(self.evidence_fields.get(field) or "").strip()
                   for field in REQUIRED_EVIDENCE_FIELDS):
            return False
        if self.evidence_integrity.get("required") and not self.evidence_integrity.get("valid"):
            return False
        return True

    def refusal_reasons(self) -> List[str]:
        reasons: List[str] = []
        if self.review_decision != "confirmed":
            reasons.append(f"review decision is {self.review_decision!r}, "
                           "not 'confirmed'")
        for field in REQUIRED_EVIDENCE_FIELDS:
            if not str(self.evidence_fields.get(field) or "").strip():
                reasons.append(f"missing required evidence field: {field}")
        if self.evidence_integrity.get("required") and not self.evidence_integrity.get("valid"):
            for error in self.evidence_integrity.get("errors") or []:
                reasons.append(f"evidence integrity: {error}")
        return reasons


class ReportingGate:
    """Review / disclosure / retest workflow for one target."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target)
        self._records: Dict[str, ReportRecord] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "reports.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                rec["disclosure"] = DisclosureRecord(**rec.get("disclosure", {}))
                record = ReportRecord(**{k: v for k, v in rec.items()
                                         if k in ReportRecord.__dataclass_fields__})
                self._records[record.finding_id] = record
            except (TypeError, json.JSONDecodeError, KeyError):
                continue

    def _persist_all(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("w", encoding="utf-8") as stream:
            for record in self._records.values():
                stream.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")

    def check(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a finding dict against the reporting gate."""
        finding_id = str(finding.get("finding_id")
                         or _sha256(json.dumps(finding, sort_keys=True)))
        evidence_fields = {
            "reproduction": str(finding.get("reproduction")
                                or finding.get("trigger_trace") or ""),
            "impact_proof": str(finding.get("impact_proof")
                                or finding.get("impact_trace")
                                or finding.get("demonstrated_impact") or ""),
            "affected_versions": str(finding.get("affected_versions")
                                     or finding.get("version") or ""),
            "remediation": str(finding.get("remediation") or ""),
        }
        evidence_integrity = validate_evidence_artifacts(
            finding, project_root=str(self.root.parent.parent.parent))
        record = ReportRecord(
            finding_id=finding_id,
            title=str(finding.get("title") or ""),
            target=self.target,
            severity=str(finding.get("severity") or "info"),
            evidence_fields=evidence_fields,
            evidence_integrity=evidence_integrity,
            reviewer=str(finding.get("reviewer") or ""),
            review_decision=str(finding.get("review_decision") or ""),
        )
        self._records[finding_id] = record
        self._persist_all()
        noise = noise_reasons(finding)
        return {
            "schema": SCHEMA,
            "finding_id": finding_id,
            "reportable": record.is_reportable(),
            "refusal_reasons": record.refusal_reasons(),
            "noise": noise,                      # advisory (Phase B, v1.25)
            "noise_held": bool(noise) and not record.is_reportable(),
            "evidence_integrity": evidence_integrity,
        }

    def review(self, finding_id: str, decision: str, *, reviewer: str = "operator",
               note: str = "") -> Dict[str, Any]:
        record = self._records.get(finding_id)
        if not record:
            raise ValueError(f"unknown finding: {finding_id}")
        if decision not in VALID_REVIEW_DECISIONS:
            raise ValueError(f"invalid review decision: {decision}")
        record.reviewer = reviewer
        record.review_decision = decision
        record.review_note = str(note or "")
        record.updated_at = _now()
        self._persist_all()
        return {
            "schema": SCHEMA,
            "finding_id": finding_id,
            "review_decision": decision,
            "reportable": record.is_reportable(),
            "refusal_reasons": record.refusal_reasons(),
        }

    def disclose(self, finding_id: str, *, vendor_contact: str = "",
                 state: str = "contacted") -> Dict[str, Any]:
        record = self._records.get(finding_id)
        if not record:
            raise ValueError(f"unknown finding: {finding_id}")
        if state not in DISCLOSURE_STATES:
            raise ValueError(f"invalid disclosure state: {state}")
        disclosure = record.disclosure
        disclosure.state = state
        if vendor_contact:
            disclosure.vendor_contact = vendor_contact
        disclosure.history.append({"state": state, "at": _now(),
                                   "vendor": vendor_contact})
        record.updated_at = _now()
        self._persist_all()
        return disclosure.to_dict()

    def record_vendor_response(self, finding_id: str, *, response: str,
                               patch_version: str = "") -> Dict[str, Any]:
        record = self._records.get(finding_id)
        if not record:
            raise ValueError(f"unknown finding: {finding_id}")
        disclosure = record.disclosure
        disclosure.vendor_response = str(response or "")
        if patch_version:
            disclosure.patch_version = patch_version
            disclosure.state = "patched"
        else:
            disclosure.state = "vendor_response"
        disclosure.history.append({"state": disclosure.state, "at": _now(),
                                   "patch": patch_version})
        record.updated_at = _now()
        self._persist_all()
        return disclosure.to_dict()

    def record_retest(self, finding_id: str, *, outcome: str) -> Dict[str, Any]:
        record = self._records.get(finding_id)
        if not record:
            raise ValueError(f"unknown finding: {finding_id}")
        disclosure = record.disclosure
        disclosure.retest_outcome = str(outcome or "")
        disclosure.state = "retested" if disclosure.patch_version else "retested"
        disclosure.history.append({"state": disclosure.state, "at": _now(),
                                   "outcome": outcome})
        record.updated_at = _now()
        self._persist_all()
        return disclosure.to_dict()

    def records(self) -> List[ReportRecord]:
        return sorted(self._records.values(), key=lambda r: r.finding_id)

    def report(self) -> Dict[str, Any]:
        reportable = [r for r in self._records.values() if r.is_reportable()]
        return {
            "schema": SCHEMA,
            "target": self.target,
            "records": len(self._records),
            "reportable": len(reportable),
            "by_disclosure_state": {
                state: sum(1 for r in self._records.values()
                           if r.disclosure.state == state)
                for state in DISCLOSURE_STATES
            },
            "reports": [r.to_dict() for r in self.records()],
        }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf reporting gate + coordinated disclosure")
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--status", action="store_true")
    actions.add_argument("--check", action="store_true",
                         help="evaluate a finding file against the gate")
    actions.add_argument("--review", action="store_true")
    actions.add_argument("--disclose", action="store_true")
    actions.add_argument("--vendor-response", action="store_true")
    actions.add_argument("--retest", action="store_true")
    parser.add_argument("--finding-file", default="")
    parser.add_argument("--finding-id", default="")
    parser.add_argument("--decision", default="confirmed",
                        choices=VALID_REVIEW_DECISIONS)
    parser.add_argument("--reviewer", default="operator")
    parser.add_argument("--note", default="")
    parser.add_argument("--vendor", default="")
    parser.add_argument("--state", default="contacted",
                        choices=DISCLOSURE_STATES)
    parser.add_argument("--response", default="")
    parser.add_argument("--patch-version", default="")
    parser.add_argument("--outcome", default="")
    args = parser.parse_args(list(argv) if argv is not None else None)

    gate = ReportingGate(args.target, args.project_root)
    try:
        if args.status:
            result = gate.report()
        elif args.check:
            finding = json.loads(Path(args.finding_file).read_text())
            result = gate.check(finding)
        elif args.review:
            result = gate.review(args.finding_id, args.decision,
                                 reviewer=args.reviewer, note=args.note)
        elif args.disclose:
            result = gate.disclose(args.finding_id, vendor_contact=args.vendor,
                                   state=args.state)
        elif args.vendor_response:
            result = gate.record_vendor_response(
                args.finding_id, response=args.response,
                patch_version=args.patch_version)
        else:
            result = gate.record_retest(args.finding_id, outcome=args.outcome)
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
