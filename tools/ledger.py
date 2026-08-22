#!/usr/bin/env python3
"""
BugWolf Ledger Verifier v1.0.0

The ledger is the truth. This tool verifies that every finding has corresponding
entries in the journal and endpoint logs — you cannot claim you tested what you
didn't test. It also generates coverage gap reports showing what should have
been tested but wasn't.

Checks:
  - Finding↔journal consistency: does every finding have evidence in the journal?
  - Finding↔endpoint consistency: does every finding have a tested endpoint entry?
  - Orphan detection: any findings with zero supporting evidence?
  - Coverage gaps: what endpoints/parameters/classes haven't been tested?
  - Journal integrity: is the append-only log intact (no gaps, no rewrites)?
  - Session coverage: which sessions contributed what findings?

Usage:
  python3 tools/ledger.py --target example.com --verify
  python3 tools/ledger.py --target example.com --verify-finding abc123
  python3 tools/ledger.py --target example.com --coverage-gaps
  python3 tools/ledger.py --target example.com --integrity-check
  python3 tools/ledger.py --target example.com --report
"""

import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
    from tools.safety import safe_target_name
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root
    from safety import safe_target_name

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

LEDGER_DIR = ROOT / "state" / "ledger"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    """A single piece of evidence from the ledger."""
    source: str  # journal, endpoints, findings, custody
    entry_id: str  # unique identifier for this record
    timestamp: str
    event_type: str = ""
    finding_id: str = ""
    endpoint: str = ""
    method: str = "GET"
    content_hash: str = ""
    session_id: str = ""
    raw: Dict = field(default_factory=dict)


@dataclass
class OrphanedFinding:
    """A finding with no supporting evidence in the ledger."""
    finding_id: str
    title: str
    bug_class: str
    endpoint: str
    severity: str
    claimed_at: str
    missing_evidence: List[str] = field(default_factory=list)
    # What's missing: "journal_entry", "endpoint_test", "custody_chain"
    confidence_penalty: float = 0.0  # How much to reduce confidence
    recommendation: str = ""


@dataclass
class CoverageGap:
    """Something that should have been tested but wasn't."""
    gap_type: str  # endpoint, parameter, bug_class, session, capability
    identifier: str = ""
    severity: str = "medium"  # how important is this gap?
    recommended_agent: str = ""
    description: str = ""
    related_findings: List[str] = field(default_factory=list)


@dataclass
class TriggerStreamIntegrity:
    """Integrity result for one post-finding trigger JSONL stream."""
    stream: str
    file: str
    total_records: int
    verified_records: int
    tampered_records: int = 0
    sequence_gaps: int = 0
    hash_chain_intact: bool = True
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)


@dataclass
class LedgerIntegrity:
    """Result of integrity checks on the journal and trigger streams."""
    target: str
    journal_file: str
    total_entries: int
    verified_entries: int
    tampered_entries: int = 0
    sequence_gaps: int = 0
    timestamp_gaps: int = 0  # Entries with timestamp going backwards
    hash_chain_intact: bool = True
    first_entry: str = ""
    last_entry: str = ""
    trigger_receipts: Optional[TriggerStreamIntegrity] = None
    trigger_queue: Optional[TriggerStreamIntegrity] = None
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)


@dataclass
class LedgerReport:
    target: str
    generated_at: str
    findings_total: int
    findings_verified: int  # Have supporting evidence
    findings_orphaned: int  # No supporting evidence
    endpoints_tested: int
    sessions_used: int
    coverage_gaps: List[CoverageGap] = field(default_factory=list)
    orphans: List[OrphanedFinding] = field(default_factory=list)
    integrity: Optional[LedgerIntegrity] = None
    verification_score: float = 0.0  # 0.0 to 1.0 — how verifiable is this audit?

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Ledger Verifier
# ---------------------------------------------------------------------------

class LedgerVerifier:
    """Cross-references findings, journal, and endpoints for truth verification."""

    def __init__(self, target: str):
        safe_target_name(target)
        self.target = target
        safe = target.replace("/", "_").replace(":", "_").replace("*", "WILDCARD")
        self._dir = LEDGER_DIR / safe
        self._dir.mkdir(parents=True, exist_ok=True)

        # Paths to state files
        try:
            from tools.state import _state_dir
            self._state_dir = _state_dir(target)
        except ImportError:
            self._state_dir = ROOT / "state" / "sessions" / safe

    # ---- Evidence Collection ----

    def _collect_journal_entries(self) -> List[Dict]:
        """Collect all journal entries for this target."""
        jf = self._state_dir / "journal.jsonl"
        if not jf.exists():
            return []
        return [json.loads(l) for l in jf.read_text().splitlines() if l.strip()]

    def _collect_endpoint_entries(self) -> List[Dict]:
        """Collect all endpoint test records."""
        ef = self._state_dir / "endpoints.jsonl"
        if not ef.exists():
            return []
        return [json.loads(l) for l in ef.read_text().splitlines() if l.strip()]

    def _collect_findings(self) -> List[Dict]:
        """Collect all findings."""
        ff = self._state_dir / "findings.jsonl"
        if not ff.exists():
            return []
        return [json.loads(l) for l in ff.read_text().splitlines() if l.strip()]

    def _collect_dead_ends(self) -> List[Dict]:
        """Collect dead end records."""
        df = self._state_dir / "dead_ends.jsonl"
        if not df.exists():
            return []
        return [json.loads(l) for l in df.read_text().splitlines() if l.strip()]

    # ---- Verification ----

    def verify_finding(self, finding: Dict) -> Tuple[bool, List[str]]:
        """Verify a single finding has supporting evidence.

        Returns (is_verified, list_of_missing_evidence_types).
        """
        finding_id = finding.get("finding_id", "")
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        bug_class = finding.get("bug_class", "")
        found_at = finding.get("found_at", "")

        missing = []

        # Check 1: Journal entry for this finding
        journal = self._collect_journal_entries()
        journal_match = False
        for entry in journal:
            data = entry.get("data", {})
            if data.get("finding_id") == finding_id:
                journal_match = True
                break
            if entry.get("event") == "finding_added" and finding_id in json.dumps(data):
                journal_match = True
                break
        if not journal_match:
            missing.append("journal_entry")

        # Check 2: Endpoint was actually tested
        endpoints = self._collect_endpoint_entries()
        endpoint_match = False
        for ep in endpoints:
            if (ep.get("url", "") == endpoint and
                    ep.get("method", "GET") == method):
                endpoint_match = True
                break
        if not endpoint_match and endpoint:
            missing.append("endpoint_test")

        # Check 3: Custody chain initiated (if available)
        try:
            from tools.chain_of_custody import verify_custody
            custody_check = verify_custody(finding_id)
            if not custody_check.get("valid"):
                missing.append("custody_chain")
        except (ImportError, Exception):
            pass  # Custody optional

        # Check 4: Timing consistency — was this finding recorded AFTER tests?
        if found_at and endpoints:
            finding_ts = found_at
            tested_before = any(
                ep.get("tested_at", "") <= finding_ts
                for ep in endpoints if ep.get("url", "") == endpoint
            )
            if not tested_before:
                missing.append("timing_consistency")

        return len(missing) == 0, missing

    def verify_all(self) -> LedgerReport:
        """Verify all findings against the ledger."""
        findings = self._collect_findings()
        journal = self._collect_journal_entries()
        endpoints = self._collect_endpoint_entries()
        dead_ends = self._collect_dead_ends()

        orphans = []
        verified = 0

        for finding in findings:
            is_verified, missing = self.verify_finding(finding)
            if is_verified:
                verified += 1
            else:
                # Calculate confidence penalty
                penalty_map = {
                    "journal_entry": 0.4,
                    "endpoint_test": 0.3,
                    "custody_chain": 0.15,
                    "timing_consistency": 0.15,
                }
                penalty = sum(penalty_map.get(m, 0.1) for m in missing)

                recommendation = ""
                if "journal_entry" in missing:
                    recommendation += "Re-run test and log to journal. "
                if "endpoint_test" in missing:
                    recommendation += f"Run GET/POST on {finding.get('endpoint', '?')}. "
                if "timing_consistency" in missing:
                    recommendation += "Verify endpoint was tested before finding was logged. "

                orphans.append(OrphanedFinding(
                    finding_id=finding.get("finding_id", "unknown"),
                    title=finding.get("title", "Untitled"),
                    bug_class=finding.get("bug_class", ""),
                    endpoint=finding.get("endpoint", ""),
                    severity=finding.get("severity", "info"),
                    claimed_at=finding.get("found_at", ""),
                    missing_evidence=missing,
                    confidence_penalty=min(penalty, 1.0),
                    recommendation=recommendation.strip(),
                ))

        # Session analysis
        sessions = set()
        for ep in endpoints:
            sid = ep.get("session_id", "")
            if sid:
                sessions.add(sid)
        for je in journal:
            sid = je.get("data", {}).get("session_id", "")
            if sid:
                sessions.add(sid)

        # Coverage gaps
        gaps = self._find_coverage_gaps(findings, endpoints, dead_ends)

        # Integrity check
        integrity = self.check_integrity()

        # Verification score
        if findings:
            score = verified / len(findings)
            # Penalize for integrity issues
            if integrity and not integrity.is_valid:
                score *= 0.8
            # Penalize for coverage gaps
            if gaps:
                score *= max(0.5, 1.0 - (len(gaps) * 0.05))
        else:
            score = 1.0

        report = LedgerReport(
            target=self.target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            findings_total=len(findings),
            findings_verified=verified,
            findings_orphaned=len(orphans),
            endpoints_tested=len(endpoints),
            sessions_used=len(sessions),
            coverage_gaps=gaps,
            orphans=orphans,
            integrity=integrity,
            verification_score=round(score, 2),
        )

        self._save_report(report)
        return report

    # ---- Coverage Gaps ----

    def _find_coverage_gaps(self, findings: List[Dict],
                             endpoints: List[Dict],
                             dead_ends: List[Dict]) -> List[CoverageGap]:
        """Identify what hasn't been tested that should have been."""
        gaps = []

        tested_endpoints = set()
        for ep in endpoints:
            tested_endpoints.add(f"{ep.get('method', 'GET')}:{ep.get('url', '')}")

        tested_urls = set()
        for ep in endpoints:
            tested_urls.add(ep.get("url", ""))

        # Gap 1: Endpoints mentioned in findings that have no test record
        for finding in findings:
            ep = finding.get("endpoint", "")
            if ep and ep not in tested_urls:
                gaps.append(CoverageGap(
                    gap_type="endpoint",
                    identifier=ep,
                    severity="high",
                    recommended_agent="web-api-agent",
                    description=f"Finding references {ep} but no test record exists",
                    related_findings=[finding.get("finding_id", "")],
                ))

        # Gap 2: Bug classes with zero findings (should some agents be run?)
        found_classes = set(f.get("bug_class", "") for f in findings)
        # Critical classes that should always be tested
        always_test = [
            "idor", "ssrf", "sqli", "xss-reflected", "xss-stored",
            "broken-auth", "csrf", "open-redirect", "path-traversal",
            "command-injection", "xxe", "deserialization",
            "information-disclosure", "mass-assignment",
        ]
        for bc in always_test:
            if bc not in found_classes:
                gaps.append(CoverageGap(
                    gap_type="bug_class",
                    identifier=bc,
                    severity="medium",
                    recommended_agent="web-api-agent",
                    description=f"No findings for {bc} — agent may not have tested it",
                ))

        # Gap 3: HTTP methods that weren't tested on discovered endpoints
        method_coverage = defaultdict(set)
        for ep in endpoints:
            method_coverage[ep.get("url", "")].add(ep.get("method", "GET"))

        for url, methods in method_coverage.items():
            missing_methods = {"POST", "PUT", "PATCH", "DELETE"} - methods
            if missing_methods and any(m in url.lower() for m in ["api", "user", "admin"]):
                gaps.append(CoverageGap(
                    gap_type="http_method",
                    identifier=f"{url} missing: {', '.join(sorted(missing_methods))}",
                    severity="low",
                    recommended_agent="web-api-agent",
                    description=f"Only tested {', '.join(sorted(methods))} on {url}",
                ))

        # Gap 4: Dead ends per tested endpoint ratio
        if endpoints and dead_ends:
            ratio = len(dead_ends) / max(len(endpoints), 1)
            if ratio < 0.1:
                gaps.append(CoverageGap(
                    gap_type="dead_end_ratio",
                    identifier="low_dead_end_ratio",
                    severity="low",
                    recommended_agent="web-api-agent",
                    description=f"Only {len(dead_ends)} dead ends for {len(endpoints)} "
                                 f"tests ({ratio:.0%}) — may not be testing edge cases",
                ))

        return gaps

    # ---- Integrity Check ----

    def _check_trigger_stream(self, path: Path, stream: str) -> Optional[TriggerStreamIntegrity]:
        """Validate one trigger JSONL stream's sequence and hash chain."""
        if not path.exists():
            return None
        raw_lines = [line for line in path.read_text(encoding="utf-8").splitlines()
                     if line.strip()]
        if not raw_lines:
            return None
        result = TriggerStreamIntegrity(
            stream=stream,
            file=str(path),
            total_records=len(raw_lines),
            verified_records=0,
        )
        previous_hash = ""
        expected_sequence = 1
        for index, line in enumerate(raw_lines):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                result.tampered_records += 1
                result.errors.append(f"Record {index}: invalid JSON: {exc.msg}")
                continue
            if not isinstance(record, dict):
                result.tampered_records += 1
                result.errors.append(f"Record {index}: record is not a JSON object")
                continue
            required = {"sequence", "previous_hash", "record_hash"}
            if not required.issubset(record):
                result.tampered_records += 1
                result.hash_chain_intact = False
                result.errors.append(
                    f"Record {index}: missing trigger hash-chain metadata")
                continue
            if record.get("sequence") != expected_sequence:
                result.sequence_gaps += 1
                result.errors.append(
                    f"Record {index}: expected sequence {expected_sequence}, "
                    f"got {record.get('sequence')}")
            if record.get("previous_hash", "") != previous_hash:
                result.hash_chain_intact = False
                result.errors.append(
                    f"Record {index}: previous hash does not match chain tip")
            unsigned = dict(record)
            stored_hash = unsigned.pop("record_hash")
            expected_hash = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if stored_hash != expected_hash:
                result.tampered_records += 1
                result.hash_chain_intact = False
                result.errors.append(f"Record {index}: record hash mismatch")
            previous_hash = str(stored_hash)
            expected_sequence += 1
            result.verified_records += 1
        result.is_valid = (
            result.tampered_records == 0
            and result.sequence_gaps == 0
            and result.hash_chain_intact
            and not result.errors
        )
        return result

    def check_integrity(self) -> Optional[LedgerIntegrity]:
        """Check journal and trigger-stream integrity — no gaps or tampering."""
        jf = self._state_dir / "journal.jsonl"
        trigger_receipts = self._check_trigger_stream(
            self._state_dir / "post-finding-triggers.jsonl", "trigger_receipts")
        trigger_queue = self._check_trigger_stream(
            self._state_dir / "post-finding-queue.jsonl", "trigger_queue")
        if not jf.exists():
            if not trigger_receipts and not trigger_queue:
                return None
            integrity = LedgerIntegrity(
                target=self.target,
                journal_file=str(jf),
                total_entries=0,
                verified_entries=0,
                trigger_receipts=trigger_receipts,
                trigger_queue=trigger_queue,
            )
            for label, stream_result in (("trigger receipts", trigger_receipts),
                                         ("trigger queue", trigger_queue)):
                if stream_result and not stream_result.is_valid:
                    integrity.hash_chain_intact = False
                    integrity.errors.extend(
                        f"{label}: {error}" for error in stream_result.errors)
            integrity.is_valid = not integrity.errors
            return integrity

        entries = []
        for line in jf.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        if not entries:
            if not trigger_receipts and not trigger_queue:
                return None
            integrity = LedgerIntegrity(
                target=self.target,
                journal_file=str(jf),
                total_entries=0,
                verified_entries=0,
                trigger_receipts=trigger_receipts,
                trigger_queue=trigger_queue,
            )
            for label, stream_result in (("trigger receipts", trigger_receipts),
                                         ("trigger queue", trigger_queue)):
                if stream_result and not stream_result.is_valid:
                    integrity.hash_chain_intact = False
                    integrity.errors.extend(
                        f"{label}: {error}" for error in stream_result.errors)
            integrity.is_valid = not integrity.errors
            return integrity

        integrity = LedgerIntegrity(
            target=self.target,
            journal_file=str(jf),
            total_entries=len(entries),
            verified_entries=0,
            first_entry=entries[0].get("ts", "unknown"),
            last_entry=entries[-1].get("ts", "unknown"),
        )

        prev_ts = None
        previous_hash = ""
        expected_sequence = 1
        # Rotation intentionally keeps only a suffix. The anchor authenticates
        # that suffix's predecessor and sequence instead of treating it as a
        # newly created journal.
        anchor_file = self._state_dir / "journal.anchor.json"
        if anchor_file.exists():
            try:
                anchor = json.loads(anchor_file.read_text())
                previous_hash = str(anchor.get("previous_hash", ""))
                expected_sequence = int(anchor.get("next_sequence", 1))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                integrity.hash_chain_intact = False
                integrity.errors.append("journal anchor is invalid")

        for i, entry in enumerate(entries):
            ts = entry.get("ts", "")
            event = entry.get("event", "")

            # Check: timestamps don't go backwards
            if prev_ts and ts < prev_ts:
                integrity.timestamp_gaps += 1
                integrity.errors.append(
                    f"Entry {i}: timestamp went backwards "
                    f"({prev_ts} → {ts}) for event '{event}'")

            # New entries carry a sequence and a hash chain. Legacy entries are
            # readable, but cannot be called tamper-evident.
            if not {"sequence", "previous_hash", "entry_hash"}.issubset(entry):
                integrity.hash_chain_intact = False
                integrity.errors.append(f"Entry {i}: legacy entry lacks hash-chain metadata")
            else:
                if entry.get("sequence") != expected_sequence:
                    integrity.sequence_gaps += 1
                    integrity.errors.append(
                        f"Entry {i}: expected sequence {expected_sequence}, "
                        f"got {entry.get('sequence')}")
                if entry.get("previous_hash", "") != previous_hash:
                    integrity.hash_chain_intact = False
                    integrity.errors.append(f"Entry {i}: previous hash does not match chain tip")
                unsigned = dict(entry)
                actual_hash = unsigned.pop("entry_hash")
                expected_hash = hashlib.sha256(
                    json.dumps(unsigned, sort_keys=True).encode()).hexdigest()
                if actual_hash != expected_hash:
                    integrity.tampered_entries += 1
                    integrity.hash_chain_intact = False
                    integrity.errors.append(f"Entry {i}: entry hash mismatch")
                previous_hash = actual_hash
                expected_sequence += 1

            # Check: essential fields present
            if "ts" not in entry or "event" not in entry:
                integrity.tampered_entries += 1
                integrity.errors.append(
                    f"Entry {i}: missing required fields (ts or event)")

            integrity.verified_entries += 1
            prev_ts = ts

        integrity.trigger_receipts = trigger_receipts
        integrity.trigger_queue = trigger_queue
        for label, stream_result in (("trigger receipts", trigger_receipts),
                                     ("trigger queue", trigger_queue)):
            if stream_result and not stream_result.is_valid:
                integrity.hash_chain_intact = False
                integrity.errors.extend(
                    f"{label}: {error}" for error in stream_result.errors)

        integrity.is_valid = (
            integrity.tampered_entries == 0 and
            integrity.sequence_gaps == 0 and
            integrity.hash_chain_intact and
            len(integrity.errors) == 0
        )

        return integrity

    # ---- Session Coverage ----

    def get_session_coverage(self) -> Dict:
        """Analyze which sessions contributed which findings."""
        findings = self._collect_findings()
        endpoints = self._collect_endpoint_entries()

        sessions = defaultdict(lambda: {
            "findings": 0,
            "endpoints_tested": 0,
            "bug_classes": set(),
            "severities": defaultdict(int),
        })

        for f in findings:
            sid = f.get("session_id", "unknown")
            sessions[sid]["findings"] += 1
            sessions[sid]["bug_classes"].add(f.get("bug_class", ""))
            sessions[sid]["severities"][f.get("severity", "info")] += 1

        for ep in endpoints:
            sid = ep.get("session_id", "unknown")
            sessions[sid]["endpoints_tested"] += 1

        return dict(sessions)

    # ---- Reporting ----

    def generate_report(self) -> str:
        report = self.verify_all()

        lines = [
            "=" * 72,
            f"  LEDGER VERIFICATION REPORT — {report.target}",
            "=" * 72,
            f"  Generated: {report.generated_at}",
            f"  Verification Score: {report.verification_score:.0%}",
            "=" * 72,
            "",
            f"Findings total:     {report.findings_total}",
            f"Findings verified:  {report.findings_verified}",
            f"Findings orphaned:  {report.findings_orphaned}",
            f"Endpoints tested:   {report.endpoints_tested}",
            f"Sessions used:      {report.sessions_used}",
            "",
        ]

        if report.integrity:
            i = report.integrity
            status = "✅ VALID" if i.is_valid else "❌ ISSUES FOUND"
            lines.extend([
                f"Journal Integrity: {status}",
                f"  Total entries:    {i.total_entries}",
                f"  Verified:         {i.verified_entries}",
                f"  Tampered:         {i.tampered_entries}",
                f"  Timestamp gaps:   {i.timestamp_gaps}",
                f"  First entry:      {i.first_entry}",
                f"  Last entry:       {i.last_entry}",
                "",
            ])
            for label, stream in (("Trigger receipts", i.trigger_receipts),
                                 ("Trigger queue", i.trigger_queue)):
                if stream:
                    stream_status = "VALID" if stream.is_valid else "ISSUES FOUND"
                    lines.extend([
                        f"{label}: {stream_status}",
                        f"  Records:          {stream.total_records}",
                        f"  Verified:         {stream.verified_records}",
                        f"  Tampered:         {stream.tampered_records}",
                        "",
                    ])
            if i.errors:
                for e in i.errors:
                    lines.append(f"  [!] {e}")
                lines.append("")

        lines.append("-" * 72)
        lines.append("")

        if report.orphans:
            lines.append(f"## ORPHANED FINDINGS ({len(report.orphans)})")
            lines.append("Findings with no supporting evidence in the ledger:")
            lines.append("")
            for o in report.orphans:
                lines.append(f"  [{o.severity.upper()}] {o.title}")
                lines.append(f"    Finding ID: {o.finding_id}")
                lines.append(f"    Endpoint: {o.endpoint}")
                lines.append(f"    Missing: {', '.join(o.missing_evidence)}")
                lines.append(f"    Confidence penalty: -{o.confidence_penalty:.0%}")
                if o.recommendation:
                    lines.append(f"    Fix: {o.recommendation}")
                lines.append("")
        else:
            lines.append("✅ All findings have supporting evidence in the ledger.")
            lines.append("")

        lines.append("-" * 72)
        lines.append("")

        if report.coverage_gaps:
            lines.append(f"## COVERAGE GAPS ({len(report.coverage_gaps)})")
            lines.append("")
            for g in report.coverage_gaps:
                lines.append(f"  [{g.severity.upper()}] {g.gap_type}: {g.identifier}")
                lines.append(f"    {g.description}")
                lines.append(f"    Recommended: run {g.recommended_agent}")
                lines.append("")

        lines.append("=" * 72)
        lines.append("  Generated by BugWolf Ledger Verifier v1.0.0")
        lines.append("=" * 72)

        return "\n".join(lines)

    # ---- Persistence ----

    def _save_report(self, report: LedgerReport):
        report_file = self._dir / "latest_report.json"
        data = asdict(report)
        # Convert objects
        data["coverage_gaps"] = [asdict(g) for g in report.coverage_gaps]
        data["orphans"] = [asdict(o) for o in report.orphans]
        if report.integrity:
            data["integrity"] = asdict(report.integrity)
        report_file.write_text(json.dumps(data, indent=2, default=str))

    def delete_all(self):
        for f in self._dir.glob("*"):
            f.unlink()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def verify_target(target: str) -> LedgerReport:
    """Quick verification for a target."""
    verifier = LedgerVerifier(target)
    return verifier.verify_all()


def verify_finding_evidence(target: str, finding: Dict) -> Tuple[bool, List[str]]:
    """Check if a single finding is backed by evidence."""
    verifier = LedgerVerifier(target)
    return verifier.verify_finding(finding)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf Ledger Verifier")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--verify", action="store_true",
                        help="Verify all findings against ledger")
    parser.add_argument("--verify-finding", help="Verify a single finding ID")
    parser.add_argument("--coverage-gaps", action="store_true",
                        help="Find coverage gaps")
    parser.add_argument("--integrity-check", action="store_true",
                        help="Check journal file integrity")
    parser.add_argument("--session-coverage", action="store_true",
                        help="Show per-session coverage")
    parser.add_argument("--report", action="store_true",
                        help="Generate full verification report")
    parser.add_argument("--output-format", default="text", choices=["text", "json"])
    args = parser.parse_args()

    verifier = LedgerVerifier(args.target)

    if args.integrity_check:
        integrity = verifier.check_integrity()
        if args.output_format == "json":
            print(json.dumps(asdict(integrity) if integrity else {}, indent=2))
        else:
            if not integrity:
                print("[!] No journal file found")
            else:
                status = "VALID" if integrity.is_valid else "COMPROMISED"
                print(f"[*] Journal integrity: {status}")
                print(f"    Entries: {integrity.total_entries}")
                print(f"    Verified: {integrity.verified_entries}")
                print(f"    Tampered: {integrity.tampered_entries}")
                print(f"    Timestamp gaps: {integrity.timestamp_gaps}")
                for label, stream in (("Trigger receipts", integrity.trigger_receipts),
                                      ("Trigger queue", integrity.trigger_queue)):
                    if stream:
                        stream_status = "VALID" if stream.is_valid else "COMPROMISED"
                        print(f"    {label}: {stream_status} "
                              f"({stream.verified_records}/{stream.total_records} verified)")
                if integrity.errors:
                    for e in integrity.errors:
                        print(f"    [!] {e}")

    elif args.verify_finding:
        findings = verifier._collect_findings()
        match = None
        for f in findings:
            if f.get("finding_id") == args.verify_finding:
                match = f
                break

        if not match:
            print(f"[!] Finding {args.verify_finding} not found")
            sys.exit(1)

        is_verified, missing = verifier.verify_finding(match)
        if is_verified:
            print(f"✅ Finding {args.verify_finding} is verified — all evidence present")
        else:
            print(f"❌ Finding {args.verify_finding} has missing evidence:")
            for m in missing:
                print(f"    Missing: {m}")

    elif args.coverage_gaps:
        findings = verifier._collect_findings()
        endpoints = verifier._collect_endpoint_entries()
        dead_ends = verifier._collect_dead_ends()
        gaps = verifier._find_coverage_gaps(findings, endpoints, dead_ends)

        if args.output_format == "json":
            print(json.dumps([asdict(g) for g in gaps], indent=2))
        else:
            print(f"[*] Coverage gaps: {len(gaps)}")
            for g in gaps:
                print(f"  [{g.severity.upper()}] {g.gap_type}: {g.identifier}")
                print(f"    {g.description}")

    elif args.session_coverage:
        coverage = verifier.get_session_coverage()
        if args.output_format == "json":
            print(json.dumps(coverage, indent=2))
        else:
            for sid, data in coverage.items():
                print(f"  Session: {sid}")
                print(f"    Findings: {data['findings']}")
                print(f"    Endpoints: {data['endpoints_tested']}")
                print(f"    Bug classes: {', '.join(data['bug_classes'])}")
                print()

    elif args.verify or args.report:
        report = verifier.verify_all()

        if args.output_format == "json":
            data = asdict(report)
            data["coverage_gaps"] = [asdict(g) for g in report.coverage_gaps]
            data["orphans"] = [asdict(o) for o in report.orphans]
            if report.integrity:
                data["integrity"] = asdict(report.integrity)
            print(json.dumps(data, indent=2, default=str))
        else:
            print(f"[*] Verification Score: {report.verification_score:.0%}")
            print(f"    Findings: {report.findings_total} total, "
                  f"{report.findings_verified} verified, "
                  f"{report.findings_orphaned} orphaned")
            print(f"    Endpoints tested: {report.endpoints_tested}")
            print(f"    Coverage gaps: {len(report.coverage_gaps)}")

            if report.orphans:
                print(f"\n[!] Orphaned findings:")
                for o in report.orphans:
                    print(f"    ❌ {o.title}")
                    print(f"       Missing: {', '.join(o.missing_evidence)}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
