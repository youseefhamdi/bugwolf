#!/usr/bin/env python3
"""BugWolf Technique Ledger v1.0.0.

Research finds new techniques faster than playbooks ship. The ledger is the
control point between "the internet says this works" and "an agent may try
it against a target":

    SUBMITTED → QUARANTINE → (operator approves) → ACTIVE → (expires) → EXPIRED

  * Every entry carries a SHA-256 content digest — what the operator
    approved is byte-identical to what an agent later receives (same
    tamper-guard as agent playbooks).
  * Approval is per-entry, human, and time-boxed (default 90 days);
    EXPIRED entries require re-approval — a technique can silently rot
    (patched, WAF rule added, program prohibits it).
  * Hunt agents receive ONLY ``active`` entries. Quarantine entries stay
    in the ledger for review; they never ride a dispatch payload.
  * Everything is a record, not a gate on deterministic work: an empty
    ledger degrades agents to their frozen playbooks, never blocks them.

Layout: ``state/intel/techniques.jsonl`` (append-only; latest entry per id
wins, like the lead ledger).

Usage:
    python3 -m tools.intel.technique_ledger --submit evidence.json \\
        --source medium --title "JWT jku bypass" --reference <url>
    python3 -m tools.intel.technique_ledger --list --json
    python3 -m tools.intel.technique_ledger --approve TL-0007
    python3 -m tools.intel.technique_ledger --reject TL-0008 --reason "out of program scope"
    python3 -m tools.intel.technique_ledger --active --json   # what agents may see
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import workspace_root

SCHEMA = "bugwolf-technique-ledger/v1"

STATUS_SUBMITTED = "SUBMITTED"
STATUS_QUARANTINE = "QUARANTINE"
STATUS_ACTIVE = "ACTIVE"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"
STATUSES = (STATUS_SUBMITTED, STATUS_QUARANTINE, STATUS_ACTIVE,
            STATUS_REJECTED, STATUS_EXPIRED)

DEFAULT_TTL_DAYS = 90


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


@dataclass
class Technique:
    technique_id: str
    title: str
    content: str                  # technique body (TTPs, payloads, refs)
    digest: str                   # sha256(content)[:16] — approval binds this
    source: str                   # medium | x-twitter | github | nvd | manual …
    reference: str = ""           # URL of the writeup / advisory / repo
    status: str = STATUS_QUARANTINE
    submitted_at: str = field(default_factory=_utc_now)
    approved_at: str = ""
    approved_by: str = ""         # operator label, never a token
    expires_at: str = ""          # ACTIVE entries re-approve after this
    rejected_reason: str = ""
    vuln_classes: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TechniqueLedger:
    def __init__(self, *, project_root: Optional[str] = None,
                 ttl_days: int = DEFAULT_TTL_DAYS) -> None:
        self.root = Path(project_root) if project_root else Path(workspace_root())
        self.ttl_days = max(1, int(ttl_days))

    def _path(self) -> Path:
        return self.root / "state" / "intel" / "techniques.jsonl"

    # -- persistence (append-only JSONL, latest wins) ------------------------

    def _append(self, tech: Technique) -> None:
        self._path().parent.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(tech.to_dict(), default=str) + "\n")

    def entries(self) -> Dict[str, Technique]:
        """Latest entry per technique id."""
        out: Dict[str, Technique] = {}
        path = self._path()
        if not path.is_file():
            return out
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                tech = Technique(
                    technique_id=str(raw.get("technique_id", "")),
                    title=str(raw.get("title", "")),
                    content=str(raw.get("content", "")),
                    digest=str(raw.get("digest", "")),
                    source=str(raw.get("source", "")),
                    reference=str(raw.get("reference", "")),
                    status=str(raw.get("status", STATUS_QUARANTINE)),
                    submitted_at=str(raw.get("submitted_at", "")),
                    approved_at=str(raw.get("approved_at", "")),
                    approved_by=str(raw.get("approved_by", "")),
                    expires_at=str(raw.get("expires_at", "")),
                    rejected_reason=str(raw.get("rejected_reason", "")),
                    vuln_classes=list(raw.get("vuln_classes") or []),
                    provenance=dict(raw.get("provenance") or {}),
                )
                out[tech.technique_id] = tech
        return out

    # -- lifecycle -------------------------------------------------------------

    def submit(self, *, title: str, content: str, source: str,
               reference: str = "", vuln_classes: Optional[List[str]] = None,
               provenance: Optional[Dict[str, Any]] = None) -> Technique:
        """SUBMITTED → QUARANTINE (agents never see quarantine entries)."""
        tech = Technique(
            technique_id=f"TL-{uuid.uuid4().hex[:6]}",
            title=title.strip()[:200], content=content,
            digest=content_digest(content), source=source,
            reference=reference, status=STATUS_QUARANTINE,
            vuln_classes=[v.strip().lower() for v in (vuln_classes or [])],
            provenance=provenance or {})
        self._append(tech)
        return tech

    def approve(self, technique_id: str, *, approved_by: str = "operator") -> Technique:
        current = self._require(technique_id)
        if current.status == STATUS_REJECTED:
            raise ValueError(f"{technique_id} is REJECTED; resubmit instead")
        # re-verify content integrity before approval takes effect
        if content_digest(current.content) != current.digest:
            raise ValueError(f"{technique_id} content digest mismatch")
        updated = Technique(**{**current.to_dict(),
                               "status": STATUS_ACTIVE,
                               "approved_at": _utc_now(),
                               "approved_by": approved_by[:80],
                               "expires_at": (datetime.now(timezone.utc)
                                              + timedelta(days=self.ttl_days)
                                              ).strftime("%Y-%m-%dT%H:%M:%SZ")})
        self._append(updated)
        return updated

    def reject(self, technique_id: str, *, reason: str = "") -> Technique:
        current = self._require(technique_id)
        updated = Technique(**{**current.to_dict(),
                               "status": STATUS_REJECTED,
                               "rejected_reason": reason[:300]})
        self._append(updated)
        return updated

    def _require(self, technique_id: str) -> Technique:
        tech = self.entries().get(technique_id)
        if tech is None:
            raise ValueError(f"unknown technique {technique_id!r}")
        return tech

    # -- consumption -------------------------------------------------------------

    def active(self, *, vuln_class: str = "",
               now: Optional[datetime] = None) -> List[Technique]:
        """ACTIVE, unexpired entries (optionally filtered by vuln class).

        Expired entries are reported as EXPIRED (lazy expiry view); the
        append-only file is rewritten only on explicit ``expire_sweep``.
        """
        now = now or datetime.now(timezone.utc)
        out: List[Technique] = []
        for tech in self.entries().values():
            if tech.status != STATUS_ACTIVE:
                continue
            if vuln_class and vuln_class.lower() not in tech.vuln_classes:
                continue
            if tech.expires_at:
                try:
                    exp = datetime.strptime(
                        tech.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                            tzinfo=timezone.utc)
                except ValueError:
                    continue
                if now >= exp:
                    continue  # lazy-expired: invisible to agents
            out.append(tech)
        out.sort(key=lambda t: t.technique_id)
        return out

    def expire_sweep(self) -> List[str]:
        """Persist EXPIRED status for anything past its approval window."""
        now = datetime.now(timezone.utc)
        expired: List[str] = []
        for tech in self.entries().values():
            if tech.status != STATUS_ACTIVE or not tech.expires_at:
                continue
            try:
                exp = datetime.strptime(
                    tech.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=timezone.utc)
            except ValueError:
                continue
            if now >= exp:
                self._append(Technique(**{**tech.to_dict(),
                                          "status": STATUS_EXPIRED}))
                expired.append(tech.technique_id)
        return expired

    def inventory(self) -> Dict[str, Any]:
        entries = self.entries()
        counts: Dict[str, int] = {}
        for t in entries.values():
            counts[t.status] = counts.get(t.status, 0) + 1
        return {"schema": SCHEMA, "total": len(entries),
                "by_status": counts,
                "active": [t.to_dict() for t in self.active()]}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description="BugWolf technique ledger (research quarantine)")
    ap.add_argument("--submit", metavar="FILE",
                    help="submit a technique file (content) for quarantine")
    ap.add_argument("--title", default="")
    ap.add_argument("--source", default="manual")
    ap.add_argument("--reference", default="")
    ap.add_argument("--classes", default="", help="comma-separated vuln classes")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--active", action="store_true")
    ap.add_argument("--approve", metavar="TL-ID")
    ap.add_argument("--reject", metavar="TL-ID")
    ap.add_argument("--reason", default="")
    ap.add_argument("--by", default="operator")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ledger = TechniqueLedger()
    if args.submit:
        content = Path(args.submit).read_text(encoding="utf-8")
        tech = ledger.submit(title=args.title or Path(args.submit).stem,
                             content=content, source=args.source,
                             reference=args.reference,
                             vuln_classes=[c for c in args.classes.split(",")
                                           if c])
        print(json.dumps({"submitted": tech.technique_id,
                          "status": tech.status,
                          "digest": tech.digest}, indent=2))
        return 0
    if args.approve:
        tech = ledger.approve(args.approve, approved_by=args.by)
        print(json.dumps({"approved": tech.technique_id,
                          "expires_at": tech.expires_at}, indent=2))
        return 0
    if args.reject:
        tech = ledger.reject(args.reject, reason=args.reason)
        print(json.dumps({"rejected": tech.technique_id}, indent=2))
        return 0
    if args.sweep:
        print(json.dumps({"expired": ledger.expire_sweep()}, indent=2))
        return 0
    if args.active:
        print(json.dumps({"active": [t.to_dict()
                                     for t in ledger.active()]}, indent=2))
        return 0
    if args.list:
        inv = ledger.inventory()
        print(json.dumps(inv, indent=2) if args.json else
              f"{inv['total']} techniques: {inv['by_status']}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
