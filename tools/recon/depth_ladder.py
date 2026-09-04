#!/usr/bin/env python3
"""BugWolf Recon Depth Ladder - the anti-satisficing layer for recon.

Mirrors ``tools/runtime/lead_protocol.py`` for the recon lane: LLM recon
agents try the most plausible enumeration once, get a partial map, and move
on.  This module makes "stopped too shallow" structurally impossible:

  * **D0 passive**         - historical (wayback/CT/passive-DNS), code-search,
                             package-registry and social scans.  Zero target
                             contact.  Techniques: ``hist-churn``,
                             ``ct-log-mining``, ``code-search``, ``pkg-registry``,
                             ``social-fingerprint``.
  * **D1 resolvable**      - enumerate + resolve every asset; probe the
                             canonical ports census (non-standard ports carry
                             the shadow surface).  Techniques: ``resolve-all``,
                             ``port-census``, ``wildcard-baseline``,
                             ``asn-neighborhood``.
  * **D2 http-surface**    - HTTP surface census of every live host:
                             well-known paths, admin/panel ladder, API doc
                             exposure, JS bundle mining, header fingerprint.
                             Techniques: ``wellknown-census``,
                             ``admin-ladder``, ``api-docs``, ``js-mining``,
                             ``header-fingerprint``.
  * **D3 deep-surface**    - the pass shallow recon skips: parameter-surface
                             census, JS route/API-map extraction from bundle
                             source, cloud-bucket permutation census, mobile
                             endpoint harvesting, historical-churn cross-ref.
                             Techniques: ``param-surface``, ``js-route-map``,
                             ``cloud-buckets``, ``mobile-endpoints``,
                             ``historical-crossref``.

Depth discipline (mirrors lead-protocol R2/R3):

  * A recon dispatch closes ``DONE`` only when its depth slice is covered
    or every shortfall is honestly recorded (``recon_close_blockers``).
  * Deep techniques (D3) may be waived by recorded finding-density, never
    silently: a waiver is an explicit ledger event, not an omission.
  * Everything is append-only JSONL (lever P5) so stop/resume loses
    nothing, and the ledger is rehydratable.

Design discipline (per DEPENDENCIES.md leaf rules): stdlib only, fully
offline (NEVER contacts the target -- it tracks what was done), imports
only ``tools.runtime_paths``.

Usage:
    from tools.recon.depth_ladder import ReconDepthLedger
    ledger = ReconDepthLedger(mission_id).load()
    ledger.record("D1", "resolve-all", outcome="done", detail="412 hosts")
    blockers = ledger.close_blockers(slice_ids=["D0", "D1", "D2", "D3"])
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import workspace_root

SCHEMA = "bugwolf-recon-depth/v1"

# Depth levels (canonical order).  D0 makes zero target contact; D3 is the
# deep surface pass shallow recon always skips.
D0, D1, D2, D3 = "D0", "D1", "D2", "D3"
DEPTHS = (D0, D1, D2, D3)

# Canonical technique families per depth (R3-equivalent).  Extensions ride
# the ledger as research-derived entries and join the required set.
DEPTH_TECHNIQUES: Dict[str, tuple] = {
    D0: ("hist-churn", "ct-log-mining", "code-search", "pkg-registry",
         "social-fingerprint"),
    D1: ("resolve-all", "port-census", "wildcard-baseline",
         "asn-neighborhood"),
    D2: ("wellknown-census", "admin-ladder", "api-docs", "js-mining",
         "header-fingerprint"),
    D3: ("param-surface", "js-route-map", "cloud-buckets",
         "mobile-endpoints", "historical-crossref"),
}

# D3 techniques waivable on recorded low finding-density (never silently).
WAIVABLE = frozenset(DEPTH_TECHNIQUES[D3])

# Finding evidence -> specialist bug class (registry vocabulary).  The
# recomposition hook cross-references these automatically: a recorded
# census detail that matches a rule staffs the matching specialist.
# Evidence-based by design: only detail/asset text that names concrete
# surface (a bucket hostname, a WAF signature, a secret pattern) produces
# a recommendation -- a census that ran clean recommends nothing, so
# noise can never staff specialists.
SIGNAL_RULES: tuple = (
    {"technique": r"cloud-buckets",
     "pattern": r"(s3\.amazonaws\.com|storage\.googleapis\.com"
                r"|blob\.core\.windows\.net|\bbucket\b)",
     "bug_class": "s3_misconfig",
     "label": "cloud bucket surface found"},
    {"technique": r"mobile-endpoints",
     "pattern": r"(deep.?link|\bmobile\b|/api/)",
     "bug_class": "shadow_api",
     "label": "mobile API surface found"},
    {"technique": r"(header-fingerprint|admin-ladder|wellknown-census)",
     "pattern": r"(\bwaf\b|cloudflare|akamai|sucuri|imperva|incapsula"
                r"|barracuda|modsecurity|\bf5\b|fastly)",
     "bug_class": "waf_bypass",
     "label": "WAF/CDN shield in front of surface"},
    {"technique": r"js-mining",
     "pattern": r"(api[_-]?key|access[_-]?token|\bsecret\b"
                r"|\bpassword\b|aws_|bearer\s+)",
     "bug_class": "js_secrets",
     "label": "secrets exposed in JS bundles"},
)

OUTCOMES = ("done", "partial", "blocked", "waived", "empty")
TERMINAL_OUTCOMES = ("done", "waived", "empty")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class ReconDepthLedger:
    """Durable per-mission recon-depth journal (append-only per lever P5)."""

    def __init__(self, mission_id: str, *,
                 project_root: Optional[str] = None) -> None:
        self.mission_id = mission_id
        self._journal = (Path(workspace_root(project_root)) / "state"
                         / "orchestrator" / "recon-depth"
                         / f"{mission_id}.jsonl")
        self._events: List[Dict[str, Any]] = []

    # -- persistence ---------------------------------------------------------

    def journal_path(self) -> Path:
        return self._journal

    def load(self) -> "ReconDepthLedger":
        """Rehydrate events from the journal (stop/resume, torn-tail safe)."""
        self._events = []
        if self._journal.is_file():
            for line in self._journal.read_text(
                    encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self._events.append(json.loads(line))
                except ValueError:
                    continue  # torn tail write: skip
        return self

    def _append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event = {"schema": SCHEMA, "mission_id": self.mission_id,
                 "ts": _now_iso(), **event}
        self._journal.parent.mkdir(parents=True, exist_ok=True)
        with self._journal.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        self._events.append(event)
        return event

    # -- recording ------------------------------------------------------------

    def record(self, depth: str, technique: str, *, outcome: str = "done",
               asset: str = "", detail: str = "",
               operator_note: str = "") -> Dict[str, Any]:
        """Record one technique attempt (the only way depth becomes durable)."""
        if outcome not in OUTCOMES:
            raise ValueError(
                f"outcome must be one of {OUTCOMES}, got {outcome!r}")
        depth = str(depth or "").strip().upper()
        if depth not in DEPTHS:
            raise ValueError(f"depth must be one of {DEPTHS}, got {depth!r}")
        return self._append({
            "event": "technique", "depth": depth,
            "technique": str(technique or "").strip().lower(),
            "outcome": outcome, "asset": str(asset or "")[:300],
            "detail": str(detail or "")[:500],
            "operator_note": str(operator_note or "")[:500],
        })

    def waive(self, technique: str, *, reason: str = "") -> Dict[str, Any]:
        """Record an explicit waiver (deep technique skipped by policy).

        A waiver is a ledger event with an operator-visible reason -- the
        anti-satisficing equivalent of lead-protocol's honest terminals:
        the technique is *consciously* not run, never silently dropped.
        """
        return self._append({
            "event": "waiver", "technique": str(technique or "").strip().lower(),
            "reason": str(reason or "")[:500],
        })

    def close(self, depth_level: str, *, note: str = "") -> Dict[str, Any]:
        """Record an operator/agent depth-close declaration."""
        depth_level = str(depth_level or "").strip().upper()
        if depth_level not in DEPTHS:
            raise ValueError(
                f"depth must be one of {DEPTHS}, got {depth_level!r}")
        return self._append({"event": "close", "depth": depth_level,
                             "note": str(note or "")[:500]})

    # -- coverage ---------------------------------------------------------------

    def _attempts(self) -> List[Dict[str, Any]]:
        return [e for e in self._events if e.get("event") == "technique"]

    def _waived(self) -> List[str]:
        return [str(e.get("technique") or "")
                for e in self._events if e.get("event") == "waiver"]

    def record_outcome(self, technique: str) -> str:
        """Best recorded outcome for a technique (last attempt wins)."""
        outcome = ""
        for e in self._attempts():
            if str(e.get("technique")) == str(technique).strip().lower():
                outcome = str(e.get("outcome") or "")
        return outcome

    def untried(self, slice_ids: Optional[List[str]] = None) -> List[str]:
        """Techniques in the depth slice with no terminal attempt yet.

        Research/waiver-derived entries join the required set: a technique
        named by a waiver request is NOT tried just because it was named.
        """
        wanted: List[str] = []
        for depth in DEPTHS:
            if slice_ids and depth not in slice_ids:
                continue
            wanted.extend(DEPTH_TECHNIQUES[depth])
        waived = set(self._waived())
        out = []
        for tech in wanted:
            if tech in waived:
                continue
            if self.record_outcome(tech) not in TERMINAL_OUTCOMES:
                out.append(tech)
        return out

    def recommendations(self) -> List[Dict[str, str]]:
        """Cross-reference recorded census evidence into agent hints.

        Applies ``SIGNAL_RULES`` to every recorded technique attempt:
        detail/asset text naming concrete surface (a bucket hostname, a
        WAF signature, a secret pattern in a bundle) yields one
        ``{bug_class, reason}`` pair per matching rule.  A census that
        ran clean recommends nothing -- recommendations are
        evidence-based, never inferred from silence.
        """
        out: List[Dict[str, str]] = []
        seen: set = set()
        for e in self._attempts():
            if str(e.get("outcome")) in ("blocked",):
                continue   # a blocked census produced no evidence
            text = " ".join((str(e.get("detail") or ""),
                              str(e.get("asset") or ""))).lower()
            if not text.strip():
                continue
            tech = str(e.get("technique") or "")
            for rule in SIGNAL_RULES:
                if not re.fullmatch(str(rule["technique"]), tech):
                    continue
                if not re.search(str(rule["pattern"]), text, re.I):
                    continue
                key = (tech, rule["bug_class"])
                if key in seen:
                    continue
                seen.add(key)
                out.append({"bug_class": rule["bug_class"],
                            "reason": f"recon D-evidence: {rule['label']} "
                                      f"({tech})"})
        return out

    def close_blockers(self, slice_ids: Optional[List[str]] = None) -> List[str]:
        """Why this recon dispatch cannot honestly close yet (may be empty)."""
        blockers: List[str] = []
        untried = self.untried(slice_ids)
        if untried:
            blockers.append(f"untried depth techniques remain: "
                            f"{untried[:6]}")
        closes = [str(e.get("depth")) for e in self._events
                  if e.get("event") == "close"]
        for depth in (slice_ids or []):
            if depth in DEPTHS and depth not in closes:
                blockers.append(f"{depth} not closed")
        return blockers

    def coverage(self, slice_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Operator-visible per-depth coverage summary (never raises)."""
        waived = set(self._waived())
        by_depth: Dict[str, Dict[str, Any]] = {}
        for depth in DEPTHS:
            if slice_ids and depth not in slice_ids:
                continue
            techs = DEPTH_TECHNIQUES[depth]
            done = [t for t in techs
                    if self.record_outcome(t) in TERMINAL_OUTCOMES]
            by_depth[depth] = {
                "techniques": list(techs),
                "covered": done,
                "waived": [t for t in techs if t in waived],
                "untried": [t for t in techs
                            if t not in done and t not in waived],
            }
        return {
            "schema": SCHEMA,
            "mission_id": self.mission_id,
            "events": len(self._events),
            "close_blockers": self.close_blockers(slice_ids),
            "depths": by_depth,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf recon depth ledger (D0-D3 anti-satisficing)")
    parser.add_argument("--mission-id", required=True)
    parser.add_argument("--record", nargs="+",
                        metavar="DEPTH TECHNIQUE OUTCOME [DETAIL...]",
                        default=[], action="append",
                        help="record a technique attempt (repeatable); "
                             "trailing words after OUTCOME become the "
                             "evidence detail text")
    parser.add_argument("--waive", nargs=2, metavar=("TECHNIQUE", "REASON"),
                        default=[], action="append")
    parser.add_argument("--close", metavar="DEPTH", default="")
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--recommendations", action="store_true",
                        help="cross-reference recorded census evidence "
                             "into specialist recommendations")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    ledger = ReconDepthLedger(args.mission_id).load()
    for rec in args.record or []:
        depth, tech, outcome = rec[0], rec[1], rec[2]
        detail = " ".join(rec[3:]) if len(rec) > 3 else ""
        ledger.record(depth, tech, outcome=outcome, detail=detail)
    for tech, reason in args.waive or []:
        ledger.waive(tech, reason=reason)
    if args.close:
        ledger.close(args.close)
    if args.coverage or args.json or args.recommendations:
        report = ledger.coverage()
        if args.recommendations:
            report["recommendations"] = ledger.recommendations()
        print(json.dumps(report, indent=2, default=str))
    elif not (args.record or args.waive or args.close):
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
