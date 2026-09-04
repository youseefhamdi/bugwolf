#!/usr/bin/env python3
"""Capture→replay loop, import half (master plan Phase 2.4).

Loads a ``captures.jsonl`` produced by ``capture_addon.py``, validates the
schema fail-closed, filters every record through the operator scope gate
(**a capture file never widens scope** — records for out-of-scope hosts
are counted and skipped, not sent), and replays the survivors through the
governed raw-socket engine.  Each replay compares the fresh response to
the captured one: status/body drift between two byte-identical sends is a
behavioral lead (cache variance, session carry-over, nondeterministic
backend) — recorded as a FACT, never a verdict.

Artifacts (``mission/captures/`` by default):

    capture_replays.jsonl  one line per replayed capture
                           (sent bytes, status, drift, transport_error)
    capture_report.json    summary: counts, per-host split, drift + error
                           tallies, the scope skips (hosts + counts)

The operator's capture file is session evidence; it is NEVER modified.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = "bugwolf-capture/v1"          # the captures.jsonl file format
                                       # (matches capture_addon.SCHEMA)
REPLAY_SCHEMA = "bugwolf-capture-replay-record/v1"
REPORT_SCHEMA = "bugwolf-capture-replay-report/v1"

REQUIRED_FIELDS = ("schema", "id", "kind", "method", "path", "host",
                   "request_raw", "request_len")


@dataclass
class SkipRecord:
    """One capture line refused, with the reason.  Refusals are data."""
    line_no: int
    reason: str
    host: str = ""


@dataclass
class CaptureRecord:
    line_no: int
    capture_id: Any
    kind: str
    method: str
    path: str
    host: str
    request_raw: str
    request_len: int
    status: Optional[int]
    response_raw: str
    framing_notes: List[str]
    transport_error: Optional[str]


@dataclass
class LoadResult:
    schema_ok: int = 0
    skipped: int = 0
    out_of_scope: int = 0
    records: List[CaptureRecord] = field(default_factory=list)
    skips: List[SkipRecord] = field(default_factory=list)


@dataclass
class ReplayOutcome:
    """One replay's facts.  The captured response is the baseline; the
    fresh send is the experiment; drift is the observation."""
    line_no: int
    capture_id: Any
    host: str
    method: str
    path: str
    sent: str
    status: Optional[int] = None
    body_bytes: int = 0
    body_preview: str = ""
    captured_status: Optional[int] = None
    drift: Optional[Dict[str, Any]] = None
    transport_error: Optional[str] = None
    framing_notes: List[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "schema": REPLAY_SCHEMA,
            "line_no": self.line_no,
            "capture_id": self.capture_id,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "sent": self.sent[:2000],
            "status": self.status,
            "body_bytes": self.body_bytes,
            "body_preview": self.body_preview[:400],
            "captured_status": self.captured_status,
            "drift": self.drift,
            "transport_error": self.transport_error,
            "framing_notes": list(self.framing_notes),
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


# ---------------------------------------------------------------------------
# Load + validate (fail-closed: a line either validates fully or is skipped
# with a reason; nothing half-parsed ever reaches the sender).
# ---------------------------------------------------------------------------

def load_captures(path: str, *, scope_hosts: Optional[set] = None
                  ) -> LoadResult:
    """Parse + validate captures.jsonl.  ``scope_hosts`` (normalized host
    suffixes from the bound gate) filters records INTO the replay set;
    records outside are counted in ``out_of_scope`` — never sent."""
    result = LoadResult()
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"captures file not found: {path}")
    for line_no, raw_line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            result.skipped += 1
            result.skips.append(SkipRecord(line_no, f"invalid JSON: {exc}"))
            continue
        if not isinstance(obj, dict) or obj.get("schema") != SCHEMA:
            result.skipped += 1
            result.skips.append(
                SkipRecord(line_no,
                           f"schema mismatch (want {SCHEMA})"))
            continue
        missing = [k for k in REQUIRED_FIELDS
                   if k not in obj or obj.get(k) in ("", None)
                   and k != "request_len"]
        if missing:
            result.skipped += 1
            result.skips.append(SkipRecord(
                line_no, f"missing fields: {', '.join(missing)}"))
            continue
        if scope_hosts is not None:
            host = str(obj.get("host") or "").lower()
            if not _host_in_scope(host, scope_hosts):
                result.out_of_scope += 1
                result.skips.append(SkipRecord(
                    line_no, "host out of scope", host=host))
                continue
        result.schema_ok += 1
        result.records.append(CaptureRecord(
            line_no=line_no,
            capture_id=obj.get("id"),
            kind=str(obj.get("kind") or "request-response"),
            method=str(obj.get("method") or "GET"),
            path=str(obj.get("path") or "/"),
            host=str(obj.get("host") or "").lower(),
            request_raw=str(obj.get("request_raw") or ""),
            request_len=int(obj.get("request_len") or 0),
            status=obj.get("status") if isinstance(obj.get("status"), int)
            else None,
            response_raw=str(obj.get("response_raw") or ""),
            framing_notes=[str(n) for n in (obj.get("framing_notes") or [])],
            transport_error=(str(obj.get("transport_error"))
                             if obj.get("transport_error") else None),
        ))
    return result


def _host_in_scope(host: str, scope_hosts: set) -> bool:
    """Suffix semantics matching the scope gate: exact or subdomain.
    Port-tolerant: captures record ``host:port`` for non-default ports,
    while the gate binds the bare hostname — and sends always go to the
    BOUND target, so the port here is a filter key, never a destination."""
    host = (host or "").lower()
    if host.count(":") == 1:               # host:port (not IPv6 literal)
        host = host.rsplit(":", 1)[0]
    if not host:
        return False
    for entry in scope_hosts:
        entry = str(entry).lower().rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def _normalize_host(value: str) -> str:
    """URL or host[:port] -> bare hostname (the scope-gate form)."""
    value = (value or "").strip()
    if "://" not in value:
        value = "//" + value
    try:
        from urllib.parse import urlparse
        return (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def replay_captures(records: Iterable[CaptureRecord], *, target: str,
                    artifacts_dir: str = "mission/captures",
                    rate_rps: float = 5.0, budget: int = 5000,
                    markers: Optional[List[str]] = None
                    ) -> Dict[str, Any]:
    """Replay validated records through the governed engine.

    Scope: the gate is bound to the mission target BEFORE any send.  A
    record whose host is neither the target nor an allowed suffix is
    skipped with a recorded fact — the capture file only ever NARROWS
    what is sent, never widens it.
    """
    from tools.runtime import scope as scope_mod
    from tools.runtime.replay.engine import replay_raw
    from tools.runtime.replay.governor import Governor

    scope_mod.GATE.bind(target, force=True)
    target_host = scope_mod.GATE.target          # bare hostname: scope key
    send_host = target                           # host[:port]: send destination
    display_host = send_host.split("://", 1)[-1]  # scheme-free for artifacts
    scope_hosts = {target_host} | {h for h in scope_mod.GATE.extra_hosts}

    out_dir = Path(artifacts_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    replays_path = out_dir / "capture_replays.jsonl"
    report_path = out_dir / "capture_report.json"

    governor = Governor(rate_rps=rate_rps, budget=budget)
    outcomes: List[ReplayOutcome] = []
    started = time.time()

    for rec in records:
        if not _host_in_scope(rec.host, scope_hosts):
            outcomes.append(ReplayOutcome(
                line_no=rec.line_no, capture_id=rec.capture_id,
                host=rec.host, method=rec.method, path=rec.path,
                sent="", skipped=True,
                skip_reason="host out of scope (not sent)"))
            continue
        if rec.kind != "request-response":
            # A capture without a captured response still replays, but the
            # drift baseline is absent — recorded as such.
            pass
        wire = rec.request_raw.encode("latin-1")
        report = replay_raw(wire, host=send_host,
                            markers=markers or [], governor=governor)
        drift = _drift(rec, report)
        outcomes.append(ReplayOutcome(
            line_no=rec.line_no, capture_id=rec.capture_id,
            host=display_host, method=rec.method, path=rec.path,
            sent=report.sent_bytes,
            status=report.status,
            body_bytes=report.body_bytes,
            body_preview=report.body_preview,
            captured_status=rec.status,
            drift=drift,
            transport_error=report.transport_error,
            framing_notes=list(rec.framing_notes),
        ))

    elapsed = time.time() - started
    summary = _summarize(outcomes, elapsed)
    # Durable artifacts: the replay journal (JSONL) + the summary report.
    with replays_path.open("w", encoding="utf-8") as fh:
        for outcome in outcomes:
            fh.write(json.dumps(outcome.to_dict(), sort_keys=True,
                                ensure_ascii=True) + "\n")
    report_path.write_text(json.dumps(summary, indent=2, sort_keys=True,
                                      ensure_ascii=True) + "\n",
                           encoding="utf-8")
    return summary


def _drift(rec: CaptureRecord, report: Any) -> Optional[Dict[str, Any]]:
    """Status/body drift between the captured and the fresh response.
    Facts only: which fields moved, not what that means."""
    if rec.status is None:
        return None
    fresh_status = report.status
    captured_body_len = _captured_body_len(rec.response_raw)
    drift: Dict[str, Any] = {}
    if fresh_status is not None and fresh_status != rec.status:
        drift["status"] = {"captured": rec.status, "replayed": fresh_status}
    if captured_body_len is not None and report.body_bytes != captured_body_len:
        drift["body_len"] = {"captured": captured_body_len,
                             "replayed": report.body_bytes}
    return drift or None


def _captured_body_len(response_raw: str) -> Optional[int]:
    _, _, body = response_raw.partition("\r\n\r\n")
    return len(body.encode("latin-1")) if body else (0 if response_raw else None)


def _summarize(outcomes: List[ReplayOutcome], elapsed: float) -> Dict[str, Any]:
    sent = [o for o in outcomes if not o.skipped]
    hosts: Dict[str, int] = {}
    for o in sent:
        hosts[o.host] = hosts.get(o.host, 0) + 1
    drift_count = sum(1 for o in sent if o.drift)
    error_count = sum(1 for o in sent if o.transport_error)
    skip_count = sum(1 for o in outcomes if o.skipped)
    statuses: Dict[str, int] = {}
    for o in sent:
        key = str(o.status)
        statuses[key] = statuses.get(key, 0) + 1
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_s": round(elapsed, 2),
        "replayed": len(sent),
        "skipped_out_of_scope": skip_count,
        "drift_count": drift_count,
        "transport_error_count": error_count,
        "statuses": statuses,
        "hosts": hosts,
        "outcomes_file": "capture_replays.jsonl",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="bugwolf-capture-replay",
        description="Replay a captures.jsonl through the governed "
                    "raw-socket engine (scope-gated; drift = facts).")
    parser.add_argument("captures", help="captures.jsonl from the addon")
    parser.add_argument("--target", required=True,
                        help="mission target (binds the scope gate)")
    parser.add_argument("--artifacts-dir", default="mission/captures")
    parser.add_argument("--rate", type=float, default=5.0)
    parser.add_argument("--budget", type=int, default=5000)
    parser.add_argument("--marker", action="append", default=[],
                        help="reflection marker to watch (repeatable)")
    args = parser.parse_args(argv)

    result = load_captures(args.captures)
    in_scope = [r for r in result.records
                if _host_in_scope(r.host, {_normalize_host(args.target)})]
    print(f"captures: {result.schema_ok} valid, {result.skipped} skipped, "
          f"{result.out_of_scope} out-of-scope")
    summary = replay_captures(in_scope, target=args.target,
                              artifacts_dir=args.artifacts_dir,
                              rate_rps=args.rate, budget=args.budget,
                              markers=args.marker or None)
    print(f"replayed: {summary['replayed']} "
          f"(drift {summary['drift_count']}, "
          f"transport errors {summary['transport_error_count']})")
    print(f"artifacts: {args.artifacts_dir}/capture_replays.jsonl, "
          f"capture_report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
