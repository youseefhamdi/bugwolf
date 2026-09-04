#!/usr/bin/env python3
"""Post-mission instinct distillation (INTEGRATION_PLAN Phase A, v1.24).

BugWolf records every hunt fact — technique outcomes in the lead journal,
reporting refusals, U-regression failures, benchmark FP/FN, governor
refusals — but until now nothing distilled them.  This module mines those
existing ledgers into *instincts*: durable, provenance-carrying facts about
past hunts that future missions consume as PRIOR WEIGHTING, never verdicts.

Architecture note (ECC continuous-learning-v2, MIT, attributed): ECC proves
the observe→distill→inject loop works.  We deliberately do NOT copy its
per-event bash observation — our ledgers already capture the same events in
structured JSONL, so distillation is deterministic post-hoc mining over
state that already exists.  The instinct schema follows ECC's
``id/trigger/confidence/domain/source`` contract, extended with bugwolf
fields (``kind``, ``evidence``, ``occurrences``, ``ttl_days``).

Storage contract (``state/instincts/instincts.jsonl``, one JSON per line):

    {
      "schema": "bugwolf-instinct/v1",
      "id": "technique:voucher-double-redeem:<proj8>",
      "kind": "technique",          # technique | noise | model | signal | transport
      "scope": "project",           # project | global (global = operator-curated)
      "trigger": {"technique": "...", "bug_class": "..."},
      "statement": "...",           # human-readable fact
      "action": "...",              # what consumers should do with it
      "evidence": [{"mission": ..., "lead": ..., "outcome": ..., "at": ...}],
      "confidence": 0.6,            # min(0.9, 0.5 + 0.1*occurrences), halved on contradiction
      "occurrences": 2,
      "active": true,               # occurrences >= ACTIVE_THRESHOLD
      "created_at": ..., "updated_at": ...,
      "ttl_days": 90
    }

Rules enforced in code + tests:
  * A candidate is *stored* from one occurrence (the ledger stays complete)
    but is ``active`` (injected anywhere) only at >= 2 occurrences — one
    failure is a fact, two is a pattern.
  * Contradicting evidence (e.g. a success after failure-instinct) HALVES
    confidence instead of deleting the pattern.
  * Instincts are facts with provenance: every one carries its evidence
    mission/lead ids.  Project-scope only, ever, from mining; ``global``
    scope is written only by an explicit operator promote.
  * Consumers treat instincts as prior weighting only — nothing here can
    override the deterministic gate, the scope gate, or the governor.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "bugwolf-instinct/v1"

KINDS = ("technique", "noise", "model", "signal", "transport")

ACTIVE_THRESHOLD = 2          # occurrences before an instinct is injected
MAX_CONFIDENCE = 0.9
BASE_CONFIDENCE = 0.5
CONFIDENCE_STEP = 0.1
DEFAULT_TTL_DAYS = 90

STORE_REL = ("state", "instincts", "instincts.jsonl")
GLOBAL_REL = ("state", "instincts", "global.jsonl")

# Technique outcomes that mean "attempted, did not win".  "signal" opens a
# lead but is explicitly NOT a success (the runner's own comment: not a
# success until an independent replay wins); "error" is transport failure.
_UNWON_OUTCOMES = ("tried", "signal", "error", "refuted")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _workspace_root(project_root: Optional[str]) -> Path:
    from tools.runtime_paths import workspace_root
    return workspace_root(project_root)


def _project_hash(project_root: Optional[str]) -> str:
    """Stable short project discriminator (instinct ids stay per-project)."""
    try:
        seed = str(Path(project_root).resolve()) if project_root else \
            str(Path.cwd().resolve())
    except OSError:
        seed = str(project_root or "cwd")
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]


def _load_jsonl(path: Path, *, cap: int = 5000) -> List[Dict[str, Any]]:
    """Fail-open JSONL reader: torn/garbage lines are skipped, not raised."""
    if not path.is_file():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
            if len(out) >= cap:
                break
    return out


def _instinct_id(kind: str, shape: str, project_root: Optional[str]) -> str:
    return f"{kind}:{shape}:{_project_hash(project_root)}"


# ---------------------------------------------------------------------------
# Miners — one per source ledger.  Each yields candidate dicts; the distiller
# merges them into the store.  Every miner is fail-open: a missing or
# malformed ledger contributes zero candidates, never an exception.
# ---------------------------------------------------------------------------

def _journal_leads(journal_dir: Path) -> List[Dict[str, Any]]:
    """Final state of every lead across the mission journals.

    Journals are append-only FULL snapshots (``LeadStore._append`` writes
    the whole lead each time; ``load()`` is last-write-wins).  Counting
    every line would multi-count each technique, so this collapses to the
    last snapshot per lead_id first.
    """
    latest: Dict[str, Dict[str, Any]] = {}
    for journal in sorted(journal_dir.glob("*.jsonl")):
        for lead in _load_jsonl(journal):
            if isinstance(lead, dict) and lead.get("lead_id"):
                latest[str(lead["lead_id"])] = lead
    return list(latest.values())


def mine_techniques(project_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lead journals -> ``technique`` candidates (unwon technique x class)."""
    from tools.runtime.lead_protocol import leads_dir

    journal_dir = leads_dir(project_root=project_root)
    if not journal_dir.is_dir():
        return []
    buckets: Dict[tuple, Dict[str, Any]] = {}
    for lead in _journal_leads(journal_dir):
        bug_class = str(lead.get("bug_class") or "generic")
        for entry in lead.get("technique_log") or []:
            if not isinstance(entry, dict):
                continue
            technique = str(entry.get("technique") or "").strip()
            outcome = str(entry.get("outcome") or "").strip()
            if not technique or outcome not in _UNWON_OUTCOMES:
                continue
            key = (technique, bug_class)
            bucket = buckets.setdefault(key, {
                "count": 0, "evidence": [],
            })
            bucket["count"] += 1
            if len(bucket["evidence"]) < 10:
                bucket["evidence"].append({
                    "mission": "",
                    "lead": str(lead.get("lead_id") or ""),
                    "outcome": outcome,
                    "at": str(entry.get("ts") or ""),
                })
    candidates = []
    for (technique, bug_class), bucket in sorted(buckets.items()):
        shape = f"{technique}:{bug_class}"
        candidates.append({
            "kind": "technique",
            "shape": shape,
            "trigger": {"technique": technique, "bug_class": bug_class},
            "statement": (f"technique {technique!r} on bug_class "
                          f"{bug_class!r} ended un-won {bucket['count']}x "
                          "across missions"),
            "action": ("order this technique LAST in untried ordering for "
                       "the class; require a scope match before reuse"),
            "occurrences": bucket["count"],
            "evidence": bucket["evidence"],
        })
    return candidates


def mine_reporting(project_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Reporting refusals/rejections -> ``noise`` candidates.

    Shape = the missing evidence field (or the rejection itself); these feed
    the ReportingGate's advisory section, never auto-deletion.
    """
    root = _workspace_root(project_root)
    buckets: Dict[str, Dict[str, Any]] = {}
    for path in sorted(root.glob("state/**/reports.jsonl")):
        for record in _load_jsonl(path):
            if not isinstance(record, dict):
                continue
            decision = str(record.get("review_decision") or "")
            reasons = record.get("refusal_reasons") or []
            if decision != "rejected" and not reasons:
                continue
            fields = sorted({
                str(r).split(":")[-1].strip()
                for r in reasons if "missing required evidence field" in str(r)
            }) or ["review-rejected"]
            for field in fields[:4]:
                bucket = buckets.setdefault(field, {"count": 0, "evidence": []})
                bucket["count"] += 1
                if len(bucket["evidence"]) < 10:
                    bucket["evidence"].append({
                        "mission": "",
                        "lead": str(record.get("finding_id") or "")[:24],
                        "outcome": decision or "refused",
                        "at": str(record.get("created_at") or ""),
                    })
    candidates = []
    for field, bucket in sorted(buckets.items()):
        shape = f"evidence:{field}"
        candidates.append({
            "kind": "noise",
            "shape": shape,
            "trigger": {"field": field},
            "statement": (f"findings missing {field!r} evidence were "
                          f"refused/rejected {bucket['count']}x"),
            "action": "surface as advisory refusal context in the gate",
            "occurrences": bucket["count"],
            "evidence": bucket["evidence"],
        })
    return candidates


def mine_model(project_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """U-regression failures -> ``model`` candidates (stage-shape)."""
    path = _workspace_root(project_root) / "state" / "benchmark" / \
        "u_regression.json"
    if not path.is_file():
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    buckets: Dict[tuple, Dict[str, Any]] = {}
    for check in report.get("checks") or []:
        if not isinstance(check, dict) or check.get("ok"):
            continue
        case_id = str(check.get("case_id") or "")
        stages = [str(s) for s in (check.get("u_stages") or [])]
        for failure in check.get("failures") or []:
            text = str(failure)
            stage = next((s for s in stages if s in text), None)
            if stage is None:
                for s in ("U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8",
                          "U9"):
                    if s in text:
                        stage = s
                        break
            key = (stage or "pipeline", case_id or "unknown")
            bucket = buckets.setdefault(key, {"count": 0, "evidence": []})
            bucket["count"] += 1
            if len(bucket["evidence"]) < 10:
                bucket["evidence"].append({
                    "mission": "u-regression", "lead": case_id,
                    "outcome": text[:120], "at": str(report.get(
                        "generated_at") or ""),
                })
    candidates = []
    for (stage, case_id), bucket in sorted(buckets.items()):
        shape = f"{stage}:{case_id}"
        candidates.append({
            "kind": "model",
            "shape": shape,
            "trigger": {"stage": stage, "case_id": case_id},
            "statement": (f"U-regression failed stage {stage} for case "
                          f"{case_id!r} {bucket['count']}x"),
            "action": ("check the declared U-stage support before trusting "
                       "the model for this class"),
            "occurrences": bucket["count"],
            "evidence": bucket["evidence"],
        })
    return candidates


def mine_signal(project_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Benchmark FP/FN -> ``signal`` candidates (detector reliability)."""
    path = _workspace_root(project_root) / "state" / "benchmark" / "latest.json"
    if not path.is_file():
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    buckets: Dict[tuple, Dict[str, Any]] = {}
    for result in report.get("results") or []:
        if not isinstance(result, dict):
            continue
        expected = bool(result.get("expected_finding"))
        fired = bool(result.get("signal"))
        bug_class = str(result.get("bug_class") or "")
        if fired == expected:
            continue  # TP/TN: the detector agreed; no instinct
        shape_kind = "false-positive" if (fired and not expected) \
            else "false-negative"
        key = (shape_kind, bug_class)
        bucket = buckets.setdefault(key, {"count": 0, "evidence": []})
        bucket["count"] += 1
        if len(bucket["evidence"]) < 10:
            bucket["evidence"].append({
                "mission": "benchmark",
                "lead": str(result.get("case_id") or ""),
                "outcome": shape_kind,
                "at": str(report.get("generated_at") or ""),
            })
    candidates = []
    for (shape_kind, bug_class), bucket in sorted(buckets.items()):
        shape = f"{shape_kind}:{bug_class}"
        candidates.append({
            "kind": "signal",
            "shape": shape,
            "trigger": {"bug_class": bug_class, "reliability": shape_kind},
            "statement": (f"detector for {bug_class!r} produced a "
                          f"{shape_kind} {bucket['count']}x in benchmark runs"),
            "action": ("weight the class accordingly; verify with the "
                       "independent replay before PWNED"),
            "occurrences": bucket["count"],
            "evidence": bucket["evidence"],
        })
    return candidates


def mine_transport(project_root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Status-0 / governor-refusal evidence -> ``transport`` candidates."""
    root = _workspace_root(project_root)
    buckets: Dict[str, Dict[str, Any]] = {}
    for path in sorted(root.glob("state/orchestrator/*/evidence.jsonl")):
        mission = path.parent.name
        for record in _load_jsonl(path):
            if not isinstance(record, dict):
                continue
            status = record.get("status")
            raw = str(record.get("raw") or "")[:2000]
            refused = status == 0 or "BackendRefused" in raw or \
                "rate limit" in raw
            if not refused:
                continue
            key = "governor-refusal"
            bucket = buckets.setdefault(key, {"count": 0, "evidence": []})
            bucket["count"] += 1
            if len(bucket["evidence"]) < 10:
                bucket["evidence"].append({
                    "mission": mission, "lead": "", "outcome": "refused",
                    "at": str(record.get("ts") or ""),
                })
    candidates = []
    for key, bucket in sorted(buckets.items()):
        candidates.append({
            "kind": "transport",
            "shape": key,
            "trigger": {"shape": key},
            "statement": (f"governor/transport refusals recorded "
                          f"{bucket['count']}x (status-0 facts)"),
            "action": ("raise the harness rate explicitly or check circuit "
                       "state before reading the crawl as model truth"),
            "occurrences": bucket["count"],
            "evidence": bucket["evidence"],
        })
    return candidates


MINERS = (mine_techniques, mine_reporting, mine_model, mine_signal,
          mine_transport)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def _confidence(occurrences: int, contradictions: int) -> float:
    value = min(MAX_CONFIDENCE,
                BASE_CONFIDENCE + CONFIDENCE_STEP * max(0, occurrences - 1))
    for _ in range(max(0, min(contradictions, 4))):
        value = round(value / 2.0, 3)
    return value


def _store_path(project_root: Optional[str], relative) -> Path:
    path = _workspace_root(project_root)
    for part in relative:
        path = path / part
    return path


def _existing_store(project_root: Optional[str]) -> Dict[str, Dict[str, Any]]:
    path = _store_path(project_root, STORE_REL)
    return {str(rec.get("id")): rec for rec in _load_jsonl(path)
            if rec.get("id")}


def distill(project_root: Optional[str] = None) -> Dict[str, Any]:
    """Mine every ledger, merge into the store, persist.

    Merge semantics per id:
      * occurrences accumulate (existing + new candidates this run);
      * confidence recomputed from occurrences, then HALVED per recorded
        contradiction (a success outcome after a failure pattern);
      * ``active`` = occurrences >= ACTIVE_THRESHOLD;
      * store-level prune of expired TTL entries runs first.
    """
    started = time.monotonic()
    pruned = prune(project_root)
    store = _existing_store(project_root)
    created = 0
    updated = 0

    # Success outcomes per (technique, class) are the contradiction source.
    successes = _technique_successes(project_root)

    for miner in MINERS:
        for candidate in miner(project_root):
            kind = candidate["kind"]
            iid = _instinct_id(kind, candidate["shape"], project_root)
            now = _now_iso()
            record = store.get(iid)
            if record is None:
                created += 1
                occurrences = int(candidate["occurrences"])
                contradictions = _contradictions(kind, candidate, successes)
                record = {
                    "schema": SCHEMA,
                    "id": iid,
                    "kind": kind,
                    "scope": "project",
                    "trigger": candidate["trigger"],
                    "statement": candidate["statement"],
                    "action": candidate["action"],
                    "evidence": candidate["evidence"],
                    "occurrences": occurrences,
                    "confidence": _confidence(occurrences, contradictions),
                    "active": occurrences >= ACTIVE_THRESHOLD,
                    "created_at": now,
                    "updated_at": now,
                    "ttl_days": DEFAULT_TTL_DAYS,
                }
                store[iid] = record
                continue
            updated += 1
            # The ledger is the source of truth: re-mining the same journal
            # REPLACES occurrences/evidence rather than accumulating, so
            # distill() is idempotent (growth comes only from new ledger
            # events, never from re-runs).
            record["occurrences"] = int(candidate["occurrences"])
            record["evidence"] = candidate["evidence"]
            contradictions = _contradictions(kind, candidate, successes)
            if contradictions:
                record["contradictions"] = contradictions
            record["confidence"] = _confidence(
                record["occurrences"],
                int(record.get("contradictions") or 0))
            record["active"] = record["occurrences"] >= ACTIVE_THRESHOLD
            record["statement"] = candidate["statement"]
            record["action"] = candidate["action"]
            record["updated_at"] = now

    path = _store_path(project_root, STORE_REL)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = sorted(store.values(), key=lambda r: str(r.get("id")))
    path.write_text(
        "".join(json.dumps(rec, sort_keys=True) + "\n" for rec in payload),
        encoding="utf-8")
    return {
        "schema": SCHEMA,
        "distilled_at": _now_iso(),
        "candidates_created": created,
        "candidates_updated": updated,
        "pruned": pruned,
        "total": len(store),
        "active": sum(1 for rec in store.values() if rec.get("active")),
        "elapsed_s": round(time.monotonic() - started, 3),
    }


def _technique_successes(project_root: Optional[str]) -> Dict[tuple, int]:
    from tools.runtime.lead_protocol import leads_dir
    journal_dir = leads_dir(project_root=project_root)
    if not journal_dir.is_dir():
        return {}
    successes: Dict[tuple, int] = {}
    for lead in _journal_leads(journal_dir):
        bug_class = str(lead.get("bug_class") or "generic")
        for entry in lead.get("technique_log") or []:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("outcome") or "") == "success":
                key = (str(entry.get("technique") or ""), bug_class)
                successes[key] = successes.get(key, 0) + 1
    return successes


def _contradictions(kind: str, candidate: Dict[str, Any],
                    successes: Dict[tuple, int]) -> int:
    """A failure-pattern instinct contradicted by a success for the same
    (technique, class) shape halves confidence instead of deleting."""
    if kind != "technique":
        return 0
    trigger = candidate.get("trigger") or {}
    return successes.get((str(trigger.get("technique") or ""),
                          str(trigger.get("bug_class") or "")), 0)


def prune(project_root: Optional[str] = None, *, now: Optional[float] = None
          ) -> int:
    """Drop expired instincts (ECC's prune-TTL semantics)."""
    path = _store_path(project_root, STORE_REL)
    records = _load_jsonl(path)
    if not records:
        return 0
    now = now if now is not None else time.time()
    kept, dropped = [], 0
    for rec in records:
        ttl_days = rec.get("ttl_days", DEFAULT_TTL_DAYS)
        updated = rec.get("updated_at") or rec.get("created_at") or ""
        try:
            then = time.mktime(time.strptime(
                str(updated)[:19], "%Y-%m-%dT%H:%M:%S"))
        except (ValueError, TypeError):
            kept.append(rec)
            continue
        if now - then > float(ttl_days) * 86400:
            dropped += 1
            continue
        kept.append(rec)
    if dropped:
        path.write_text(
            "".join(json.dumps(rec, sort_keys=True) + "\n" for rec in kept),
            encoding="utf-8")
    return dropped


def load_instincts(project_root: Optional[str] = None, *,
                   include_global: bool = True,
                   active_only: bool = True) -> List[Dict[str, Any]]:
    """Load instincts for consumption (fail-open; expired entries skipped)."""
    records = _load_jsonl(_store_path(project_root, STORE_REL))
    if include_global:
        records += _load_jsonl(_store_path(project_root, GLOBAL_REL))
    now = time.time()
    out = []
    for rec in records:
        if active_only and not rec.get("active"):
            continue
        ttl_days = rec.get("ttl_days", DEFAULT_TTL_DAYS)
        updated = str(rec.get("updated_at") or rec.get("created_at") or "")
        try:
            then = time.mktime(time.strptime(updated[:19],
                                             "%Y-%m-%dT%H:%M:%S"))
            if now - then > float(ttl_days) * 86400:
                continue
        except (ValueError, TypeError):
            pass  # unparseable timestamp: keep (prune owns expiry)
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Consumers — weighting only; every consumer fail-open.
# ---------------------------------------------------------------------------

def cockpit_section(project_root: Optional[str] = None, *, cap: int = 5
                    ) -> List[Dict[str, Any]]:
    """Top instincts for the SessionStart cockpit (confidence desc)."""
    ranked = sorted(load_instincts(project_root),
                    key=lambda r: (-float(r.get("confidence") or 0),
                                   -int(r.get("occurrences") or 0)))
    return [{
        "id": rec.get("id"), "kind": rec.get("kind"),
        "statement": rec.get("statement"), "action": rec.get("action"),
        "confidence": rec.get("confidence"),
        "occurrences": rec.get("occurrences"),
    } for rec in ranked[:cap]]


_DISPATCH_MODIFIERS = {"signal": 0.25, "noise": -0.25}


def dispatch_modifier(bug_class: str,
                      instincts: Optional[List[Dict[str, Any]]] = None,
                      project_root: Optional[str] = None) -> float:
    """Bounded priority modifier for a bug class (recorded by the caller).

    +0.25 for a class with an active signal instinct (proven detector
    pattern), −0.25 for an active noise instinct.  Never exceeds ±0.25.
    """
    if instincts is None:
        instincts = load_instincts(project_root)
    modifier = 0.0
    for rec in instincts:
        trigger = rec.get("trigger") or {}
        if str(trigger.get("bug_class") or "") != str(bug_class or ""):
            continue
        modifier += _DISPATCH_MODIFIERS.get(str(rec.get("kind") or ""), 0.0)
    return max(-0.25, min(0.25, modifier))


def order_techniques(required: List[str], instincts: List[Dict[str, Any]],
                     bug_class: str) -> List[str]:
    """Untried-technique ordering: techniques with an active failure
    pattern for this class go LAST (stable otherwise, nothing removed)."""
    demoted = set()
    for rec in instincts:
        if rec.get("kind") != "technique":
            continue
        trigger = rec.get("trigger") or {}
        if str(trigger.get("bug_class") or "") == str(bug_class or ""):
            demoted.add(str(trigger.get("technique") or ""))
    if not demoted:
        return list(required)
    return ([t for t in required if t not in demoted]
            + [t for t in required if t in demoted])


def promote(instinct_id: str, project_root: Optional[str] = None) -> bool:
    """Operator-gated promotion to global scope (never done by mining)."""
    path = _store_path(project_root, STORE_REL)
    records = _load_jsonl(path)
    hit = False
    for rec in records:
        if rec.get("id") == instinct_id:
            rec["scope"] = "global"
            rec["updated_at"] = _now_iso()
            hit = True
    if hit:
        path.write_text(
            "".join(json.dumps(rec, sort_keys=True) + "\n"
                    for rec in records), encoding="utf-8")
        gpath = _store_path(project_root, GLOBAL_REL)
        gpath.parent.mkdir(parents=True, exist_ok=True)
        with gpath.open("a", encoding="utf-8") as stream:
            for rec in records:
                if rec.get("id") == instinct_id:
                    stream.write(json.dumps(rec, sort_keys=True) + "\n")
    return hit
