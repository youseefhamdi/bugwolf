#!/usr/bin/env python3
"""Mandatory post-finding trigger layer.

A finding is not the end of the workflow. After each finding is persisted, this
module records an auditable receipt, refreshes the target-local chain graph,
and queues bounded research/escalation work. The queue is planning state only:
it never sends requests, runs a probe, changes permissions, or approves a
finding.

The module is deliberately called after the append to ``findings.jsonl``. A
trigger failure therefore cannot erase evidence, but it is recorded as an
explicit ``error`` receipt and must be resolved before downstream automation
may treat the post-finding handoff as complete.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

try:
    from tools.chain_orchestrator import refresh_target as refresh_chain_target
    from tools.evidence import redact
    from tools.runtime_paths import workspace_root
    from tools.safety import safe_target_name
except ImportError:  # direct script execution
    from chain_orchestrator import refresh_target as refresh_chain_target
    from evidence import redact
    from runtime_paths import workspace_root
    from safety import safe_target_name


SCHEMA = "bugwolf-post-finding-trigger/v1"
TRIGGER_LOG = "post-finding-triggers.jsonl"
QUEUE_LOG = "post-finding-queue.jsonl"
SUMMARY_FILE = "post-finding-latest.json"
SIGNAL_SUMMARY_FILE = "post-signal-latest.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value: Any, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _state_dir(project: Path, target: str) -> Path:
    safe = safe_target_name(target).replace(":", "_")[:200]
    return project / "state" / "sessions" / safe


def _append(path: Path, value: Dict[str, Any]) -> None:
    """Append one redacted, hash-linked trigger record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        if fcntl:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        lines = [line for line in handle.read().splitlines() if line.strip()]
        previous = ""
        sequence = 1
        if lines:
            try:
                last = json.loads(lines[-1])
                previous = str(last.get("record_hash", ""))
                sequence = int(last.get("sequence", len(lines))) + 1
            except (TypeError, ValueError, json.JSONDecodeError):
                # A malformed existing stream is preserved; the new record is
                # still linked to an empty tip and the verifier will report the
                # prior corruption explicitly.
                sequence = len(lines) + 1
        record = dict(redact(value))
        record["sequence"] = sequence
        record["previous_hash"] = previous
        record["record_hash"] = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        if fcntl:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _evidence_check(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Classify whether the persisted record has enough evidence to continue.

    This is a routing gate, not a claim that the finding is exploitable. A
    description, evidence reference, proof reference, or oracle signal is
    sufficient to create a review task; missing core identity fields always
    block the handoff.
    """
    missing: List[str] = []
    for field in ("finding_id", "title", "endpoint", "bug_class"):
        if not _clean(finding.get(field)):
            missing.append(field)
    evidence_fields = (
        "evidence", "description", "proof_of_concept", "observation_id",
    )
    has_evidence = any(_clean(finding.get(field)) for field in evidence_fields)
    if str(finding.get("observation_state", "")).lower() == "signal":
        has_evidence = True
    if not has_evidence:
        missing.append("evidence_reference")
    return {
        "state": "finding" if not missing else "blocked",
        "missing": missing,
        "has_evidence": has_evidence,
        "review_required": True,
    }


def _queue_items(finding: Dict[str, Any], evidence: Dict[str, Any],
                 chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    finding_id = _clean(finding.get("finding_id"), 120)
    bug_class = _clean(finding.get("bug_class"), 120) or "unknown"
    base = {
        "finding_id": finding_id,
        "automatic_execution": False,
        "requires": ["explicit_scope", "active_confirmation", "human_review"],
    }
    items: List[Dict[str, Any]] = []
    if chain.get("status") == "error":
        items.append({
            **base,
            "queue_id": f"{finding_id}:chain-repair",
            "kind": "chain_refresh_repair",
            "status": "blocked_trigger_error",
            "reason": "The chain graph could not be refreshed; downstream chain work is blocked.",
        })
    elif evidence["state"] == "finding":
        items.append({
            **base,
            "queue_id": f"{finding_id}:chain-review",
            "kind": "chain_review",
            "status": "pending_review",
            "reason": "Review the refreshed graph and continue from its highest-ranked missing link.",
            "chain_id": (chain.get("resume") or {}).get("chain_id"),
            "next_queue_item": (chain.get("resume") or {}).get("next_queue_item"),
        })
    else:
        items.append({
            **base,
            "queue_id": f"{finding_id}:evidence-repair",
            "kind": "evidence_repair",
            "status": "blocked_missing_evidence",
            "reason": "Add a redacted trigger/impact evidence reference before chain escalation.",
            "missing": evidence["missing"],
        })
    items.append({
        **base,
        "queue_id": f"{finding_id}:research",
        "kind": "post_finding_research",
        "status": (
            "blocked_trigger_error" if chain.get("status") == "error" else
            "pending_review" if evidence["state"] == "finding" else
            "blocked_missing_evidence"
        ),
        "bug_class": bug_class,
        "reason": "Recheck current research and competing explanations before escalation.",
    })
    severity = str(finding.get("severity", "info")).lower()
    if severity in {"critical", "high"}:
        items.append({
            **base,
            "queue_id": f"{finding_id}:impact-review",
            "kind": "impact_escalation_review",
            "status": (
                "blocked_trigger_error" if chain.get("status") == "error" else
                "pending_review" if evidence["state"] == "finding" else
                "blocked_missing_evidence"
            ),
            "severity": severity,
            "reason": "Review impact and chain terminal conditions; do not infer severity from novelty alone.",
        })
    return items


def trigger_after_finding(target: str, finding: Dict[str, Any], *,
                          project_root: Optional[str | Path] = None) -> Dict[str, Any]:
    """Run the mandatory offline trigger for one persisted finding.

    The returned receipt is always structured. Exceptions from the graph
    refresh become an explicit error receipt and a blocked repair item.
    """
    project = Path(project_root or workspace_root()).expanduser().resolve()
    safe_target_name(target)
    finding_copy = redact(dict(finding))
    finding_id = _clean(finding_copy.get("finding_id"), 120)
    evidence = _evidence_check(finding_copy)
    chain: Dict[str, Any]
    try:
        chain = refresh_chain_target(project, target, max_chains=32)
    except Exception as exc:
        chain = {
            "schema": "bugwolf-chain-orchestration/v1",
            "status": "error",
            "offline": True,
            "error": f"{type(exc).__name__}: {_clean(exc, 300)}",
            "stats": {"nodes": 0, "edges": 0, "chains": 0,
                      "complete_chains": 0, "blocked_chains": 0},
        }
    queue = _queue_items(finding_copy, evidence, chain)
    status = "error" if chain.get("status") == "error" else evidence["state"]
    receipt: Dict[str, Any] = {
        "schema": SCHEMA,
        "target": target,
        "finding_id": finding_id,
        "triggered_at": _now(),
        "status": status,
        "automatic_execution": False,
        "evidence": evidence,
        "chain": {
            "status": chain.get("status", "ready"),
            "offline": bool(chain.get("offline", True)),
            "stats": chain.get("stats", {}),
            "top_chain": (chain.get("chains") or [None])[0],
            "persistence": chain.get("persistence", {}),
            "resume": chain.get("resume"),
        },
        "queue_ids": [item["queue_id"] for item in queue],
        "gates": {
            "scope_required": True,
            "active_confirmation_required": True,
            "state_change_confirmation_required": True,
            "human_review_required": True,
            "automatic_execution": False,
        },
    }
    if chain.get("status") == "error":
        receipt["error"] = chain.get("error", "chain refresh failed")
    directory = _state_dir(project, target)
    _append(directory / TRIGGER_LOG, receipt)
    for item in queue:
        item["schema"] = SCHEMA
        item["target"] = target
        item["created_at"] = receipt["triggered_at"]
        _append(directory / QUEUE_LOG, item)
    latest = directory / SUMMARY_FILE
    temporary = latest.with_suffix(".tmp")
    temporary.write_text(json.dumps(redact({**receipt, "queue": queue}), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, latest)
    try:
        # Keep the existing tamper-evident journal as the cross-module audit
        # anchor. Import locally to avoid an import cycle during state startup.
        from tools.state import log_journal
        log_journal(target, "post_finding_triggered", {
            "finding_id": finding_id,
            "status": status,
            "queue_ids": receipt["queue_ids"],
        })
    except Exception as exc:
        # The receipt remains authoritative if journal integration itself fails.
        receipt["journal_status"] = "error"
        receipt["journal_error"] = f"{type(exc).__name__}: {_clean(exc, 200)}"
    return {**receipt, "queue": queue}


def trigger_after_signal(target: str, signal: Dict[str, Any], *,
                          project_root: Optional[str | Path] = None) -> Dict[str, Any]:
    """Run the same hard trigger for one persisted cross-agent signal.

    Signals are treated as evidence-bearing handoffs, not as findings. A
    signal can queue review and research, but it never promotes itself into the
    findings ledger or grants permission to execute a chain step.
    """
    project = Path(project_root or workspace_root()).expanduser().resolve()
    safe_target_name(target)
    signal_copy = redact(dict(signal))
    signal_id = _clean(signal_copy.get("signal_id"), 120)
    missing = [field for field in ("signal_id", "signal_type", "from_agent", "to_agents")
               if not _clean(signal_copy.get(field))]
    has_evidence = bool(signal_copy.get("finding_ref") or signal_copy.get("signal_data"))
    if not has_evidence:
        missing.append("signal_data_or_finding_ref")
    evidence = {
        "state": "signal" if not missing else "blocked",
        "missing": missing,
        "has_evidence": has_evidence,
        "review_required": True,
    }
    try:
        chain = refresh_chain_target(project, target, max_chains=32)
    except Exception as exc:
        chain = {
            "schema": "bugwolf-chain-orchestration/v1",
            "status": "error",
            "offline": True,
            "error": f"{type(exc).__name__}: {_clean(exc, 300)}",
            "stats": {"nodes": 0, "edges": 0, "chains": 0,
                      "complete_chains": 0, "blocked_chains": 0},
        }
    status = "error" if chain.get("status") == "error" else evidence["state"]
    queue_status = (
        "blocked_trigger_error" if status == "error" else
        "pending_review" if status == "signal" else
        "blocked_missing_evidence"
    )
    base = {
        "schema": SCHEMA,
        "target": target,
        "event_kind": "signal",
        "signal_id": signal_id,
        "automatic_execution": False,
        "requires": ["explicit_scope", "active_confirmation", "human_review"],
    }
    queue = [
        {
            **base,
            "queue_id": f"{signal_id}:signal-review",
            "kind": "cross_agent_signal_review",
            "status": queue_status,
            "signal_type": _clean(signal_copy.get("signal_type"), 120),
            "from_agent": _clean(signal_copy.get("from_agent"), 120),
            "reason": "Review the signal, provenance, and competing explanations before using it for chaining.",
        },
        {
            **base,
            "queue_id": f"{signal_id}:research",
            "kind": "post_signal_research",
            "status": queue_status,
            "reason": "Recheck the signal's bug class and current research before escalation.",
        },
    ]
    if status == "error":
        queue.append({
            **base,
            "queue_id": f"{signal_id}:chain-repair",
            "kind": "chain_refresh_repair",
            "status": "blocked_trigger_error",
            "reason": "The chain graph could not be refreshed; signal chaining is blocked.",
        })
    receipt: Dict[str, Any] = {
        "schema": SCHEMA,
        "target": target,
        "event_kind": "signal",
        "signal_id": signal_id,
        "triggered_at": _now(),
        "status": status,
        "automatic_execution": False,
        "signal": {
            "signal_type": _clean(signal_copy.get("signal_type"), 120),
            "from_agent": _clean(signal_copy.get("from_agent"), 120),
            "to_agents": signal_copy.get("to_agents", []),
            "finding_ref": _clean(signal_copy.get("finding_ref"), 120),
            "signal_data_keys": sorted(signal_copy.get("signal_data", {}).keys())
            if isinstance(signal_copy.get("signal_data"), dict) else [],
        },
        "evidence": evidence,
        "chain": {
            "status": chain.get("status", "ready"),
            "offline": bool(chain.get("offline", True)),
            "stats": chain.get("stats", {}),
            "top_chain": (chain.get("chains") or [None])[0],
            "persistence": chain.get("persistence", {}),
            "resume": chain.get("resume"),
        },
        "queue_ids": [item["queue_id"] for item in queue],
        "gates": {
            "scope_required": True,
            "active_confirmation_required": True,
            "state_change_confirmation_required": True,
            "human_review_required": True,
            "automatic_execution": False,
        },
    }
    if chain.get("status") == "error":
        receipt["error"] = chain.get("error", "chain refresh failed")
    directory = _state_dir(project, target)
    _append(directory / TRIGGER_LOG, receipt)
    for item in queue:
        item["created_at"] = receipt["triggered_at"]
        _append(directory / QUEUE_LOG, item)
    latest = directory / SIGNAL_SUMMARY_FILE
    temporary = latest.with_suffix(".tmp")
    temporary.write_text(json.dumps(redact({**receipt, "queue": queue}), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, latest)
    try:
        from tools.state import log_journal
        log_journal(target, "cross_agent_signal_triggered", {
            "signal_id": signal_id,
            "status": status,
            "queue_ids": receipt["queue_ids"],
        })
    except Exception:
        # The receipt/queue remain authoritative if journal integration fails.
        pass
    return {**receipt, "queue": queue}


def record_trigger_failure(target: str, finding: Dict[str, Any], error: str, *,
                           project_root: Optional[str | Path] = None,
                           event_kind: str = "finding") -> Dict[str, Any]:
    """Persist a minimal blocked receipt when the normal trigger cannot start."""
    project = Path(project_root or workspace_root()).expanduser().resolve()
    safe_target_name(target)
    finding_id = _clean(finding.get("finding_id"), 120)
    triggered_at = _now()
    queue = {
        "schema": SCHEMA,
        "target": target,
        "event_kind": event_kind,
        "created_at": triggered_at,
        "finding_id": finding_id,
        "queue_id": f"{finding_id}:trigger-repair",
        "kind": "trigger_repair",
        "status": "blocked_trigger_error",
        "reason": "The hard post-finding trigger failed before its normal receipt was written.",
        "error": _clean(error, 300),
        "automatic_execution": False,
        "requires": ["trigger_repair", "human_review"],
    }
    receipt = {
        "schema": SCHEMA,
        "target": target,
        "event_kind": event_kind,
        "finding_id": finding_id,
        "triggered_at": triggered_at,
        "status": "error",
        "automatic_execution": False,
        "error": _clean(error, 300),
        "queue_ids": [queue["queue_id"]],
        "gates": {
            "scope_required": True,
            "active_confirmation_required": True,
            "state_change_confirmation_required": True,
            "human_review_required": True,
            "automatic_execution": False,
        },
    }
    directory = _state_dir(project, target)
    _append(directory / TRIGGER_LOG, receipt)
    _append(directory / QUEUE_LOG, queue)
    latest = directory / (SIGNAL_SUMMARY_FILE if event_kind == "signal" else SUMMARY_FILE)
    temporary = latest.with_suffix(".tmp")
    temporary.write_text(json.dumps({**receipt, "queue": [queue]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, latest)
    return {**receipt, "queue": [queue]}


def load_latest_trigger(target: str, *, project_root: Optional[str | Path] = None,
                        event_kind: str = "finding") -> Optional[Dict[str, Any]]:
    project = Path(project_root or workspace_root()).expanduser().resolve()
    path = _state_dir(project, target) / (
        SIGNAL_SUMMARY_FILE if event_kind == "signal" else SUMMARY_FILE
    )
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


__all__ = ["SCHEMA", "trigger_after_finding", "trigger_after_signal", "record_trigger_failure", "load_latest_trigger"]
