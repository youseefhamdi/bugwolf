#!/usr/bin/env python3
"""BugWolf harness hooks 3.2 + 3.3 + cockpit 3.4 (master plan Phase 3).

Contract (identical to the other hook shims): read one JSON event from
stdin, do bounded local work (small file reads/writes only), write one
JSON decision to stdout, exit 0.  Stdlib only, no network, no model
calls — milliseconds.  Never raises: a hook failure must never block
the harness.

Usage (wired from hooks/hooks.json):

    bugwolf_hooks.py user-prompt-submit
        Injects mission context into the prompt: the declared target and
        boundary (from the scope contract), open-lead counts, and — when
        a persisted Target Model exists — a FRESHNESS WARNING when the
        model is older than BUGWOLF_MODEL_MAX_AGE_H (default 24): hunting
        against a stale model contradicts the Understanding Layer's
        thesis, so staleness must be visible at every prompt.

    bugwolf_hooks.py post-tool-use
        Auto-captures HTTP-ish tool outputs into a hash-chained evidence
        ledger (``state/orchestrator/<mission>/evidence.jsonl``).  Each
        record carries ``replay_key`` — the SHA-256 of (mission, target,
        method, path, chain head) — which pins the exact request bytes
        needed to reproduce the observation via the replay engine.  The
        chain head is stored in ``state/orchestrator/<mission>/
        evidence_head`` so tampering is detectable.

    bugwolf_hooks.py session-start
        The SessionStart COCKPIT (upgrades the v1.14 preflight digest):
        preflight digest, scope-contract state, sandbox kill-switch
        state, open leads by status, mode state, and target-model
        freshness (hours since the U9 Target Model was generated).
        Everything is read from durable state; nothing probes.

Environment:
    BUGWOLF_MISSION_ID     mission to scope state to (default: default)
    BUGWOLF_PROJECT_ROOT   workspace root (default: cwd)
    BUGWOLF_MODEL_MAX_AGE_H  freshness window in hours (default 24)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared helpers (stdlib only; fail-soft readers everywhere)
# ---------------------------------------------------------------------------

MODEL_MAX_AGE_H = 24.0

HTTPISH_KEYS = ("status", "status_code", "http_status", "response_status")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _root() -> Path:
    return Path(os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")


def _mission() -> str:
    return os.environ.get("BUGWOLF_MISSION_ID") or "default"


def _mission_dir() -> Path:
    return _root() / "state" / "orchestrator" / _mission()


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - missing/corrupt state is data
        return None


def _read_jsonl(path: Path) -> list:
    try:
        return [json.loads(l) for l in
                path.read_text(encoding="utf-8").splitlines() if l.strip()]
    except Exception:  # noqa: BLE001
        return []


def _slug(value: str) -> str:
    """Filesystem slug matching tools.runtime_paths.target_slug."""
    import re
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    slug = slug.strip(".")[:200]
    return slug or "default"


# ---------------------------------------------------------------------------
# 3.4 target-model freshness (read by both the cockpit and 3.2)
# ---------------------------------------------------------------------------

def model_freshness() -> dict:
    """Age of the persisted Target Model (U9), in hours.

    Reads ``state/targets/<slug>/model/u9-target-model.json`` — the
    artifact ``/bugwolf-understand`` persists.  Missing model =>
    ``{"state": "absent"}`` (never hunted with a model that doesn't
    exist); corrupt => ``{"state": "unreadable"}``; present => hours
    since ``generated_at``.
    """
    target = _target_from_contract()
    out = {"target": target}
    if not target:
        out["state"] = "no-target"
        return out
    path = _root() / "state" / "targets" / _slug(target) / "model" / \
        "u9-target-model.json"
    data = _read_json(path)
    if data is None:
        out["state"] = "absent"
        return out
    generated = str(data.get("generated_at") or "")
    parsed = _parse_ts(generated)
    if parsed is None:
        out["state"] = "unreadable"
        return out
    age_h = max(0.0, (time.time() - parsed) / 3600.0)
    out.update({
        "state": "present",
        "age_hours": round(age_h, 2),
        "generated_at": generated,
        "stale": age_h > _max_age(),
    })
    return out


def _max_age() -> float:
    try:
        return float(os.environ.get("BUGWOLF_MODEL_MAX_AGE_H")
                     or MODEL_MAX_AGE_H)
    except ValueError:
        return MODEL_MAX_AGE_H


def _parse_ts(value: str):
    """Parse ISO-8601 timestamps (UTC 'Z' or with offset) without
    dateutil.  Returns a POSIX timestamp or None."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        from datetime import datetime
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _target_from_contract() -> str:
    contract = _read_json(_root() / "state" / "scope_contract.json") or {}
    if not isinstance(contract, dict):
        return ""
    return str(contract.get("target") or "")


# ---------------------------------------------------------------------------
# 3.2 UserPromptSubmit: mission context + stale-model warning
# ---------------------------------------------------------------------------

def user_prompt_submit() -> dict:
    """Mission-context injection (additionalContext, never a block)."""
    contract = _read_json(_root() / "state" / "scope_contract.json") or {}
    contract = contract if isinstance(contract, dict) else {}
    bound = bool(contract.get("schema"))
    leads = _read_jsonl(_mission_dir() / "leads" / "leads.jsonl")
    open_leads = sum(1 for l in leads if l.get("status") == "OPEN")
    freshness = model_freshness()

    lines: list = []
    if bound:
        lines.append(
            f"[bugwolf] mission {_mission()}: target={contract.get('target')} "
            f"scope=deny-by-default")
    if open_leads:
        lines.append(f"[bugwolf] open leads: {open_leads} "
                     f"(resume /bugwolf-resume first)")
    if freshness.get("state") == "present" and freshness.get("stale"):
        lines.append(
            f"[bugwolf] TARGET MODEL STALE: generated "
            f"{freshness.get('age_hours')}h ago (window "
            f"{_max_age():g}h) — run /bugwolf-understand before hunting")
    elif freshness.get("state") == "absent" and bound:
        lines.append("[bugwolf] no Target Model — run /bugwolf-understand "
                     "before hunting")
    context = "\n".join(lines)

    decision: dict = {"continue": True}
    if context:
        # Claude Code UserPromptSubmit contract: additionalContext is
        # prepended to the prompt.  Hook-only surface; never a block.
        decision["hookSpecificOutput"] = {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": context,
        }
    decision["context_lines"] = len(lines)
    return decision


# ---------------------------------------------------------------------------
# 3.3 PostToolUse: HTTP-ish output -> hash-chained evidence ledger
# ---------------------------------------------------------------------------

# Keys under which tool payloads plausibly carry HTTP observations.  The
# capture is BEST-EFFORT and conservative: a payload is captured only when
# it unambiguously names a status (or raw HTTP) — never raw tool dumps.
_PAYLOAD_KEYS = ("response", "result", "output", "report", "data")

_HTTPISH_MIN = 24


_REQUEST_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                    "OPTIONS", "PRI"}


def _parse_request_line(sent: str):
    """method + path from the request wire text (replay reports carry the
    full request as ``sent_bytes`` but no explicit method/path fields)."""
    first = sent.split("\r\n", 1)[0]
    parts = first.split(" ")
    if len(parts) >= 2 and parts[0].upper() in _REQUEST_METHODS:
        return parts[0].upper(), parts[1]
    return None


def _extract_observations(payload) -> list:
    """Pull HTTP-ish observations out of an arbitrary tool payload.

    Forms recognized (dicts only, bounded recursion):
      * ``{"status": 200, "method": ..., "path": ..., ...}`` shaped records;
      * bugwolf replay reports (``sent_bytes`` request wire text + status) —
        method/path parsed from the request line;
      * ``{"raw_response": "HTTP/1.1 200 OK\\r\\n..."}`` byte-captures.
    """
    out: list = []
    if isinstance(payload, dict):
        status = None
        for key in HTTPISH_KEYS:
            value = payload.get(key)
            if isinstance(value, int):
                status = value
                break
        raw = payload.get("raw_response") or payload.get("raw")
        if status is None and isinstance(raw, str) and \
                raw[:8].startswith("HTTP/"):
            first = raw.split("\r\n", 1)[0].split(" ")
            if len(first) >= 2:
                try:
                    status = int(first[1])
                except ValueError:
                    status = None
        if status is not None:
            sent = payload.get("sent_bytes")
            parsed = (_parse_request_line(sent)
                      if isinstance(sent, str) else None)
            method, path = parsed or (
                str(payload.get("method") or "GET"),
                str(payload.get("path") or payload.get("target")
                    or payload.get("url") or "/"))
            out.append({
                "method": method,
                "path": path,
                "status": int(status),
                "raw": raw if isinstance(raw, str) else "",
                "request": sent if isinstance(sent, str)
                else str(payload.get("request") or ""),
            })
        for key in _PAYLOAD_KEYS:
            if key in payload:
                out.extend(_extract_observations(payload[key]))
    elif isinstance(payload, list):
        for item in payload[:50]:                 # bounded breadth
            out.extend(_extract_observations(item))
    return out


def _chain_head() -> str:
    try:
        return (_mission_dir() / "evidence_head").read_text(
            encoding="utf-8").strip()
    except OSError:
        return ""


def post_tool_use(event: dict) -> dict:
    """Capture HTTP-ish outputs into the hash-chained evidence ledger."""
    decision: dict = {"continue": True}
    tool_input = event.get("tool_input") or {}
    tool_output = event.get("tool_output") or event.get("tool_response") or {}
    observations = _extract_observations(tool_output)
    if not observations:
        decision["captured"] = 0
        return decision

    head = _chain_head()
    target = _target_from_contract()
    ledger_path = _mission_dir() / "evidence.jsonl"
    records = []
    for obs in observations[:20]:                  # bounded per event
        replay_key = hashlib.sha256(
            "\x1f".join((_mission(), target, obs["method"], obs["path"],
                         head)).encode("utf-8")).hexdigest()
        record = {
            "schema": "bugwolf-evidence/v1",
            "ts": _now_iso(),
            "hook": "post-tool-use",
            "mission_id": _mission(),
            "target": target,
            "tool": str(event.get("tool_name") or ""),
            "method": obs["method"],
            "path": obs["path"],
            "status": obs["status"],
            "request_bytes": obs["request"][:4000],
            "raw_response": obs["raw"][:8000],
            "prev_head": head,
            "replay_key": replay_key,
        }
        head = hashlib.sha256(
            (head + json.dumps(record, sort_keys=True, default=str))
            .encode("utf-8")).hexdigest()
        record["entry_hash"] = head
        records.append(record)

    try:
        _mission_dir().mkdir(parents=True, exist_ok=True)
        with ledger_path.open("a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, sort_keys=True,
                                    default=str) + "\n")
        (_mission_dir() / "evidence_head").write_text(head,
                                                      encoding="utf-8")
        decision["captured"] = len(records)
        decision["replay_keys"] = [r["replay_key"] for r in records]
    except Exception as exc:  # noqa: BLE001 - hooks never block the harness
        decision["hook_error"] = str(exc)[:200]
    return decision


# ---------------------------------------------------------------------------
# 3.4 SessionStart cockpit
# ---------------------------------------------------------------------------

def _sandbox_state() -> dict:
    kill = _root() / "state" / "sandbox" / "KILL_SWITCH"
    state = {"kill_switch": kill.exists()}
    grants = _read_json(_root() / "state" / "sandbox" / "grants.json")
    if isinstance(grants, dict):
        state["grants"] = len(grants)
    return state


def _mode_state() -> dict:
    journal = _read_jsonl(_mission_dir() / "modes.jsonl")
    if not journal:
        return {"mode": None}
    last = journal[-1]
    return {"mode": last.get("mode") or last.get("action"),
            "since": last.get("ts")}


def _leads_state() -> dict:
    leads = _read_jsonl(_mission_dir() / "leads" / "leads.jsonl")
    by_status: dict = {}
    for lead in leads:
        status = str(lead.get("status") or "OPEN")
        by_status[status] = by_status.get(status, 0) + 1
    return {"total": len(leads), "by_status": by_status}


def session_start() -> dict:
    """The cockpit: everything the operator needs in one digest."""
    contract = _read_json(_root() / "state" / "scope_contract.json") or {}
    contract = contract if isinstance(contract, dict) else {}
    preflight = _read_json(_root() / "state" / "preflight" / "manifest.json") \
        or {}
    cockpit = {
        "schema": "bugwolf-cockpit/v1",
        "mission": _mission(),
        "scope": {
            "bound": bool(contract.get("schema")),
            "target": contract.get("target"),
            "mode": contract.get("mode"),
        },
        "preflight_digest": str(preflight.get("digest") or ""),
        "sandbox": _sandbox_state(),
        "leads": _leads_state(),
        "mode": _mode_state(),
        "target_model": model_freshness(),
        "instincts": _instincts_section(),
    }
    return {"continue": True, "cockpit": cockpit,
            "preflight_digest": cockpit["preflight_digest"]}


def _instincts_section() -> list:
    """Top learned instincts (v1.24 Phase A) — weighting-only facts from
    past missions, mined by tools/instincts.py.  Fail-open: mining loss is
    a missing cockpit line, never a stall."""
    try:
        root = str(_root().resolve())
        if root not in sys.path:
            sys.path.insert(0, root)
        from tools.instincts import cockpit_section
        return cockpit_section(root)
    except Exception:  # noqa: BLE001 - instincts never block the cockpit
        return []


def pre_compact() -> dict:
    """PreCompact persist (ECC memory-persistence pattern, v1.24): re-emit
    the SessionStart digest to ``state/orchestrator/<mission>/
    session_context_last.json`` so the post-compact session's cockpit is
    instant.  Fail-open by construction."""
    cockpit = session_start().get("cockpit", {})
    out = _mission_dir() / "session_context_last.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(cockpit, indent=2, sort_keys=True),
                       encoding="utf-8")
    except OSError:
        return {"continue": True}
    return {"continue": True, "persisted": str(out)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    try:
        if action == "user-prompt-submit":
            decision = user_prompt_submit()
        elif action == "post-tool-use":
            decision = post_tool_use(event)
        elif action == "session-start":
            decision = session_start()
        elif action == "pre-compact":
            decision = pre_compact()
        else:
            decision = {"continue": True}
    except Exception as exc:  # noqa: BLE001 - hooks never block the harness
        decision = {"continue": True, "hook_error": str(exc)[:200]}
    print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
