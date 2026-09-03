#!/usr/bin/env python3
"""BugWolf hook shim (plan v2 section 5.2 P2: microsecond hooks).

Contract: read one JSON event from stdin, append one JSONL line to the
mission journal, write one JSON decision to stdout, exit 0.  No module
imports beyond stdlib, no network, no model calls -- the whole script is
milliseconds.  Never raises: a hook failure must never block the harness.

Usage (wired from hooks/hooks.json):
    bugwolf_stop_hook.py stop     # /bugwolf-stop freezes mode state
    bugwolf_stop_hook.py resume   # /bugwolf-resume re-dispatches open leads
    bugwolf_stop_hook.py session-start   # preflight digest from cache

Environment:
    BUGWOLF_MISSION_ID   mission to journal against (default: none)
    BUGWOLF_PROJECT_ROOT workspace root (default: cwd)
"""

import json
import os
import sys
import time
from pathlib import Path


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _journal_path() -> Path:
    root = Path(os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
    mission = os.environ.get("BUGWOLF_MISSION_ID") or "default"
    d = root / "state" / "orchestrator" / mission
    d.mkdir(parents=True, exist_ok=True)
    return d / "hooks.jsonl"


def _preflight_digest() -> str:
    """Cached preflight digest (<10 ms: one small file read, no probing)."""
    root = Path(os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
    manifest = root / "state" / "preflight" / "manifest.json"
    try:
        return str(json.loads(manifest.read_text()).get("digest", ""))
    except Exception:  # noqa: BLE001 - cache miss is data, not failure
        return ""


# Only allowlisted scalar fields are journalled: hook callers are other
# processes on the operator's machine, and the journal file must never
# become a dumping ground for arbitrary payloads (product audit fix).
_JOURNAL_KEYS = ("mission_id", "session_id", "reason", "trigger", "source")


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "stop"
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    line = {"ts": _now_iso(), "hook": action, **{
        k: event[k] for k in _JOURNAL_KEYS if k in event}}
    decision: dict = {"continue": True}
    try:
        if action == "session-start":
            line["preflight_digest"] = _preflight_digest()
            decision["preflight_digest"] = line["preflight_digest"]
        elif action == "stop":
            line["action"] = "freeze"
            decision["action"] = "frozen"
        elif action == "resume":
            line["action"] = "resume"
            decision["action"] = "resume-open-leads-first"
        with _journal_path().open("a") as fh:
            fh.write(json.dumps(line, default=str) + "\n")
    except Exception as exc:  # noqa: BLE001 - hooks never block the harness
        decision = {"continue": True, "hook_error": str(exc)[:200]}
    print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
