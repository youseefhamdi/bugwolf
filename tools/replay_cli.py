#!/usr/bin/env python3
"""Replay engine CLI (Phase 1.8) — the agent-facing tool surface.

Modes:
  structured   -- captured/constructed request text + field-level mutations
  raw          -- verbatim bytes (smuggling, malformed framing, odd-case headers)
  desync       -- front + smuggled pair (the CL.TE / TE.CL detection pattern)

All sends pass the deny-by-default scope gate (the CLI binds the gate
EXPLICITLY to --target before any send — no auto-bind ambiguity) and the
governor. Output is JSON facts; verdicts belong to the F0.5 gate.

Usage:
  python3 tools/replay_cli.py --target http://127.0.0.1:8080 \
      --request-file req.txt --mutations mutations.json --compare --json

  python3 tools/replay_cli.py --target http://127.0.0.1:8080 \
      --raw-file smuggled.txt --json

  python3 tools/replay_cli.py --target http://127.0.0.1:8080 \
      --desync front.txt smuggled.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime.replay.engine import (  # noqa: E402
    replay_request, replay_raw, desync_probe)
from tools.runtime.replay.governor import Governor  # noqa: E402
from tools.runtime.replay.apply import OPS  # noqa: E402
from tools.runtime import scope as scope_mod  # noqa: E402

SCHEMA = "bugwolf-replay-cli/v1"


def _bind_gate(target: str, scope_file: Optional[str],
               exclude: Optional[List[str]]) -> None:
    """EXPLICIT bind: the declared mission target authorizes; nothing else."""
    extra = []
    denies = list(exclude or [])
    if scope_file:
        data = json.loads(Path(scope_file).read_text(encoding="utf-8"))
        extra = [str(h) for h in (data.get("in_scope_domains")
                                  or data.get("extra_hosts") or [])]
        denies += [str(h) for h in (data.get("out_of_scope_domains") or [])]
    scope_mod.GATE.bind(target, extra_hosts=extra, force=False,
                        deny_entries=denies)


def _load_mutations(spec: str):
    """Accept either a JSON literal (inline) or a path to a .json file."""
    candidate = Path(spec)
    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))
    return json.loads(spec)


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf replay engine")
    parser.add_argument("--target", required=True,
                        help="mission target origin (authorizes the scope gate)")
    parser.add_argument("--request-file", dest="request_file",
                        help="raw request text (structured mode)")
    parser.add_argument("--mutations",
                        help="mutation ops: inline JSON list or a .json file")
    parser.add_argument("--compare", action="store_true",
                        help="send a baseline first and report the delta")
    parser.add_argument("--raw-file", dest="raw_file",
                        help="verbatim request bytes (raw mode)")
    parser.add_argument("--desync", nargs=2, metavar=("FRONT", "SMUGGLED"),
                        help="front + smuggled byte files (desync mode)")
    parser.add_argument("--scope-file", dest="scope_file")
    parser.add_argument("--exclude", action="append",
                        help="program carve-out host (wins over wildcards)")
    parser.add_argument("--markers", help="comma-separated probe canaries")
    parser.add_argument("--rate", type=float, default=5.0,
                        help="governor rate limit (requests/sec)")
    parser.add_argument("--budget", type=int, default=5000,
                        help="governor global request budget")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    _bind_gate(args.target, args.scope_file, args.exclude)
    governor = Governor(rate_rps=args.rate, budget=args.budget)
    markers = [m for m in (args.markers or "").split(",") if m]

    if args.desync:
        front = Path(args.desync[0]).read_bytes()
        smuggled = Path(args.desync[1]).read_bytes()
        report = desync_probe(args.target, front, smuggled,
                              governor=governor)
    elif args.raw_file:
        raw = Path(args.raw_file).read_bytes()
        report = replay_raw(raw, host=args.target,
                            markers=markers, governor=governor)
    elif args.request_file:
        # BYTE-FIDELITY: read as bytes and decode latin-1 — text mode's
        # universal-newline translation would rewrite \r\n to \n and destroy
        # the exact wire bytes this engine exists to preserve.
        request_text = Path(args.request_file).read_bytes().decode("latin-1")
        mutations = _load_mutations(args.mutations) \
            if args.mutations else None
        report = replay_request(request_text, host=args.target,
                                mutations=mutations,
                                compare_baseline=args.compare,
                                markers=markers, governor=governor)
    else:
        parser.error("one of --request-file, --raw-file, --desync is required")
        return 2

    payload = {"schema": SCHEMA,
               **(report.to_dict() if hasattr(report, "to_dict") else report)}
    print(json.dumps(payload, indent=2 if args.as_json else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
