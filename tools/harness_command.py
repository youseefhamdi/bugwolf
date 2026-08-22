#!/usr/bin/env python3
"""Parse direct conversational BugWolf invocations.

Freebuff users should not need to know BugWolf's internal Python commands. This
module translates a request such as ``bugwolf --full attack this target
https://example.test`` into an execution *plan*. It never executes a command,
contacts a target, infers authorization, or treats ``--active`` as permission.

The model/harness remains responsible for asking for missing authorization and
operator confirmations, then invoking the existing staged workflow.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-harness-command/v1"
MARKER = "BUGWOLF-HARNESS-COMMAND-V1"

MODE_FLAGS = {
    "--web": "web",
    "--web-api": "web_api",
    "--solidity": "smart_contract",
    "--move": "smart_contract",
    "--solana": "smart_contract",
    "--contract": "smart_contract",
    "--cicd": "cloud_cicd",
    "--cloud": "cloud_cicd",
    "--llm-ai": "llm_ai",
    "--llm": "llm_ai",
    "--agentic": "llm_ai",
    "--mobile": "mobile",
    "--report": "report",
    "--triage": "triage",
}

CONTROL_FLAGS = {
    "--active": "active_requested",
    "--confirm-active": "active_confirmation_present",
    "--confirm-destructive": "destructive_confirmation_present",
    "--learn": "learning_requested",
    "--mcp": "mcp_requested",
}

_TARGET_RE = re.compile(
    r"(?:attack|audit|review|assess|scan|test)\s+(?:this\s+)?target\s+([^\s,;]+)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s,;]+", re.IGNORECASE)


def _strip_target(value: str) -> str:
    return value.strip().strip("`'\"<>()[].")


def _target_from_text(text: str, tokens: List[str]) -> Optional[str]:
    match = _TARGET_RE.search(text)
    if match:
        return _strip_target(match.group(1)) or None
    url = _URL_RE.search(text)
    if url:
        return _strip_target(url.group(0)) or None
    for index, token in enumerate(tokens[:-1]):
        if token == "--target":
            return _strip_target(tokens[index + 1]) or None
    return None


def parse_invocation(text: str) -> Dict[str, Any]:
    """Return a non-executing plan for one direct BugWolf request."""
    raw = str(text or "").strip()
    try:
        tokens = shlex.split(raw)
    except ValueError as exc:
        return {
            "schema": SCHEMA,
            "marker": MARKER,
            "recognized": False,
            "needs_clarification": True,
            "errors": [f"cannot parse invocation: {exc}"],
            "offline": True,
        }

    if not tokens or tokens[0].lower() not in {"bugwolf", "/bugwolf"}:
        return {
            "schema": SCHEMA,
            "marker": MARKER,
            "recognized": False,
            "needs_clarification": False,
            "errors": ["request does not begin with the BugWolf invocation"],
            "offline": True,
        }

    flags = [token for token in tokens[1:] if token.startswith("--")]
    full = "--full" in flags
    modes = sorted({MODE_FLAGS[token] for token in flags if token in MODE_FLAGS})
    if full:
        modes = ["all_applicable"]
    elif not modes:
        modes = ["all_applicable"]

    controls = {
        name: (flag in flags)
        for flag, name in CONTROL_FLAGS.items()
    }
    target = _target_from_text(raw, tokens)
    errors: List[str] = []
    if "--full" not in flags and not any(flag in MODE_FLAGS for flag in flags):
        errors.append("no mode flag supplied; defaulting to all applicable modes")
    if not target:
        errors.append("target is missing")

    return {
        "schema": SCHEMA,
        "marker": MARKER,
        "recognized": True,
        "offline": True,
        "intent": "authorized_security_assessment",
        "target": target,
        "modes": modes,
        "full": full,
        "controls_requested": controls,
        "requires": {
            "harness_verification": True,
            "staged_workflow": True,
            "explicit_scope": True,
            "environment_preflight": True,
            "active_confirmation": True,
            "destructive_confirmation": True,
        },
        "next_actions": [
            "Verify or initialize the project-local harness contract.",
            "Start and inspect the target workflow at setup; do not jump to hunt.py.",
            "Ask only for missing environment declaration, scope, or required confirmation.",
            "After artifact intake, run applicable paper-derived offline analysis and preserve its uncertainty status.",
            "After every finding or cross-agent signal, refresh the persistent chain graph internally and resume from its next queue item.",
            "Execute each applicable stage with the existing JSON-producing tools; chain queue items never grant permission.",
        ],
        "needs_clarification": not bool(target),
        "errors": errors,
        "operator_message": (
            "I can run the full authorized BugWolf workflow for this target. "
            "Missing scope or confirmations must be supplied before target-facing work."
            if target else
            "Please provide the target after 'attack this target'."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse a BugWolf conversational invocation")
    parser.add_argument("--text", required=True, help="Direct user invocation to parse")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()
    result = parse_invocation(args.text)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["operator_message"])
        if result.get("target"):
            print(f"Target: {result['target']} | Modes: {', '.join(result['modes'])}")
    return 0 if result.get("recognized") else 2


if __name__ == "__main__":
    raise SystemExit(main())
