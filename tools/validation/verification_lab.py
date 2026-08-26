#!/usr/bin/env python3
"""BugWolf Verification Lab Planner — disposable dynamic-validation labs.

For high-value candidates, plans a sandboxed, disposable verification lab
(OpenAnt-style): a container/dir spec with setup → reproduce → verify →
capture → discard steps, generated deterministically from the candidate's
bug class.  **Plans only** — nothing is executed; the lab is operator-run.

Each plan includes:

  * base image / runtime per bug class (web, api, auth, cloud, mobile,
    smart-contract, llm),
  * the reproduce script (payload/request template), verify script (asserts
    the expected observable), and capture artifact list,
  * network posture (loopback / outbound-only / none),
  * required operator-supplied inputs (URLs, tokens, fixtures),
  * a mandatory discard step so the lab cannot leak into production.

Output lands at ``research/<target>/verification/lab-plans.json`` (a
``research`` artifact) and emits ``LAB_PLANNED`` on the signal bus.

Offline and deterministic; uncensored; no commands are run.

Usage:
  python3 tools/validation/verification_lab.py --target acme --candidates findings.json
  python3 tools/validation/verification_lab.py --target acme --candidates findings.json --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


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
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus

SCHEMA = "bugwolf/verification-lab/v1"

# Deterministic lab recipes per bug-class family.
#   image:        container base / runtime
#   reproduce:    script template (with placeholders)
#   verify:       assertion template
#   network:      loopback | outbound_only | none
#   tools:        required operator tooling
RECIPES: Dict[str, Dict[str, Any]] = {
    "web": {
        "image": "python:3.12-slim",
        "network": "loopback",
        "tools": ["curl", "python3"],
        "reproduce": (
            "# reproduce.py\n"
            "import subprocess, sys\n"
            "# 1. Stand up the disposable target (operator-supplied endpoint or fixture).\n"
            "TARGET = sys.argv[1]  # e.g. http://127.0.0.1:8000/echo\n"
            "# 2. Send the crafted request recorded in the finding (payload template).\n"
            "print(f'[reproduce] sending payload to {TARGET}')\n"
            "# 3. Capture the raw response to capture/response.txt\n"),
        "verify": (
            "# verify.py\n"
            "# Assert the expected observable recorded in the finding\n"
            "# (reflected payload, timing delta, auth error vs 200, etc.)\n"
            "EXPECTED = sys.argv[1]\n"
            "actual = open('capture/response.txt').read()\n"
            "print('[verify]', 'MATCH' if EXPECTED in actual else 'NO MATCH')\n"
            "sys.exit(0 if EXPECTED in actual else 1)\n"),
    },
    "api": {
        "image": "python:3.12-slim",
        "network": "loopback",
        "tools": ["curl", "python3", "jq"],
        "reproduce": (
            "# reproduce.py\n"
            "# Replay the API sequence from the finding (auth step, then the\n"
            "# BOLA/BFLA/BOPLA/GraphQL request under test) against the lab endpoint.\n"
            "import sys\n"
            "TARGET = sys.argv[1]\n"
            "print(f'[reproduce] API sequence against {TARGET}')\n"),
        "verify": (
            "# verify.py\n"
            "# Assert object A's data is not returned to account B, or the\n"
            "# over-POSTed property did not bind, per the finding's invariant.\n"
            "print('[verify] checking cross-account / property-binding invariant')\n"),
    },
    "auth": {
        "image": "python:3.12-slim",
        "network": "loopback",
        "tools": ["python3", "jq", "openssl"],
        "reproduce": (
            "# reproduce.py\n"
            "# JWT/oauth replay: craft the forgery from the plan (alg=none,\n"
            "# HS256 confusion, redirect_uri tamper) and submit to the lab IdP/app.\n"
            "import sys\n"
            "TARGET = sys.argv[1]\n"
            "print(f'[reproduce] auth flow against {TARGET}')\n"),
        "verify": (
            "# verify.py\n"
            "# Assert the unexpected acceptance (token accepted with alg=none,\n"
            "# auth code delivered to the tampered redirect_uri, etc.).\n"
            "print('[verify] checking auth acceptance invariant')\n"),
    },
    "cloud": {
        "image": "amazon/aws-cli:latest",
        "network": "outbound_only",
        "tools": ["aws", "jq"],
        "reproduce": (
            "# reproduce.sh\n"
            "# In the isolated lab account/workspace, exercise the IAM\n"
            "# privesc or container-escape plan with disposable resources.\n"
            "TARGET=\"${1:?usage: reproduce.sh <lab-profile>}\"\n"
            "echo \"[reproduce] running capability plan under profile $TARGET\"\n"),
        "verify": (
            "# verify.sh\n"
            "# Assert the capability was granted (e.g. new admin policy version\n"
            "# effective, role assumed) and then tear the lab resources down.\n"
            "echo '[verify] checking granted capability; destroying lab resources'\n"),
    },
    "mobile": {
        "image": "ubuntu:24.04",
        "network": "loopback",
        "tools": ["adb", "apktool", "python3"],
        "reproduce": (
            "# reproduce.sh\n"
            "# On the lab emulator: launch the deep link / exported component\n"
            "# and capture the resulting navigation or component start.\n"
            "PACKAGE=\"${1:?usage: reproduce.sh <package>}\"\n"
            "echo \"[reproduce] deep-link trigger for $PACKAGE\"\n"),
        "verify": (
            "# verify.sh\n"
            "# Assert the component opened without auth, or the policy\n"
            "# finding reproduced (cleartext, exported-without-permission).\n"
            "echo '[verify] checking component-trigger invariant'\n"),
    },
    "smart-contract": {
        "image": "ghcr.io/foundry-rs/foundry:latest",
        "network": "none",
        "tools": ["forge", "cast"],
        "reproduce": (
            "# reproduce.sh\n"
            "# Deploy the fixture contract to the local anvil chain and run\n"
            "# the exploit sequence from the triage verdict.\n"
            "echo '[reproduce] deploying fixture and running exploit sequence'\n"),
        "verify": (
            "# verify.sh\n"
            "# Assert the state change (balance drain, ownership change)\n"
            "# and print the transaction trace.\n"
            "echo '[verify] checking state-change invariant'\n"),
    },
    "llm": {
        "image": "python:3.12-slim",
        "network": "loopback",
        "tools": ["python3", "curl"],
        "reproduce": (
            "# reproduce.py\n"
            "# Against the lab model endpoint, submit the prompt-injection /\n"
            "# tool-auth / RAG-poisoning payload from the plan.\n"
            "import sys\n"
            "ENDPOINT = sys.argv[1]\n"
            "print(f'[reproduce] injection payload against {ENDPOINT}')\n"),
        "verify": (
            "# verify.py\n"
            "# Assert the model followed the injected instruction or the\n"
            "# tool was invoked with the attacker-controlled argument.\n"
            "print('[verify] checking injection-success observable')\n"),
    },
}

_FAMILY_FOR_CLASS: List[tuple] = [
    (("xss", "sqli", "ssrf", "ssti", "smuggling", "idor", "waf", "csrf"), "web"),
    (("bola", "bfla", "bopla", "graphql", "api", "rate-limit"), "api"),
    (("jwt", "oauth", "auth", "ato", "session", "login", "pkce"), "auth"),
    (("iam", "cloud", "s3", "lambda", "container", "escape", "eks", "ecs"), "cloud"),
    (("deep-link", "deeplink", "mobile", "android", "ios", "webview", "apk"), "mobile"),
    (("contract", "solidity", "defi", "reentrancy", "oracle", "flash-loan"), "smart-contract"),
    (("prompt", "injection", "llm", "rag", "agent", "tool-auth", "jailbreak", "mcp"), "llm"),
]


def _family_for(bug_class: str) -> str:
    low = bug_class.lower()
    for markers, family in _FAMILY_FOR_CLASS:
        if any(m in low for m in markers):
            return family
    return "web"


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class LabStep:
    order: int
    action: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LabPlan:
    lab_id: str
    finding_id: str
    bug_class: str
    family: str
    image: str
    network: str
    tools: List[str]
    steps: List[LabStep] = field(default_factory=list)
    reproduce_script: str = ""
    verify_script: str = ""
    operator_inputs: List[str] = field(default_factory=list)
    capture_artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lab_id": self.lab_id,
            "finding_id": self.finding_id,
            "bug_class": self.bug_class,
            "family": self.family,
            "image": self.image,
            "network": self.network,
            "tools": self.tools,
            "steps": [s.to_dict() for s in self.steps],
            "reproduce_script": self.reproduce_script,
            "verify_script": self.verify_script,
            "operator_inputs": self.operator_inputs,
            "capture_artifacts": self.capture_artifacts,
            "discard": "Mandatory: destroy the lab container/volume after "
                       "verification — no lab state may persist.",
        }


@dataclass
class LabPlanSet:
    target: str
    generated_at: str
    plans: List[LabPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "plan_count": len(self.plans),
            "plans": [p.to_dict() for p in self.plans],
        }


def plan_labs(target: str, candidates: List[Dict[str, Any]]) -> LabPlanSet:
    """Deterministically generate a disposable-lab plan per candidate."""
    plan_set = LabPlanSet(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        finding_id = str(candidate.get("finding_id")
                         or candidate.get("candidate_id") or "unknown")
        bug_class = str(candidate.get("bug_class")
                        or candidate.get("type") or "web")
        family = _family_for(bug_class)
        recipe = RECIPES.get(family, RECIPES["web"])
        target_hint = str(candidate.get("target") or candidate.get("url")
                          or candidate.get("endpoint") or "")
        inputs: List[str] = []
        if target_hint:
            inputs.append(f"target endpoint/asset: {target_hint}")
        if candidate.get("payload"):
            inputs.append("payload template from the finding")
        if candidate.get("tokens") or candidate.get("credentials"):
            inputs.append("disposable credentials/tokens (operator-supplied)")
        if family == "smart-contract":
            inputs.append("fixture contract source (from the verdict)")
        if family == "mobile":
            inputs.append("APK/IPA binary (from asset-intelligence)")

        plan_set.plans.append(LabPlan(
            lab_id=_id("lab", finding_id, family),
            finding_id=finding_id,
            bug_class=bug_class,
            family=family,
            image=recipe["image"],
            network=recipe["network"],
            tools=list(recipe["tools"]),
            steps=[
                LabStep(1, "setup", f"Provision disposable container "
                                    f"({recipe['image']}), isolated network "
                                    f"({recipe['network']}), empty capture/ "
                                    f"volume."),
                LabStep(2, "reproduce", f"Run reproduce script with the "
                                        f"operator-supplied inputs."),
                LabStep(3, "verify", "Run verify script; require the finding's "
                                     "expected observable before accepting."),
                LabStep(4, "capture", "Save response artifacts, traces, and "
                                      "logs to capture/ (evidence, not "
                                      "production data)."),
                LabStep(5, "discard", "Destroy the container and volume; "
                                      "delete capture/ after the verdict is "
                                      "recorded."),
            ],
            reproduce_script=recipe["reproduce"],
            verify_script=recipe["verify"],
            operator_inputs=inputs,
            capture_artifacts=["capture/response.txt", "capture/trace.log",
                               "capture/verdict.json"],
        ))
    return plan_set


def write_plan_set(plan_set: LabPlanSet, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/verification/lab-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", plan_set.target) or "default"
    out_dir = root / "research" / target_slug / "verification"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "lab-plans.json"
    out.write_text(json.dumps(plan_set.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Verification lab planner")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--candidates", required=True,
                        help="path to candidates JSON (list or {candidates: [...]})")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.candidates).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read candidates: {exc}"}))
        return 2
    candidates = raw.get("candidates") if isinstance(raw, dict) else raw
    if not isinstance(candidates, list):
        candidates = [raw]

    plan_set = plan_labs(args.target, candidates)
    out = write_plan_set(plan_set, project_root=args.project_root,
                         base_dir=args.base_dir)

    if plan_set.plans:
        try:
            bus = SignalBus(args.target,
                            project_root=args.project_root or args.base_dir)
            for plan in plan_set.plans:
                bus.publish("LAB_PLANNED", source="verification_lab",
                            payload={"lab_id": plan.lab_id,
                                     "finding_id": plan.finding_id,
                                     "family": plan.family,
                                     "image": plan.image})
        except Exception as exc:  # advisory, never a gate
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(plan_set.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(plan_set.plans)} lab plans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
