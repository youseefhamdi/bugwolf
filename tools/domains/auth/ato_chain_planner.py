#!/usr/bin/env python3
"""BugWolf ATO Chain Planner — account-takeover chain synthesis from leads.

Chains email-change, password-reset, MFA-recovery, session, OAuth, JWT and
enabler leads (XSS/CSRF/IDOR/open-redirect) into account-takeover plans.
Given the discovered leads (endpoints + kinds), every ATO chain whose steps
are supported is planned with:

  * the concrete endpoints per step (from the leads),
  * prerequisites that are met vs. still missing,
  * a two-account validation sequence (attacker account A + victim account B).

Deterministic: same leads => same plans.  The ATO step catalog and chain
templates are fixed tables; the planner only activates chains whose steps are
covered by real leads, so nothing speculative is reported as reachable.

Output lands at ``recon/<target>/discovery/ato-chain-plans.json`` (a
``coverage-plan`` artifact) and emits ``AUTH_CANDIDATE`` for high/critical
chains.  Uncensored: no scope gates; validation is the operator's step.

Usage:
  python3 tools/domains/auth/ato_chain_planner.py --target acme --leads leads.json
  python3 tools/domains/auth/ato_chain_planner.py --target acme --leads leads.json --json
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
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import SignalBus, publish_or_warn
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, publish_or_warn

SCHEMA = "bugwolf/ato-chain-planner/v1"

# ---------------------------------------------------------------------------
# ATO step catalog: kind -> the action an attacker performs at that step.
# ---------------------------------------------------------------------------

ATO_STEPS: Dict[str, Dict[str, str]] = {
    "email_change": {
        "action": "Change the account's email to an attacker-controlled "
                  "address (via authenticated email-change, IDOR on the "
                  "change endpoint, or CSRF).",
        "validation": "As account A, change the email to an address the "
                      "attacker controls; confirm the confirmation link "
                      "lands there.",
    },
    "password_reset": {
        "action": "Reset the password using the email-change confirmation "
                  "link (or a weak/unprotected reset flow).",
        "validation": "Request a reset and confirm it is delivered to the "
                      "attacker-controlled address, then set a new "
                      "password.",
    },
    "mfa_recovery": {
        "action": "Bypass MFA via recovery codes, backup flows, "
                  "enrollment re-binding, or response manipulation.",
        "validation": "On account B, exercise the recovery flow and confirm "
                      "it can be completed without the enrolled factor.",
    },
    "session": {
        "action": "Steal or fix the session: XSS to exfiltrate the cookie, "
                  "session fixation, no rotation on privilege change.",
        "validation": "Replay the victim's session token from account B "
                      "against account A's session context.",
    },
    "oauth": {
        "action": "Bind an attacker OAuth identity to the victim account "
                  "(cross-app COAT), or steal the authorization code via a "
                  "missing PKCE / open redirect.",
        "validation": "Two-app replay: low-priv app's grant replayed against "
                      "the high-priv app.",
    },
    "jwt": {
        "action": "Forge or confuse a JWT (alg=none, RS256->HS256, jwk "
                  "injection, kid traversal) to impersonate the victim.",
        "validation": "Submit the forged token to account B's privileged "
                      "endpoints and confirm acceptance.",
    },
    "xss": {
        "action": "Execute attacker script in the victim's session (stored "
                  "or reflected without CSP).",
        "validation": "Trigger the payload in account B's browser and "
                      "capture the session/CSRF token.",
    },
    "csrf": {
        "action": "Forge a cross-site request against a state-changing "
                  "endpoint (email change, password set, MFA disable).",
        "validation": "From a separate origin, submit the forged form to "
                      "account B and confirm the change applied.",
    },
    "idor": {
        "action": "Access or mutate another account's resources by "
                  "swapping object identifiers (e.g. the email-change "
                  "endpoint keyed by user id).",
        "validation": "Two-account A/B: use account A's token to modify "
                      "account B's email field.",
    },
    "open_redirect": {
        "action": "Redirect the victim (or an OAuth code flow) to an "
                  "attacker origin via an unvalidated redirect parameter.",
        "validation": "Confirm the redirect target is attacker-controlled "
                      "and carries a sensitive parameter (code/state).",
    },
}

# ---------------------------------------------------------------------------
# ATO chain templates: name, severity, required step kinds (in order),
# and a one-line description.  A chain activates when *all* required kinds
# are present among the leads.
# ---------------------------------------------------------------------------

ATO_CHAINS: List[Dict[str, Any]] = [
    {
        "id": "email-ato",
        "name": "Email-change takeover",
        "severity": "critical",
        "steps": ["email_change", "password_reset"],
        "description": "Change the victim's email and reset the password to "
                       "the attacker-controlled address — full account "
                       "takeover.",
    },
    {
        "id": "session-theft-ato",
        "name": "Session-theft takeover",
        "severity": "critical",
        "steps": ["xss", "session"],
        "description": "XSS in the victim's session exfiltrates the session "
                       "token, which is then replayed.",
    },
    {
        "id": "oauth-coat-ato",
        "name": "Cross-app OAuth takeover (COAT)",
        "severity": "critical",
        "steps": ["oauth"],
        "description": "Low-privilege app's OAuth grant is replayed against "
                       "a high-privilege app, binding attacker identity.",
    },
    {
        "id": "jwt-impersonation-ato",
        "name": "JWT impersonation takeover",
        "severity": "high",
        "steps": ["jwt", "email_change"],
        "description": "A forged JWT grants victim-level access, which is "
                       "then used to bind the account to an attacker email.",
    },
    {
        "id": "mfa-recovery-ato",
        "name": "MFA-recovery takeover",
        "severity": "high",
        "steps": ["mfa_recovery", "password_reset"],
        "description": "MFA recovery/backup flow is bypassable, then the "
                       "password is reset to complete the takeover.",
    },
    {
        "id": "idor-email-ato",
        "name": "IDOR email-change takeover",
        "severity": "high",
        "steps": ["idor", "email_change", "password_reset"],
        "description": "IDOR on the email-change endpoint rewrites the "
                       "victim's email; the reset link then lands on the "
                       "attacker.",
    },
    {
        "id": "csrf-email-ato",
        "name": "CSRF email-change takeover",
        "severity": "high",
        "steps": ["csrf", "email_change"],
        "description": "A forged cross-site request changes the victim's "
                       "email (no CSRF token or weak origin check).",
    },
    {
        "id": "open-redirect-oauth-ato",
        "name": "Open-redirect OAuth code theft",
        "severity": "high",
        "steps": ["open_redirect", "oauth"],
        "description": "An open redirect steals the OAuth authorization "
                       "code (or state) for the victim's login.",
    },
]

_LEAD_KIND_HINTS = {
    "email": "email_change", "password": "password_reset",
    "reset": "password_reset", "mfa": "mfa_recovery", "2fa": "mfa_recovery",
    "otp": "mfa_recovery", "session": "session", "login": "session",
    "oauth": "oauth", "authorize": "oauth", "token": "jwt", "jwt": "jwt",
    "xss": "xss", "csrf": "csrf", "idor": "idor", "profile": "idor",
    "redirect": "open_redirect", "callback": "open_redirect",
}


def _infer_kind(lead: Dict[str, Any]) -> str:
    kind = str(lead.get("kind") or "").lower()
    if kind:
        return kind
    endpoint = str(lead.get("endpoint") or lead.get("url") or "")
    low = endpoint.lower()
    for hint, resolved in _LEAD_KIND_HINTS.items():
        if hint in low:
            return resolved
    return ""


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class AtoStep:
    kind: str
    action: str
    endpoint: str
    validation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AtoChainPlan:
    chain_id: str
    name: str
    severity: str
    description: str
    steps: List[AtoStep] = field(default_factory=list)
    missing_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "missing_steps": self.missing_steps,
        }


@dataclass
class AtoPlanSet:
    target: str
    generated_at: str
    plans: List[AtoChainPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "plan_count": len(self.plans),
            "plans": [p.to_dict() for p in self.plans],
        }


def plan_chains(target: str, leads: List[Dict[str, Any]]) -> AtoPlanSet:
    """Deterministically plan every ATO chain supported by the leads."""
    plan_set = AtoPlanSet(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    by_kind: Dict[str, List[Dict[str, Any]]] = {}
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        kind = _infer_kind(lead)
        if kind:
            by_kind.setdefault(kind, []).append(lead)

    for chain in ATO_CHAINS:
        required = list(chain["steps"])
        covered = [k for k in required if k in by_kind]
        if len(covered) < len(required):
            # Only fully-supported chains become plans (nothing speculative).
            continue
        steps: List[AtoStep] = []
        for kind in required:
            lead = by_kind[kind][0]
            steps.append(AtoStep(
                kind=kind,
                action=ATO_STEPS[kind]["action"],
                endpoint=str(lead.get("endpoint") or lead.get("url") or ""),
                validation=ATO_STEPS[kind]["validation"],
            ))
        plan_set.plans.append(AtoChainPlan(
            chain_id=chain["id"],
            name=chain["name"],
            severity=chain["severity"],
            description=chain["description"],
            steps=steps,
            missing_steps=[],
        ))
    return plan_set


def write_plan_set(plan_set: AtoPlanSet, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to recon/<target>/discovery/ato-chain-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(plan_set.target)
    out_dir = root / "recon" / target_dir / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "ato-chain-plans.json"
    out.write_text(json.dumps(plan_set.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="ATO chain planner")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--leads", required=True,
                        help="path to leads JSON (list or {leads: [...]})")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.leads).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read leads: {exc}"}))
        return 2
    leads = raw.get("leads") if isinstance(raw, dict) else raw
    if not isinstance(leads, list):
        leads = [raw]

    plan_set = plan_chains(args.target, leads)
    out = write_plan_set(plan_set, project_root=args.project_root,
                         base_dir=args.base_dir)

    high = [p for p in plan_set.plans if p.severity in ("high", "critical")]
    for plan in high:
        publish_or_warn(args.target, "AUTH_CANDIDATE",
                        source="ato_chain_planner",
                        payload={"chain_id": plan.chain_id,
                                 "name": plan.name,
                                 "severity": plan.severity,
                                 "steps": [s.kind for s in plan.steps]},
                        project_root=args.project_root, base_dir=args.base_dir)

    if args.json:
        print(json.dumps(plan_set.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(plan_set.plans)} ATO chain plans -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
