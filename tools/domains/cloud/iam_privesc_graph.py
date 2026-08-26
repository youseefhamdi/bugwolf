#!/usr/bin/env python3
"""BugWolf IAM Privilege-Escalation Graph — offline capability analysis (AWS).

Encodes the 21 Rhino Security Labs AWS IAM privilege-escalation methods
(plus the common PassRole-trigger variants) as a directed capability graph:
each method is an edge from the actions a principal already holds to the
capability it gains by exercising that method.  Ingesting an operator-supplied
IAM policy dump produces:

  * which of the 21 methods are *directly* reachable from the policy,
  * the escalation closure (e.g. iam:AttachUserPolicy -> admin -> everything),
  * and the concrete escalation paths with the actions that unlock each hop.

Deterministic core, uncensored, workflow-aware:

  * Offline: input is a policy dump (JSON); output is a plan written to
    ``state/capability/iam-privesc-<target>.json`` (a ``coverage-plan``
    artifact).  No cloud API calls are made.
  * Emits ``CLOUD_CANDIDATE`` on the signal bus for each directly reachable
    high-impact method (admin / role-takeover class).
  * Uncensored: no scope/confirmation gates.  The operator owns the
    environment and any validation.

Usage:
  python3 tools/domains/cloud/iam_privesc_graph.py --target acme --policy dump.json
  python3 tools/domains/cloud/iam_privesc_graph.py --target acme --policy dump.json --json
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
from typing import Any, Dict, List, Optional, Set, Tuple


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

SCHEMA = "bugwolf/iam-privesc-graph/v1"

# ---------------------------------------------------------------------------
# The 21 Rhino methods (Rhino Security Labs, "AWS IAM Privilege Escalation
# Methods") plus the PassRole-trigger variants, as a capability graph.
#
# Each entry: the action set that unlocks the method, and the capability it
# grants.  `gained` is one of:
#   admin          - effective full admin (attach/policy-version methods)
#   credentials    - new IAM credentials / login profile (identity takeover)
#   role_takeover  - assume or execute-as another role via PassRole triggers
#   group_membership - add self to a privileged group
#   policy_write   - write/attach arbitrary policies (subset of admin)
# ---------------------------------------------------------------------------

PRIVESC_METHODS: List[Dict[str, Any]] = [
    # --- policy-version / policy-write family (direct admin) ---
    {
        "id": "CreatePolicyVersion",
        "name": "iam:CreatePolicyVersion",
        "required_actions": ["iam:CreatePolicyVersion"],
        "gained": "admin",
        "impact": "Create a new version of an existing policy with admin "
                  "permissions, then set it as default — instant admin.",
        "family": "policy_write",
    },
    {
        "id": "SetDefaultPolicyVersion",
        "name": "iam:SetDefaultPolicyVersion",
        "required_actions": ["iam:SetDefaultPolicyVersion"],
        "gained": "admin",
        "impact": "Set an existing policy version (e.g. one created via "
                  "CreatePolicyVersion) as the default — admin.",
        "family": "policy_write",
    },
    {
        "id": "AttachUserPolicy",
        "name": "iam:AttachUserPolicy",
        "required_actions": ["iam:AttachUserPolicy"],
        "gained": "admin",
        "impact": "Attach an admin policy to yourself (or any user).",
        "family": "policy_write",
    },
    {
        "id": "AttachGroupPolicy",
        "name": "iam:AttachGroupPolicy",
        "required_actions": ["iam:AttachGroupPolicy"],
        "gained": "admin",
        "impact": "Attach an admin policy to a group you belong to.",
        "family": "policy_write",
    },
    {
        "id": "AttachRolePolicy",
        "name": "iam:AttachRolePolicy",
        "required_actions": ["iam:AttachRolePolicy"],
        "gained": "admin",
        "impact": "Attach an admin policy to a role you can assume.",
        "family": "policy_write",
    },
    {
        "id": "PutUserPolicy",
        "name": "iam:PutUserPolicy",
        "required_actions": ["iam:PutUserPolicy"],
        "gained": "admin",
        "impact": "Write an inline admin policy on your own user.",
        "family": "policy_write",
    },
    {
        "id": "PutGroupPolicy",
        "name": "iam:PutGroupPolicy",
        "required_actions": ["iam:PutGroupPolicy"],
        "gained": "admin",
        "impact": "Write an inline admin policy on a group you belong to.",
        "family": "policy_write",
    },
    {
        "id": "PutRolePolicy",
        "name": "iam:PutRolePolicy",
        "required_actions": ["iam:PutRolePolicy"],
        "gained": "admin",
        "impact": "Write an inline admin policy on a role you can assume.",
        "family": "policy_write",
    },
    # --- identity / credential family ---
    {
        "id": "AddUserToGroup",
        "name": "iam:AddUserToGroup",
        "required_actions": ["iam:AddUserToGroup"],
        "gained": "group_membership",
        "impact": "Add yourself to a privileged group (e.g. admins).",
        "family": "identity",
    },
    {
        "id": "CreateAccessKey",
        "name": "iam:CreateAccessKey",
        "required_actions": ["iam:CreateAccessKey"],
        "gained": "credentials",
        "impact": "Create an access key for a more privileged user — "
                  "credential-based takeover.",
        "family": "identity",
    },
    {
        "id": "CreateLoginProfile",
        "name": "iam:CreateLoginProfile",
        "required_actions": ["iam:CreateLoginProfile"],
        "gained": "credentials",
        "impact": "Set a login password for another user (console takeover).",
        "family": "identity",
    },
    {
        "id": "UpdateLoginProfile",
        "name": "iam:UpdateLoginProfile",
        "required_actions": ["iam:UpdateLoginProfile"],
        "gained": "credentials",
        "impact": "Reset another user's console password.",
        "family": "identity",
    },
    # --- PassRole trigger family (role_takeover) ---
    {
        "id": "PassRoleEC2",
        "name": "iam:PassRole + ec2:RunInstances",
        "required_actions": ["iam:PassRole", "ec2:RunInstances"],
        "gained": "role_takeover",
        "impact": "Launch an EC2 instance with an arbitrary role and read its "
                  "instance profile credentials / user-data.",
        "family": "passrole",
    },
    {
        "id": "PassRoleLambdaCreate",
        "name": "iam:PassRole + lambda:CreateFunction",
        "required_actions": ["iam:PassRole", "lambda:CreateFunction"],
        "gained": "role_takeover",
        "impact": "Create a Lambda with an arbitrary role and invoke it to "
                  "execute with that role's permissions.",
        "family": "passrole",
    },
    {
        "id": "PassRoleLambdaUpdate",
        "name": "iam:PassRole + lambda:UpdateFunctionCode",
        "required_actions": ["iam:PassRole", "lambda:UpdateFunctionCode"],
        "gained": "role_takeover",
        "impact": "Replace the code of an existing Lambda that already carries "
                  "a privileged role.",
        "family": "passrole",
    },
    {
        "id": "PassRoleGlue",
        "name": "iam:PassRole + glue:CreateDevEndpoint",
        "required_actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "gained": "role_takeover",
        "impact": "Create a Glue dev endpoint with an arbitrary role and SSH "
                  "into it to assume the role.",
        "family": "passrole",
    },
    {
        "id": "PassRoleEcs",
        "name": "iam:PassRole + ecs:RegisterTaskDefinition / RunTask",
        "required_actions": ["iam:PassRole", "ecs:RegisterTaskDefinition",
                             "ecs:RunTask"],
        "gained": "role_takeover",
        "impact": "Register/run an ECS task with an arbitrary role and execute "
                  "code inside it.",
        "family": "passrole",
    },
    {
        "id": "PassRoleCloudFormation",
        "name": "iam:PassRole + cloudformation:CreateStack",
        "required_actions": ["iam:PassRole", "cloudformation:CreateStack"],
        "gained": "role_takeover",
        "impact": "Create a CloudFormation stack with an arbitrary role; custom "
                  "resources execute with it.",
        "family": "passrole",
    },
    {
        "id": "PassRoleDataPipeline",
        "name": "iam:PassRole + datapipeline:CreatePipeline",
        "required_actions": ["iam:PassRole", "datapipeline:CreatePipeline"],
        "gained": "role_takeover",
        "impact": "Create a Data Pipeline that runs with an arbitrary role.",
        "family": "passrole",
    },
    {
        "id": "PassRoleSageMaker",
        "name": "iam:PassRole + sagemaker:CreateNotebookInstance",
        "required_actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "gained": "role_takeover",
        "impact": "Create a SageMaker notebook with an arbitrary role and "
                  "execute code as it.",
        "family": "passrole",
    },
    {
        "id": "PassRoleCodePipeline",
        "name": "iam:PassRole + codepipeline:CreatePipeline",
        "required_actions": ["iam:PassRole", "codepipeline:CreatePipeline"],
        "gained": "role_takeover",
        "impact": "Create a CodePipeline that runs with an arbitrary role.",
        "family": "passrole",
    },
    {
        "id": "PassRoleEcsCape",
        "name": "iam:PassRole + ecs agent socket (ECS-cape)",
        "required_actions": ["iam:PassRole", "ecs:RunTask"],
        "gained": "role_takeover",
        "impact": "ECS-cape class (Black Hat USA 2025): low-priv ECS task "
                  "hijacks privileges via the ecs-agent docker socket.",
        "family": "passrole",
    },
    {
        "id": "AssumeRole",
        "name": "sts:AssumeRole",
        "required_actions": ["sts:AssumeRole"],
        "gained": "role_takeover",
        "impact": "Directly assume any role whose trust policy permits this "
                  "principal (when combined with a broad PassRole/resource).",
        "family": "identity",
    },
]

# Actions that imply a whole service's admin surface.
_WILDCARD_SERVICE_ADMIN = {"iam:*"}


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _action_set(actions: Any) -> Set[str]:
    """Normalize an IAM Action/NotAction value to a set of action strings."""
    if isinstance(actions, str):
        return {actions}
    if isinstance(actions, list):
        out: Set[str] = set()
        for a in actions:
            if isinstance(a, str):
                out.add(a)
        return out
    return set()


def _wildcard_matches(pattern: str, action: str) -> bool:
    """Match an IAM action pattern ('iam:*', 'iam:Get*', '*') against an action."""
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == action
    # Convert glob to regex, anchored.
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, action) is not None


def _granted_actions(statements: List[Dict[str, Any]]) -> Set[str]:
    """Effective granted action set from a list of policy statements."""
    granted: Set[str] = set()
    for st in statements:
        if not isinstance(st, dict):
            continue
        effect = str(st.get("Effect", "")).lower()
        if effect == "allow":
            granted |= _action_set(st.get("Action"))
    return granted


def _has_action(granted: Set[str], required: str) -> bool:
    """True if the granted set can satisfy a required action pattern."""
    return any(_wildcard_matches(pattern, required) for pattern in granted)


def _method_unlocked(method: Dict[str, Any], granted: Set[str],
                     admin_override: bool = False) -> bool:
    """A method is unlocked when every required action is granted (or admin)."""
    if admin_override:
        return True
    return all(_has_action(granted, req) for req in method["required_actions"])


# ---------------------------------------------------------------------------

@dataclass
class EscalationHop:
    method_id: str
    method_name: str
    family: str
    gained: str
    impact: str
    unlocking_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EscalationPath:
    path_id: str
    hops: List[EscalationHop]
    end_capability: str
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "hops": [h.to_dict() for h in self.hops],
            "end_capability": self.end_capability,
            "summary": self.summary,
        }


@dataclass
class IamPrivescAnalysis:
    target: str
    generated_at: str
    base_actions: List[str]
    directly_reachable: List[EscalationHop] = field(default_factory=list)
    paths: List[EscalationPath] = field(default_factory=list)
    admin_reachable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "base_action_count": len(self.base_actions),
            "base_actions": sorted(self.base_actions),
            "admin_reachable": self.admin_reachable,
            "directly_reachable": [h.to_dict() for h in self.directly_reachable],
            "paths": [p.to_dict() for p in self.paths],
        }


def parse_policy_dump(raw: Any) -> List[Dict[str, Any]]:
    """Extract a list of policy statements from an operator-supplied dump.

    Accepts: a list of policy documents, a dict with a 'Policies'/'Statement'
    key, or a single policy document dict.
    """
    if isinstance(raw, list):
        statements: List[Dict[str, Any]] = []
        for entry in raw:
            statements.extend(parse_policy_dump(entry))
        return statements
    if not isinstance(raw, dict):
        return []
    for key in ("Policies", "policies", "PolicyDocument", "policy"):
        value = raw.get(key)
        if isinstance(value, dict):
            return parse_policy_dump(value)
        if isinstance(value, list):
            return parse_policy_dump(value)
    statement = raw.get("Statement")
    if isinstance(statement, list):
        return [s for s in statement if isinstance(s, dict)]
    if isinstance(statement, dict):
        return [statement]
    return []


def _analyze_closure(methods: List[Dict[str, Any]], granted: Set[str]) -> Tuple[bool, Set[str]]:
    """Compute the escalation closure: returns (admin_reachable, granted_closure).

    If any policy-write method is reachable, the principal can mint admin and
    therefore every method becomes reachable.
    """
    admin = False
    for method in methods:
        if method["family"] == "policy_write" and _method_unlocked(method, granted):
            admin = True
            break
    if not admin:
        return False, granted
    # Admin override makes every method reachable.
    return True, granted | {"*"}


def analyze(target: str, policy_dump: Any) -> IamPrivescAnalysis:
    """Deterministically compute the privesc graph from a policy dump."""
    statements = parse_policy_dump(policy_dump)
    granted = _granted_actions(statements)
    admin, closure = _analyze_closure(PRIVESC_METHODS, granted)

    analysis = IamPrivescAnalysis(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        base_actions=sorted(granted),
        admin_reachable=admin,
    )

    # Directly reachable methods from the closure.
    direct: List[EscalationHop] = []
    for method in PRIVESC_METHODS:
        if not _method_unlocked(method, closure, admin_override=False):
            continue
        unlocking = [a for a in method["required_actions"]
                     if not _has_action(granted, a) and not admin]
        if admin:
            unlocking = []
        direct.append(EscalationHop(
            method_id=method["id"],
            method_name=method["name"],
            family=method["family"],
            gained=method["gained"],
            impact=method["impact"],
            unlocking_actions=sorted(set(unlocking)),
        ))
    analysis.directly_reachable = direct

    # Build escalation paths: one per directly-reachable method, plus the
    # admin closure path when policy-write methods exist.
    seen_methods: Set[str] = set()
    for hop in direct:
        if hop.method_id in seen_methods:
            continue
        seen_methods.add(hop.method_id)
        end = "admin" if admin else hop.gained
        if end == "admin" and not admin:
            end = hop.gained
        path = EscalationPath(
            path_id=_id("path", target, hop.method_id),
            hops=[hop],
            end_capability=end,
            summary=f"{hop.method_name} -> {end}",
        )
        analysis.paths.append(path)

    # If policy-write methods exist, add the canonical multi-hop admin path.
    policy_write = [h for h in direct if h.family == "policy_write"]
    if policy_write and len(policy_write) == 1:
        # A single method that lands on admin directly is already captured.
        pass
    if admin and policy_write:
        first = policy_write[0]
        summary = f"{first.method_name} -> admin (escalation closure)"
        analysis.paths.append(EscalationPath(
            path_id=_id("path", target, "admin-closure"),
            hops=[first],
            end_capability="admin",
            summary=summary,
        ))

    return analysis


def write_analysis(analysis: IamPrivescAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to state/capability/iam-privesc-<target>.json (coverage-plan artifact)."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", analysis.target) or "default"
    out_dir = root / "state" / "capability"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"iam-privesc-{target_slug}.json"
    out.write_text(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="IAM privilege-escalation capability graph")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--policy", required=True, help="path to IAM policy dump JSON")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    policy_path = Path(args.policy)
    try:
        raw = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read policy dump: {exc}"}))
        return 2

    analysis = analyze(args.target, raw)
    out = write_analysis(analysis, project_root=args.project_root,
                         base_dir=args.base_dir)

    # Publish CLOUD_CANDIDATE for high-impact reachable methods.
    high = [h for h in analysis.directly_reachable
            if h.gained in ("admin", "role_takeover", "credentials")]
    if high:
        try:
            bus = SignalBus(args.target,
                            project_root=args.project_root or args.base_dir)
            for hop in high:
                bus.publish("CLOUD_CANDIDATE", source="iam_privesc_graph",
                            payload={"method": hop.method_name,
                                     "gained": hop.gained,
                                     "impact": hop.impact})
        except Exception as exc:  # advisory, never a gate
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(analysis.directly_reachable)} reachable "
              f"privesc methods "
              f"(admin={analysis.admin_reachable}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
