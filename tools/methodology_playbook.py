#!/usr/bin/env python3
"""Offline methodology and validation planning for BugWolf.

This module converts recon/scanner signals into human-review tasks. It does
not send requests or execute ffuf, nuclei, SQLMap, or XSStrike. The generated
argv plans are intentionally confirmation-gated and exclude database dumping,
credential attacks, takeover actions, and destructive workflow operations.

Usage:
  python3 tools/methodology_playbook.py --target T --urls-file recon/T/urls.txt --signals-file recon/T/nuclei.txt --output-dir recon/T/methodology --scope-file scope.json
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import parse_qs, urlparse

try:
    from tools.ai_defense import analyze_paths as analyze_ai_paths
    from tools.chain_analyzer import analyze_paths as analyze_chain_paths
    from tools.idor_research import build_idor_matrix
    from tools.safety import AuthorizationError, safe_target_name, target_in_scope
except ImportError:  # direct script execution
    from ai_defense import analyze_paths as analyze_ai_paths  # type: ignore
    from chain_analyzer import analyze_paths as analyze_chain_paths  # type: ignore
    from idor_research import build_idor_matrix  # type: ignore
    from safety import AuthorizationError, safe_target_name, target_in_scope  # type: ignore


PLAYBOOK_SCHEMA = "bugwolf-methodology-playbook-v1"


@dataclass
class WorkflowPlan:
    plan_id: str
    target: str
    category: str
    location: str
    title: str
    purpose: str
    baseline: List[str]
    mutations: List[str]
    invariant: str
    impact_questions: List[str]
    evidence_required: List[str]
    stop_conditions: List[str]
    risk: str = "read_only_manual_review"
    status: str = "hypothesis_only"


@dataclass
class ValidationTask:
    task_id: str
    target: str
    signal_type: str
    location: str
    title: str
    trigger_questions: List[str]
    impact_questions: List[str]
    evidence_required: List[str]
    stop_conditions: List[str]
    recommended_next_step: str
    severity_hint: str = "info"
    status: str = "pending_human_validation"
    tool_plan_ids: List[str] = field(default_factory=list)


@dataclass
class ToolPlan:
    plan_id: str
    tool: str
    purpose: str
    argv: List[str]
    input_location: str
    safety_requirements: List[str]
    excluded_actions: List[str]
    status: str = "not_executed_offline_plan"


def _id(prefix: str, *parts: str) -> str:
    import hashlib
    raw = "|".join(str(part).strip().lower() for part in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _scope_urls(urls: Iterable[str], target: str, scope: Optional[Dict[str, Any]]) -> List[str]:
    result = []
    seen = set()
    for value in urls:
        value = str(value).strip()
        if not value or value in seen:
            continue
        try:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            if scope is not None and not target_in_scope(value, scope):
                continue
            if scope is None and not (parsed.hostname == target or parsed.hostname.endswith("." + target)):
                continue
        except (ValueError, AuthorizationError):
            continue
        result.append(value)
        seen.add(value)
    return result


def _plan(target: str, category: str, location: str, title: str,
          purpose: str, mutations: Sequence[str], invariant: str,
          impact: Sequence[str], evidence: Sequence[str],
          *, risk: str = "read_only_manual_review") -> WorkflowPlan:
    return WorkflowPlan(
        plan_id=_id("workflow", target, category, location, title),
        target=target,
        category=category,
        location=location,
        title=title,
        purpose=purpose,
        baseline=["Use a dedicated authorized test account and record one normal successful flow.",
                  "Capture request, response, actor/role, object ownership, and state before/after."],
        mutations=list(mutations),
        invariant=invariant,
        impact_questions=list(impact),
        evidence_required=list(evidence),
        stop_conditions=[
            "Stop at the first non-test account, sensitive record, real payment, or irreversible action.",
            "Do not continue when scope, authorization, or test-data ownership is unclear.",
            "A response difference is only a signal until trigger and victim impact are independently proven.",
        ],
        risk=risk,
    )


def build_workflow_plans(target: str, urls: Iterable[str], *,
                         scope: Optional[Dict[str, Any]] = None,
                         max_plans: int = 96) -> List[WorkflowPlan]:
    """Generate bounded workflow hypotheses from scoped endpoint names."""
    safe_target_name(target)
    plans: List[WorkflowPlan] = []
    for url in _scope_urls(urls, target, scope):
        parsed = urlparse(url)
        blob = (parsed.path + "?" + parsed.query).lower()
        params = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
        categories: List[str] = []
        if re.search(r"verify|activate|confirm|signup|register|reset|password", blob):
            categories.extend(["step_skip", "token_reuse"])
        if re.search(r"checkout|payment|purchase|order|subscription|upgrade|downgrade|coupon|refund", blob):
            categories.extend(["payment_state", "repeat_or_reorder"])
        if re.search(r"admin|manage|dashboard|role|permission|export|internal", blob):
            categories.extend(["role_boundary", "hidden_feature"])
        if re.search(r"upload|download|export|import|attachment|file|media", blob):
            categories.append("file_boundary")
        if params.intersection({"id", "uid", "user", "user_id", "account", "account_id", "order", "order_id", "profile"}):
            categories.append("ownership_boundary")
        if re.search(r"resend|retry|cancel|submit|transfer|invite|apply", blob):
            categories.append("replay_idempotency")
        if not categories and parsed.query:
            categories.append("server_side_validation")

        for category in dict.fromkeys(categories):
            if len(plans) >= max_plans:
                return plans
            common_evidence = [
                "Sanitized request/response pair for baseline and mutation.",
                "Test-account identifiers and ownership/role mapping, without victim data.",
                "State transition or invariant comparison with timestamps and hashes.",
            ]
            if category == "step_skip":
                plans.append(_plan(target, category, url, "Skip a required workflow step",
                    "Determine whether the server enforces sequence rather than relying on the client UI.",
                    ["Call the final endpoint without the preceding step.", "Remove client-only completion or verification fields."],
                    "A protected state cannot be reached before its prerequisite is completed.",
                    ["Does the actor gain access, capability, or value without the prerequisite?", "Is the result limited to the test account?"], common_evidence))
            elif category == "token_reuse":
                plans.append(_plan(target, category, url, "Check one-time token invalidation",
                    "Determine whether a completed reset, verification, or action token remains usable.",
                    ["Replay the same token once using the same test account.", "Compare behavior after expiry or successful completion."],
                    "A one-time token is accepted at most once and is bound to the intended account and action.",
                    ["Can the token repeat an account or authorization action?", "Can it be transferred across test accounts?"], common_evidence))
            elif category == "payment_state":
                plans.append(_plan(target, category, url, "Check payment/state transition integrity",
                    "Determine whether fulfillment depends on a server-verified payment event rather than a client flag or sequence assumption.",
                    ["Use a zero-value or sandbox transaction only.", "Omit or alter client-visible payment status in a test order.", "Request confirmation before the payment step."],
                    "No fulfillment, credit, upgrade, or refund occurs without a verified authorized payment transition.",
                    ["Is any real value created or transferred?", "Can the result be rolled back in the sandbox?"], common_evidence,
                    risk="state_change_test_account_only"))
            elif category == "repeat_or_reorder":
                plans.append(_plan(target, category, url, "Check repeat and reorder handling",
                    "Determine whether actions are idempotent and whether step ordering is enforced server-side.",
                    ["Replay one request once with the same idempotency key.", "Submit the later step before the earlier step.", "Swap two adjacent test-flow steps."],
                    "Repeating or reordering a workflow cannot create duplicate value or bypass a prerequisite.",
                    ["Are duplicate records, credits, messages, or permissions created?", "Can the test state be restored?"], common_evidence,
                    risk="state_change_test_account_only"))
            elif category == "role_boundary":
                plans.append(_plan(target, category, url, "Compare role and field authorization",
                    "Determine whether server authorization, not UI visibility or a client field, controls privileged actions.",
                    ["Compare a regular test account with an authorized privileged test account.", "Remove or alter role/permission fields only on owned test data."],
                    "A caller cannot gain a role or privileged operation by changing client-controlled fields.",
                    ["Does the lower-privilege account cross the boundary?", "What is the minimum affected test resource?"], common_evidence))
            elif category == "hidden_feature":
                plans.append(_plan(target, category, url, "Validate hidden endpoint authorization",
                    "Determine whether a feature hidden from the UI is still protected at the server boundary.",
                    ["Request the endpoint with the lower-privilege test account.", "Compare allowed method and role combinations."],
                    "Removing a UI control does not change server-side authorization requirements.",
                    ["Does the response expose only the test account's data?", "Is the action read-only?"], common_evidence))
            elif category == "file_boundary":
                plans.append(_plan(target, category, url, "Validate file ownership and access boundary",
                    "Determine whether upload/download/export references are bound to the owning test account and intended content type.",
                    ["Swap two owned test-file references.", "Compare direct access before and after authorization changes.", "Use harmless text fixtures only."],
                    "A file reference cannot cross an account or authorization boundary.",
                    ["Is any private or executable content exposed?", "Can the fixture be deleted or revoked?"], common_evidence))
            elif category == "ownership_boundary":
                plans.append(_plan(target, category, url, "Compare owned test objects",
                    "Determine whether object access is authorized independently of predictable or client-supplied identifiers.",
                    ["Use two cooperating test accounts and swap only their owned object IDs.", "Compare status, body class, and side effects without collecting sensitive data."],
                    "An account can access only objects authorized for that account and tenant.",
                    ["Does the second test account see data or perform an action on the first account's object?", "Can the test objects be deleted?"], common_evidence))
            elif category == "replay_idempotency":
                plans.append(_plan(target, category, url, "Check one-time and idempotency controls",
                    "Determine whether retries, duplicate submissions, and concurrent-safe retries preserve the intended single outcome.",
                    ["Replay once with the same request and idempotency key.", "Replay once without the key only in a disposable test flow."],
                    "A retried operation has one intended outcome and cannot multiply value or privilege.",
                    ["Did the server create duplicate value or state?", "Is the operation reversible?"], common_evidence,
                    risk="state_change_test_account_only"))
            elif category == "server_side_validation":
                plans.append(_plan(target, category, url, "Compare client and server validation",
                    "Determine whether constraints shown in JavaScript are enforced by the server.",
                    ["Use a minimally out-of-range value on a disposable test record.", "Remove client-only fields or submit an alternate content type."],
                    "Server-side validation enforces security and business constraints regardless of the client.",
                    ["Does the change create security or business impact?", "Can the record be removed?"], common_evidence,
                    risk="state_change_test_account_only"))
    return plans


def _signal_type(record: Dict[str, Any]) -> str:
    blob = json.dumps(record, sort_keys=True, default=str).lower()
    if "idor" in blob or "object reference" in blob:
        return "idor_signal"
    if "sql" in blob or "injection" in blob:
        return "sql_injection_signal"
    if "xss" in blob or "cross-site scripting" in blob:
        return "xss_signal"
    if "nuclei" in blob or "template-id" in blob or "template_id" in blob:
        return "known_scanner_signal"
    if "ffuf" in blob or "directory" in blob or "discovery" in blob:
        return "surface_discovery_signal"
    if "httpx" in blob or "status_code" in blob or "status-code" in blob:
        return "surface_signal"
    if "differential" in blob or "response" in blob:
        return "response_differential_signal"
    return "unclassified_signal"


def _location(record: Dict[str, Any]) -> str:
    for key in ("location", "url", "matched-at", "matched_at", "endpoint", "host"):
        value = record.get(key)
        if value:
            return str(value)
    info = record.get("info")
    if isinstance(info, dict):
        for key in ("matched-at", "name", "template-id"):
            if info.get(key):
                return str(info[key])
    return "unknown"


def _task_for_signal(target: str, record: Dict[str, Any]) -> ValidationTask:
    signal_type = _signal_type(record)
    location = _location(record)
    common_trigger = [
        "Can the signal be reproduced from an authorized test account?",
        "Is the behavior caused by the suspected input or merely a normal response difference?",
    ]
    common_impact = [
        "What exact asset, identity, state, or capability is affected?",
        "Can impact be demonstrated only with disposable test data?",
        "Does the result cross an authorization, tenant, or value boundary?",
    ]
    evidence = [
        "Baseline and mutated request/response with secrets and personal data redacted.",
        "Test-account/role/object ownership map.",
        "Observed trigger and bounded impact trace, not a scanner label alone.",
    ]
    if signal_type == "idor_signal":
        title = "Validate object authorization with two cooperating test accounts"
        trigger = common_trigger + ["Does swapping only an owned test object reference change authorization behavior?"]
        impact = common_impact + ["Can the second test account read or modify the first account's disposable object?"]
        severity = "high"
        next_step = "Manual two-account comparison; never access a third party's data."
    elif signal_type == "sql_injection_signal":
        title = "Validate suspected injection without data extraction"
        trigger = common_trigger + ["Does a minimally invasive, controlled input produce a stable database-error or differential signal?"]
        impact = common_impact + ["Can impact be bounded to a sandbox or test database without enumerating or dumping data?"]
        severity = "high"
        next_step = "Capture the request, reproduce manually, then consider a confirmation-only SQLMap plan; no --dbs, --tables, or --dump flags."
    elif signal_type == "xss_signal":
        title = "Validate reflection and execution context"
        trigger = common_trigger + ["Is the value reflected in a security-relevant browser context under a harmless marker?"]
        impact = common_impact + ["Is execution demonstrated only in a controlled browser/test account?"]
        severity = "medium"
        next_step = "Inspect context manually before considering an XSStrike confirmation plan."
    elif signal_type == "known_scanner_signal":
        title = "Reproduce and impact-bound a scanner signal"
        trigger = common_trigger + ["Does the named template match the actual version, route, and response?", "Is the signal a duplicate or known behavior?"]
        impact = common_impact + ["What is the smallest safe proof of impact?"]
        severity = "info"
        next_step = "Read the template, reproduce minimally, and record a manual evidence bundle."
    elif signal_type == "surface_discovery_signal":
        title = "Classify discovered surface before testing"
        trigger = ["Is the path in scope and reachable with an authorized test account?", "Does it expose a new workflow or object boundary?"]
        impact = ["What sensitive capability could this surface expose?", "Can it be assessed without brute force or sensitive content collection?"]
        severity = "info"
        next_step = "Prioritize manually; ffuf output is discovery evidence, not a vulnerability."
    else:
        title = "Classify and validate recon signal"
        trigger = common_trigger
        impact = common_impact
        severity = "info"
        next_step = "Correlate with workflow, authorization, and state maps before testing."
    return ValidationTask(
        task_id=_id("task", target, signal_type, location), target=target,
        signal_type=signal_type, location=location, title=title,
        trigger_questions=trigger, impact_questions=impact,
        evidence_required=evidence,
        stop_conditions=["Stop on sensitive data, non-test accounts, irreversible state, or scope ambiguity."],
        recommended_next_step=next_step, severity_hint=severity,
    )


def build_validation_tasks(target: str, signals: Iterable[Dict[str, Any]], *,
                           max_tasks: int = 128) -> List[ValidationTask]:
    safe_target_name(target)
    tasks: List[ValidationTask] = []
    seen = set()
    for record in signals:
        task = _task_for_signal(target, record)
        if task.task_id in seen:
            continue
        seen.add(task.task_id)
        tasks.append(task)
        if len(tasks) >= max_tasks:
            break
    return tasks


def build_tool_plans(target: str, tasks: Iterable[ValidationTask], *,
                     wordlist: str = "target-specific-wordlist.txt",
                     request_file: str = "authorized-request.txt",
                     output_dir: str = "validation-artifacts") -> List[ToolPlan]:
    """Create non-executing, confirmation-gated plans for installed tools."""
    safe_target_name(target)
    plans: List[ToolPlan] = []
    for task in tasks:
        if task.signal_type == "surface_discovery_signal":
            plan = ToolPlan(
                plan_id=_id("tool", "ffuf", task.task_id), tool="ffuf",
                purpose="Bounded endpoint/surface confirmation; discovery only.",
                argv=["ffuf", "-request", request_file, "-w", wordlist,
                      "-rate", "5", "-t", "5", "-mc", "200,204,301,302,401,403",
                      "-of", "json", "-o", f"{output_dir}/ffuf.json"],
                input_location=task.location,
                safety_requirements=["explicit scope", "test account where authentication is required", "separate active confirmation", "bounded wordlist and rate"],
                excluded_actions=["no destructive methods", "no credential brute force", "no out-of-scope hosts"],
            )
        elif task.signal_type == "known_scanner_signal":
            plan = ToolPlan(
                plan_id=_id("tool", "nuclei", task.task_id), tool="nuclei",
                purpose="Confirm a named template signal against the exact authorized URL.",
                argv=["nuclei", "-l", request_file, "-jsonl", "-rl", "5", "-c", "2",
                      "-severity", "info,low,medium,high,critical", "-o", f"{output_dir}/nuclei-confirm.jsonl"],
                input_location=task.location,
                safety_requirements=["read template before use", "explicit scope", "active confirmation", "bounded rate/concurrency"],
                excluded_actions=["no template execution outside the matched scope", "no destructive templates", "no automatic finding promotion"],
            )
        elif task.signal_type == "sql_injection_signal":
            plan = ToolPlan(
                plan_id=_id("tool", "sqlmap", task.task_id), tool="sqlmap",
                purpose="Confirmation-only injection check after manual evidence.",
                argv=["sqlmap", "-r", request_file, "--batch", "--smart", "--level=1", "--risk=1",
                      "--flush-session", "--output-dir", f"{output_dir}/sqlmap"],
                input_location=task.location,
                safety_requirements=["manual signal first", "explicit active confirmation", "sandbox/test data", "scope and rate review"],
                excluded_actions=["no --dbs", "no --tables", "no --dump", "no credential extraction", "no destructive statements"],
            )
        elif task.signal_type == "xss_signal":
            plan = ToolPlan(
                plan_id=_id("tool", "xsstrike", task.task_id), tool="xsstrike",
                purpose="Confirmation-only reflected/DOM context check after manual review.",
                argv=["xsstrike", "-u", task.location, "--crawl", "0"],
                input_location=task.location,
                safety_requirements=["manual reflection/context review", "explicit active confirmation", "controlled browser/test account"],
                excluded_actions=["no stored payloads", "no mass crawling", "no out-of-scope URLs", "no automatic finding promotion"],
            )
        else:
            continue
        plans.append(plan)
        task.tool_plan_ids.append(plan.plan_id)
    return plans


# ---------------------------------------------------------------------------
# Specification-first methodology (Sewell — "Escaping the Quicksand" 2608.19674)
# ---------------------------------------------------------------------------

_SPEC_CATEGORIES = (
    ("precondition", "What must be true before the operation? (auth, state, ownership, time)"),
    ("postcondition", "What must be true after? (balance change, state transition, event emission)"),
    ("invariant", "What must never be violated? (total supply, access control, monotonicity)"),
    ("boundary", "Where does trust end? (user input, cross-contract call, bridge, oracle)"),
    ("failure_mode", "What happens on failure? (revert, partial state, silent, fallback)"),
)


def build_specification_plans(
    target: str,
    context: Mapping[str, Any] | None = None,
    *,
    categories: Sequence[str] = (),
) -> List[WorkflowPlan]:
    """Generate executable-oracle specification plans for a target.

    Based on Sewell & Pichon-Pharabod's argument that incrementally
    co-developing executable partial specifications alongside code provides
    more discriminating test oracles than prose descriptions alone.

    Each plan is a hypothesis about a specification condition that can be
    tested; it does not execute the target or mutate state.
    """
    ctx = dict(context or {})
    selected = [cat for cat in categories if cat in dict(_SPEC_CATEGORIES)] if categories \
        else [name for name, _ in _SPEC_CATEGORIES]

    plans: List[WorkflowPlan] = []
    for category in selected:
        description = dict(_SPEC_CATEGORIES).get(category, category)
        plan_id = _spec_plan_id(target, category)
        plans.append(WorkflowPlan(
            plan_id=plan_id, target=target, category=f"specification:{category}",
            location="target-boundary",
            title=f"Specification check: {category}",
            purpose=f"Verify that the {category} condition is explicit and testable.",
            baseline=[
                f"Document the {category} condition in prose and executable form.",
                f"Identify at least one positive and one negative test case.",
            ],
            mutations=[
                f"Probe what happens when the {category} is violated.",
                f"Test at boundary values (minimum, maximum, zero, absent).",
            ],
            invariant=description,
            impact_questions=[
                f"Is the {category} enforced in code or only documented?",
                f"Can the condition be verified without full system execution?",
                f"Does a human or an automated test verify this today?",
            ],
            evidence_required=[
                "Executable test that passes when condition holds.",
                "Executable test that correctly fails when condition is violated.",
                "Specification snapshot (hash) for regression.",
            ],
            stop_conditions=[
                "Do not execute tests that modify production state.",
                "Do not infer specification from observed behavior alone.",
            ],
            status="specification_hypothesis",
        ))
    return plans


def _spec_plan_id(target: str, category: str) -> str:
    return "spec-" + hashlib.sha256(f"{target}:{category}".encode()).hexdigest()[:12]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
        except json.JSONDecodeError:
            rows.append({"source": str(path), "text": line})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline methodology playbook")
    parser.add_argument("--target", required=True)
    parser.add_argument("--urls-file", default="")
    parser.add_argument("--signals-file", default="")
    parser.add_argument("--source-file", action="append", default=[],
                        help="local source/config artifact for static chain and AI analysis")
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--wordlist", default="target-specific-wordlist.txt")
    parser.add_argument("--request-file", default="authorized-request.txt")
    args = parser.parse_args()
    safe_target_name(args.target)
    scope = None
    if args.scope_file:
        scope_data = json.loads(Path(args.scope_file).read_text(encoding="utf-8"))
        if scope_data.get("authorized") is not True:
            raise SystemExit(2)
        scope = scope_data
    urls = []
    if args.urls_file and Path(args.urls_file).is_file():
        urls = Path(args.urls_file).read_text(encoding="utf-8", errors="replace").splitlines()
    plans = build_workflow_plans(args.target, urls, scope=scope)
    idor_plans = build_idor_matrix(args.target, urls, scope=scope)
    signals = load_jsonl(Path(args.signals_file)) if args.signals_file and Path(args.signals_file).is_file() else []
    tasks = build_validation_tasks(args.target, signals)
    tool_plans = build_tool_plans(args.target, tasks, wordlist=args.wordlist, request_file=args.request_file)
    source_paths = [Path(path) for path in args.source_file]
    chain_findings, chain_plans = analyze_chain_paths(source_paths)
    ai_findings, ai_plans = analyze_ai_paths(source_paths)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    for name, rows in (("workflow-plans.jsonl", plans), ("idor-matrix.jsonl", idor_plans), ("validation-tasks.jsonl", tasks), ("tool-plans.jsonl", tool_plans), ("static-findings.jsonl", chain_findings), ("chain-plans.jsonl", chain_plans), ("ai-findings.jsonl", ai_findings), ("ai-defense-plans.jsonl", ai_plans)):
        with (output / name).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    manifest = {"schema": PLAYBOOK_SCHEMA, "target": args.target,
                "workflow_plans": len(plans), "idor_plans": len(idor_plans),
                "validation_tasks": len(tasks), "tool_plans": len(tool_plans),
                "static_findings": len(chain_findings), "chain_plans": len(chain_plans),
                "ai_findings": len(ai_findings), "ai_defense_plans": len(ai_plans),
                "execution": "offline_only"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
