#!/usr/bin/env python3
"""Offline IDOR/access-control research planning.

The planner covers direct, UUID, encoded, composite, function-level,
second-order, file/export, GraphQL, mobile, and WebSocket references, plus
the additional surfaces from the common-vectors checklist: numeric path ids
(/users/42), file names (/uploads/<uuid>.pdf), custom account headers
(X-Account-Id: 42), cookie variables (userid=42; tenant=7), GraphQL global
node ids (gid://... via node(id:)), and JWT claim references ("sub": 42).
Case-study patterns are represented as planning notes: gid:// node-ID
enumeration (HackerOne #1618347), chained mass-assignment IDOR (Buganizer-
style chains), and Android PendingIntent notification hijack.

It never enumerates users, requests victim data, replays sessions, or
performs state changes. Plans require two cooperating authorized test
accounts and disposable fixtures.

Usage:
  python3 tools/idor_research.py --target T --endpoints-file recon/T/urls.txt --json
  python3 tools/idor_research.py --target T --bfla --openapi openapi.json --role-sets roles.json --json
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from tools.safety import AuthorizationError, safe_target_name, target_in_scope
except ImportError:  # direct script execution
    from safety import AuthorizationError, safe_target_name, target_in_scope  # type: ignore


OBJECT_KEYS = {
    "id", "uid", "user", "user_id", "target_user", "target", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "message", "message_id", "profile",
    "profile_id", "document", "document_id", "file", "file_id", "photo", "photo_id",
    "post_id", "comment_id", "tenant", "tenant_id", "org", "org_id", "project",
    "project_id", "export", "export_id", "job", "job_id", "token", "uuid",
    "recipient", "receiver", "owner", "creator", "actor", "customer", "customer_id",
    "client", "client_id", "company", "company_id", "vendor", "supplier", "group",
    "group_id", "team", "team_id", "workspace", "workspace_id", "channel", "card",
    "event", "event_id", "booking", "reservation", "payment", "payment_id",
    "transaction", "transaction_id", "subscription", "subscription_id", "license",
    "asset", "asset_id", "device", "device_id", "patient", "patient_id", "student",
    "student_id", "employee", "employee_id", "member", "member_id", "sub", "sub_id",
}

# Custom headers that commonly carry a cross-account object reference. When an
# application trusts the client for the *acting* tenant/account (instead of
# deriving it from the authenticated session), the header becomes an IDOR
# surface (X-Account-Id: 42 from the common-vectors checklist).
ID_HEADER_NAMES = {
    "x-account-id", "x-user-id", "x-tenant-id", "x-org-id", "x-organization-id",
    "x-customer-id", "x-client-id", "x-company-id", "x-group-id", "x-workspace-id",
    "x-team-id", "x-project-id", "x-uid", "x-uuid", "account-id", "user-id",
    "tenant-id", "org-id", "customer-id", "client-id",
}

# Cookie names that commonly carry an object/tenant reference (userid=42;
# tenant=7 from the common-vectors checklist).
ID_COOKIE_NAMES = {
    "userid", "uid", "user_id", "account_id", "tenant", "tenant_id", "org",
    "org_id", "customer_id", "client_id", "uuid", "profile_id", "company_id",
}

# GraphQL global (node) IDs: gid://<type>/<class>::<Type>/<id> — the HackerOne
# disclosure (#1618347) shows composite ids like gid://hackerone/PolicyPage
# AssetGroupsIndex::PolicyPageAssetGroup/3981-41287 leaking private program
# scope when passed to node(id:).
_GID_RE = re.compile(r"gid://[A-Za-z0-9_]+/[^/\s]+/\d[0-9-]*")


@dataclass
class IdorReference:
    reference_id: str
    location: str
    parameter: str
    reference_type: str
    operation: str = "read"
    notes: List[str] = field(default_factory=list)


@dataclass
class IdorValidationPlan:
    plan_id: str
    location: str
    reference_type: str
    accounts: List[str]
    baseline: List[str]
    mutations: List[str]
    invariant: str
    impact_boundaries: List[str]
    evidence_required: List[str]
    prohibited_actions: List[str]
    status: str = "offline_plan_only"


@dataclass
class BflaValidationPlan:
    """Function-level (BFLA) authorization plan: call function X as role Y.

    BFLA is the function-level twin of BOLA: the object is in scope for the
    caller, but the *function* (privileged action) requires a role the caller
    does not hold.  Plans are offline-only and require cooperating test
    accounts with distinct declared roles.
    """
    plan_id: str
    function: str
    method: str
    location: str
    declared_roles: List[str]
    required_role: str
    baseline: List[str]
    mutations: List[str]
    invariant: str
    impact_boundaries: List[str]
    evidence_required: List[str]
    prohibited_actions: List[str]
    status: str = "offline_plan_only"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(item).strip().lower() for item in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _decode_hint(value: str) -> bool:
    value = unquote(value).strip()
    if len(value) < 8 or len(value) % 4:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode(errors="ignore")
    except Exception:
        return False
    return bool(re.search(r"(?i)(user|account|order|invoice|file|document|id)[_-]?\d+", decoded))


def classify_endpoint(url: str, *, method: str = "GET", body: str = "",
                      headers: str = "", cookies: str = "") -> List[IdorReference]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parse_qs(parsed.query, keep_blank_values=True)
    body_lower = body.lower()
    keys = list(query)
    keys.extend(re.findall(r"[\"']([A-Za-z][A-Za-z0-9_-]*(?:id|uuid|token|user|tenant|account|org))[\"']\s*:", body))
    unique_keys = list(dict.fromkeys(key.lower() for key in keys))
    object_keys = [key for key in unique_keys if key in OBJECT_KEYS or key.endswith(("_id", "id", "uuid"))]
    references: List[IdorReference] = []
    operation = method.upper().lower()
    if operation in {"PUT", "PATCH", "POST", "DELETE"}:
        operation = "function" if any(term in path for term in ("delete", "update", "role", "export", "close", "ban", "invite", "transfer")) else "write"
    if not object_keys and re.search(r"/[0-9a-f]{8}-[0-9a-f-]{27,}/", path):
        object_keys = ["path_uuid"]
    for key in object_keys:
        values = query.get(key, [])
        reference_type = "direct"
        notes: List[str] = []
        if key == "path_uuid" or any(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27,}", value, re.I) for value in values):
            reference_type = "uuid_or_opaque"
            notes.append("Check whether the reference leaks through owned responses, JS, mail, or shared fixtures.")
        if any(_decode_hint(value) for value in values):
            reference_type = "encoded"
            notes.append("Use an owned fixture and compare only a transformed reference; do not decode or access third-party files.")
        if len(object_keys) > 1:
            reference_type = "composite"
            notes.append("Test ownership consistency across each reference pair; avoid cartesian enumeration.")
        if any(term in path for term in ("graphql", "query", "mutation")) or "graphql" in body_lower:
            reference_type = "graphql"
            notes.append("Compare query fields and object arguments using two cooperating test accounts.")
        if path.startswith("/api/v") or "/mobile" in path or "android" in body_lower or "ios" in body_lower:
            if reference_type == "direct":
                reference_type = "mobile_api"
            notes.append("Treat mobile APIs as the same server-side authorization boundary; client secrecy is not authorization.")
        if re.search(r"/(?:files?|downloads?|uploads?|exports?|invoices?|attachments?)(?:/|$)", path):
            reference_type = "file_or_export"
            notes.append("Use harmless disposable files or exports; never download private content.")
        if any(term in path for term in ("favorite", "callback", "webhook", "notification", "preview")):
            reference_type = "second_order"
            notes.append("Record the write, then inspect only the requesting test account's later view.")
        if parsed.scheme == "ws" or parsed.scheme == "wss" or "websocket" in body_lower:
            reference_type = "websocket"
            notes.append("Use a local fixture message and two test sessions; do not subscribe to another user's stream.")
        references.append(IdorReference(
            _id("idor-ref", url, key, reference_type), url, key, reference_type, operation, notes,
        ))

    # --- additional surfaces from the common-vectors checklist -----------
    # Numeric object ids in the URL path (/users/42/profile).
    path_id = re.search(r"/(?!v\d)([a-z][a-z0-9_-]{1,40})/(\d{1,12})(?:[/?]|$)", path)
    if path_id and path_id.group(1) not in {"api", "static", "assets", "uploads", "img", "css", "js", "fonts"}:
        references.append(IdorReference(
            _id("idor-ref", url, path_id.group(1), "path_id"), url, path_id.group(1),
            "path_id", operation,
            ["A numeric resource id in the path is a classic direct-object reference; "
             "check the path-resource->session ownership mapping.",
             "Compare an owned fixture id under both test accounts; do not enumerate adjacent ids."],
        ))
    # File names under upload/download roots (/uploads/<uuid>.pdf).
    file_name = re.search(r"/(?:uploads?|downloads?|files?|attachments?|exports?)/[^/?#]+\.(?:pdf|docx?|xlsx?|png|jpg|jpeg|zip|tar|gz|csv|json|txt)\b", path)
    if file_name:
        references.append(IdorReference(
            _id("idor-ref", url, "filename", "file_or_export"), url, "filename",
            "file_or_export", operation,
            ["File-name references are second-order objects: only test with an owned, "
             "harmless disposable file and never fetch private content.",
             "Check whether the filename/id in the path is guessable or predictable."],
        ))
    # GraphQL global node ids and node(id:) queries (HackerOne #1618347).
    if _GID_RE.search(path) or _GID_RE.search(body) or "node(id:" in body_lower or "nodes(ids:" in body_lower:
        references.append(IdorReference(
            _id("idor-ref", url, "gid", "graphql_gid"), url, "gid", "graphql_gid", operation,
            ["Global node ids (gid://) passed to node(id:) bypass field-level filters "
             "(HackerOne #1618347: private program scope leaked via enumerable ids).",
             "A gid may be composite (e.g. gid://app/Type/group-id-program-id); treat each "
             "numeric component as a separate ownership axis and avoid sequential enumeration.",
             "Replay an owned node id under both test accounts before touching any other id."],
        ))
    # JWT claim references ("sub": 42, "tenant": 7).
    claim_keys = re.findall(r"[\"'](sub|tenant|user_id|account_id|org_id|uid|role)[\"']\s*:\s*(\d+)", body)
    for claim, _value in claim_keys:
        references.append(IdorReference(
            _id("idor-ref", url, claim, "jwt_claim"), url, claim, "jwt_claim", operation,
            ["Server-asserted claims (sub/tenant) must come from the validated token, not "
             "from request tampering; test only the claim-validation boundary.",
             "Use two test accounts' own tokens; never forge or replay another user's token."],
        ))
    # Custom headers carrying the acting account/tenant (X-Account-Id: 42).
    for raw_line in headers.splitlines():
        if ":" not in raw_line:
            continue
        name, _value = raw_line.split(":", 1)
        name = name.strip().lower()
        if name in ID_HEADER_NAMES:
            references.append(IdorReference(
                _id("idor-ref", url, name, "header_reference"), url, name,
                "header_reference", operation,
                ["A client-supplied account/tenant header is an authorization boundary only "
                 "if the server re-derives it from the session; test by swapping only the "
                 "acting-account header with a second test account's fixture id."],
            ))
    # Cookie variables carrying object/tenant ids (userid=42; tenant=7).
    for pair in cookies.split(";"):
        if "=" not in pair:
            continue
        name, _value = pair.split("=", 1)
        name = name.strip().lower()
        if name in ID_COOKIE_NAMES:
            references.append(IdorReference(
                _id("idor-ref", url, name, "cookie_reference"), url, name,
                "cookie_reference", operation,
                ["An id-bearing cookie that the server trusts for the acting tenant/account "
                 "is an IDOR surface; treat cookies as attacker-controllable input.",
                 "Use each test account's own session cookie; never replay a captured cookie."],
            ))
    # Mobile intent surfaces (Android PendingIntent / intent extras hijack).
    if re.search(r"(?i)(pendingintent|intent://|intent#|startactivity|getextra|extras|notification\s*(?:hijack|tap|pending))", body_lower + " " + path):
        references.append(IdorReference(
            _id("idor-ref", url, "intent", "mobile_intent"), url, "intent",
            "mobile_intent", operation,
            ["Mutable/implicit PendingIntents let another app hijack the notification tap "
             "target (PendingIntent notification-hijack class); check FLAG_IMMUTABLE and "
             "explicit package/component targeting in the app source.",
             "Static review only: inspect manifest/intent flags; do not send crafted intents."],
        ))
    return references


# ---------------------------------------------------------------------------
# BFLA (function-level authorization) matrix
# ---------------------------------------------------------------------------

# Signal words that mark an endpoint/operation as a privileged function.
# These are the function-level counterpart of OBJECT_KEYS: a route containing
# one of these is a candidate "role-B-only" function to test as role A.
PRIVILEGED_FUNCTION_MARKERS = (
    "delete", "remove", "update", "patch", "role", "permission", "grant",
    "revoke", "promote", "demote", "ban", "suspend", "invite", "transfer",
    "export", "import", "admin", "manage", "approve", "reject", "publish",
    "deploy", "config", "setting", "billing", "invoice", "refund", "payout",
    "impersonate", "masquerade", "sudo", "run-as", "elevate", "privilege",
    "access-control", "acl", "policy", "webhook", "token", "apikey",
    "apikeys", "secret", "key", "credential", "mfa", "2fa", "recovery",
    "owner", "team", "workspace", "billing-portal", "gateway", "payout",
)

# Default role ladder for the two-account model (lowest -> highest).
DEFAULT_ROLE_SETS = [
    ["user", "admin"],
    ["member", "owner"],
    ["viewer", "editor"],
    ["user", "support"],
    ["user", "operator"],
]


class BflaMatrixError(RuntimeError):
    """Raised for invalid BFLA matrix inputs."""


def _looks_privileged(url: str, method: str, operation: str) -> bool:
    """Heuristic: does this endpoint look like a privileged function?"""
    path = urlparse(url).path.lower()
    return bool(any(marker in path for marker in PRIVILEGED_FUNCTION_MARKERS)
                or operation in {"function", "write"}
                or method.upper() in {"DELETE", "PATCH"})


def _required_role_for(endpoint: Dict[str, Any]) -> str:
    """Best-effort required-role hint from the endpoint/surface model.

    Uses the declared role (when supplied), an admin signal in the path, or
    defaults to the top of the role ladder.
    """
    declared = str(endpoint.get("required_role") or "").strip()
    if declared:
        return declared
    path = urlparse(str(endpoint.get("url") or "")).path.lower()
    for marker in ("admin", "owner", "operator", "support"):
        if marker in path:
            return marker
    return "admin"


def build_bfla_matrix(
    target: str,
    endpoints: Iterable[Dict[str, Any] | str],
    *,
    role_sets: Optional[List[List[str]]] = None,
    max_plans: int = 128,
) -> List[BflaValidationPlan]:
    """Build function-level authorization (BFLA) validation plans.

    For every endpoint that looks like a privileged function, produce a plan
    of the form "call function X as role Y": the baseline is role A's own
    legitimate call (if any), and the mutation is the same function invoked
    with a lower-privileged session — the server must reject it with an
    authorization error, not just a missing-parameter error.

    Role sets are operator-declared (two cooperating accounts with distinct
    roles); ``required_role`` on an endpoint overrides the heuristic.

    Uncensored: no scope filtering here — the operator declares authorization.
    Offline: plans only; nothing is executed.
    """
    safe_target_name(target)
    roles = role_sets or DEFAULT_ROLE_SETS
    plans: List[BflaValidationPlan] = []
    seen = set()
    for item in endpoints:
        if isinstance(item, str):
            endpoint: Dict[str, Any] = {"url": item, "method": "GET", "operation": "read"}
        else:
            endpoint = dict(item)
        url = str(endpoint.get("url") or endpoint.get("location") or "")
        if not url:
            continue
        method = str(endpoint.get("method") or "GET")
        operation = str(endpoint.get("operation") or "")
        if not _looks_privileged(url, method, operation):
            continue
        required_role = _required_role_for(endpoint)
        for role_set in roles:
            if required_role not in role_set:
                continue
            # The lower-privileged caller is the role just below required_role
            # in this ladder (or any other role in the set when the required
            # role is at the bottom).
            try:
                idx = role_set.index(required_role)
            except ValueError:
                continue
            caller_roles = role_set[:idx] if idx > 0 else [r for r in role_set if r != required_role]
            if not caller_roles:
                continue
            key = (url, method, required_role)
            if key in seen or len(plans) >= max_plans:
                continue
            seen.add(key)
            plans.append(BflaValidationPlan(
                plan_id=_id("bfla-plan", target, url, method, required_role),
                function=f"{method.upper()} {url}",
                method=method.upper(),
                location=url,
                declared_roles=role_set,
                required_role=required_role,
                baseline=[
                    f"Provision two cooperating test accounts: one with the '{required_role}' role "
                    "and one with only the lower-privileged role(s) "
                    + ", ".join(caller_roles) + ".",
                    "Call the privileged function as the privileged account to record the "
                    "expected success shape (status, body keys, side effects).",
                ],
                mutations=[
                    f"Call the same function with the '{caller_roles[0]}' session (same object/"
                    "endpoint, nothing else changed).",
                    "The server must reject with an authorization error (403/401 or an "
                    "explicit role/denied body); a 200/201 or a generic missing-parameter "
                    "error is a BFLA signal — record both shapes for comparison.",
                    "If the lower-privileged call succeeds, try the remaining caller roles "
                    "in the same ladder to bound the missing check.",
                ],
                invariant=(
                    "A session may invoke only functions authorized for its declared role; "
                    "privileged functions must fail closed with an authorization error."),
                impact_boundaries=[
                    "privileged function invoked by unauthorized role",
                    "role escalation",
                    "cross-tenant admin action",
                ],
                evidence_required=[
                    "sanitized A/B requests (privileged vs lower-role session)",
                    "response fingerprints for both callers",
                    "declared role map for both test accounts",
                    "bounded impact trace",
                    "rollback confirmation for state-changing functions",
                ],
                prohibited_actions=[
                    "no victim-account or third-party data access",
                    "no bulk role enumeration",
                    "no destructive irreversible actions without separate approval",
                ],
            ))
    return plans


def openapi_role_inventory(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract privileged-function candidates from an OpenAPI/Swagger spec.

    Reads the paths/operations and their ``security``/``x-permission`` hints to
    build the endpoint inventory the BFLA matrix consumes.  Deterministic and
    offline — pass the parsed spec dict.
    """
    inventory: List[Dict[str, Any]] = []
    paths = spec.get("paths", {}) if isinstance(spec, dict) else {}
    for path, item in (paths.items() if isinstance(paths, dict) else []):
        if not isinstance(item, dict):
            continue
        for method in ("get", "put", "post", "delete", "patch"):
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            operation_id = str(operation.get("operationId") or "")
            required_role = ""
            security = operation.get("security") or spec.get("security")
            if isinstance(security, list):
                for requirement in security:
                    if isinstance(requirement, dict):
                        for scheme, scopes in requirement.items():
                            if isinstance(scopes, list) and scopes:
                                required_role = str(scopes[0])
                                break
                        if required_role:
                            break
            permissions = operation.get("x-permission") or operation.get("x-acl") or ""
            if not required_role and permissions:
                required_role = str(permissions)
            inventory.append({
                "url": path,
                "method": method.upper(),
                "operation": operation_id or method,
                "summary": str(operation.get("summary") or ""),
                "required_role": required_role,
            })
    return inventory


def build_idor_matrix(target: str, endpoints: Iterable[Dict[str, Any] | str], *,
                      scope: Optional[Dict[str, Any]] = None,
                      max_plans: int = 128) -> List[IdorValidationPlan]:
    safe_target_name(target)
    plans: List[IdorValidationPlan] = []
    seen = set()
    for item in endpoints:
        if isinstance(item, str):
            url, method, body, headers, cookies = item, "GET", "", "", ""
        else:
            url = str(item.get("url") or item.get("location") or "")
            method = str(item.get("method") or "GET")
            body = str(item.get("body") or "")
            headers = str(item.get("headers") or "")
            cookies = str(item.get("cookies") or "")
        if not url:
            continue
        try:
            if scope is not None and not target_in_scope(url, scope):
                continue
            if scope is None:
                parsed = urlparse(url)
                if parsed.hostname not in {target, f"www.{target}"} and not (parsed.hostname or "").endswith("." + target):
                    continue
        except (AuthorizationError, ValueError):
            continue
        for reference in classify_endpoint(url, method=method, body=body,
                                           headers=headers, cookies=cookies):
            key = (url, reference.parameter, reference.reference_type)
            if key in seen or len(plans) >= max_plans:
                continue
            seen.add(key)
            risk = "read_only_test_fixture"
            if reference.operation in {"function", "write"}:
                risk = "state_change_test_account_only"
            plans.append(IdorValidationPlan(
                plan_id=_id("idor-plan", target, url, reference.parameter, reference.reference_type),
                location=url, reference_type=reference.reference_type,
                accounts=["Account A: owner of disposable fixture", "Account B: separate cooperating test account"],
                baseline=["Create one disposable object as Account A and one equivalent object as Account B.",
                          "Record object references, actor, tenant, role, status, and response fingerprints without sensitive content."],
                mutations=[
                    "Replay Account A's request under Account B with only the owned reference changed.",
                    "Compare status, body shape, ownership marker, and side effects; do not enumerate adjacent IDs.",
                ] + reference.notes,
                invariant="A session may read or change only objects authorized for that session and tenant.",
                impact_boundaries=["cross-account read", "cross-account write", "cross-tenant access", "privileged function", "blind side effect"],
                evidence_required=["sanitized A/B baseline and mutation requests", "response fingerprints", "test-object ownership map", "bounded impact trace", "rollback confirmation for state changes"],
                prohibited_actions=["no victim-data access", "no sequential enumeration", "no bulk/batch scraping", "no captured-session replay", "no irreversible DELETE/transfer without separate approval"],
                status=risk,
            ))
    return plans


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    import json
    parser = argparse.ArgumentParser(
        description="BugWolf IDOR/BFLA access-control research planner")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--bfla", action="store_true",
                        help="Build the BFLA (function-level authorization) matrix")
    parser.add_argument("--openapi", default="",
                        help="Path to an OpenAPI/Swagger spec JSON for the role inventory")
    parser.add_argument("--endpoints-file", default="",
                        help="JSONL/JSON file of endpoint objects (url, method, body, ...)")
    parser.add_argument("--role-sets", default="",
                        help="JSON array of role ladders, e.g. '[[\"user\",\"admin\"]]'")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    endpoints: List[Dict[str, Any]] = []
    if args.endpoints_file:
        try:
            raw = Path(args.endpoints_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}))
            return 2
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = [json.loads(line) for line in raw.splitlines() if line.strip()]
        endpoints = parsed if isinstance(parsed, list) else [parsed]
    if not endpoints:
        print(json.dumps({"ok": False,
                          "error": "--bfla requires --endpoints-file (endpoint objects)"},
                         indent=2))
        return 2

    role_sets = None
    if args.role_sets:
        try:
            role_sets = json.loads(args.role_sets)
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False, "error": f"--role-sets invalid: {exc}"}))
            return 2

    if args.bfla:
        inventory = endpoints
        if args.openapi:
            try:
                spec = json.loads(Path(args.openapi).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(json.dumps({"ok": False, "error": f"invalid OpenAPI spec: {exc}"}))
                return 2
            inventory = openapi_role_inventory(spec)
        plans = build_bfla_matrix(args.target, inventory, role_sets=role_sets)
        output = {"schema": "bugwolf/bfla-matrix/v1", "ok": True,
                  "target": args.target, "plan_count": len(plans),
                  "plans": [asdict(p) for p in plans]}
        print(json.dumps(output, indent=2) if args.json else
              f"[+] {args.target}: {len(plans)} BFLA validation plans")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
