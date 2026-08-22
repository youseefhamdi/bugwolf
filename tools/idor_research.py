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
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

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
