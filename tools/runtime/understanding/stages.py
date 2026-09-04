#!/usr/bin/env python3
"""The nine Understanding-Layer stage engines (master plan §8.1).

Every engine is DETERMINISTIC code over captured facts: fetched pages, the
per-credential crawl (``authed_crawl.CrawlReport``), the session context
store (``session_context.SessionContextStore``), and an OpenAPI document
when the target publishes one.  The plan's bounded LLM reasoning passes are
operator-side; each stage's assumptions carry a ``challenge`` field ready
for that pass.  No model calls.

Stage contracts (§8.1):

    U1 business-model   : pages  -> money paths, entities, trust decisions
    U2 census           : crawl + openapi -> business-ranked surface
    U3 logic            : crawl forms + openapi -> workflows + state machines
    U4 identity         : session store + crawl matrix -> roles, boundaries
    U5 data & state     : session store + crawl -> object IDs, client fields
    U6 trust            : crawl headers + optional probe results -> boundaries
    U7 capabilities     : U1 x U4 x U5 -> (role, object, verb, impact) map
    U8 assumption ledger: U1..U7 assumptions -> zero-day seed list (jsonl)
    U9 synthesis        : everything -> target-model.json + Hunting Brief
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from tools.runtime.understanding.base import ASSUMPTION_ORIGINS, Assumption

# ---------------------------------------------------------------------------
# Money-path / commerce vocabulary (deterministic U1 extraction)
# ---------------------------------------------------------------------------

MONEY_TERMS = ("pricing", "price", "plan", "subscription", "billing",
               "checkout", "cart", "payment", "invoice", "tier", "premium",
               "upgrade", "purchase", "order", "pay", "fee", "credit",
               "voucher", "coupon", "refund", "withdraw", "deposit",
               "balance", "wallet")
TRUST_TERMS = ("verify", "verification", "confirm", "kyc", "approve",
               "review", "moderate", "authenticate", "authorize",
               "password", "recovery", "reset", "2fa", "mfa", "otp")
ENTITY_TERMS = ("user", "merchant", "admin", "seller", "buyer", "vendor",
                "customer", "team", "organization", "workspace", "guest")
MODEL_TYPES = {
    "marketplace": ("marketplace", "seller", "merchant", "listing", "commission"),
    "saas": ("subscription", "workspace", "team", "seat", "tenant"),
    "fintech": ("wallet", "withdraw", "deposit", "kyc", "transfer", "payout"),
    "content": ("article", "post", "subscribe", "newsletter", "comment"),
    "dev-tool": ("api key", "token", "sdk", "docs", "cli", "repo"),
}

_WORKFLOW_PREFIXES = ("login", "signup", "register", "auth", "password",
                      "recovery", "reset", "checkout", "payment", "order",
                      "invite", "voucher", "coupon", "redeem", "verify",
                      "onboarding", "billing", "withdraw", "2fa", "mfa")
_ID_KEYS = ("id", "user_id", "uid", "uuid", "guid", "account_id",
            "order_id", "invoice_id", "object_id", "record_id")
_MONEY_KEYS = ("price", "amount", "total", "balance", "quantity", "fee",
               "discount", "currency", "cost", "value")
_PRIV_KEYS = ("role", "isAdmin", "is_admin", "admin", "permissions",
              "scopes", "group", "level")   # mass-assignment targets
_STATE_VERBS = ("create", "update", "delete", "approve", "cancel",
                "complete", "submit", "close", "reopen", "transfer",
                "withdraw", "redeem", "refund", "issue", "revoke")

OPENAPI_PATH_RE = re.compile(r"\{[^}]+\}")


def _lowered(text: str) -> str:
    return str(text or "").lower()


def _term_hits(text: str, terms: Iterable[str]) -> List[str]:
    low = _lowered(text)
    return [t for t in terms if t in low]


# ---------------------------------------------------------------------------
# U1 — Business model
# ---------------------------------------------------------------------------

def stage_u1(pages: Dict[str, str],
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Business model from fetched pages (path -> body text).

    Deterministic extraction: model-type classification, monetization
    points, money paths (page/term evidence), entities, trust decisions.
    """
    money: List[Dict[str, Any]] = []
    trust: List[Dict[str, Any]] = []
    entities: List[str] = []
    evidence_paths: List[str] = []
    vocab_counter: Dict[str, int] = {}

    for path in sorted(pages):
        body = pages[path]
        low = _lowered(body)
        if not low:
            continue
        hits = _term_hits(low, MONEY_TERMS + TRUST_TERMS + ENTITY_TERMS)
        if hits:
            evidence_paths.append(path)
        for term in hits:
            vocab_counter[term] = vocab_counter.get(term, 0) + 1

        for term in _term_hits(low, MONEY_TERMS):
            money.append({"path": path, "term": term,
                          "kind": "monetization-point"})
        for term in _term_hits(low, TRUST_TERMS):
            trust.append({"path": path, "term": term,
                          "kind": "trust-decision"})
        for term in _term_hits(low, ENTITY_TERMS):
            if term not in entities:
                entities.append(term)

    scores = {m: sum(vocab_counter.get(t, 0) for t in terms)
              for m, terms in MODEL_TYPES.items()}
    best = max(scores, key=lambda m: scores[m]) if any(scores.values()) else ""
    model_type = best if scores.get(best, 0) > 0 else "unknown"

    money_paths: List[Dict[str, Any]] = []
    seen: set = set()
    for entry in sorted(money, key=lambda e: (e["path"], e["term"])):
        key = (entry["path"], entry["term"])
        if key in seen:
            continue
        seen.add(key)
        money_paths.append(entry)

    data = {
        "model_type": model_type,
        "model_type_scores": {k: v for k, v in sorted(scores.items(), key=lambda kv: -kv[1])},
        "entities": entities,
        "monetization_points": money_paths[:60],
        "money_paths": money_paths[:60],
        "trust_decisions": trust[:60],
        "evidence_paths": evidence_paths[:40],
    }

    if assumptions_out is not None:
        if money_paths:
            assumptions_out.append(Assumption(
                stage="U1", origin="observed", confidence=0.7,
                statement=(f"Commerce flows through the observed money terms "
                           f"on {len({e['path'] for e in money_paths})} page(s); "
                           f"server-side revalidation exists for each."),
                dispro_plan=("Replay a money-path transaction with a tampered "
                             "amount (replay engine compare mode) and check "
                             "whether the server recomputes totals."),
                evidence=f"terms: {sorted({e['term'] for e in money_paths})[:8]}",
            ))
        if trust:
            assumptions_out.append(Assumption(
                stage="U1", origin="inferred", confidence=0.5,
                statement=("Trust decisions surfaced on pages are enforced "
                           "server-side, not just rendered client-side."),
                dispro_plan=("Probe the corresponding endpoints for the "
                             "decision bypass (skip/reorder the flow step)."),
                evidence=f"pages: {sorted({e['path'] for e in trust})[:8]}",
            ))
    return data


# ---------------------------------------------------------------------------
# U2 — Recon census (business-criticality ranking)
# ---------------------------------------------------------------------------

def stage_u2(crawl: Any, openapi: Optional[Dict[str, Any]] = None,
             u1: Optional[Dict[str, Any]] = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Rank the observed surface by U1 business criticality, not severity."""
    pages = getattr(crawl, "pages", {})
    weights: Dict[str, int] = {}
    evidence: Dict[str, List[str]] = {}

    def _bump(path: str, weight: int, why: str) -> None:
        weights[path] = weights.get(path, 0) + weight
        evidence.setdefault(path, [])
        if why not in evidence[path]:
            evidence[path].append(why)

    for path, page in pages.items():
        low = _lowered(getattr(page, "title", "") + " " +
                       json.dumps([f.get("action", "") for f in getattr(page, "forms", [])]))
        for term in _term_hits(low, MONEY_TERMS):
            _bump(path, 6, f"money-term:{term}")
        for term in _term_hits(low, TRUST_TERMS):
            _bump(path, 3, f"trust-term:{term}")
        diffs = getattr(page, "status_by_label", {})
        if len({s for s in diffs.values() if s}) > 1:
            _bump(path, 8, "identity-differential")
        if getattr(page, "forms", []):
            _bump(path, 2, "accepts-input")

    if openapi:
        spec_paths = openapi.get("paths", {})
        for spec_path, methods in spec_paths.items():
            concrete = OPENAPI_PATH_RE.sub("{param}", spec_path)
            for method in methods:
                if not isinstance(methods, dict):
                    continue
                op = methods[method]
                if not isinstance(op, dict):
                    continue
                low = _lowered(json.dumps(op))
                weight = 4 if any(t in low for t in MONEY_TERMS) else 1
                _bump(concrete, weight, f"openapi:{method}")

    ranked = sorted(weights.items(), key=lambda kv: (-kv[1], kv[0]))
    data = {
        "surface_count": len(ranked),
        "ranked_surface": [
            {"path": path, "criticality": weight, "evidence": evidence[path][:6]}
            for path, weight in ranked[:80]
        ],
        "business_lens": (u1 or {}).get("model_type", "unknown"),
    }
    if assumptions_out is not None:
        top = ranked[:3]
        if top:
            assumptions_out.append(Assumption(
                stage="U2", origin="inferred", confidence=0.6,
                statement=(f"Business-criticality ranking holds: "
                           f"{', '.join(p for p, _ in top)} concentrate value."),
                dispro_plan=("Allocate one probe budget to the BOTTOM of the "
                             "ranking — unranked surface is where the map is "
                             "most wrong."),
                evidence=f"weights: {[(p, w) for p, w in top]}",
            ))
    return data


# ---------------------------------------------------------------------------
# U3 — Application logic (workflows + state machines)
# ---------------------------------------------------------------------------

def stage_u3(crawl: Any, openapi: Optional[Dict[str, Any]] = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Workflows from observed forms + OpenAPI operations.

    A workflow = (name, entry path, steps).  State-machine candidates come
    from OpenAPI operations whose path carries a state verb.
    """
    workflows: Dict[str, Dict[str, Any]] = {}

    _MAP = {"checkout": "purchase", "payment": "purchase", "order": "purchase",
            "cart": "purchase", "billing": "purchase",
            "voucher": "redemption", "coupon": "redemption",
            "redeem": "redemption", "login": "auth", "signup": "auth",
            "register": "auth", "auth": "auth", "password": "recovery",
            "recovery": "recovery", "reset": "recovery",
            "verify": "verification", "2fa": "verification",
            "mfa": "verification", "invite": "onboarding",
            "onboarding": "onboarding", "withdraw": "funds-out"}

    def _name_for(path: str) -> Optional[str]:
        low = _lowered(path)
        for prefix in _WORKFLOW_PREFIXES:
            if prefix in low:
                return _MAP.get(prefix, prefix)
        return None

    def _add_step(name: str, path: str, source: str, fields: int = 0) -> None:
        wf = workflows.setdefault(name, {"name": name, "steps": [],
                                         "assumed_flow": "", "sources": []})
        step = {"path": path, "source": source}
        if fields:
            step["fields"] = fields
        if not any(s["path"] == path and s["source"] == source
                   for s in wf["steps"]):
            wf["steps"].append(step)
        if source not in wf["sources"]:
            wf["sources"].append(source)

    for path, page in getattr(crawl, "pages", {}).items():
        for form in getattr(page, "forms", []):
            action = form.get("action", "")
            if not action:
                continue
            name = _name_for(action) or _name_for(path)
            if name:
                _add_step(name, action or path, "form",
                          fields=len(form.get("fields", [])))

    spec_paths = (openapi or {}).get("paths", {})
    for spec_path, methods in spec_paths.items():
        if not isinstance(methods, dict):
            continue
        name = _name_for(spec_path)
        if not name:
            continue
        for method in methods:
            _add_step(name, spec_path, f"openapi:{method}")

    # State-machine candidates from state verbs on OpenAPI operations.
    machines: List[Dict[str, Any]] = []
    for spec_path, methods in spec_paths.items():
        if not isinstance(methods, dict):
            continue
        low = _lowered(spec_path)
        verbs = [v for v in _STATE_VERBS if v in low]
        if not verbs:
            continue
        machines.append({
            "object": OPENAPI_PATH_RE.sub("{param}", spec_path),
            "verbs_observed": sorted({v for spec_path2 in [spec_path]
                                      for v in verbs}),
            "candidate_states": sorted({v for v in verbs} |
                                       {"created", "updated", "deleted"}),
        })

    data = {
        "workflow_count": len(workflows),
        "workflows": dict(sorted(workflows.items())),
        "state_machine_candidates": machines[:20],
    }
    if assumptions_out is not None:
        for name, wf in sorted(workflows.items()):
            if not wf["steps"]:
                continue
            fields_total = sum(s.get("fields", 0) for s in wf["steps"])
            assumptions_out.append(Assumption(
                stage="U3", origin="observed", confidence=0.6,
                statement=(f"Workflow '{name}' executes as modeled: "
                           f"{len(wf['steps'])} step(s) in the intended order."),
                dispro_plan=("Replay the flow with steps reordered, repeated, "
                             "or skipped (replay engine, per-step mutation) — "
                             "the classic workflow-bypass family."),
                evidence=f"steps: {[s['path'] for s in wf['steps']][:6]}",
            ))
            if fields_total:
                assumptions_out.append(Assumption(
                    stage="U3", origin="observed", confidence=0.5,
                    statement=(f"Workflow '{name}' validates field VALUES "
                               f"server-side ({fields_total} client-supplied "
                               f"field(s) across steps)."),
                    dispro_plan=("Mutate each field to a boundary/forbidden "
                                 "value (mass-assignment set) and compare "
                                 "responses (compare mode)."),
                    evidence=f"fields observed in forms: {fields_total}",
                ))
    return data


# ---------------------------------------------------------------------------
# U4 — Identity / authz model
# ---------------------------------------------------------------------------

def stage_u4(session_store: Any = None, crawl: Any = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Roles, JWT shape, ownership hints, and observed authz boundaries."""
    roles: Dict[str, Dict[str, Any]] = {}
    boundaries: List[Dict[str, Any]] = []
    matrix: Dict[str, Dict[str, int]] = {}

    if session_store is not None:
        try:
            matrix = dict(session_store.identity_matrix())
        except Exception:  # noqa: BLE001 - a partial store is still a model
            matrix = {}
        for label, ctx in getattr(session_store, "sessions", {}).items():
            roles[label] = {
                "role": ctx.role,
                "role_source": ctx.role_source,
                "jwt_alg": (ctx.jwt_header or {}).get("alg", ""),
                "claim_names": sorted((ctx.jwt_claims or {}).keys()),
                "object_id_count": len(ctx.object_ids or []),
                "endpoint_count": len(ctx.endpoints or []),
            }

    if crawl is not None:
        for path in crawl.differential_paths():
            page = crawl.pages.get(path)
            statuses = dict(getattr(page, "status_by_label", {})) if page else {}
            boundaries.append({
                "path": path, "status_by_label": statuses,
                "kind": "observed-differential",
            })

    data = {
        "roles": roles,
        "identity_matrix": matrix,
        "authz_boundaries": boundaries,
        "differential_count": len(boundaries),
    }
    if assumptions_out is not None:
        for boundary in boundaries[:10]:
            assumptions_out.append(Assumption(
                stage="U4", origin="observed", confidence=0.8,
                statement=(f"The boundary at {boundary['path']} is enforced "
                           f"uniformly for every identity and method."),
                dispro_plan=("Replay the boundary path with sibling methods "
                             "(POST/PUT/PATCH), sibling IDs from the U5 "
                             "inventory, and header variants — differential "
                             "crawl only observed GET."),
                evidence=f"statuses: {boundary['status_by_label']}",
            ))
        if session_store is not None and any(
                r.get("jwt_alg") for r in roles.values()):
            assumptions_out.append(Assumption(
                stage="U4", origin="observed", confidence=0.6,
                statement=("Token verification validates the signature "
                           "algorithm the token declares (alg confusion "
                           "resistant)."),
                dispro_plan=("Forge tokens: alg=none, HS256-with-public-key, "
                             "and missing-kid variants; replay a protected "
                             "path with each."),
                evidence=f"algs: {sorted({r['jwt_alg'] for r in roles.values() if r.get('jwt_alg')})}",
            ))
    return data


# ---------------------------------------------------------------------------
# U5 — Data & state model
# ---------------------------------------------------------------------------

def stage_u5(session_store: Any = None, crawl: Any = None,
             openapi: Optional[Dict[str, Any]] = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Object-ID inventory, client-controlled fields, state observations."""
    id_formats: Dict[str, List[str]] = {}
    for obj_id in (session_store.object_ids() if session_store else []):
        if re.fullmatch(r"\d+", obj_id):
            fmt = "sequential-integer"
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                          obj_id, re.I):
            fmt = "uuid"
        elif re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", obj_id) and \
                not obj_id.isdigit() and "-" not in obj_id[:8]:
            fmt = "encoded-or-hash"
        else:
            fmt = "opaque"
        id_formats.setdefault(fmt, []).append(obj_id)

    client_fields: List[str] = []
    for spec_path, methods in (openapi or {}).get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            body = (op.get("requestBody", {}) or {}).get(
                "content", {}).get("application/json", {}).get(
                "schema", {}).get("properties", {})
            for field_name, schema in body.items():
                if isinstance(schema, dict) and \
                        field_name in _MONEY_KEYS + _ID_KEYS + _PRIV_KEYS:
                    client_fields.append(f"{method.upper()} {spec_path}::{field_name}")

    observed_states: List[Dict[str, Any]] = []
    for path, page in getattr(crawl, "pages", {}).items():
        low = _lowered(getattr(page, "title", ""))
        hits = _term_hits(low, _STATE_VERBS)
        if hits:
            observed_states.append({"path": path, "verbs": hits})

    data = {
        "object_id_inventory": {k: v[:20] for k, v in sorted(id_formats.items())},
        "object_id_format_counts": {k: len(v) for k, v in sorted(id_formats.items())},
        "client_controlled_fields": client_fields[:40],
        "observed_state_terms": observed_states[:20],
    }
    if assumptions_out is not None:
        if "sequential-integer" in id_formats:
            assumptions_out.append(Assumption(
                stage="U5", origin="observed", confidence=0.9,
                statement=("Sequential integer object IDs are referenced "
                           "server-side (IDOR surface is live)."),
                dispro_plan=("Enumerate ±1..±5 IDs per inventoried endpoint "
                             "across identities (compare mode); the U5 "
                             "inventory supplies the concrete values."),
                evidence=f"ids: {id_formats['sequential-integer'][:8]}",
            ))
        if client_fields:
            assumptions_out.append(Assumption(
                stage="U5", origin="observed", confidence=0.6,
                statement=(f"Client-controlled fields ({len(client_fields)}) "
                           f"are validated server-side before commit."),
                dispro_plan=("Mass-assignment sweep: replay each field with "
                             "boundary/forbidden values; compare-mode deltas "
                             "expose missing validation."),
                evidence=f"fields: {client_fields[:8]}",
            ))
    return data


# ---------------------------------------------------------------------------
# U6 — Trust & boundary model
# ---------------------------------------------------------------------------

def stage_u6(crawl: Any = None, probe_results: Optional[List[Dict[str, Any]]] = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Where does the server trust client-supplied data?

    ``probe_results`` are optional outputs from ``header_trust.py`` /
    ``parser_differential.py`` probes the operator ran; the crawl's own
    header echoes (X-Forwarded-*, Host handling) seed the map.
    """
    trust_points: List[Dict[str, Any]] = []
    header_families: Dict[str, List[str]] = {}

    for path, page in getattr(crawl, "pages", {}).items():
        low = _lowered(json.dumps(getattr(page, "links", [])[:5]))
        for family in ("x-forwarded", "host", "x-original-url",
                       "x-rewrite", "forwarded"):
            if family in low:
                header_families.setdefault(family, []).append(path)

    for probe in probe_results or []:
        trust_points.append({
            "source": "probe",
            "header": probe.get("header", ""),
            "path": probe.get("path", ""),
            "observed": probe.get("observed", ""),
            "kind": "header-trust",
        })

    data = {
        "trust_points": trust_points,
        "header_families_observed": {k: v[:10] for k, v in sorted(header_families.items())},
        "probe_count": len(trust_points),
    }
    if assumptions_out is not None:
        assumptions_out.append(Assumption(
            stage="U6", origin="inferred", confidence=0.4,
            statement=("Header/trust boundaries observed on crawled paths "
                       "hold for uncrawled paths on the same host."),
            dispro_plan=("Run header_trust.py against the top U2-ranked "
                         "paths and compare the trust map (stated vs "
                         "actual boundary crossings)."),
            evidence=f"families: {sorted(header_families)}",
        ))
    return data


# ---------------------------------------------------------------------------
# U7 — Capability & authority map (U1 x U4 x U5)
# ---------------------------------------------------------------------------

_IMPACT_BY_OBJECT = {
    "balance": "dollars", "price": "dollars", "amount": "dollars",
    "total": "dollars", "withdraw": "dollars", "wallet": "dollars",
    "voucher": "dollars", "coupon": "dollars", "payment": "dollars",
    "invoice": "dollars", "order": "dollars",
    "user": "PII/ATO", "email": "PII/ATO", "profile": "PII/ATO",
    "account": "PII/ATO", "password": "ATO", "session": "ATO",
    "token": "ATO", "admin": "privilege", "role": "privilege",
    "permission": "privilege",
}


def stage_u7(u1: Dict[str, Any], u4: Dict[str, Any], u5: Dict[str, Any],
             openapi: Optional[Dict[str, Any]] = None,
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Capabilities = (role, object, verb, impact) from U1 x U4 x U5."""
    capabilities: List[Dict[str, Any]] = []
    roles = [label for label, info in (u4.get("roles") or {}).items()]
    role_admin_flags = {
        label: bool(_lowered((info or {}).get("role", "")).find("admin") >= 0)
        for label, info in (u4.get("roles") or {}).items()
    }

    for entry in (u1.get("money_paths") or [])[:30]:
        path = entry.get("path", "")
        obj = entry.get("term", "")
        impact = _IMPACT_BY_OBJECT.get(obj, "business")
        for label in roles or ["anon"]:
            capabilities.append({
                "role_label": label, "object": obj, "verb": "modify",
                "path": path, "impact": impact,
                "reversible": obj not in ("withdraw", "payment"),
                "observable": True,
                "evidence": f"U1 money path ({entry.get('kind', 'monetization-point')})",
            })

    for field in (u5.get("client_controlled_fields") or [])[:25]:
        method_path, _, field_name = field.partition("::")
        method, _, path = method_path.partition(" ")
        impact = _IMPACT_BY_OBJECT.get(
            _lowered(field_name), "business")
        for label in roles or ["anon"]:
            capabilities.append({
                "role_label": label, "object": field_name, "verb": "modify",
                "path": path, "impact": impact,
                "reversible": True, "observable": True,
                "evidence": f"U5 client-controlled ({method})",
            })

    # Dedup + rank: dollars > privilege > ATO/PII > business.
    rank = {"dollars": 0, "privilege": 1, "ATO": 2, "PII/ATO": 2, "business": 3}
    capabilities.sort(key=lambda c: (rank.get(c["impact"], 9),
                                     c.get("role_label", ""), c.get("path", "")))
    data = {
        "capability_count": len(capabilities),
        "capabilities": capabilities[:80],
        "impact_distribution": {
            impact: sum(1 for c in capabilities if c["impact"] == impact)
            for impact in sorted({c["impact"] for c in capabilities})
        },
    }
    if assumptions_out is not None and capabilities:
        top = capabilities[0]
        assumptions_out.append(Assumption(
            stage="U7", origin="inferred", confidence=0.5,
            statement=(f"Capability '{top['object']}' ({top['impact']}) "
                       f"requires the role it was mapped to "
                       f"({top.get('role_label', '')})."),
            dispro_plan=("Replay the capability with a LOWER-privilege "
                         "identity and a forged/higher-role token — "
                         "capability/authority mismatch is the bug."),
            evidence=f"top capability: {top}",
        ))
    return data


# ---------------------------------------------------------------------------
# U8 — Assumption ledger (the zero-day seed list)
# ---------------------------------------------------------------------------

def stage_u8(assumptions: List[Assumption],
             stage_rank: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """Merge, dedupe, and rank every stage's assumptions by fragility.

    Rank = expected-bug-value = (1 - confidence) * stage_weight.  Low
    confidence on a load-bearing assumption is exactly where zero-days live.
    """
    weights = {"U1": 1.0, "U3": 1.0, "U4": 0.9, "U5": 0.9, "U7": 0.8,
               "U2": 0.5, "U6": 0.6}
    weights.update(stage_rank or {})
    merged: Dict[str, Assumption] = {}
    for assumption in assumptions:
        existing = merged.get(assumption.assumption_id)
        if existing is None:
            merged[assumption.assumption_id] = assumption
        else:
            # Same statement seen twice: keep the stronger evidence.
            if assumption.confidence > existing.confidence:
                merged[assumption.assumption_id] = assumption
    ranked = sorted(merged.values(),
                    key=lambda a: (-(1 - a.confidence) * weights.get(a.stage, 0.5),
                                   a.stage, a.statement))
    data = {
        "ledger_size": len(ranked),
        "ranked": [a.to_dict() for a in ranked],
        "origin_distribution": {
            origin: sum(1 for a in ranked if a.origin == origin)
            for origin in ASSUMPTION_ORIGINS if any(a.origin == origin for a in ranked)
        },
        "stage_distribution": {
            stage: sum(1 for a in ranked if a.stage == stage)
            for stage in sorted({a.stage for a in ranked})
        },
        "fragile_top": [a.assumption_id for a in ranked[:10]],
    }
    return data, ranked


# ---------------------------------------------------------------------------
# U9 — Synthesis, coverage gate, Hunting Brief
# ---------------------------------------------------------------------------

# Bug classes the hunt can execute, with the model support each requires.
COVERAGE_CLASSES: Dict[str, Dict[str, str]] = {
    "idor": {"requires": "object_ids", "stage": "U5"},
    "authz-bypass": {"requires": "authz_boundaries", "stage": "U4"},
    "mass-assignment": {"requires": "client_controlled_fields", "stage": "U5"},
    "business-logic": {"requires": "workflows", "stage": "U3"},
    "price-manipulation": {"requires": "client_controlled_fields", "stage": "U5"},
    "voucher-race": {"requires": "workflows", "stage": "U3"},
    "jwt-confusion": {"requires": "jwt_algs", "stage": "U4"},
    "header-trust": {"requires": "header_families_observed", "stage": "U6"},
    "ssrf-callback": {"requires": "oast", "stage": "U2"},
    "xss-dom": {"requires": "browser", "stage": "U2"},
    "fuzzing": {"requires": "ranked_surface", "stage": "U2"},
}


def stage_u9(stage_data: Dict[str, Dict[str, Any]],
             ranked_assumptions: List[Assumption],
             chain: List[Dict[str, str]],
             assumptions_out: Optional[List[Assumption]] = None) -> Dict[str, Any]:
    """Merge the model, run the coverage gate, and build the Hunting Brief.

    The coverage gate: a class HUNTS only when its model support exists;
    otherwise it is PARKED WITH REASON (master plan §8.1 U9).  The brief
    ranks hypotheses by U7 impact x U8 fragility.
    """
    support = {
        "workflows": stage_data.get("U3", {}).get("workflow_count", 0),
        "authz_boundaries": stage_data.get("U4", {}).get("differential_count", 0),
        "object_ids": sum(stage_data.get("U5", {}).get("object_id_format_counts", {}).values()),
        "client_controlled_fields": len(stage_data.get("U5", {}).get("client_controlled_fields", [])),
        "jwt_algs": len([1 for r in stage_data.get("U4", {}).get("roles", {}).values()
                         if (r or {}).get("jwt_alg")]),
        "header_families_observed": len(stage_data.get("U6", {}).get("header_families_observed", {})),
        "ranked_surface": len(stage_data.get("U2", {}).get("ranked_surface", [])),
        "oast": 0,
        "browser": 0,
    }
    coverage = []
    for bug_class, spec in COVERAGE_CLASSES.items():
        have = support.get(spec["requires"], 0) > 0
        coverage.append({
            "bug_class": bug_class,
            "status": "hunts" if have else "parked",
            "requires": spec["requires"],
            "support_stage": spec["stage"],
            "reason": ("" if have else
                       f"no {spec['requires']} in the model (stage {spec['stage']} "
                       "produced none) — parked, not sprayed"),
        })

    # Hypotheses: fragile assumptions x the model paths that support them.
    impact_of_stage = {"U1": "business", "U3": "business", "U4": "PII/ATO",
                       "U5": "dollars", "U7": "dollars", "U2": "business",
                       "U6": "business"}
    hypotheses = []
    for assumption in ranked_assumptions[:15]:
        hypotheses.append({
            "assumption_id": assumption.assumption_id,
            "stage": assumption.stage,
            "statement": assumption.statement,
            "dispro_plan": assumption.dispro_plan,
            "confidence": assumption.confidence,
            "origin": assumption.origin,
            "predicted_impact": impact_of_stage.get(assumption.stage, "business"),
            "fragility": round(1 - assumption.confidence, 2),
        })

    data = {
        "coverage_gate": coverage,
        "hunts": [c["bug_class"] for c in coverage if c["status"] == "hunts"],
        "parked": [c for c in coverage if c["status"] == "parked"],
        "hypotheses": hypotheses,
        "model_chain": chain,
        "assumption_dispro_rate": None,  # filled post-hunt (Phase 7 metric)
    }
    return data


def render_brief(target: str, u9: Dict[str, Any],
                 stage_data: Dict[str, Dict[str, Any]]) -> str:
    """The Hunting Brief markdown (the /bugwolf-understand front door)."""
    coverage = u9.get("coverage_gate", [])
    hunts = [c for c in coverage if c["status"] == "hunts"]
    parked = [c for c in coverage if c["status"] == "parked"]
    lines: List[str] = []
    lines.append(f"# Hunting Brief — {target}")
    lines.append("")
    lines.append(f"_Generated {datetime.now(timezone.utc).isoformat()} — "
                 "deterministic Understanding Layer (U1–U9), hash-chained._")
    lines.append("")
    lines.append("## Model at a glance")
    lines.append("")
    lines.append(f"- Business model: **{stage_data.get('U1', {}).get('model_type', 'unknown')}**"
                 f" (evidence paths: {len(stage_data.get('U1', {}).get('evidence_paths', []))})")
    lines.append(f"- Surface ranked: {stage_data.get('U2', {}).get('surface_count', 0)} paths "
                 f"(business-criticality order)")
    lines.append(f"- Workflows modeled: {stage_data.get('U3', {}).get('workflow_count', 0)}")
    lines.append(f"- Identities: {len(stage_data.get('U4', {}).get('roles', {}))} "
                 f"(differentials: {stage_data.get('U4', {}).get('differential_count', 0)})")
    lines.append(f"- Object IDs: {sum(stage_data.get('U5', {}).get('object_id_format_counts', {}).values())} "
                 f"(client-controlled fields: {len(stage_data.get('U5', {}).get('client_controlled_fields', []))})")
    lines.append(f"- Capabilities ranked: {stage_data.get('U7', {}).get('capability_count', 0)}")
    lines.append("")
    lines.append("## Coverage gate")
    lines.append("")
    lines.append(f"**Hunts ({len(hunts)}):** {', '.join(c['bug_class'] for c in hunts) or '—'}")
    lines.append("")
    if parked:
        lines.append(f"**Parked with reason ({len(parked)}):**")
        lines.append("")
        for entry in parked:
            lines.append(f"- `{entry['bug_class']}` — {entry['reason']}")
        lines.append("")
    lines.append("## Hypotheses (attack these, in order)")
    lines.append("")
    if not u9.get("hypotheses"):
        lines.append("_No assumptions recorded — the model is empty; "
                     "fix the inputs (crawl/session store) before hunting._")
        lines.append("")
    for position, hypothesis in enumerate(u9.get("hypotheses", []), start=1):
        lines.append(f"### H{position} — [{hypothesis['stage']}] "
                     f"fragility {hypothesis['fragility']} "
                     f"→ {hypothesis['predicted_impact']}")
        lines.append("")
        lines.append(f"**Assumption:** {hypothesis['statement']}")
        lines.append("")
        lines.append(f"**Dispro plan:** {hypothesis['dispro_plan']}")
        lines.append("")
    lines.append("## Dispatch")
    lines.append("")
    lines.append("`/bugwolf-run` dispatches against THIS brief: hunting agents")
    lines.append("test the dispro plans above; they do not wander. Classes in")
    lines.append("the parked list are out of scope until the model gains the")
    lines.append("support they require — expanding scope is a model change,")
    lines.append("not a payload change.")
    lines.append("")
    return "\n".join(lines)
