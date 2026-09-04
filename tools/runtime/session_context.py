#!/usr/bin/env python3
"""BugWolf session context store (master plan Phase 2.2).

The per-credential model of the target's identity layer — what makes
authorization testing *automatic* instead of guesswork:

    * tokens         — live session values per label (memory-first, redacted
                       on disk, never in logs/reports);
    * JWT claims     — LIVE decode of the session token (not static
                       analysis): roles/expiry/tenant straight from the
                       credential the target actually issued;
    * roles          — inferred role for each label (JWT claims first, then
                       response-object role fields, then the operator's
                       declared identifiers);
    * object IDs     — every object identifier observed reachable under a
                       credential (the U5 object-ID inventory);
    * endpoints      — which endpoints each credential can reach, with the
                       observed status per identity (the U4 identity matrix).

Feeds: U4 (identity/authz model) consumes ``to_model_dict()`` directly;
the 8 authz-family testers consume ``object_ids()`` / ``endpoints_for()``
instead of re-deriving per probe.

Security contract (inherited from accounts.py and hardened):

  * tokens are redacted to ``{kind}:<first4>...({len})`` for anything that
    leaves the store (logs, reports, to_dict) — raw tokens live in memory
    only, and on-disk persistence is opt-in via ``save(include_tokens=True)``;
  * decoded JWT claims are redacted per-claim before export (claims are
    operator-scoped data, not report decoration).

Deterministic tier: no model calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.runtime_paths import runtime_path, target_slug
from tools.runtime.accounts import redact, decode_jwt_claims

SCHEMA = "bugwolf-session-context/v1"


@dataclass
class EndpointFact:
    """One endpoint's observed behavior under one credential."""

    path: str
    method: str = "GET"
    status: int = 0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "method": self.method,
                "status": self.status, "note": self.note}


@dataclass
class SessionContext:
    """Everything the engine knows about ONE credential."""

    label: str
    username: str = ""
    token_redacted: str = ""
    raw_token: str = ""                      # memory only — never exported
    jwt_header: Dict[str, Any] = field(default_factory=dict)
    jwt_claims: Dict[str, Any] = field(default_factory=dict)
    role: str = ""                           # inferred (see _infer_role)
    role_source: str = ""                    # jwt | response | operator
    identifiers: List[str] = field(default_factory=list)
    object_ids: List[str] = field(default_factory=list)
    endpoints: List[EndpointFact] = field(default_factory=list)
    bound_via: str = ""                      # pre-baked | login | none
    status: str = "unbound"                  # unbound | bound | failed

    def role_is_admin(self) -> bool:
        lowered = (self.role or "").lower()
        return any(k in lowered
                   for k in ("admin", "root", "superuser", "manage"))

    def to_dict(self, *, include_tokens: bool = False) -> Dict[str, Any]:
        # Redaction is STRUCTURAL: derived from the raw token when the
        # pre-computed field is empty, so a directly-constructed context
        # can never export an unredacted session value.
        token = self.token_redacted or \
            (redact(self.raw_token) if self.raw_token else "")
        out: Dict[str, Any] = {
            "label": self.label,
            "username": self.username,
            "token": token,
            "role": self.role,
            "role_source": self.role_source,
            "identifiers": list(self.identifiers),
            "object_ids": list(self.object_ids),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "bound_via": self.bound_via,
            "status": self.status,
        }
        if self.jwt_header:
            out["jwt_header"] = dict(self.jwt_header)
        if self.jwt_claims:
            out["jwt_claims"] = redact_claims(self.jwt_claims)
        if include_tokens and self.raw_token:
            out["raw_token"] = self.raw_token       # explicit opt-in only
        return out


def redact_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Redact the values of identity-bearing claims for export.

    Claim NAMES stay (they are structural facts — ``roles`` exists, ``exp``
    exists); VALUES are redacted except for booleans/numbers and expiry —
    the shape is the evidence, the values are operator data.
    """
    sensitive = ("email", "username", "sub", "name", "preferred_username",
                 "user_id", "uid", "phone", "address")
    out: Dict[str, Any] = {}
    for key, value in claims.items():
        lowered = key.lower()
        if lowered == "exp" and isinstance(value, (int, float)):
            out[key] = int(value)
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            out[key] = value
            continue
        if lowered in sensitive or any(s in lowered for s in sensitive):
            out[key] = redact(str(value))
            continue
        if isinstance(value, str):
            out[key] = value if len(value) <= 64 else value[:61] + "..."
        elif isinstance(value, (dict, list)):
            out[key] = json.dumps(value)[:120]
        else:
            out[key] = str(value)[:64]
    return out


def _extract_object_ids(obj: Any, found: List[str], *, depth: int = 0) -> None:
    """Collect candidate object identifiers from a JSON body (bounded)."""
    if depth > 4 or len(found) >= 64:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = key.lower()
            if lowered in ("id", "user_id", "uuid", "guid", "account_id",
                           "order_id", "object_id", "sub", "ref") \
                    and isinstance(value, (str, int)) and str(value):
                found.append(str(value))
            else:
                _extract_object_ids(value, found, depth=depth + 1)
    elif isinstance(obj, list):
        for item in obj[:32]:
            _extract_object_ids(item, found, depth=depth + 1)


class SessionContextStore:
    """Per-credential session context for one mission (A/B/C + anon)."""

    def __init__(self, mission_id: str, *, project_root=None) -> None:
        self.mission_id = mission_id
        self.root = runtime_path("state", "orchestrator", mission_id,
                                 "sessions", root=project_root)
        self.sessions: Dict[str, SessionContext] = {}

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_matrix(cls, matrix, mission_id: str, *,
                    project_root=None) -> "SessionContextStore":
        """Build from a bound AccountMatrix (accounts stay the source of
        truth for credentials; this store is the model layer above them)."""
        store = cls(mission_id, project_root=project_root)
        for label in ("A", "B", "C"):
            binding = matrix.binding(label)
            if binding is None or binding.status != "bound":
                continue
            ctx = SessionContext(
                label=label,
                username=binding.username,
                raw_token=binding.token,
                token_redacted=redact(binding.token),
                identifiers=list(binding.identifiers) or
                ([binding.username] if binding.username else []),
                status="bound",
                bound_via="pre-baked" if binding.token else "login",
            )
            store._hydrate_jwt(ctx)
            store.sessions[label] = ctx
        return store

    def _hydrate_jwt(self, ctx: SessionContext) -> None:
        """LIVE decode of the session token (Phase 2.2's whole point)."""
        claims = decode_jwt_claims(ctx.raw_token)
        if claims is None:
            ctx.jwt_claims = {}
            return
        # Header too (alg/kid inventory is the JWT-confusion family's input).
        try:
            import base64
            parts = ctx.raw_token.split(".")
            padded = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded.encode()))
            ctx.jwt_header = header if isinstance(header, dict) else {}
        except (ValueError, TypeError, IndexError):
            ctx.jwt_header = {}
        ctx.jwt_claims = claims
        # Role inference, priority 1: JWT claims.
        for key in ("role", "roles", "groups", "scope", "permissions",
                    "authority", "authorities"):
            value = claims.get(key)
            if isinstance(value, str) and value:
                ctx.role, ctx.role_source = value, "jwt"
                return
            if isinstance(value, list) and value:
                ctx.role, ctx.role_source = str(value[0]), "jwt"
                return
        # priority 2: username/sub claims as identifier.
        sub = claims.get("sub") or claims.get("user_id")
        if sub and not ctx.identifiers:
            ctx.identifiers = [str(sub)]

    def observe_response(self, label: str, path: str, *, method: str = "GET",
                         status: int = 0, body: str = "",
                         role_hint: str = "") -> None:
        """Record one authenticated response's facts into the context.

        Updates: endpoint reachability, object-ID inventory, and (when the
        body carries a role field and the JWT did not already give one)
        the inferred role.
        """
        ctx = self.sessions.get(label)
        if ctx is None or label == "anon":
            return
        facts = EndpointFact(path=path, method=method, status=status)
        ctx.endpoints = [e for e in ctx.endpoints
                         if not (e.path == path and e.method == method)]
        ctx.endpoints.append(facts)
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if isinstance(data, dict):
            found: List[str] = []
            _extract_object_ids(data, found)
            for obj_id in found:
                if obj_id not in ctx.object_ids:
                    ctx.object_ids.append(obj_id)
            # Role inference, priority 2: the response object's role field.
            if not ctx.role and role_hint:
                ctx.role, ctx.role_source = role_hint, "response"
            elif not ctx.role:
                role = data.get("role")
                if isinstance(role, str) and role:
                    ctx.role, ctx.role_source = role, "response"

    def register_anon(self) -> SessionContext:
        ctx = SessionContext(label="anon", status="bound",
                             bound_via="none")
        self.sessions["anon"] = ctx
        return ctx

    # -- the U4 identity matrix -------------------------------------------------

    def identity_matrix(self) -> Dict[str, Dict[str, int]]:
        """label x path -> observed status (the authz hunt's base map)."""
        matrix: Dict[str, Dict[str, int]] = {}
        for label, ctx in self.sessions.items():
            matrix[label] = {e.path: e.status for e in ctx.endpoints}
        return matrix

    def reachable(self, label: str) -> List[str]:
        ctx = self.sessions.get(label)
        if ctx is None:
            return []
        return sorted({e.path for e in ctx.endpoints if e.status == 200})

    def object_ids(self, label: Optional[str] = None) -> List[str]:
        """Object-ID inventory for one label (or the union across labels)."""
        if label is not None:
            ctx = self.sessions.get(label)
            return list(ctx.object_ids) if ctx else []
        union: List[str] = []
        for ctx in self.sessions.values():
            for obj_id in ctx.object_ids:
                if obj_id not in union:
                    union.append(obj_id)
        return union

    def roles(self) -> Dict[str, str]:
        return {label: ctx.role for label, ctx in self.sessions.items()
                if ctx.role}

    def endpoints_for(self, label: str) -> List[EndpointFact]:
        ctx = self.sessions.get(label)
        return list(ctx.endpoints) if ctx else []

    # -- persistence -------------------------------------------------------------

    def save(self, *, include_tokens: bool = False) -> Path:
        """Persist the model.  Tokens are redacted unless explicitly
        included (opt-in for resumability; the file is operator-local)."""
        self.root.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA,
            "mission_id": self.mission_id,
            "sessions": {label: ctx.to_dict(include_tokens=include_tokens)
                         for label, ctx in sorted(self.sessions.items())},
            "identity_matrix": self.identity_matrix(),
            "roles": self.roles(),
        }
        path = self.root / "context.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(path)
        return path

    def load(self) -> "SessionContextStore":
        """Rehydrate a saved context (tokens absent unless saved with
        ``include_tokens=True`` — the model survives, credentials re-bind)."""
        path = self.root / "context.json"
        if not path.exists():
            return self
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self
        for label, data in (payload.get("sessions") or {}).items():
            ctx = SessionContext(
                label=label,
                username=str(data.get("username", "")),
                token_redacted=str(data.get("token", "")),
                identifiers=[str(x) for x in (data.get("identifiers") or [])],
                object_ids=[str(x) for x in (data.get("object_ids") or [])],
                role=str(data.get("role", "")),
                role_source=str(data.get("role_source", "")),
                bound_via=str(data.get("bound_via", "")),
                status=str(data.get("status", "unbound")),
            )
            header = data.get("jwt_header")
            if isinstance(header, dict):
                ctx.jwt_header = header
            claims = data.get("jwt_claims")
            if isinstance(claims, dict):
                ctx.jwt_claims = claims
            for fact in data.get("endpoints") or []:
                ctx.endpoints.append(EndpointFact(
                    path=str(fact.get("path", "")),
                    method=str(fact.get("method", "GET")),
                    status=int(fact.get("status", 0) or 0),
                    note=str(fact.get("note", "")),
                ))
            self.sessions[label] = ctx
        return self

    # -- the U4 artifact ----------------------------------------------------------

    def to_model_dict(self) -> Dict[str, UnderstandingModel_Artifact]:
        """The Understanding-Layer U4 artifact payload (roles, claims,
        ownership, reachability) — what /bugwolf-understand will consume."""
        return {
            "schema": SCHEMA,
            "mission_id": self.mission_id,
            "roles": self.roles(),
            "role_sources": {label: ctx.role_source
                             for label, ctx in self.sessions.items()
                             if ctx.role_source},
            "identity_matrix": self.identity_matrix(),
            "object_inventory": {label: list(ctx.object_ids)
                                 for label, ctx in self.sessions.items()
                                 if ctx.object_ids},
            "endpoints": {label: [e.to_dict() for e in ctx.endpoints]
                          for label, ctx in self.sessions.items()
                          if ctx.endpoints},
        }
# The U4 artifact is a plain JSON-able dict; the alias keeps the annotation
# honest without inventing a class hierarchy for a future schema module.
UnderstandingModel_Artifact = Dict[str, Any]
