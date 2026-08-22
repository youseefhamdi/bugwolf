#!/usr/bin/env python3
"""Structured Web/API attack-surface model for BugWolf's discovery core.

Parses the artifacts recon already collects (OpenAPI/Swagger, GraphQL
introspection, and URL+parameter lists) into a uniform model of operations,
parameters, sibling surfaces, and inferred state transitions. Downstream
tools (mutator, discovery scheduler) consume this model to generate
structure-aware, differential experiments.

This module is offline and deterministic: it never makes network requests and
never invents credentials or values — it only structures what the operator
supplies.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "bugwolf-surface-model-v1"

_MAX_DEPTH = 4
_MAX_PARAMS = 200
_MAX_OPS = 2000


class ParamLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"


@dataclass
class Parameter:
    """One mutable parameter (flattened; body fields use dotted names)."""
    name: str
    location: ParamLocation | str
    type: str = "string"            # string|integer|number|boolean|array|object|any
    required: bool = False
    enum: List[Any] = field(default_factory=list)
    format: str = ""                # email|uuid|date|date-time|uri|byte|...
    default: Any = None
    description: str = ""
    items: Optional["Parameter"] = None       # array element shape
    properties: Dict[str, "Parameter"] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.location, ParamLocation):
            self.location = ParamLocation(self.location)
        self.type = (self.type or "any").lower()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["location"] = self.location.value
        if self.items is not None:
            data["items"] = self.items.to_dict()
        data["properties"] = {k: v.to_dict() for k, v in self.properties.items()}
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Parameter":
        raw = dict(data)
        raw["items"] = Parameter.from_dict(raw["items"]) if raw.get("items") else None
        raw["properties"] = {k: Parameter.from_dict(v)
                             for k, v in raw.get("properties", {}).items()}
        return cls(**raw)


@dataclass
class Operation:
    operation_id: str
    method: str
    path: str
    params: List[Parameter] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)
    auth_required: bool = True
    roles: List[str] = field(default_factory=list)
    summary: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = "unknown"         # openapi | graphql | urls

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["params"] = [p.to_dict() for p in self.params]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Operation":
        raw = dict(data)
        raw["params"] = [Parameter.from_dict(p) for p in raw.get("params", [])]
        return cls(**raw)


@dataclass
class SiblingGroup:
    """Operations that should behave identically but may diverge (v1 vs v2)."""
    group_id: str
    reason: str                    # version | method | content_type
    operation_ids: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateTransition:
    """One named step in a resource's inferred workflow."""
    resource: str
    step: str                      # create | update | approve | cancel | ...
    method: str
    path: str
    operation_id: str
    order: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SurfaceModel:
    target: str
    base_urls: List[str] = field(default_factory=list)
    operations: List[Operation] = field(default_factory=list)
    siblings: List[SiblingGroup] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)
    vhost_candidates: List["VhostCandidate"] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def operation_by_id(self, operation_id: str) -> Optional[Operation]:
        for op in self.operations:
            if op.operation_id == operation_id:
                return op
        return None

    def params(self, operation_id: str) -> List[Parameter]:
        op = self.operation_by_id(operation_id)
        return op.params if op else []

    def transition_steps(self, resource: str) -> List[StateTransition]:
        return sorted((t for t in self.transitions if t.resource == resource),
                      key=lambda t: t.order)

    def fingerprint(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "target": self.target,
            "base_urls": list(self.base_urls),
            "operations": [op.to_dict() for op in self.operations],
            "siblings": [s.to_dict() for s in self.siblings],
            "transitions": [t.to_dict() for t in self.transitions],
            "vhost_candidates": [v.to_dict() for v in self.vhost_candidates],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SurfaceModel":
        return cls(
            target=data["target"],
            base_urls=list(data.get("base_urls", [])),
            operations=[Operation.from_dict(o) for o in data.get("operations", [])],
            siblings=[SiblingGroup(**s) for s in data.get("siblings", [])],
            transitions=[StateTransition(**t) for t in data.get("transitions", [])],
            vhost_candidates=[VhostCandidate(**v) for v in data.get("vhost_candidates", [])],
            metadata=dict(data.get("metadata", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Path / name normalization helpers
# ---------------------------------------------------------------------------

_VERSION_SEGMENT = re.compile(r"^v\d+$", re.IGNORECASE)


def normalize_path(path: str) -> str:
    """Replace version segments with ``{ver}`` so v1/v2 paths group together."""
    segments = path.split("/")
    out = []
    for seg in segments:
        if _VERSION_SEGMENT.match(seg):
            out.append("{ver}")
        else:
            out.append(seg)
    return "/".join(out)


def resource_of(path: str) -> str:
    """A stable resource key: path with version and ID segments collapsed."""
    segments = normalize_path(path).split("/")
    out = []
    for seg in segments:
        if not seg:
            continue
        if seg.startswith("{") and seg.endswith("}"):
            out.append("{param}")
        elif _VERSION_SEGMENT.match(seg):
            continue
        elif seg.isdigit() or re.fullmatch(r"[0-9a-fA-F]{8,}", seg):
            out.append("{param}")
        else:
            out.append(seg)
    return "/" + "/".join(out)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

_TYPE_ALIASES = {
    "string": "string", "str": "string", "text": "string",
    "integer": "integer", "int": "integer", "int32": "integer", "int64": "integer",
    "number": "number", "float": "number", "double": "number", "decimal": "number",
    "boolean": "boolean", "bool": "boolean",
    "array": "array", "object": "object",
    "file": "string",
}


def _norm_type(raw: Any) -> str:
    if isinstance(raw, dict):
        raw = raw.get("type", "any")
    return _TYPE_ALIASES.get(str(raw).lower(), "any")


def _param(name: str, location: ParamLocation, *, required: bool = False,
           type_: str = "string", enum: Optional[List[Any]] = None,
           fmt: str = "", description: str = "",
           items: Optional[Parameter] = None) -> Parameter:
    return Parameter(name=name, location=location, type=type_, required=required,
                     enum=list(enum or []), format=fmt, description=description,
                     items=items)


def _parse_parameter(pspec: Dict[str, Any], body: bool = False) -> Optional[Parameter]:
    """Parse one OpenAPI/Swagger parameter object (or body schema field)."""
    location = ParamLocation.BODY if body else ParamLocation(
        pspec.get("in", "query"))
    name = pspec.get("name", "")
    if not name:
        return None
    required = bool(pspec.get("required", False))
    if body:
        schema = pspec.get("schema", {})
        type_ = _norm_type(schema.get("type", "string"))
        fmt = schema.get("format", "")
        enum = schema.get("enum", [])
        return _param(name, location, required=required, type_=type_,
                      enum=enum, fmt=fmt,
                      description=pspec.get("description", ""))
    # Non-body parameter: Swagger 2.0 keeps type/enum/format inline.
    type_ = _norm_type(pspec.get("type", pspec.get("schema", {}).get("type", "string")))
    schema = pspec.get("schema", {}) if isinstance(pspec.get("schema"), dict) else {}
    fmt = pspec.get("format", schema.get("format", ""))
    enum = pspec.get("enum", schema.get("enum", []))
    items = None
    if pspec.get("items") and isinstance(pspec["items"], dict):
        items = _param(name + "[]", location, type_=_norm_type(pspec["items"].get("type", "string")),
                       enum=pspec["items"].get("enum", []))
    return _param(name, location, required=required, type_=type_, enum=enum,
                  fmt=fmt, description=pspec.get("description", ""), items=items)


def _flatten_schema(schema: Dict[str, Any], prefix: str, *, depth: int = 0,
                    required_fields: Optional[set] = None) -> List[Parameter]:
    """Flatten a JSON schema into dotted-name scalar parameters (bounded)."""
    if depth >= _MAX_DEPTH or not isinstance(schema, dict):
        return []
    required_fields = required_fields or set()
    type_ = _norm_type(schema.get("type", "object"))

    if type_ == "array":
        items = schema.get("items", {})
        if isinstance(items, dict) and _norm_type(items.get("type", "object")) == "object":
            return _flatten_schema(items, prefix, depth=depth + 1,
                                   required_fields=set(items.get("required", [])))
        return [_param(prefix, ParamLocation.BODY, type_="array",
                       required=prefix in required_fields,
                       fmt=schema.get("format", ""))]

    if type_ == "object":
        out: List[Parameter] = []
        props = schema.get("properties", {})
        req = set(schema.get("required", []))
        for key, sub in props.items():
            child_name = f"{prefix}.{key}" if prefix else key
            sub_type = _norm_type(sub.get("type", "object"))
            if sub_type == "object":
                out.extend(_flatten_schema(sub, child_name, depth=depth + 1,
                                           required_fields=set(sub.get("required", []))))
            elif sub_type == "array":
                items = sub.get("items", {})
                if isinstance(items, dict) and _norm_type(items.get("type", "object")) == "object":
                    out.extend(_flatten_schema(items, child_name, depth=depth + 1,
                                               required_fields=set(items.get("required", []))))
                else:
                    out.append(_param(child_name, ParamLocation.BODY, type_="array",
                                      required=key in req, fmt=sub.get("format", "")))
            else:
                out.append(_param(child_name, ParamLocation.BODY, type_=sub_type,
                                  required=key in req,
                                  enum=sub.get("enum", []),
                                  fmt=sub.get("format", ""),
                                  description=sub.get("description", "")))
        return out

    # Scalar at the top level of a body schema.
    return [_param(prefix or "body", ParamLocation.BODY, type_=type_,
                   required=prefix in required_fields,
                   enum=schema.get("enum", []), fmt=schema.get("format", ""))]


def parse_openapi(spec: Dict[str, Any], target: str,
                  base_url: str = "") -> SurfaceModel:
    """Parse an OpenAPI 3.x or Swagger 2.0 document into a SurfaceModel."""
    base_urls = []
    if base_url:
        base_urls.append(base_url)
    elif spec.get("servers"):
        base_urls = [s.get("url", "") for s in spec.get("servers", []) if s.get("url")]
    elif spec.get("host"):
        scheme = spec.get("schemes", ["https"])[0]
        base_urls = [f"{scheme}://{spec['host']}{spec.get('basePath', '')}"]

    operations: List[Operation] = []
    for path, methods in (spec.get("paths") or {}).items():
        for method, op_spec in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete",
                                      "head", "options"}:
                continue
            params: List[Parameter] = []
            for pspec in op_spec.get("parameters", []):
                p = _parse_parameter(pspec)
                if p:
                    params.append(p)
            body = op_spec.get("requestBody")
            if body and isinstance(body, dict):
                content = body.get("content", {})
                for ctype, media in content.items():
                    schema = media.get("schema", {})
                    required_fields = set(schema.get("required", [])) \
                        if isinstance(schema, dict) else set()
                    for p in _flatten_schema(schema, "",
                                             required_fields=required_fields):
                        if not any(q.name == p.name for q in params):
                            params.append(p)
            params = params[:_MAX_PARAMS]
            op = Operation(
                operation_id=op_spec.get("operationId")
                            or f"{method.upper()} {path}".strip(),
                method=method.upper(),
                path=path,
                params=params,
                content_types=[c for c in body.get("content", {}).keys()] if body else [],
                auth_required=bool(op_spec.get("security", True)),
                summary=op_spec.get("summary", ""),
                tags=op_spec.get("tags", []),
                source="openapi",
            )
            operations.append(op)
            if len(operations) >= _MAX_OPS:
                break

    model = SurfaceModel(target=target, base_urls=base_urls, operations=operations)
    model.siblings = pair_version_siblings(operations)
    model.transitions = infer_transitions(operations)
    return model


def _graphql_type_name(type_ref: Dict[str, Any]) -> Tuple[str, bool]:
    """Return (base_name, is_required) for a GraphQL type reference."""
    required = False
    cur = type_ref
    while isinstance(cur, dict):
        kind = cur.get("kind", "")
        if kind == "NON_NULL":
            required = True
            cur = cur.get("ofType")
        elif kind == "LIST":
            cur = cur.get("ofType")
        else:
            return (cur.get("name", "String") or "String"), required
    return ("String", required)


_GRAPHQL_SCALARS = {
    "String": "string", "ID": "string", "Int": "integer", "Float": "number",
    "Boolean": "boolean",
}


def parse_graphql(introspection: Dict[str, Any], target: str,
                  base_url: str = "") -> SurfaceModel:
    """Parse a GraphQL introspection result into a SurfaceModel.

    Accepts either the raw ``{data: {__schema: ...}}`` envelope or a bare
    ``__schema`` object. Query and Mutation root fields become operations;
    their arguments become body parameters. Enum arguments are populated from
    the schema's ENUM type definitions.
    """
    schema = introspection.get("__schema") or introspection.get("data", {}).get("__schema", {})
    if not schema:
        return SurfaceModel(target=target, base_urls=[base_url] if base_url else [])

    types: Dict[str, Dict[str, Any]] = {}
    for t in schema.get("types", []):
        if isinstance(t, dict) and t.get("name"):
            types[t["name"]] = t

    def _enum_values(name: str) -> List[Any]:
        t = types.get(name, {})
        if t.get("kind") == "ENUM":
            return [e.get("name") for e in t.get("enumValues", [])]
        return []

    def _arg_param(name: str, arg: Dict[str, Any]) -> Parameter:
        base, required = _graphql_type_name(arg.get("type", {}))
        base_name = base.rstrip("!")
        if base_name in _GRAPHQL_SCALARS:
            type_ = _GRAPHQL_SCALARS[base_name]
            fmt = "uuid" if base_name == "ID" else ""
        elif base_name in types and types[base_name].get("kind") == "ENUM":
            type_ = "string"
            fmt = ""
            return _param(name, ParamLocation.BODY, type_=type_,
                          required=required, enum=_enum_values(base_name),
                          description=arg.get("description", ""))
        else:
            type_ = "object" if types.get(base_name, {}).get("kind") == "INPUT_OBJECT" \
                else "any"
        return _param(name, ParamLocation.BODY, type_=type_, required=required,
                      description=arg.get("description", ""))

    operations: List[Operation] = []
    root_names = []
    for key in ("queryType", "mutationType", "subscriptionType"):
        node = schema.get(key)
        if isinstance(node, dict) and node.get("name"):
            root_names.append(node["name"])

    for root_name in root_names:
        root = types.get(root_name, {})
        for field in root.get("fields", []):
            name = field.get("name", "")
            if not name:
                continue
            args = [_arg_param(a.get("name", ""), a) for a in field.get("args", [])
                    if a.get("name")]
            operations.append(Operation(
                operation_id=f"{root_name}.{name}",
                method="POST",
                path="/graphql",
                params=args[:_MAX_PARAMS],
                content_types=["application/json"],
                auth_required=True,
                summary=field.get("description", ""),
                tags=[root_name],
                source="graphql",
            ))

    model = SurfaceModel(target=target,
                         base_urls=[base_url] if base_url else [],
                         operations=operations[:_MAX_OPS])
    model.siblings = pair_version_siblings(operations)
    model.transitions = infer_transitions(operations)
    return model


def parse_urls(urls: Iterable[str], target: str,
               base_urls: Optional[Iterable[str]] = None) -> SurfaceModel:
    """Build a SurfaceModel from a recon URL/parameter list.

    Query parameters become query Parameters; explicit ``{param}`` path
    placeholders become path Parameters. No value-type guessing beyond id-like
    names (treated as integers for boundary mutation).
    """
    operations: List[Operation] = []
    seen: set = set()
    for raw in urls:
        raw = str(raw).strip()
        if not raw or raw.startswith("#"):
            continue
        parsed = urllib.parse.urlparse(raw)
        if not parsed.netloc and not parsed.path:
            continue
        path = parsed.path or "/"
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        params: List[Parameter] = []
        for name, _value in qs:
            type_ = "integer" if re.search(r"(^|_)id$|^id$", name) else "string"
            params.append(_param(name, ParamLocation.QUERY, type_=type_))
        for seg in path.split("/"):
            if seg.startswith("{") and seg.endswith("}"):
                params.append(_param(seg[1:-1], ParamLocation.PATH,
                                     required=True, type_="string"))
        key = f"{parsed.netloc}|{path}|{parsed.query}"
        if key in seen:
            continue
        seen.add(key)
        operations.append(Operation(
            operation_id=f"GET {path}" if path else f"GET {raw}",
            method="GET",
            path=path,
            params=params[:_MAX_PARAMS],
            auth_required=False,
            source="urls",
        ))
        if len(operations) >= _MAX_OPS:
            break

    model = SurfaceModel(target=target,
                         base_urls=list(base_urls or []),
                         operations=operations)
    model.siblings = pair_version_siblings(operations)
    model.transitions = infer_transitions(operations)
    return model


# ---------------------------------------------------------------------------
# Sibling pairing + state-transition inference
# ---------------------------------------------------------------------------

def pair_version_siblings(operations: Iterable[Operation]) -> List[SiblingGroup]:
    """Group operations whose paths differ only by version segment.

    The classic 'fixed one surface, forgot the sibling' divergence lives here:
    ``/v1/users/{id}`` vs ``/v2/users/{id}``.
    """
    buckets: Dict[Tuple[str, str], List[Operation]] = {}
    for op in operations:
        key = (normalize_path(op.path), op.method.upper())
        buckets.setdefault(key, []).append(op)

    groups: List[SiblingGroup] = []
    for (norm_path, method), ops in sorted(buckets.items()):
        distinct = sorted({o.operation_id for o in ops})
        if len(distinct) < 2:
            continue
        groups.append(SiblingGroup(
            group_id=hashlib.sha256(f"{norm_path}|{method}".encode()).hexdigest()[:16],
            reason="version",
            operation_ids=distinct,
        ))
    return groups


_STEP_PRIORITY = {
    "create": 0, "register": 0, "signup": 0, "initiate": 0, "start": 0, "open": 0,
    "submit": 1, "verify": 1, "confirm": 1, "validate": 1,
    "approve": 2, "authorize": 2, "activate": 2, "publish": 2,
    "complete": 3, "fulfill": 3, "settle": 3, "deliver": 3,
    "update": 4, "modify": 4, "edit": 4, "patch": 4,
    "cancel": 5, "revoke": 5, "reject": 5, "deny": 5, "decline": 5,
    "delete": 6, "remove": 6, "destroy": 6,
}


def _step_of(method: str, path: str) -> str:
    """Infer a workflow step label from an HTTP method + path keywords."""
    m = method.upper()
    text = (path or "").lower()
    for keyword, label in (("cancel", "cancel"), ("revoke", "revoke"),
                           ("reject", "reject"), ("deny", "deny"),
                           ("approve", "approve"), ("activate", "activate"),
                           ("publish", "publish"), ("verify", "verify"),
                           ("confirm", "confirm"), ("submit", "submit"),
                           ("complete", "complete"), ("fulfill", "fulfill"),
                           ("settle", "settle"), ("create", "create"),
                           ("register", "register"), ("signup", "signup"),
                           ("initiate", "initiate"), ("start", "start")):
        if keyword in text:
            return label
    if m == "POST":
        return "create"
    if m in ("PUT", "PATCH"):
        return "update"
    if m == "DELETE":
        return "delete"
    return "read"


_WORKFLOW_VERBS = {
    "create", "register", "signup", "initiate", "start", "open",
    "submit", "verify", "confirm", "validate", "approve", "authorize",
    "activate", "publish", "complete", "fulfill", "settle", "deliver",
    "update", "modify", "edit", "patch", "cancel", "revoke", "reject",
    "deny", "decline", "delete", "remove", "destroy", "list", "search",
}


def workflow_resource(path: str) -> str:
    """Collapse a path to its noun root so sub-path verbs group together.

    ``/orders/approve`` and ``/orders/cancel`` both reduce to ``/orders``.
    """
    segments = resource_of(path).split("/")
    while len(segments) > 1 and segments[-1].lower() in _WORKFLOW_VERBS:
        segments.pop()
    return "/".join(segments) or "/"


def infer_transitions(operations: Iterable[Operation]) -> List[StateTransition]:
    """Derive a lightweight per-resource workflow from method + path verbs.

    Steps are ordered by a fixed verb priority so the mutator can generate
    skip / repeat / reorder probes (e.g. call ``approve`` before ``create``).
    """
    by_resource: Dict[str, List[Operation]] = {}
    for op in operations:
        by_resource.setdefault(workflow_resource(op.path), []).append(op)

    transitions: List[StateTransition] = []
    for resource, ops in by_resource.items():
        if len(ops) < 2:
            continue
        steps = sorted(
            ((_step_of(op.method, op.path), op) for op in ops),
            key=lambda pair: (_STEP_PRIORITY.get(pair[0], 9), pair[1].path),
        )
        for order, (step, op) in enumerate(steps):
            transitions.append(StateTransition(
                resource=resource, step=step, method=op.method,
                path=op.path, operation_id=op.operation_id, order=order,
            ))
    return transitions


# ---------------------------------------------------------------------------
# Special high-value surfaces (sitemap + pagination SQLi)
# ---------------------------------------------------------------------------

# Query parameters commonly consumed as sortable/paginated input. These are
# classic injection sinks (e.g. ``/sitemap.xml?offset=1``) and are represented
# as typed integer parameters so the mutator plans time-based blind-SQLi checks.
_PAGINATION_PARAMS = ("offset", "page", "limit", "sort", "order", "filter")


def ensure_special_surfaces(model: SurfaceModel) -> SurfaceModel:
    """Add high-value surfaces recon may have missed (offline, deterministic).

    Ensures ``GET /sitemap.xml`` is present with pagination parameters so the
    mutator emits structure-aware SQLi detection plans even when recon recorded
    a bare ``/sitemap.xml`` with no query string. Existing operations are
    extended rather than duplicated.
    """
    sitemap = next((op for op in model.operations
                    if op.path.rstrip("/").lower() == "/sitemap.xml"), None)
    if sitemap is None:
        sitemap = Operation(
            operation_id="GET /sitemap.xml",
            method="GET",
            path="/sitemap.xml",
            params=[],
            auth_required=False,
            source="special",
        )
        model.operations.append(sitemap)
    existing = {p.name for p in sitemap.params}
    for name in _PAGINATION_PARAMS:
        if name not in existing:
            sitemap.params.append(_param(name, ParamLocation.QUERY, type_="integer"))
    return model


# ---------------------------------------------------------------------------
# Vhost grouping: internal vhost candidates for host-confusion probes
# ---------------------------------------------------------------------------

# Labels that suggest an internal / backend / admin surface. Subdomains of the
# target carrying these labels (admin.example.com, api.example.com, …) are the
# high-value Host-header candidates when a proxy or app trusts a forged Host.
_VHOST_LABELS = {
    "admin", "administrator", "dashboard", "panel", "backoffice", "backend",
    "internal", "intranet", "api", "dev", "development", "staging", "stage",
    "stg", "uat", "qa", "test", "testing", "mgmt", "manage", "console",
    "portal", "gateway", "status", "graphql", "graph", "db", "database",
    "redis", "elastic", "kibana", "jenkins", "gitlab", "grafana", "mail",
    "ftp", "ssh", "vpn", "ws", "sso", "auth", "idp", "identity", "billing",
    "payments", "finance", "hr", "corp", "office",
}


@dataclass
class VhostCandidate:
    """One candidate hostname for Host/forwarded-host confusion.

    ``group`` is the shared resolved-IP key (or ``""``) so hosts that resolve
    to the same server can be recognized as each other's vhosts.
    """

    host: str
    label: str
    source: str = "subdomain"   # subdomain | generic
    group: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalize_host(raw: str) -> str:
    """Lower-case a host, stripping scheme, port, path, and trailing dot."""
    host = str(raw).strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0].split("@")[-1]
    return host.rstrip(".")


def _vhost_label(hostname: str, apex: str) -> str:
    prefix = hostname[: -len(apex) - 1] if hostname.endswith("." + apex) else hostname
    for label in (part for part in prefix.split(".") if part):
        if label.lower() in _VHOST_LABELS:
            return label.lower()
    return "subdomain"


def infer_vhost_candidates(
    target: str,
    hosts: Iterable[str],
    *,
    resolved_map: Optional[Dict[str, str]] = None,
    live_hosts: Optional[Iterable[str]] = None,
    max_candidates: int = 64,
) -> List[VhostCandidate]:
    """Rank internal vhost candidates from the target's discovered hosts.

    Keeps only subdomains of ``target``. Internal-looking labels rank first,
    then candidates that share a resolved IP with a live host (true vhosts on
    the same server), then the rest. ``resolved_map`` maps host -> IP; when
    absent, the IP-sharing tier is skipped.
    """
    apex = _normalize_host(target)
    live_ips: set = set()
    if resolved_map and live_hosts:
        for live in live_hosts:
            ip = resolved_map.get(_normalize_host(live))
            if ip:
                live_ips.add(ip)

    candidates: Dict[str, VhostCandidate] = {}
    seen: set = set()
    for raw in hosts:
        host = _normalize_host(raw)
        if not host or host in seen:
            continue
        seen.add(host)
        if not host.endswith("." + apex) or host == apex:
            continue
        label = _vhost_label(host, apex)
        group = (resolved_map or {}).get(host, "")
        candidates.setdefault(host, VhostCandidate(host, label, "subdomain", group))

    return sorted(
        candidates.values(),
        key=lambda c: (
            c.label not in _VHOST_LABELS,               # internal label first
            not (c.group and c.group in live_ips),       # same-server vhost next
            c.host,
        ),
    )[:max_candidates]


# ---------------------------------------------------------------------------
# Loading helpers + CLI
# ---------------------------------------------------------------------------

def load_surface(*, target: str, openapi_file: str = "", graphql_file: str = "",
                 urls_file: str = "", surface_file: str = "",
                 base_url: str = "") -> SurfaceModel:
    """Load a SurfaceModel from one or more artifact files."""
    if surface_file:
        return SurfaceModel.from_dict(json.loads(Path(surface_file).read_text()))

    models: List[SurfaceModel] = []
    if openapi_file:
        models.append(parse_openapi(json.loads(Path(openapi_file).read_text()),
                                    target, base_url=base_url))
    if graphql_file:
        models.append(parse_graphql(json.loads(Path(graphql_file).read_text()),
                                    target, base_url=base_url))
    if urls_file:
        urls = [l for l in Path(urls_file).read_text().splitlines() if l.strip()]
        models.append(parse_urls(urls, target))

    if not models:
        raise ValueError("no surface artifacts supplied (openapi/graphql/urls/surface)")

    merged = models[0]
    seen_ops = {op.operation_id for op in merged.operations}
    base_urls = set(merged.base_urls)
    for model in models[1:]:
        base_urls.update(model.base_urls)
        for op in model.operations:
            if op.operation_id not in seen_ops:
                merged.operations.append(op)
                seen_ops.add(op.operation_id)
    merged.base_urls = sorted(base_urls)
    merged.siblings = pair_version_siblings(merged.operations)
    merged.transitions = infer_transitions(merged.operations)
    merged.metadata["sources"] = {
        "openapi": bool(openapi_file), "graphql": bool(graphql_file),
        "urls": bool(urls_file),
    }
    return ensure_special_surfaces(merged)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Build a BugWolf Web/API surface model from recon artifacts")
    parser.add_argument("--target", required=True)
    parser.add_argument("--openapi", help="OpenAPI/Swagger JSON file")
    parser.add_argument("--graphql", help="GraphQL introspection JSON file")
    parser.add_argument("--urls-file", help="Recon URL list (one per line)")
    parser.add_argument("--surface-file", help="Load a previously saved surface model")
    parser.add_argument("--recon-dir", help="Auto-discover schemas from a recon output directory")
    parser.add_argument("--base-url", default="", help="Base URL for operations")
    parser.add_argument("--output", help="Write the model JSON to this path")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = parser.parse_args()

    try:
        if args.recon_dir:
            from tools.schema_extractor import build_surface
            model = build_surface(args.target, args.recon_dir)
        else:
            model = load_surface(
                target=args.target, openapi_file=args.openapi,
                graphql_file=args.graphql, urls_file=args.urls_file,
                surface_file=args.surface_file, base_url=args.base_url)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    if args.output:
        Path(args.output).write_text(model.to_json() + "\n")

    if args.json:
        print(model.to_json())
    else:
        print(f"[*] Surface model: {args.target}")
        print(f"    operations: {len(model.operations)}")
        print(f"    siblings:   {len(model.siblings)}")
        print(f"    transitions:{len(model.transitions)}")
        for op in model.operations[:20]:
            print(f"    {op.method:6s} {op.path}  [{op.source}]")


if __name__ == "__main__":
    main()
