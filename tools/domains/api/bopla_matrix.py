#!/usr/bin/env python3
"""BugWolf BOPLA Matrix — object-property level authorization (OWASP API3).

BOPLA (Broken Object Property Level Authorization) is the successor to
"mass assignment".  Two failure shapes, both property-level:

  * **over-POST / mass assignment** — the server accepts request-body
    properties it never declared (or properties it should never let the
    client set): ``role``, ``is_admin``, ``balance``, ``verified``, …
  * **under-POST / implicit trust** — the server derives a sensitive
    property from the session/context instead of the request, so a *missing*
    field or an untouched nested object grants more than intended.

Unlike ``mutator.py`` (which injects a static list of 8 field names), this
matrix is **schema-driven**: it reads the OpenAPI request-body schema and
builds the property inventory from what the API itself declares, then
flags the writeable-sensitive candidates plus the common implicit-trust
properties — producing per-endpoint, per-property validation plans.

Design (deterministic core, uncensored, workflow-aware):

  * Deterministic: same spec + observed bodies => identical matrix.
  * Offline: input is an OpenAPI spec (and optionally observed request
    bodies); output is *plans* written to
    ``recon/<target>/discovery/bopla-matrix.json`` (a ``coverage-plan``
    artifact).  Live over-POST replay is the operator's step.
  * Emits ``AUTH_CANDIDATE`` on the signal bus for high-confidence
    writeable-sensitive properties.
  * Uncensored: no scope/confirmation gates.

Usage:
  python3 tools/domains/api/bopla_matrix.py --target acme --openapi spec.json
  python3 tools/domains/api/bopla_matrix.py --target acme --openapi spec.json --bodies observed.jsonl
  python3 tools/domains/api/bopla_matrix.py --target acme --json
"""

import json
import re
import sys
from dataclasses import dataclass, field, asdict
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

SCHEMA = "bugwolf/bopla-matrix/v1"

# Properties that are extremely unlikely to be legitimate client-writeable.
# A server accepting any of these from the request body is a mass-assignment
# (over-POST) finding candidate.  These are the property-level counterpart of
# the IDOR object keys — the "who is allowed to set this field" question.
SENSITIVE_WRITEABLE = (
    "role", "roles", "is_admin", "admin", "isadmin", "is_staff", "is_superuser",
    "permissions", "permission", "acl", "scope", "scopes", "privilege",
    "privileges", "is_verified", "verified", "is_active", "is_enabled",
    "is_approved", "approved", "is_paid", "paid", "payment_status", "status",
    "balance", "credit", "quota", "trial", "plan", "subscription",
    "organization_id", "org_id", "team_id", "owner_id", "owner", "creator_id",
    "user_id", "uid", "account_id", "account", "tenant_id", "tenant",
    "password", "password_hash", "secret", "token", "api_key", "apikey",
    "email_verified", "phone_verified", "mfa_enabled", "2fa_enabled",
    "suspended", "banned", "blocked", "locked", "deactivated",
    "is_public", "visibility", "share_link", "public",
)

# Read-only markers in the schema — properties the server explicitly declares
# as response-only; if the request schema includes them, that is already odd.
READ_ONLY_MARKERS = ("readonly", "readOnly", "read_only", "read-only")

# Common implicit-trust properties for under-POST detection: fields the server
# likely derives from the session, so a client sending them (or omitting them)
# may probe the trust boundary.
IMPLICIT_TRUST = (
    "role", "is_admin", "owner_id", "user_id", "tenant_id", "org_id",
    "created_by", "updated_by", "is_verified", "is_approved",
)


@dataclass
class BoplaFinding:
    property_name: str
    shape: str  # over_post | under_post | read_only_declared
    endpoint: str
    method: str
    schema_declared: bool
    sensitive: bool
    risk: str  # high | medium | low
    rationale: str
    validation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BoplaMatrix:
    target: str
    generated_at: str
    findings: List[BoplaFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _id(prefix: str, *parts: str) -> str:
    import hashlib
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _ref_name(value: Any) -> str:
    """Pull the schema name out of a $ref (or an inline schema name)."""
    if isinstance(value, dict):
        ref = value.get("$ref") or ""
        if ref:
            return ref.rsplit("/", 1)[-1]
        return str(value.get("title") or value.get("name") or "")
    return ""


def _resolve_schema(ref: str, components: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = ref.rsplit("/", 1)[-1]
    schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
    if not isinstance(schemas, dict):
        return None
    value = schemas.get(name)
    return value if isinstance(value, dict) else None


def _collect_properties(schema: Dict[str, Any], components: Dict[str, Any],
                        *, depth: int = 0) -> Dict[str, Dict[str, Any]]:
    """Flatten a (possibly $ref'd) object schema into {name: prop_schema}."""
    if depth > 6:
        return {}
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if ref:
        resolved = _resolve_schema(ref, components)
        if not resolved:
            return {}
        return _collect_properties(resolved, components, depth=depth + 1)
    out: Dict[str, Dict[str, Any]] = {}
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for name, prop in properties.items():
            if isinstance(prop, dict):
                out[name] = prop
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for part in all_of:
            merged = _collect_properties(part, components, depth=depth + 1)
            for name, prop in merged.items():
                out.setdefault(name, prop)
    return out


def _is_read_only(prop: Dict[str, Any]) -> bool:
    return any(bool(prop.get(marker)) for marker in READ_ONLY_MARKERS)



def _body_schema_for(operation: Dict[str, Any], components: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the request-body schema from an OpenAPI operation."""
    if not isinstance(operation, dict):
        return None
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return None
    content = request_body.get("content", {})
    if not isinstance(content, dict):
        return None
    for media_type in ("application/json", "*/*"):
        media = content.get(media_type)
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def build_matrix(target: str, spec: Dict[str, Any],
                 observed_bodies: Optional[List[Dict[str, Any]]] = None) -> BoplaMatrix:
    """Deterministically build the BOPLA matrix from an OpenAPI spec.

    ``observed_bodies`` (optional) are real request bodies seen during recon;
    when supplied, properties present in the body but absent from the schema
    are flagged as shadow-property over-POST candidates.
    """
    matrix = BoplaMatrix(target=target,
                         generated_at=datetime.now(timezone.utc).isoformat())
    components = spec.get("components", {}) if isinstance(spec, dict) else {}
    paths = spec.get("paths", {}) if isinstance(spec, dict) else {}
    observed_props: Dict[str, List[str]] = {}
    if observed_bodies:
        for body in observed_bodies:
            if not isinstance(body, dict):
                continue
            endpoint = str(body.get("url") or body.get("endpoint") or body.get("path") or "")
            method = str(body.get("method") or "POST").upper()
            data = body.get("body")
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    data = None
            if isinstance(data, dict):
                key = f"{method} {endpoint}"
                observed_props.setdefault(key, [])
                observed_props[key].extend(str(k) for k in data.keys())

    findings: List[BoplaFinding] = []
    seen: set = set()
    for path, item in (paths.items() if isinstance(paths, dict) else []):
        if not isinstance(item, dict):
            continue
        for method in ("post", "put", "patch"):
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            endpoint = f"{method.upper()} {path}"
            schema = _body_schema_for(operation, components)
            declared: Dict[str, Dict[str, Any]] = {}
            if schema:
                declared = _collect_properties(schema, components)

            # -- over-POST: sensitive properties the schema allows in the body.
            for prop_name, prop in declared.items():
                key = (endpoint, prop_name)
                if key in seen:
                    continue
                lower = prop_name.lower()
                sensitive = lower in SENSITIVE_WRITEABLE or any(
                    marker in lower for marker in ("is_", "role", "admin", "permission"))
                if not sensitive:
                    continue
                seen.add(key)
                risk = "high" if lower in (
                    "role", "roles", "is_admin", "admin", "balance", "paid",
                    "permissions", "is_verified", "approved", "owner_id",
                    "tenant_id", "organization_id", "password", "secret",
                ) else "medium"
                findings.append(BoplaFinding(
                    property_name=prop_name, shape="over_post",
                    endpoint=endpoint, method=method.upper(),
                    schema_declared=True, sensitive=True, risk=risk,
                    rationale=(
                        f"The request schema for {endpoint} declares writeable "
                        f"property '{prop_name}' — the server may bind it "
                        f"directly to the object (mass assignment / BOPLA)."),
                    validation_steps=[
                        "Create a disposable object with the two test accounts.",
                        f"Send the request body with '{prop_name}' set to a "
                        "value the caller should not control (e.g. a second "
                        "account's id, a higher role, paid=true).",
                        "Check the persisted object: if the property changed, "
                        "the server over-binds it — record the A/B diff.",
                    ],
                ))

            # -- over-POST: read-only properties present in the request schema.
            for prop_name, prop in declared.items():
                if not _is_read_only(prop):
                    continue
                key = ("ro", endpoint, prop_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(BoplaFinding(
                    property_name=prop_name, shape="read_only_declared",
                    endpoint=endpoint, method=method.upper(),
                    schema_declared=True, sensitive=False, risk="medium",
                    rationale=(
                        f"'{prop_name}' is marked read-only in the schema yet "
                        f"appears in the request body contract — sending it "
                        f"may still bind server-side."),
                    validation_steps=[
                        "Send the read-only property with a sentinel value "
                        "and check whether the object reflects it.",
                        "If it binds, the read-only marker is not enforced "
                        "server-side (BOPLA variant).",
                    ],
                ))

            # -- over-POST: shadow properties observed in real bodies.
            observed = observed_props.get(endpoint, [])
            shadow = [name for name in observed if name not in declared]
            for prop_name in shadow:
                key = ("shadow", endpoint, prop_name)
                if key in seen:
                    continue
                seen.add(key)
                lower = prop_name.lower()
                sensitive = lower in SENSITIVE_WRITEABLE or any(
                    marker in lower for marker in ("is_", "role", "admin"))
                findings.append(BoplaFinding(
                    property_name=prop_name, shape="over_post",
                    endpoint=endpoint, method=method.upper(),
                    schema_declared=False, sensitive=sensitive,
                    risk="high" if sensitive else "low",
                    rationale=(
                        f"Observed request body for {endpoint} carries "
                        f"'{prop_name}', which the OpenAPI request schema does "
                        f"not declare — the server may accept undocumented "
                        f"properties (shadow over-POST surface)."),
                    validation_steps=[
                        "Confirm the endpoint accepts the shadow property "
                        "(no 4xx validation error) with a harmless value.",
                        "If accepted and sensitive, escalate via the "
                        "over-POST steps above.",
                    ],
                ))

            # -- under-POST: implicit-trust properties absent from the body.
            for prop_name in IMPLICIT_TRUST:
                key = ("under", endpoint, prop_name)
                if key in seen or prop_name in declared:
                    continue
                seen.add(key)
                findings.append(BoplaFinding(
                    property_name=prop_name, shape="under_post",
                    endpoint=endpoint, method=method.upper(),
                    schema_declared=False, sensitive=True, risk="medium",
                    rationale=(
                        f"'{prop_name}' is not part of the {endpoint} request "
                        f"contract, so the server either derives it from the "
                        f"session (correct) or trusts a client hint "
                        f"(under-POST / implicit-trust BOPLA)."),
                    validation_steps=[
                        "Observe the created object with two test accounts: "
                        "the property must come from each session, not from "
                        "any client-supplied hint.",
                        "Send the property explicitly with a second account's "
                        "value and check whether the server honors it — "
                        "honoring it is the under-POST finding.",
                    ],
                ))

    matrix.findings = findings
    return matrix


def write_matrix(matrix: BoplaMatrix, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to recon/<target>/discovery/bopla-matrix.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", matrix.target) or "default"
    out_dir = root / "recon" / target_slug / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "bopla-matrix.json"
    out_path.write_text(json.dumps(matrix.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf BOPLA Matrix — object-property level auth (OWASP API3)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--openapi", required=True,
                        help="Path to the OpenAPI/Swagger spec JSON")
    parser.add_argument("--bodies", default="",
                        help="Optional JSON/JSONL of observed request bodies "
                             "(url/method/body)")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    try:
        spec = json.loads(Path(args.openapi).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": f"invalid OpenAPI spec: {exc}"},
                         indent=2))
        return 2

    observed = None
    if args.bodies:
        try:
            raw = Path(args.bodies).read_text(encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"ok": False, "error": f"--bodies unreadable: {exc}"},
                             indent=2))
            return 2
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = [json.loads(line) for line in raw.splitlines() if line.strip()]
        observed = parsed if isinstance(parsed, list) else [parsed]

    matrix = build_matrix(args.target, spec, observed_bodies=observed)
    out_path = write_matrix(matrix, project_root=args.project_root)

    high = [f for f in matrix.findings if f.risk == "high"]
    if high:
        try:
            bus = SignalBus(args.target, project_root=args.project_root)
            for finding in high[:8]:
                bus.publish("AUTH_CANDIDATE", source="bopla_matrix",
                            payload={"property": finding.property_name,
                                     "shape": finding.shape,
                                     "endpoint": finding.endpoint,
                                     "rationale": finding.rationale[:300]})
        except Exception:
            pass  # event bus is advisory

    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "finding_count": len(matrix.findings),
        "high_count": len(high),
        "shapes": sorted({f.shape for f in matrix.findings}),
        "output_file": str(out_path),
        "matrix": matrix.to_dict(),
    }
    print(json.dumps(output, indent=2) if args.json else
          f"[+] {args.target}: {len(matrix.findings)} BOPLA findings "
          f"({len(high)} high) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
