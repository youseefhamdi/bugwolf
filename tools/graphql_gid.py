#!/usr/bin/env python3
"""GraphQL introspection + global node-id (gid://) harvesting adapter.

GraphQL relay-style deployments expose ``node(id:)`` / ``nodes(ids:)``, which
resolve *any* object from its global id without field-level filters. When the
global ids are enumerable or guessable, an unauthenticated or low-privilege
caller can walk objects across visibility boundaries — the HackerOne #1618347
case leaked private program scope and report titles through
``gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}``.

This adapter does two offline jobs:

1. **Introspection analysis.** Given an introspection result (e.g. produced
   by ``tools/schema_extractor.py --fetch`` under the gated controller), it
   finds ``node``/``nodes`` resolvers and the object types that carry global
   ids (Node-interface implementors and ``id: ID!`` carriers).
2. **gid:// harvesting.** It extracts global-id references that are *already
   present* in the supplied artifacts (JS bundles, saved queries, schema
   docs) — it never generates or enumerates ids. Output ids are redacted and
   stored as hashes; the raw id stays only in the operator's own artifacts.

The result is a bounded candidate list plus per-candidate two-account
validation plans (Account A owns a disposable fixture; Account B replays
A's *owned* gid). Harvested ids from other users' artifacts are never used
in validation. Offline by default; the only network step — fetching the
introspection itself — stays behind ``schema_extractor.py --fetch`` gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tools.idor_research import IdorValidationPlan
except ImportError:  # direct script execution
    from idor_research import IdorValidationPlan  # type: ignore

SCHEMA_VERSION = "bugwolf-graphql-gid-v1"
DEFAULT_MAX_CANDIDATES = 64

# Relay global-id shape: gid://<app>/<class>::<Type>/<id>.
_GID_RE = re.compile(
    r"gid://([A-Za-z0-9_]+)/([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*)/([A-Za-z0-9_.%-]+)")

# Sensitivity keywords in type/class names.
_HIGH_TERMS = (
    "report", "program", "policy", "private", "admin", "internal", "payment",
    "invoice", "billing", "credential", "password", "secret", "token",
    "scope", "account", "user", "customer", "patient", "employee",
    "subscription", "order",
)
_MEDIUM_TERMS = (
    "asset", "document", "file", "message", "member", "group", "team", "org",
    "organization", "project", "profile", "comment", "post", "notification",
    "activity", "device", "license", "workspace", "channel",
)

_REDACTED = "█" * 8


def _sha(*parts: str) -> str:
    raw = "|".join(part.strip().lower() for part in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _named_type(type_ref: Any) -> str:
    """The innermost named type of a GraphQL type reference."""
    while isinstance(type_ref, dict) and type_ref.get("ofType"):
        type_ref = type_ref["ofType"]
    if isinstance(type_ref, dict):
        return type_ref.get("name", "")
    return ""


def sensitivity_for(name: str) -> str:
    lowered = name.lower()
    if any(term in lowered for term in _HIGH_TERMS):
        return "high"
    if any(term in lowered for term in _MEDIUM_TERMS):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# 1. Introspection surface analysis
# ---------------------------------------------------------------------------


@dataclass
class IntrospectionSurface:
    has_node_resolver: bool = False
    has_nodes_resolver: bool = False
    resolver_return_types: List[str] = field(default_factory=list)
    # Object types that carry global ids: Node-interface implementors plus
    # object types with a non-null id: ID! field.
    global_id_types: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


def _schema_of(introspection: Dict[str, Any]) -> Dict[str, Any]:
    return (introspection.get("__schema")
            or introspection.get("data", {}).get("__schema", {}) or {})


def analyze_introspection(introspection: Dict[str, Any],
                          source: str = "introspection") -> IntrospectionSurface:
    """Find node/nodes resolvers and global-id-carrying object types."""
    surface = IntrospectionSurface(sources=[source])
    schema = _schema_of(introspection)
    if not schema:
        return surface
    types: Dict[str, Dict[str, Any]] = {}
    for t in schema.get("types", []):
        if isinstance(t, dict) and t.get("name"):
            types[t["name"]] = t

    query_type = schema.get("queryType", {}).get("name")
    if query_type and query_type in types:
        for field in types[query_type].get("fields", []):
            name = (field.get("name") or "").lower()
            if name == "node":
                surface.has_node_resolver = True
                ret = _named_type(field.get("type"))
                if ret:
                    surface.resolver_return_types.append(ret)
            elif name == "nodes":
                surface.has_nodes_resolver = True
                ret = _named_type(field.get("type"))
                if ret:
                    surface.resolver_return_types.append(ret)

    interface_names = {name for name, t in types.items()
                       if t.get("kind") == "INTERFACE" and name in surface.resolver_return_types}
    for name, t in types.items():
        if t.get("kind") != "OBJECT":
            continue
        ifaces = [i.get("name") for i in t.get("interfaces", []) if isinstance(i, dict)]
        id_field = next((f for f in t.get("fields", [])
                         if (f.get("name") or "").lower() == "id"), None)
        id_is_global = bool(id_field) and _named_type(id_field.get("type")) == "ID"
        if ifaces and any(i in interface_names for i in ifaces):
            surface.global_id_types.append(name)
        elif id_is_global:
            surface.global_id_types.append(name)
    surface.global_id_types = sorted(set(surface.global_id_types))
    surface.resolver_return_types = sorted(set(surface.resolver_return_types))
    return surface


# ---------------------------------------------------------------------------
# 2. gid:// harvesting (extraction only — no enumeration)
# ---------------------------------------------------------------------------


@dataclass
class HarvestedGid:
    app: str
    class_name: str          # e.g. PolicyPageAssetGroupsIndex::PolicyPageAssetGroup
    type_name: str           # base type after the last "::"
    composite: bool
    sensitivity: str
    source: str
    example_redacted: str
    gid_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _redact_gid(app: str, class_name: str, _id_part: str) -> str:
    return f"gid://{app}/{class_name}/{_REDACTED}"


def harvest_gids(text: str, source: str = "artifact") -> List[HarvestedGid]:
    """Extract gid:// references already present in the artifact text.

    The raw id component is never emitted: candidates carry a redacted
    example and a hash of the full gid (for dedup/reference). Validation must
    use owned-fixture ids, not harvested ones.
    """
    results: List[HarvestedGid] = []
    seen = set()
    for match in _GID_RE.finditer(text):
        app, class_name, id_part = match.group(1), match.group(2), match.group(3)
        type_name = class_name.split("::")[-1]
        composite = bool(re.fullmatch(r"\d+-\d+", id_part))
        key = (app, class_name)
        if key in seen:
            continue
        seen.add(key)
        results.append(HarvestedGid(
            app=app, class_name=class_name, type_name=type_name,
            composite=composite, sensitivity=sensitivity_for(type_name),
            source=source, example_redacted=_redact_gid(app, class_name, id_part),
            gid_hash=_sha(app, class_name, id_part),
        ))
    return results


def harvest_artifacts(paths: Iterable[Path]) -> List[HarvestedGid]:
    results: List[HarvestedGid] = []
    for path in paths:
        if path.is_dir():
            results.extend(harvest_artifacts(sorted(path.rglob("*"))))
        elif path.is_file():
            results.extend(harvest_gids(
                path.read_text(encoding="utf-8", errors="replace"), str(path)))
    return results


# ---------------------------------------------------------------------------
# 3. Candidate list
# ---------------------------------------------------------------------------


@dataclass
class GidCandidate:
    candidate_id: str
    target: str
    type_name: str
    interface: str               # node | nodes | interface | id_field | artifact
    sensitivity: str
    source: str
    example_gid_redacted: str = ""
    gid_hash: str = ""
    composite: bool = False
    class_name: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_candidates(target: str, *,
                     introspection: Optional[Dict[str, Any]] = None,
                     artifacts: Iterable[Path] = (),
                     max_candidates: int = DEFAULT_MAX_CANDIDATES) -> List[GidCandidate]:
    """Build the bounded, deduplicated candidate list.

    Introspection contributes the node/nodes resolver surface; artifact
    harvesting contributes concrete gid classes already seen in the target's
    own material. Both are offline; ids are redacted.
    """
    candidates: Dict[str, GidCandidate] = {}

    def _put(candidate: GidCandidate) -> None:
        existing = candidates.get(candidate.candidate_id)
        if existing is None or _sensitivity_rank(candidate.sensitivity) > _sensitivity_rank(existing.sensitivity):
            candidates[candidate.candidate_id] = candidate

    surface = analyze_introspection(introspection) if introspection else IntrospectionSurface()
    if surface.has_node_resolver or surface.has_nodes_resolver:
        for type_name in surface.global_id_types:
            interface = ("node" if surface.has_node_resolver
                         else "nodes" if surface.has_nodes_resolver else "interface")
            _put(GidCandidate(
                candidate_id=_sha(target, type_name, interface, "introspection"),
                target=target, type_name=type_name, interface=interface,
                sensitivity=sensitivity_for(type_name), source="introspection",
                notes=[_resolver_note(surface)],
            ))

    for gid in harvest_artifacts(artifacts):
        interface = "node" if surface.has_node_resolver else "artifact"
        notes = []
        if gid.composite:
            notes.append("Composite gid (two numeric components) — each component may be an "
                         "independent ownership axis (HackerOne #1618347 pattern).")
        _put(GidCandidate(
            candidate_id=_sha(target, gid.type_name, interface, "artifact"),
            target=target, type_name=gid.type_name, interface=interface,
            sensitivity=gid.sensitivity, source=gid.source,
            example_gid_redacted=gid.example_redacted, gid_hash=gid.gid_hash,
            composite=gid.composite, class_name=gid.class_name, notes=notes,
        ))

    ordered = sorted(candidates.values(),
                     key=lambda c: (_sensitivity_rank(c.sensitivity),
                                    c.type_name.lower(), c.interface))
    for candidate in ordered:
        candidate.notes.append(
            "Use the requesting test account's own fixture gid; never reuse ids "
            "harvested from other users' artifacts.")
    return ordered[:max_candidates]


def _sensitivity_rank(sensitivity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(sensitivity, 3)


def _resolver_note(surface: IntrospectionSurface) -> str:
    kind = "node(id:)" if surface.has_node_resolver else "nodes(ids:)"
    return (f"Schema exposes {kind} global-id lookup — resolvers bypass "
            f"field-level filters; validate visibility with two accounts.")


# ---------------------------------------------------------------------------
# 4. Two-account validation plans
# ---------------------------------------------------------------------------


def build_validation_plans(candidates: Sequence[GidCandidate], target: str, *,
                           graphql_path: str = "/graphql") -> List[IdorValidationPlan]:
    """Turn high/medium candidates into the two-account validation flow.

    Reuses ``idor_research.IdorValidationPlan`` so the same discipline applies
    as the rest of the access-control track: two cooperating test accounts,
    disposable fixtures, owned references only, no enumeration.
    """
    plans: List[IdorValidationPlan] = []
    for candidate in candidates:
        if candidate.sensitivity not in ("high", "medium"):
            continue
        plans.append(IdorValidationPlan(
            plan_id=_sha("gid-plan", target, candidate.candidate_id),
            location=f"{graphql_path} node(id:) on {candidate.type_name}",
            reference_type="graphql_gid",
            accounts=[
                f"Account A: owner of one disposable {candidate.type_name} fixture",
                "Account B: separate cooperating test account with no relation to A",
            ],
            baseline=[
                f"As Account A, create one disposable {candidate.type_name} object and record its gid.",
                "As Account A, run node(id: <own gid>) and record status and returned fields (the allowed control).",
                "Use only your own fixture gid; harvested ids from other users are out of scope.",
            ],
            mutations=[
                "As Account B, replay Account A's fixture gid through node(id:) / nodes(ids:).",
                "Compare every field returned to Account B against Account A's control; flag any field B is not authorized for.",
                "For composite gids, replay each numeric component separately against Account A's fixture.",
                "If node(id:) returns an error for B but resolves for A, probe field-level (non-node) queries with the same gid for comparison.",
            ],
            invariant=("node(id:) may return an object to a session only if that session is "
                       "authorized for every requested field and every ownership axis of the gid."),
            impact_boundaries=[
                "cross-account read of object fields",
                "cross-tenant or private-program visibility",
                "report/program title or scope disclosure",
                "admin/internal object access via global id",
            ],
            evidence_required=[
                "sanitized A/B gid requests and responses",
                "owned-fixture gid map",
                "redacted responses (no third-party ids or titles)",
                "bounded impact trace in victim terms",
            ],
            prohibited_actions=[
                "no sequential or bulk node(id:) id enumeration",
                "no reuse of gids harvested from other users' artifacts",
                "no reading real private objects' report/program titles",
                "no state-changing mutations through gids",
            ],
            status="read_only_test_fixture",
        ))
    return plans


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_json(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(errors="replace"))


def _artifact_paths(raw: Sequence[str]) -> List[Path]:
    paths = []
    for item in raw:
        path = Path(item)
        if path.exists():
            paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GraphQL introspection + gid:// node-id harvesting adapter "
                    "(offline; produces two-account validation plans)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--introspection",
                        help="GraphQL introspection JSON (e.g. from schema_extractor --fetch)")
    parser.add_argument("--artifacts", action="append", default=[],
                        help="File or directory to harvest gid:// references from "
                             "(repeatable: JS bundles, saved queries, docs)")
    parser.add_argument("--graphql-path", default="/graphql")
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument("--output-dir", default="graphql-gid")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    introspection = _load_json(args.introspection) if args.introspection else None
    artifacts = _artifact_paths(args.artifacts)
    candidates = build_candidates(
        args.target, introspection=introspection, artifacts=artifacts,
        max_candidates=args.max_candidates)
    plans = build_validation_plans(candidates, args.target,
                                   graphql_path=args.graphql_path)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "gid-candidates.jsonl").open("w") as stream:
        for candidate in candidates:
            stream.write(json.dumps(candidate.to_dict(), sort_keys=True) + "\n")
    with (out_dir / "gid-validation-plans.jsonl").open("w") as stream:
        for plan in plans:
            stream.write(json.dumps(asdict(plan), sort_keys=True) + "\n")
    harvested = harvest_artifacts(artifacts)
    manifest = {
        "schema": SCHEMA_VERSION,
        "target": args.target,
        "mode": "offline",
        "introspection": bool(introspection),
        "artifacts": sorted({gid.source for gid in harvested}),
        "candidates": len(candidates),
        "validation_plans": len(plans),
        "gids_harvested": len({(g.app, g.class_name) for g in harvested}),
        "claims": "candidate_list_only_no_enumeration",
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    if args.json:
        print(json.dumps({
            "schema": SCHEMA_VERSION, "target": args.target, "mode": "offline",
            "candidates": [c.to_dict() for c in candidates],
            "validation_plans": [asdict(p) for p in plans],
        }, indent=2, default=str))
        return

    print(f"[*] GraphQL gid candidates for {args.target} "
          f"(introspection={bool(introspection)}, artifacts={len(artifacts)})")
    print(f"    candidates: {len(candidates)}  plans: {len(plans)}  "
          f"gid classes harvested: {manifest['gids_harvested']}")
    for candidate in candidates:
        print(f"    [{candidate.sensitivity}] {candidate.type_name} "
              f"(interface {candidate.interface}, source {candidate.source})"
              + ("  [composite]" if candidate.composite else ""))
    for plan in plans[:5]:
        print(f"    plan: {plan.location}")
    print(f"    written to {out_dir / 'gid-candidates.jsonl'} and "
          f"{out_dir / 'gid-validation-plans.jsonl'}")


if __name__ == "__main__":
    main()
