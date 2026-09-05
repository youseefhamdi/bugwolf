#!/usr/bin/env python3
"""Auto-extract OpenAPI/Swagger and GraphQL schemas from recon output.

The recon engine already collects the raw material (``urls.txt``,
``live-hosts.txt``, ``swagger.txt``, ``jsfiles.txt``, ``js-endpoints.txt``,
downloaded JS). This module turns that into a ready-to-use
:class:`tools.surface_model.SurfaceModel` without the operator hand-pointing at
schema files:

1. **Discover** (offline) — scan recon artifacts for OpenAPI/Swagger and
   GraphQL endpoint URLs, plus schema JSON paths referenced in JS.
2. **Load cached schemas** (offline) — parse any schema already saved under
   ``recon/<target>/schemas/``.
3. **Build** (offline) — merge cached schemas with a URL-list baseline.
4. **Fetch** (gated live) — download discovered schemas and run GraphQL
   introspection only through the authorization controller with explicit
   active confirmation.

Usage:
  python3 tools/schema_extractor.py --target T --recon-dir recon/T --output recon/T/discovery/surface-model.json --json
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from tools.safety import AuthorizationError, target_in_scope, validate_http_url
except ImportError:  # direct script execution
    from safety import AuthorizationError, target_in_scope, validate_http_url

try:
    from tools.surface_model import (
        SurfaceModel, infer_vhost_candidates, load_surface, parse_graphql,
        parse_openapi, parse_urls,
    )
except ImportError:  # direct script execution
    from surface_model import (  # type: ignore
        SurfaceModel, infer_vhost_candidates, load_surface, parse_graphql,
        parse_openapi, parse_urls,
    )

SCHEMA_VERSION = "bugwolf-schema-extractor-v1"

# Explicit schema files / endpoints are high-confidence; UI-only paths are lower.
_OPENAPI_FILE_RE = re.compile(
    r"(openapi|swagger)\.(json|ya?ml)|api-docs\.(json|ya?ml)|"
    r"swagger/v\d+/swagger\.json|v[23]/api-docs|api-docs/?$|/api-docs$",
    re.IGNORECASE)
_OPENAPI_UI_RE = re.compile(r"swagger-ui|redoc|/docs/?$|/api/?$", re.IGNORECASE)
_GRAPHQL_RE = re.compile(r"(^|/)(graphql|gql|graphiql)(/|$)", re.IGNORECASE)

# Schema JSON paths referenced inside JS bundles.
_JS_SCHEMA_REF_RE = re.compile(
    r"""["'`](/[^"'`\s]*(?:openapi|swagger|api-docs|graphql)[^"'`\s]*\.json)["'`]""",
    re.IGNORECASE)

_GRAPHQL_INTROSPECTION_QUERY = (
    "{__schema{queryType{name} mutationType{name} subscriptionType{name} "
    "types{kind name description fields{name description args{name description "
    "type{kind name ofType{kind name ofType{kind name}}}} type{kind name ofType{kind name}}} "
    "enumValues{name}}}}"
)

_USER_AGENT = "bugwolf-schema-extractor/1.0"
_MAX_SCHEMA_BYTES = 2_000_000


@dataclass
class SchemaCandidate:
    url: str
    kind: str                     # openapi | graphql
    source: str                   # artifact file provenance
    confidence: str = "medium"    # high | medium | low

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SchemaDiscovery:
    target: str
    openapi: List[SchemaCandidate] = field(default_factory=list)
    graphql: List[SchemaCandidate] = field(default_factory=list)
    cached_schemas: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "target": self.target,
            "openapi": [c.to_dict() for c in self.openapi],
            "graphql": [c.to_dict() for c in self.graphql],
            "cached_schemas": list(self.cached_schemas),
        }

    def total(self) -> int:
        return len(self.openapi) + len(self.graphql)


def _read_lines(path: Path) -> List[str]:
    try:
        return [l.strip() for l in path.read_text(errors="replace").splitlines()
                if l.strip()]
    except OSError:
        return []


def _host_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or ""


def _normalize(candidate: str, bases: List[str]) -> Optional[str]:
    """Return a full URL from a path/host fragment, using discovered bases."""
    candidate = candidate.strip()
    if not candidate or candidate.startswith("#"):
        return None
    if candidate.startswith(("http://", "https://")):
        return candidate
    if candidate.startswith("/"):
        for base in bases:
            if base:
                return base.rstrip("/") + candidate
        return None
    # Bare host:path (e.g. from swagger.txt) — add scheme if missing.
    if candidate.startswith(("http://", "https://")):
        return candidate
    return f"https://{candidate}" if candidate else None


def discover(recon_dir: str | Path, target: str) -> SchemaDiscovery:
    """Scan recon artifacts for schema endpoints (offline, deterministic)."""
    recon = Path(recon_dir)
    discovery = SchemaDiscovery(target=target)

    bases: List[str] = []
    for line in _read_lines(recon / "live-hosts.txt"):
        bases.append(line.split()[0].rstrip("/") if line.split() else "")
    for line in _read_lines(recon / "urls.txt"):
        host = _host_of(line)
        if host and f"https://{host}" not in bases:
            bases.append(f"https://{host}")

    seen_openapi: set = set()
    seen_graphql: set = set()

    def add(kind: str, url: str, source: str, confidence: str) -> None:
        bucket = seen_openapi if kind == "openapi" else seen_graphql
        if url in bucket:
            return
        bucket.add(url)
        (discovery.openapi if kind == "openapi" else discovery.graphql).append(
            SchemaCandidate(url=url, kind=kind, source=source,
                            confidence=confidence))

    for artifact in ("urls.txt", "swagger.txt", "dirs.txt", "js-endpoints.txt",
                     "jsfiles.txt"):
        for line in _read_lines(recon / artifact):
            raw = line.split()[0] if line.split() else line
            url = _normalize(raw, bases)
            if not url:
                continue
            path = urllib.parse.urlparse(url).path
            if _GRAPHQL_RE.search(path):
                add("graphql", url, artifact, "high")
            if _OPENAPI_FILE_RE.search(path):
                add("openapi", url, artifact, "high")
            elif _OPENAPI_UI_RE.search(path):
                add("openapi", url, artifact, "medium")

    # JS schema references (downloaded JS + JS file URLs).
    for js in Path(recon / "js").glob("*.js"):
        text = js.read_text(errors="replace")[:200_000]
        for match in _JS_SCHEMA_REF_RE.findall(text):
            url = _normalize(match, bases)
            if url:
                add("openapi", url, f"js/{js.name}", "medium")

    # Cached schemas already downloaded under recon/<target>/schemas/.
    discovery.cached_schemas = load_cached_schemas(recon / "schemas")

    discovery.openapi.sort(key=lambda c: (c.confidence != "high", c.url))
    discovery.graphql.sort(key=lambda c: (c.confidence != "high", c.url))
    return discovery


def load_cached_schemas(schemas_dir: str | Path) -> List[Dict[str, str]]:
    """Detect and classify already-downloaded schema files (offline)."""
    out: List[Dict[str, str]] = []
    d = Path(schemas_dir)
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.json")):
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
            out.append({"kind": "openapi", "path": str(path)})
        elif isinstance(data, dict) and (
                "__schema" in data or "data" in data and "__schema" in data.get("data", {})):
            out.append({"kind": "graphql", "path": str(path)})
    return out


def _merge(models: List[SurfaceModel], target: str,
           metadata: Optional[Dict[str, Any]] = None) -> SurfaceModel:
    if not models:
        raise ValueError("no surface artifacts to merge")
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
    merged.target = target
    merged.metadata.update(metadata or {})
    try:
        from tools.surface_model import (
            ensure_special_surfaces, infer_transitions, pair_version_siblings)
    except ImportError:  # direct script execution (python3 tools/xxx.py)
        from surface_model import (
            ensure_special_surfaces, infer_transitions, pair_version_siblings)
    merged.siblings = pair_version_siblings(merged.operations)
    merged.transitions = infer_transitions(merged.operations)
    return ensure_special_surfaces(merged)


def build_surface(target: str, recon_dir: str | Path) -> SurfaceModel:
    """Build a SurfaceModel from recon artifacts — no manual schema files.

    Precedence: cached OpenAPI/GraphQL schemas first, then a URL-list baseline.
    """
    recon = Path(recon_dir)
    discovery = discover(recon, target)
    models: List[SurfaceModel] = []
    bases: List[str] = []

    for cached in discovery.cached_schemas:
        path = Path(cached["path"])
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        if cached["kind"] == "openapi":
            models.append(parse_openapi(data, target))
        else:
            models.append(parse_graphql(data, target))
        for base in models[-1].base_urls:
            if base and base not in bases:
                bases.append(base)

    urls_file = recon / "urls.txt"
    if urls_file.exists():
        urls = [l.strip() for l in urls_file.read_text(errors="replace").splitlines()
                if l.strip()]
        if urls:
            models.append(parse_urls(urls, target, base_urls=bases or None))

    if not models:
        raise ValueError(
            f"no schemas or URLs found under {recon_dir}; run recon first")

    merged = _merge(models, target, metadata={
        "recon_dir": str(recon),
        "openapi_candidates": [c.to_dict() for c in discovery.openapi],
        "graphql_candidates": [c.to_dict() for c in discovery.graphql],
    })

    # Internal vhost candidates for host-confusion probing, grouped by resolved
    # IP so subdomains that share a server are recognized as each other's vhosts.
    hosts: List[str] = list(bases)
    for artifact in ("subs.txt", "resolved.txt", "live-hosts.txt", "urls.txt"):
        for line in _read_lines(recon / artifact):
            token = line.split()[0] if line.split() else ""
            if token:
                hosts.append(token)

    resolved_map: Dict[str, str] = {}
    for line in _read_lines(recon / "resolved.txt"):
        if not line.split():
            continue
        host = line.split()[0]
        if "[" in line and "]" in line:
            ip = line.split("[", 1)[1].split("]", 1)[0].strip()
            if ip:
                resolved_map[host] = ip

    live_hosts = [line.split()[0] for line in _read_lines(recon / "live-hosts.txt")
                  if line.split()]
    merged.vhost_candidates = infer_vhost_candidates(
        target, hosts,
        resolved_map=resolved_map or None,
        live_hosts=live_hosts or None,
    )
    return merged


# ---------------------------------------------------------------------------
# Gated live fetch
# ---------------------------------------------------------------------------

class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Revalidate every redirect hop against the operator's scope."""

    def __init__(self, scope: Dict[str, Any]):
        super().__init__()
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            validate_http_url(newurl, self.scope)
        except AuthorizationError as exc:
            raise urllib.error.URLError(str(exc)) from exc
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_json(url: str, *, method: str = "GET",
                payload: Optional[Dict[str, Any]] = None,
                timeout: int = 12,
                scope: Optional[Dict[str, Any]] = None) -> Tuple[int, Any, str]:
    body = None
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    try:
        validate_http_url(url, scope)
    except AuthorizationError as exc:
        return 0, None, str(exc)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(_ScopedRedirectHandler(scope)) if scope \
        else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            # Check the final URL too; a custom handler is defense in depth for
            # unusual redirect responses and nonstandard handlers.
            validate_http_url(resp.geturl(), scope)
            length = resp.headers.get("Content-Length")
            if length and int(length) > _MAX_SCHEMA_BYTES:
                raise ValueError("schema response exceeds size limit")
            raw_bytes = resp.read(_MAX_SCHEMA_BYTES + 1)
            if len(raw_bytes) > _MAX_SCHEMA_BYTES:
                raise ValueError("schema response exceeds size limit")
            raw = raw_bytes.decode("utf-8", "ignore")
            return resp.status, json.loads(raw), ""
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError) as exc:
        return 0, None, f"{type(exc).__name__}: {exc}"


def fetch_schemas(target: str, recon_dir: str | Path, *, scope_file: str,
                  confirm_active: bool, max_fetch: int = 12) -> Dict[str, Any]:
    """Download discovered schemas + GraphQL introspection (gated live).

    Every request passes through the execution controller, so an unauthorized
    or unconfirmed run raises before any network call. Downloaded schemas are
    saved under ``recon/<target>/schemas/``.
    """
    try:
        from tools.execution_controller import (
            ActionClass, ActiveExecutionController, ExecutionDenied, ExecutionPolicy,
        )
    except ImportError:
        from execution_controller import (
            ActionClass, ActiveExecutionController, ExecutionDenied, ExecutionPolicy,
        )

    # Phase 0: scope-file is required; allowed actions are bounded
    # (PASSIVE/READ/ACTIVE only) with max_requests=max_fetch*2.

    recon = Path(recon_dir)
    discovery = discover(recon, target)
    schemas_dir = recon / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)

    policy = ExecutionPolicy(
        target=target, scope_file=scope_file,
        allow_active=True, confirm_active=True,
        allowed_actions={ActionClass.PASSIVE, ActionClass.READ, ActionClass.ACTIVE},
        max_requests=max_fetch * 2,
    )
    controller = ActiveExecutionController(policy)

    results: Dict[str, Any] = {"openapi": [], "graphql": [], "errors": []}

    for candidate in discovery.openapi[:max_fetch]:
        def _get(url=candidate.url):
            status, data, err = _fetch_json(url, scope=controller.scope)
            return status, data, err

        try:
            (status, data, err), receipt = controller.run(
                ActionClass.READ, candidate.url, _get,
                metadata={"kind": "openapi"})
            if not receipt.executed:
                continue
            if status and data and isinstance(data, dict) and (
                    "openapi" in data or "swagger" in data):
                digest = hashlib.sha256(candidate.url.encode()).hexdigest()[:12]
                out = schemas_dir / f"openapi-{digest}.json"
                out.write_text(json.dumps(data))
                results["openapi"].append({"url": candidate.url, "saved": str(out)})
        except (ExecutionDenied, Exception) as exc:
            results["errors"].append({"url": candidate.url, "error": str(exc)[:200]})

    for candidate in discovery.graphql[:max_fetch]:
        def _post(url=candidate.url):
            return _fetch_json(url, method="POST",
                               payload={"query": _GRAPHQL_INTROSPECTION_QUERY},
                               scope=controller.scope)

        try:
            (status, data, err), receipt = controller.run(
                ActionClass.ACTIVE, candidate.url, _post,
                metadata={"kind": "graphql-introspection"})
            if not receipt.executed:
                continue
            if status and data and isinstance(data, dict):
                digest = hashlib.sha256(candidate.url.encode()).hexdigest()[:12]
                out = schemas_dir / f"graphql-{digest}.json"
                out.write_text(json.dumps(data))
                results["graphql"].append({"url": candidate.url, "saved": str(out)})
        except (ExecutionDenied, Exception) as exc:
            results["errors"].append({"url": candidate.url, "error": str(exc)[:200]})

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Auto-extract OpenAPI/GraphQL schemas from recon output")
    parser.add_argument("--target", required=True)
    parser.add_argument("--recon-dir", required=True)
    parser.add_argument("--fetch", action="store_true",
                        help="Fetch discovered schemas (requires scope + confirmation)")
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--confirm-active", action="store_true")
    parser.add_argument("--output", help="Write the built surface model JSON here")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        if args.fetch:
            try:
                result = fetch_schemas(args.target, args.recon_dir,
                                       scope_file=args.scope_file,
                                       confirm_active=args.confirm_active)
            except Exception as exc:
                print(f"[!] {exc}", file=sys.stderr)
                raise SystemExit(2)
            if args.json:
                print(json.dumps(result, indent=2))
                return
            print(json.dumps(result, indent=2))
            return

        discovery = discover(args.recon_dir, args.target)
        model = build_surface(args.target, args.recon_dir)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    if args.output:
        Path(args.output).write_text(model.to_json() + "\n")

    if args.json:
        print(json.dumps({
            "discovery": discovery.to_dict(),
            "operations": len(model.operations),
            "siblings": len(model.siblings),
            "transitions": len(model.transitions),
            "model": model.to_dict(),
        }, indent=2, default=str))
        return

    print(f"[*] Schema discovery for {args.target}")
    print(f"    openapi candidates: {len(discovery.openapi)}")
    print(f"    graphql candidates: {len(discovery.graphql)}")
    print(f"    cached schemas:     {len(discovery.cached_schemas)}")
    print(f"    surface operations: {len(model.operations)}")
    for c in discovery.openapi[:10]:
        print(f"    [openapi:{c.confidence}] {c.url}  ({c.source})")
    for c in discovery.graphql[:10]:
        print(f"    [graphql:{c.confidence}] {c.url}  ({c.source})")


if __name__ == "__main__":
    main()
