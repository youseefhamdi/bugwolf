#!/usr/bin/env python3
"""Header-trust / proxy-trust analysis for BugWolf's discovery core.

A large, high-yield bug class lives in *forwarded/trust headers*: when a proxy,
CDN, or application layer trusts a client-supplied header, an attacker can
pretend to be a trusted peer and unlock IP allowlists, reach internal-only
hosts, confuse virtual-host routing, override the request scheme/method, or
rewrite the request path (which can escalate to SSRF/RCE).

This module is the *canonical taxonomy* for that surface plus a probe planner
and a gated live replay runner:

- ``HEADER_TAXONOMY`` — the curated list of forwarded/trust headers, grouped by
  bug class (IP trust, host/vhost confusion, scheme/port override, path/URI
  rewrite, method override) with forged values and expected effect notes.
- ``build_probes`` — expands the taxonomy into concrete ``HeaderProbe`` requests
  against the supplied hosts/paths (offline, deterministic).
- ``run`` — executes each probe (baseline vs forged header) through an injected
  transport, scores the divergence with the shared oracle
  (:class:`tools.observation.OracleValidator`), and classifies the result.

Safety model (unchanged): the planner never sends requests. Live replay runs
only behind ``--confirm-active`` + a scope file, routed through the execution
controller, and reports *signals* — never zero-day claims. Forged header values
are trust *hypotheses*, and IP/URI values are plans, not executed payloads.

Usage:
  python3 tools/header_trust.py --target T --recon-dir recon/T --base-url https://target --output recon/T/header-trust-plan.json --json
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

try:
    from tools.observation import (
        HttpObservation,
        ObservationState,
        OracleValidator,
    )
except ImportError:  # direct script execution
    from observation import HttpObservation, ObservationState, OracleValidator

SCHEMA_VERSION = "bugwolf-header-trust-v1"

# ---------------------------------------------------------------------------
# Canonical taxonomy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeaderSpec:
    """One canonical forwarded/trust header + a forged value to try."""

    name: str
    value: str
    bug_class: str        # ip_trust | host_confusion | scheme_override |
                          # port_override | path_rewrite | method_override | misc
    category: str         # human-readable grouping
    severity: str = "medium"    # critical | high | medium | low
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.name}|{self.value}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Forged values — trust *hypotheses*, never executed payloads.
_TRUSTED_IPS = [
    "127.0.0.1", "127.0.1", "127.0.0.0", "0.0.0.0", "::1", "localhost",
    "192.168.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1", "169.254.169.254",
]
_INTERNAL_HOSTS = ["localhost", "127.0.0.1", "internal", "admin", "api",
                   "intranet", "backend", "dev", "staging", "10.0.0.1"]
_INTERNAL_PATHS = ["/", "/admin", "/internal", "/api/internal", "/actuator",
                   "/server-status", "/debug", "/console", "/health"]

# Forwarded-host headers used to override the perceived Host. These are also
# used to replay discovered vhost candidates during host-confusion probing.
_HOST_CONFUSION_HEADERS = (
    "Host", "X-Forwarded-Host", "X-Host", "X-HTTP-Host-Override",
    "X-Original-Host", "X-Rewrite-Host", "X-Forwarded-Server", "X-Backend",
    "X-Backend-Server", "X-Gateway-Host",
)


def _specs(name: str, values: Iterable[str], bug_class: str, category: str,
           severity: str, note: str) -> List[HeaderSpec]:
    return [HeaderSpec(name=name, value=v, bug_class=bug_class,
                       category=category, severity=severity, note=note)
            for v in values]


def _taxonomy() -> List[HeaderSpec]:
    specs: List[HeaderSpec] = []

    # IP trust — IP-allowlist / proxy-trust bypass.
    ip_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Remote-IP", "X-Remote-Addr",
        "X-Client-IP", "X-Originating-IP", "True-Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "X-Cluster-Client-IP",
        "X-ProxyUser-IP", "X-Original-Forwarded-For", "X-Custom-IP-Authorization",
        "X-Custom-IP", "X-Original-Remote-Addr", "X-Original-Remote-IP",
        "X-Envoy-External-Address",
    ]
    for name in ip_headers:
        specs.extend(_specs(
            name, _TRUSTED_IPS, "ip_trust", "IP trust / allowlist bypass",
            "high", "Pretend to originate from a trusted/internal address."))
    # Standardized Forwarded header (RFC 7239).
    specs.extend(_specs(
        "Forwarded", ["for=127.0.0.1", "for=[::1]", "for=127.0.0.1;proto=https"],
        "ip_trust", "IP trust / allowlist bypass", "high",
        "RFC 7239 Forwarded element claiming a trusted client."))

    # Host / virtual-host confusion.
    host_headers = [
        "X-Forwarded-Host", "X-Host", "X-HTTP-Host-Override", "X-Original-Host",
        "X-Rewrite-Host", "X-Forwarded-Server", "X-Backend", "X-Backend-Server",
        "X-Gateway-Host",
    ]
    for name in host_headers:
        specs.extend(_specs(
            name, _INTERNAL_HOSTS, "host_confusion",
            "Host / virtual-host confusion", "high",
            "Rewrite the perceived Host to reach internal vhosts or SSRF sinks."))
    specs.extend(_specs(
        "Host", ["localhost", "127.0.0.1", "10.0.0.1"], "host_confusion",
        "Host / virtual-host confusion", "high",
        "Override the raw Host header to probe vhost routing."))

    # Scheme override — HTTPS downgrade / mixed-content trust.
    specs.extend(_specs(
        "X-Forwarded-Proto", ["https", "http"], "scheme_override",
        "Scheme override", "medium",
        "Claim the request arrived over a different scheme."))
    specs.extend(_specs(
        "X-Forwarded-Scheme", ["https", "http"], "scheme_override",
        "Scheme override", "medium", "Alias of X-Forwarded-Proto."))
    for name in ("X-Forwarded-Ssl", "X-SSL", "X-HTTPS", "X-Forwarded-HTTPS",
                 "Front-End-Https", "X-ARR-SSL"):
        specs.extend(_specs(
            name, ["on", "1"], "scheme_override", "Scheme override", "medium",
            "Boolean TLS-flag header used by some proxies."))
    specs.extend(_specs(
        "X-Original-Proto", ["https", "http"], "scheme_override",
        "Scheme override", "medium", "Original-scheme trust header."))
    specs.extend(_specs(
        "X-URL-Scheme", ["https", "http"], "scheme_override", "Scheme override",
        "medium", "URL-scheme trust header."))
    specs.extend(_specs(
        "X-Scheme", ["https", "http"], "scheme_override", "Scheme override",
        "medium", "Scheme trust header."))

    # Port override.
    specs.extend(_specs(
        "X-Forwarded-Port", ["443", "8443", "80", "8080"], "port_override",
        "Port override", "medium", "Override the perceived front-end port."))
    specs.extend(_specs(
        "X-Forwarded-By", ["127.0.0.1", "localhost"], "port_override",
        "Port override", "low", "Proxy-identity header sometimes used for routing."))

    # Path / URI rewrite — the SSRF→RCE escalation surface.
    path_headers = [
        "X-Original-URL", "X-Rewrite-URL", "X-Original-URI", "X-Rewrite-URI",
        "X-Forwarded-URI", "X-Forwarded-URL", "X-Forwarded-Path",
        "X-Accel-Redirect", "X-Proxy-URL", "X-Canonical-URL", "X-Internal-URL",
        "X-Request-URI", "Request-URI", "X-Original-Request-URI",
        "X-Original-Path", "X-Path", "X-Internal-Path", "X-Resource",
        "X-Envoy-Original-Path", "X-Gateway-Path",
    ]
    for name in path_headers:
        specs.extend(_specs(
            name, _INTERNAL_PATHS, "path_rewrite", "Path / URI rewrite",
            "high", "Rewrite the backend-perceived path to reach internal routes."))
    specs.extend(_specs(
        "X-Forwarded-Prefix", ["/", "/internal"], "path_rewrite",
        "Path / URI rewrite", "high", "Strip/rewrite a route prefix."))
    specs.extend(_specs(
        "X-Accel-Mapping", ["/=/", "/admin=/"], "path_rewrite",
        "Path / URI rewrite", "high", "nginx X-Accel internal mapping."))
    specs.extend(_specs(
        "Destination", ["http://127.0.0.1/", "/admin"], "path_rewrite",
        "Path / URI rewrite", "high", "WebDAV/redirect destination header."))

    # Method override.
    for name in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method",
                 "X-Original-Method", "X-Forwarded-Method"):
        specs.extend(_specs(
            name, ["POST", "PUT", "DELETE", "PATCH"], "method_override",
            "Method override", "medium",
            "Override the HTTP verb the backend enforces."))

    # Misc routing/tracing headers (lower value, still worth a probe).
    specs.extend(_specs(
        "X-Forwarded-Proto-Version", ["h2", "http/1.1"], "misc",
        "Protocol hints", "low", "Protocol-version hint."))
    specs.extend(_specs(
        "X-Requested-With", ["XMLHttpRequest"], "misc", "Request hints", "low",
        "Mark request as an XHR (can change server-side routing)."))
    specs.extend(_specs(
        "X-Request-ID", ["00000000-0000-0000-0000-000000000001"], "misc",
        "Tracing IDs", "low", "Trace-id trust (log/SSRF injection hypothesis)."))
    specs.extend(_specs(
        "X-Correlation-ID", ["1"], "misc", "Tracing IDs", "low",
        "Correlation-id trust hypothesis."))
    specs.extend(_specs(
        "X-Amzn-Trace-Id", ["Root=1-00000000-00000000deadbeef"], "misc",
        "Tracing IDs", "low", "AWS trace-id header."))
    specs.extend(_specs(
        "X-Azure-Ref", ["1"], "misc", "Tracing IDs", "low", "Azure ref header."))
    specs.extend(_specs(
        "X-Azure-FDID", ["00000000-0000-0000-0000-000000000000"], "misc",
        "Tracing IDs", "low", "Azure front-door ID header."))

    return specs


HEADER_TAXONOMY: List[HeaderSpec] = _taxonomy()

_BUG_CLASS_LABEL = {
    "ip_trust": "ip_allowlist_bypass",
    "host_confusion": "host_header_confusion",
    "scheme_override": "scheme_override",
    "port_override": "port_override",
    "path_rewrite": "path_rewrite_ssrf",
    "method_override": "method_override",
    "misc": "header_trust",
}


@dataclass
class HeaderProbe:
    """A concrete baseline-vs-forged request plan for one header/value."""

    probe_id: str = ""
    name: str = ""
    value: str = ""
    bug_class: str = ""
    bug_class_label: str = ""
    category: str = ""
    severity: str = "medium"
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = "/"
    note: str = ""

    def __post_init__(self) -> None:
        if not self.bug_class_label:
            self.bug_class_label = _BUG_CLASS_LABEL.get(self.bug_class, "header_trust")
        if not self.probe_id:
            raw = f"{self.host}|{self.name}|{self.value}|{self.method}|{self.path}"
            self.probe_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


@dataclass
class HeaderTrustResult:
    """The oracle-classified outcome of one baseline-vs-forged replay.

    ``state`` is owned by the shared oracle (conservative: status divergence is
    UNKNOWN pending follow-up). ``trust_signal`` is the *characteristic*
    header-trust pattern (denied -> allowed) surfaced alongside it as a
    hypothesis to validate — it never overrides the oracle state.
    """

    probe: HeaderProbe
    state: str = ""                 # signal | unknown | refuted | error
    decisive_rule: str = ""
    observation_id: str = ""
    baseline_status: int = 0
    probe_status: int = 0
    body_similarity: float = 1.0
    trust_signal: bool = False
    trust_reason: str = ""
    hypothesis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


# ---------------------------------------------------------------------------
# Probe planning (offline)
# ---------------------------------------------------------------------------


def _dedupe_hosts(hosts: Iterable[str], max_hosts: int = 8) -> List[str]:
    seen: List[str] = []
    for h in hosts:
        h = str(h).strip()
        if not h:
            continue
        if h not in seen:
            seen.append(h)
        if len(seen) >= max_hosts:
            break
    return seen


def representative_paths(paths: Iterable[str], max_paths: int = 6) -> List[str]:
    """Pick a small, diverse set of probe paths (root first)."""
    ordered = ["/"]
    for p in paths:
        p = str(p).strip()
        if not p or p == "/":
            continue
        if not p.startswith("/"):
            p = "/" + p
        if p not in ordered:
            ordered.append(p)
    # Prefer admin/auth/API paths if present; otherwise keep insertion order.
    ranked = sorted(
        ordered[1:],
        key=lambda p: (0 if any(k in p.lower() for k in
                                ("admin", "login", "auth", "api", "internal"))
                       else 1),
    )
    return (ordered[:1] + ranked)[:max_paths]


def build_probes(
    hosts: Iterable[str],
    paths: Optional[Iterable[str]] = None,
    *,
    methods: Optional[Iterable[str]] = None,
    scheme: str = "https",
    max_hosts: int = 8,
    max_paths: int = 6,
    max_probes: int = 4000,
    taxonomy: Optional[List[HeaderSpec]] = None,
) -> List[HeaderProbe]:
    """Expand the taxonomy into concrete probes for the given hosts/paths.

    The *same* probe is emitted once per (host, path, method) combination so a
    change in response is attributable to the forged header alone.
    """
    taxonomy = taxonomy or HEADER_TAXONOMY
    methods = list(methods or ["GET"])
    path_list = representative_paths(paths or ["/"], max_paths=max_paths)

    probes: List[HeaderProbe] = []
    for host in _dedupe_hosts(hosts, max_hosts):
        for path in path_list:
            for method in methods:
                for spec in taxonomy:
                    url = f"{scheme}://{host}{path}"
                    probes.append(HeaderProbe(
                        name=spec.name, value=spec.value,
                        bug_class=spec.bug_class, category=spec.category,
                        severity=spec.severity, method=method.upper(),
                        url=url, host=host, path=path, note=spec.note,
                    ))
                    if len(probes) >= max_probes:
                        return probes
    return probes


def build_host_confusion_probes(
    hosts: Iterable[str],
    paths: Optional[Iterable[str]],
    values: Iterable[str],
    *,
    scheme: str = "https",
    max_hosts: int = 8,
    max_paths: int = 1,
    max_probes: int = 2000,
) -> List[HeaderProbe]:
    """Build Host/forwarded-host confusion probes for candidate vhost hostnames.

    Unlike the full taxonomy, this targets *specific* internal vhost candidates
    (e.g. ``admin.example.com``) derived from the surface model, probing the
    root path with the raw ``Host`` and forwarded-host headers.
    """
    probes: List[HeaderProbe] = []
    path_list = representative_paths(paths or ["/"], max_paths=max_paths)
    deduped_values: List[str] = []
    seen_values: set = set()
    for raw in values:
        value = str(raw).strip()
        if value and value not in seen_values:
            seen_values.add(value)
            deduped_values.append(value)

    for host in _dedupe_hosts(hosts, max_hosts):
        for path in path_list:
            for value in deduped_values:
                for name in _HOST_CONFUSION_HEADERS:
                    url = f"{scheme}://{host}{path}"
                    probes.append(HeaderProbe(
                        name=name, value=value, bug_class="host_confusion",
                        category="Host / virtual-host confusion", severity="high",
                        method="GET", url=url, host=host, path=path,
                        note="Rewrite the perceived Host to an internal vhost candidate.",
                    ))
                    if len(probes) >= max_probes:
                        return probes
    return probes


def probes_from_model(model, *, scheme: str = "https",
                      max_hosts: int = 8, max_paths: int = 6,
                      max_probes: int = 4000) -> List[HeaderProbe]:
    """Build probes from a SurfaceModel's base URLs, target, and operation paths.

    In addition to the generic taxonomy, discovered internal vhost candidates
    (``model.vhost_candidates``) are replayed as Host/forwarded-host values so
    host-confusion probes target the application's own subdomains.
    """
    hosts: List[str] = []
    for base in model.base_urls:
        try:
            import urllib.parse
            hosts.append(urllib.parse.urlparse(base).netloc or base)
        except Exception:
            hosts.append(base)
    if not hosts:
        hosts = [model.target]
    paths = [op.path for op in model.operations]
    probes = build_probes(hosts, paths, scheme=scheme,
                          max_hosts=max_hosts, max_paths=max_paths,
                          max_probes=max_probes)

    vhost_candidates = getattr(model, "vhost_candidates", None) or []
    if vhost_candidates:
        generic = {h.lower() for h in _INTERNAL_HOSTS}
        values: List[str] = []
        for candidate in vhost_candidates:
            value = getattr(candidate, "host", None) or str(candidate)
            value = str(value).strip()
            if value and value.lower() not in generic:
                values.append(value)
        if values:
            probes.extend(build_host_confusion_probes(
                hosts, paths, values, scheme=scheme, max_hosts=max_hosts,
                max_probes=max_probes - len(probes)))

    return probes[:max_probes]


# ---------------------------------------------------------------------------
# Live replay + oracle scoring
# ---------------------------------------------------------------------------

# A transport executes one request and returns an HttpObservation. The runner
# calls it twice per probe: baseline (no forged header) then candidate (forged).
Transport = Callable[[str, str, Dict[str, str]], HttpObservation]

_DENIED_STATUS = {401, 403, 404, 405, 407}


def classify_trust(baseline: HttpObservation,
                   probe: HttpObservation) -> Dict[str, Any]:
    """Deterministic header-trust hypothesis from a baseline-vs-forged pair.

    Complements (never overrides) the oracle: this labels the characteristic
    "denied -> allowed" pattern a proxy/allowlist/vhost trust bug produces.
    """
    denied = baseline.status in _DENIED_STATUS
    allowed = 200 <= probe.status < 300
    if denied and allowed:
        return {
            "trust_signal": True,
            "reason": (f"access-denied baseline ({baseline.status}) became "
                       f"access-allowed ({probe.status}) with the forged header"),
        }
    if baseline.status != probe.status:
        return {
            "trust_signal": False,
            "reason": (f"status changed ({baseline.status} -> {probe.status}) "
                       f"but not the denied->allowed pattern"),
        }
    return {"trust_signal": False, "reason": "status unchanged"}


class HeaderTrustRunner:
    """Replay baseline-vs-forged header requests and classify with the oracle."""

    def __init__(self, validator: Optional[OracleValidator] = None):
        self.validator = validator or OracleValidator()
        # Phase 0 H-7: probes whose forged value is a trusted/internal host
        # or IP are skipped unless explicitly allowed via --scope-internal-host.
        self.allow_internal_hosts: bool = False

    def run(self, probes: List[HeaderProbe],
            transport: Transport,
            target: str = "",
            ) -> List[HeaderTrustResult]:
        results: List[HeaderTrustResult] = []
        for probe in probes:
            # Phase 0 H-7: gated by allow_internal_hosts (default False).
            if not self.allow_internal_hosts and probe.value in _INTERNAL_HOSTS:
                continue
            if not self.allow_internal_hosts and probe.value in _TRUSTED_IPS:
                continue
            baseline = transport(probe.method, probe.url, {})
            candidate = transport(probe.method, probe.url,
                                  {probe.name: probe.value})
            record = self.validator.validate(
                candidate, baseline,
                url=probe.url, control_url=probe.url, method=probe.method,
                bug_class=probe.bug_class_label,
                probe_label=f"{probe.name}: {probe.value}",
                experiment_id=probe.probe_id, target=target,
            )
            trust = classify_trust(baseline, candidate)
            hypothesis = self._hypothesis(probe, record.state)
            results.append(HeaderTrustResult(
                probe=probe, state=record.state.value,
                decisive_rule=record.decisive_rule,
                observation_id=record.observation_id,
                baseline_status=baseline.status,
                probe_status=candidate.status,
                body_similarity=record.metrics.body_similarity,
                trust_signal=bool(trust["trust_signal"]),
                trust_reason=trust["reason"],
                hypothesis=hypothesis,
            ))
        return results

    @staticmethod
    def _hypothesis(probe: HeaderProbe, state: ObservationState) -> str:
        if state == ObservationState.SIGNAL:
            return (f"Header {probe.name} changed behavior — the proxy/app may "
                    f"trust it ({probe.category}). Confirm the trust boundary "
                    f"and demonstrate impact (allowlist bypass, internal reach, "
                    f"or path rewrite) before claiming a finding.")
        if state == ObservationState.UNKNOWN:
            return (f"Header {probe.name} produced an ambiguous delta "
                    f"({probe.category}) — run the oracle follow-up to separate "
                    f"trust-driven change from endpoint noise.")
        if state == ObservationState.REFUTED:
            return f"Header {probe.name} was ignored (no observable delta)."
        return f"Transport error while probing {probe.name}."


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_surface_from_args(args) -> Any:
    try:
        if args.recon_dir:
            from tools.schema_extractor import build_surface
            return build_surface(args.target, args.recon_dir)
        from tools.surface_model import load_surface
        return load_surface(target=args.target, openapi_file=args.openapi,
                            graphql_file=args.graphql,
                            urls_file=args.urls_file,
                            surface_file=args.surface_file,
                            base_url=args.base_url)
    except ImportError:
        if args.recon_dir:
            from schema_extractor import build_surface
            return build_surface(args.target, args.recon_dir)
        from surface_model import load_surface
        return load_surface(target=args.target, openapi_file=args.openapi,
                            graphql_file=args.graphql,
                            urls_file=args.urls_file,
                            surface_file=args.surface_file,
                            base_url=args.base_url)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Header-trust / proxy-trust probe planner and runner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--openapi", help="OpenAPI/Swagger JSON file")
    parser.add_argument("--graphql", help="GraphQL introspection JSON file")
    parser.add_argument("--urls-file", help="Recon URL list")
    parser.add_argument("--surface-file", help="Previously saved surface model")
    parser.add_argument("--recon-dir", help="Auto-discover schemas from recon output")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--scheme", default="https", choices=["http", "https"])
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--confirm-active", action="store_true",
                        help="Authorize live baseline-vs-forged replay")
    parser.add_argument("--scope-internal-host", action="store_true",
                        help="Phase 0 H-7: allow probes whose forged value is "
                             "a trusted/internal host or IP (off by default)")
    parser.add_argument("--max-probes", type=int, default=4000)
    parser.add_argument("--output", help="Write the plan (or live results) JSON to this file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        model = _load_surface_from_args(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(2)

    probes = probes_from_model(model, scheme=args.scheme,
                               max_probes=args.max_probes)

    if not args.confirm_active:
        payload = {
            "schema": SCHEMA_VERSION,
            "target": args.target,
            "mode": "plan_only",
            "probes": len(probes),
            "plan": [p.to_dict() for p in probes],
        }
        if args.output:
            Path(args.output).write_text(
                json.dumps(payload, indent=2, default=str) + "\n")
        if args.json:
            print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"[*] Header-trust probes for {args.target}: {len(probes)}")
            by_class: Dict[str, int] = {}
            for p in probes:
                by_class[p.category] = by_class.get(p.category, 0) + 1
            for cat, n in sorted(by_class.items()):
                print(f"    {cat}: {n}")
            for p in probes[:25]:
                print(f"    {p.name}: {p.value!r}  ->  {p.method} {p.url}")
        return

    # Phase 0 H7: scope-file is required for live replay; internal-host
    # probes (Host: localhost / 127.0.0.1 / admin, X-Forwarded-For with
    # loopback IPs) require --scope-internal-host. The policy below caps
    # allowed_actions to PASSIVE/READ and bounds the request budget.

    try:
        import tools.hunt as hunt
        from tools.execution_controller import (
            ActionClass, ActiveExecutionController, ExecutionPolicy,
        )
    except ImportError as exc:
        print(f"[!] live replay unavailable: {exc}", file=sys.stderr)
        raise SystemExit(2)

    policy = ExecutionPolicy(
        target=args.target, scope_file=args.scope_file,
        allow_active=True, confirm_active=True,
        allowed_actions={ActionClass.PASSIVE, ActionClass.READ},
        max_requests=len(probes) * 2 + 2,
    )
    hunt.ACTIVE_CONTROLLER = ActiveExecutionController(policy)
    session = hunt.HuntSession(name="header_trust", target=args.target)

    def transport(method: str, url: str, headers: Dict[str, str]) -> HttpObservation:
        return hunt.curl_fetch_observation(method, url, session,
                                           extra_headers=headers)

    runner = HeaderTrustRunner()
    runner.allow_internal_hosts = bool(args.scope_internal_host)
    results = runner.run(probes, transport, target=args.target)

    payload = {
        "schema": SCHEMA_VERSION,
        "target": args.target,
        "mode": "live",
        "results": [r.to_dict() for r in results],
        "signals": sum(1 for r in results if r.state == "signal"),
        "unknowns": sum(1 for r in results if r.state == "unknown"),
    }
    if args.output:
        Path(args.output).write_text(
            json.dumps(payload, indent=2, default=str) + "\n")

    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(f"[*] Live header-trust results for {args.target}")
        for r in results:
            flag = " ⚡SIGNAL" if r.state == "signal" else ""
            print(f"  [{r.state}]{flag} {r.probe.name}: {r.probe.value!r}  "
                  f"({r.baseline_status}->{r.probe_status}, "
                  f"similarity {r.body_similarity})")
            if r.state in ("signal", "unknown"):
                print(f"      {r.hypothesis}")


if __name__ == "__main__":
    main()
