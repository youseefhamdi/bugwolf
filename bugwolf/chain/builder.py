## Source: BugWolf Phase 3.5 (in-house) — CrossProtocolChainBuilder
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.builder — CrossProtocolChainBuilder + dataclasses.

Phase 3.5 layer on top of the existing ``tools.kill_chain.KillChainBuilder``.
The cross-protocol builder extends the legacy single-protocol chain
semantics with explicit transitions between two protocols (e.g.
``http`` → ``grpc``, ``graphql`` → ``db``). It is STUB-SAFE everywhere —
missing dependencies, malformed input, or scope conflicts degrade to
the :class:`Unavailable` dataclass instead of raising.

This module is stdlib-only. It imports the legacy ``KillChainBuilder``
class lazily so the module remains importable in pure offline mode.
"""
from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


SCHEMA = "bugwolf-chain-v1"


# ---------------------------------------------------------------------------
# Protocol taxonomy
# ---------------------------------------------------------------------------

# Canonical set of protocols the builder understands. Anything else
# degrades gracefully — the chain is marked validity=False and a
# warning is recorded.
CANONICAL_PROTOCOLS: Tuple[str, ...] = (
    "http",
    "https",
    "graphql",
    "grpc",
    "websocket",
    "ws",
    "soap",
    "xml-rpc",
    "dns",
    "smtp",
    "ssh",
    "db",
    "redis",
    "kafka",
    "s3",
    "cloud",
    "iam",
    "ci-cd",
    "ci",
    "registry",
    "mobile",
    "internal",
)

DESTRUCTIVE_VERBS: frozenset = frozenset({
    "PUT", "POST", "PATCH", "DELETE",
})

# Per the CI gate AP-XP-8 — never emit these as a chain step verb.
FORBIDDEN_METHODS: frozenset = frozenset({
    "POUET", "UNCHECKOUT", "LABEL",
})


# ---------------------------------------------------------------------------
# Frozen dataclasses — public surface
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainStep:
    """One step inside a multi-step chain.

    ``order`` is 1-indexed and must be unique within a chain.
    ``protocol`` is the protocol in which the step is executed
    (e.g. ``http``, ``grpc``, ``db``). ``evidence`` is the structured
    evidence-block describing the reproducible artefact (request,
    response, hash, log line, etc.).
    """

    order: int
    description: str
    protocol: str
    technique: str = ""
    preconditions: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Dict[str, Any] = field(default_factory=dict)
    destructive: bool = False
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "order": int(self.order),
            "description": str(self.description),
            "protocol": str(self.protocol),
            "technique": str(self.technique),
            "preconditions": list(self.preconditions),
            "evidence": dict(self.evidence),
            "destructive": bool(self.destructive),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class CrossProtocolChain:
    """Chain that transitions between two protocols.

    ``validity`` is computed by :class:`bugwolf.chain.validator.ChainValidator`.
    ``confidence`` is a heuristic 0..1 — never 1.0 because real-world
    exploitation carries noise.
    """

    chain_id: str
    source_protocol: str
    target_protocol: str
    steps: Tuple[ChainStep, ...]
    validity: bool
    confidence: float
    rationale: str = ""
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "chain_id": str(self.chain_id),
            "source_protocol": str(self.source_protocol),
            "target_protocol": str(self.target_protocol),
            "steps": [s.to_dict() for s in self.steps],
            "validity": bool(self.validity),
            "confidence": float(self.confidence),
            "rationale": str(self.rationale),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class CrossTargetChain:
    """Chain that pivots from a primary target into lateral targets.

    The ``total_severity`` and ``estimated_bounty_range`` are computed
    heuristically (see :meth:`CrossTargetChainBuilder._estimate_severity`).
    """

    chain_id: str
    primary_target: str
    lateral_targets: Tuple[str, ...]
    steps: Tuple[ChainStep, ...]
    total_severity: str
    estimated_bounty_range: str
    confidence: float = 0.5
    rationale: str = ""
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "chain_id": str(self.chain_id),
            "primary_target": str(self.primary_target),
            "lateral_targets": list(self.lateral_targets),
            "steps": [s.to_dict() for s in self.steps],
            "total_severity": str(self.total_severity),
            "estimated_bounty_range": str(self.estimated_bounty_range),
            "confidence": float(self.confidence),
            "rationale": str(self.rationale),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class Unavailable:
    """STUB-SAFE fallback returned when a chain cannot be built."""

    reason: str
    code: str = "unavailable"
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "code": str(self.code),
            "reason": str(self.reason),
            "diagnostics": dict(self.diagnostics),
        }


# Union of every chain shape the rest of the package operates on.
Chain = Union[CrossProtocolChain, CrossTargetChain]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_protocol(p: str) -> str:
    """Normalize a protocol label.

    Returns a lowercase, hyphen-normalized string. Empty / non-strings
    degrade to the empty string (which :class:`ChainValidator` flags).
    """
    if not isinstance(p, str):
        return ""
    return p.strip().lower().replace("_", "-")


def _safe_import_kill_chain_builder():
    """Lazy import of the legacy KillChainBuilder.

    Returns ``None`` if the import fails so the rest of this module
    degrades to :class:`Unavailable`.
    """
    try:
        # Prefer the canonical bugwolf.tools path
        from tools.kill_chain import KillChainBuilder  # type: ignore
        return KillChainBuilder
    except Exception:  # noqa: BLE001
        pass
    try:
        from bugwolf.tools.kill_chain import KillChainBuilder  # type: ignore
        return KillChainBuilder
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Pattern table — H100 proven cross-protocol transitions
# ---------------------------------------------------------------------------

# Each tuple is (source, target, technique, severity_hint, confidence_hint)
# ``confidence_hint`` is a ceiling — the actual confidence is multiplied
# by 0.9 to leave room for noise.
_CROSS_PROTOCOL_PATTERNS: Tuple[Dict[str, Any], ...] = (
    {
        "source": "http",
        "target": "grpc",
        "technique": "http_to_grpc_translation",
        "rationale": (
            "Public HTTP endpoint proxies or mirrors a private gRPC "
            "service; cache or WAF bypass on the HTTP surface leaks "
            "the gRPC body schema."),
        "confidence": 0.75,
        "references": ("H1 #489146", "H1 #792927"),
    },
    {
        "source": "graphql",
        "target": "db",
        "technique": "graphql_introspection_to_db",
        "rationale": (
            "GraphQL introspection reveals the underlying DB schema; "
            "missing field-level authZ enables direct DB-table reads "
            "via the resolver path."),
        "confidence": 0.85,
        "references": ("H1 #489146 (1032 upvotes)",),
    },
    {
        "source": "http",
        "target": "cloud",
        "technique": "ssrf_to_cloud_metadata",
        "rationale": (
            "Server-side request forgery on an HTTP fetch endpoint "
            "allows the application to pull IAM credentials from the "
            "cloud metadata service (IMDS)."),
        "confidence": 0.9,
        "references": ("Shopify #446585",),
    },
    {
        "source": "http",
        "target": "iam",
        "technique": "oauth_redirect_to_token",
        "rationale": (
            "OAuth redirect_uri accepts a wildcard subdomain; matching "
            "subdomain capture returns the auth code which is exchanged "
            "for an IAM bearer token."),
        "confidence": 0.8,
        "references": ("H1 #115669", "Shopify #791775"),
    },
    {
        "source": "graphql",
        "target": "http",
        "technique": "graphql_field_to_http",
        "rationale": (
            "GraphQL field resolver falls through to an HTTP backend; "
            "IDOR on the HTTP backend leaks data through the typed "
            "GraphQL surface."),
        "confidence": 0.7,
        "references": ("H1 #792927",),
    },
    {
        "source": "http",
        "target": "websocket",
        "technique": "http_to_ws_upgrade_hijack",
        "rationale": (
            "Origin-less WebSocket upgrade allows a malicious site to "
            "ride the authenticated session over an http→ws transition."),
        "confidence": 0.65,
        "references": ("H1 #737140",),
    },
    {
        "source": "http",
        "target": "ci-cd",
        "technique": "ssrf_to_cicd_trigger",
        "rationale": (
            "SSRF reaches the internal CI/CD API (Jenkins, GitLab) "
            "and triggers a build that runs attacker-controlled code."),
        "confidence": 0.7,
        "references": ("Google #169438",),
    },
    {
        "source": "http",
        "target": "registry",
        "technique": "ssrf_to_internal_registry",
        "rationale": (
            "SSRF can resolve internal container/artifact registries; "
            "the registry tokens grant push access to production images."),
        "confidence": 0.6,
        "references": ("Shopify #1087489",),
    },
)


# ---------------------------------------------------------------------------
# CrossProtocolChainBuilder
# ---------------------------------------------------------------------------

class CrossProtocolChainBuilder:
    """Builder for chains that cross a protocol boundary.

    Compatible with the legacy :class:`tools.kill_chain.KillChainBuilder`
    in the sense that a ``findings`` payload accepted by the legacy
    builder can be re-scored against the cross-protocol pattern table.

    All public methods are STUB-SAFE — they return an :class:`Unavailable`
    object instead of raising on missing data, malformed input, or
    scope conflict.
    """

    def __init__(self, target: str = ""):
        self.target = str(target or "")
        self._legacy = _safe_import_kill_chain_builder()
        # Working dir for chain artefacts. Created on first use.
        self._workdir: Optional[Path] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_cross_protocol_chain(self, *,
                                   source_protocol: str = "http",
                                   target_protocol: str = "grpc",
                                   findings: Optional[Sequence[Dict[str, Any]]] = None,
                                   references: Sequence[str] = (),
                                   ) -> Union[CrossProtocolChain, Unavailable]:
        """Build a cross-protocol chain between two protocols.

        Args:
            source_protocol: the entry protocol (e.g. ``"http"``).
            target_protocol: the pivot protocol (e.g. ``"grpc"``).
            findings: optional list of finding dicts (legacy format
                understood by ``tools.kill_chain``). Used to enrich
                ``confidence`` and ``rationale`` when supplied.
            references: optional human-readable references list.

        Returns:
            :class:`CrossProtocolChain` on success, otherwise
            :class:`Unavailable` describing why the chain could not
            be built.
        """
        sp = _normalize_protocol(source_protocol)
        tp = _normalize_protocol(target_protocol)

        if not sp or not tp:
            return Unavailable(
                reason="empty source/target protocol",
                code="invalid_protocol",
                diagnostics={"source": sp, "target": tp},
            )
        if sp == tp:
            return Unavailable(
                reason="source and target protocols are identical — not cross-protocol",
                code="identical_protocol",
                diagnostics={"protocol": sp},
            )
        if FORBIDDEN_METHODS.intersection({sp.upper(), tp.upper()}):
            return Unavailable(
                reason="protocol name uses a forbidden HTTP verb",
                code="forbidden_method",
                diagnostics={"source": sp, "target": tp},
            )

        pattern = self._match_pattern(sp, tp)
        if pattern is None:
            return Unavailable(
                reason=f"no cross-protocol pattern known for {sp}->{tp}",
                code="no_pattern",
                diagnostics={"source": sp, "target": tp},
            )

        steps = self._build_steps(sp, tp, pattern, findings or ())
        confidence = self._score_confidence(pattern, findings or ())
        chain_id = f"xproto-{_hash(sp + '->' + tp + '|' + pattern['technique'])}"

        chain = CrossProtocolChain(
            chain_id=chain_id,
            source_protocol=sp,
            target_protocol=tp,
            steps=steps,
            validity=True,  # pre-validator pass; post-validator may flip
            confidence=round(confidence, 4),
            rationale=pattern["rationale"],
            references=tuple(list(references) + list(pattern.get("references", []))),
        )
        return chain

    def list_known_patterns(self) -> Tuple[Dict[str, Any], ...]:
        """Return the immutable pattern table."""
        return _CROSS_PROTOCOL_PATTERNS

    def extend_legacy(self, findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Re-score ``findings`` against the legacy KillChainBuilder.

        Returns a list of dict records (one per matched chain) with the
        legacy scoring fields. Returns an empty list if the legacy
        builder is unavailable.
        """
        if self._legacy is None:
            return []
        try:
            legacy = self._legacy(self.target or "cross-protocol")
            candidates = legacy.build_all_chains(list(findings))
        except Exception:  # noqa: BLE001
            return []
        out: List[Dict[str, Any]] = []
        for c in candidates:
            try:
                out.append({
                    "pattern_id": c.pattern.chain_id,
                    "match_score": float(c.match_score),
                    "combined_severity": str(c.combined_severity),
                    "estimated_bounty": str(c.estimated_bounty),
                    "auto_testable": bool(c.auto_testable),
                })
            except Exception:  # noqa: BLE001
                continue
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _match_pattern(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        for p in _CROSS_PROTOCOL_PATTERNS:
            if p["source"] == source and p["target"] == target:
                return p
        return None

    def _build_steps(self, source: str, target: str,
                     pattern: Dict[str, Any],
                     findings: Sequence[Dict[str, Any]]) -> Tuple[ChainStep, ...]:
        technique = pattern["technique"]
        refs = tuple(pattern.get("references", ()))

        if technique == "http_to_grpc_translation":
            return (
                ChainStep(
                    order=1, description="Identify HTTP gateway endpoint", protocol=source,
                    technique="http_endpoint_discovery", destructive=False,
                    evidence={"kind": "endpoint", "url": "/api/grpc-gateway/EchoService/Echo"},
                ),
                ChainStep(
                    order=2, description="Inspect gRPC frame schema via HTTP reflection", protocol=source,
                    technique="grpc_reflection", destructive=False,
                    evidence={"kind": "schema", "service": "EchoService"},
                ),
                ChainStep(
                    order=3, description="Replay gRPC payload over HTTP gateway", protocol=target,
                    technique="http_to_grpc_replay", destructive=False,
                    evidence={"kind": "request", "content-type": "application/grpc-web+json"},
                ),
            )
        if technique == "graphql_introspection_to_db":
            return (
                ChainStep(
                    order=1, description="Run GraphQL introspection query", protocol=source,
                    technique="introspection", destructive=False,
                    evidence={"kind": "query", "q": "{ __schema { types { name } } }"},
                ),
                ChainStep(
                    order=2, description="Map GraphQL types to underlying DB tables", protocol=source,
                    technique="schema_mapping", destructive=False,
                    evidence={"kind": "mapping", "fields": ["User", "Account"]},
                ),
                ChainStep(
                    order=3, description="Craft query bypassing field-level authZ", protocol=source,
                    technique="field_authz_bypass", destructive=False,
                    evidence={"kind": "query", "q": "{ users { email } }"},
                ),
                ChainStep(
                    order=4, description="Bulk extract rows from the resolved DB table", protocol=target,
                    technique="db_table_dump", destructive=False,
                    evidence={"kind": "table", "name": "users"},
                ),
            )
        if technique == "ssrf_to_cloud_metadata":
            return (
                ChainStep(
                    order=1, description="Confirm SSRF reachability on HTTP fetch endpoint", protocol=source,
                    technique="ssrf_confirm", destructive=False,
                    evidence={"kind": "request", "url": "/api/v1/fetch"},
                ),
                ChainStep(
                    order=2, description="Probe cloud metadata service over SSRF", protocol=source,
                    technique="metadata_probe", destructive=False,
                    evidence={"kind": "request", "target": "169.254.169.254"},
                ),
                ChainStep(
                    order=3, description="Extract IAM credentials from metadata", protocol=target,
                    technique="iam_extract", destructive=False,
                    evidence={"kind": "credential", "service": "imds"},
                ),
            )
        if technique == "oauth_redirect_to_token":
            return (
                ChainStep(
                    order=1, description="Test wildcard redirect_uri on OAuth provider", protocol=source,
                    technique="oauth_redirect_test", destructive=False,
                    evidence={"kind": "request", "url": "/oauth/authorize"},
                ),
                ChainStep(
                    order=2, description="Register matching subdomain under attacker control", protocol=source,
                    technique="subdomain_register", destructive=False,
                    evidence={"kind": "dns", "record": "CNAME", "host": "evil.example.com"},
                ),
                ChainStep(
                    order=3, description="Capture authorization code at attacker's endpoint", protocol=source,
                    technique="auth_code_capture", destructive=False,
                    evidence={"kind": "server_log", "fields": ["code", "state"]},
                ),
                ChainStep(
                    order=4, description="Exchange code for IAM bearer token", protocol=target,
                    technique="code_exchange", destructive=False,
                    evidence={"kind": "token", "service": "iam"},
                ),
            )
        if technique == "graphql_field_to_http":
            return (
                ChainStep(
                    order=1, description="Locate GraphQL field that resolves via HTTP", protocol=source,
                    technique="field_resolver_mapping", destructive=False,
                    evidence={"kind": "field", "name": "user"},
                ),
                ChainStep(
                    order=2, description="Test IDOR on the underlying HTTP backend", protocol=target,
                    technique="idor_probe", destructive=False,
                    evidence={"kind": "request", "method": "GET", "url": "/users/:id"},
                ),
                ChainStep(
                    order=3, description="Aggregate leaked data through GraphQL field", protocol=source,
                    technique="aggregate", destructive=False,
                    evidence={"kind": "query", "q": "{ user(id: 1) { email } }"},
                ),
            )
        if technique == "http_to_ws_upgrade_hijack":
            return (
                ChainStep(
                    order=1, description="Identify WebSocket upgrade endpoint", protocol=source,
                    technique="ws_endpoint_discovery", destructive=False,
                    evidence={"kind": "endpoint", "url": "/ws"},
                ),
                ChainStep(
                    order=2, description="Confirm Origin header is not checked", protocol=source,
                    technique="origin_check_bypass", destructive=False,
                    evidence={"kind": "request", "headers": {"Origin": "https://attacker.example"}},
                ),
                ChainStep(
                    order=3, description="Open WebSocket from attacker-controlled origin", protocol=target,
                    technique="ws_hijack", destructive=False,
                    evidence={"kind": "action", "description": "wss://target/ws"},
                ),
            )
        if technique == "ssrf_to_cicd_trigger":
            return (
                ChainStep(
                    order=1, description="Confirm SSRF can reach internal network", protocol=source,
                    technique="ssrf_internal_reach", destructive=False,
                    evidence={"kind": "request", "target": "10.0.0.0/8"},
                ),
                ChainStep(
                    order=2, description="Identify internal CI/CD service on common ports", protocol=source,
                    technique="internal_service_enum", destructive=False,
                    evidence={"kind": "scan", "ports": [8080, 8443]},
                ),
                ChainStep(
                    order=3, description="Trigger build/deploy with attacker payload", protocol=target,
                    technique="build_trigger", destructive=True,
                    preconditions=("scope_approval", "ci_token_discovered"),
                    evidence={"kind": "action", "description": "POST /job/build"},
                ),
            )
        if technique == "ssrf_to_internal_registry":
            return (
                ChainStep(
                    order=1, description="Enumerate internal registries via SSRF", protocol=source,
                    technique="registry_enum", destructive=False,
                    evidence={"kind": "request", "target": "registry.internal"},
                ),
                ChainStep(
                    order=2, description="Capture registry auth tokens from response", protocol=source,
                    technique="token_capture", destructive=False,
                    evidence={"kind": "token", "service": "registry"},
                ),
                ChainStep(
                    order=3, description="Push poisoned image to production registry", protocol=target,
                    technique="image_push", destructive=True,
                    preconditions=("scope_approval", "registry_token_present"),
                    evidence={"kind": "action", "description": "POST /v2/<repo>/blobs/uploads/"},
                ),
            )

        # Generic fallback (still STUB-SAFE)
        return (
            ChainStep(
                order=1, description=f"Identify entry point on {source}", protocol=source,
                technique="entry_discovery", destructive=False, references=refs,
            ),
            ChainStep(
                order=2, description=f"Pivot to {target}", protocol=target,
                technique=technique, destructive=False, references=refs,
            ),
        )

    def _score_confidence(self, pattern: Dict[str, Any],
                          findings: Sequence[Dict[str, Any]]) -> float:
        base = float(pattern.get("confidence", 0.5))
        if not findings:
            return min(base, 0.9)
        # If findings match the technique/pattern class, nudge confidence.
        classes = {str(f.get("bug_class", "")).lower() for f in findings}
        boost = 0.0
        if {"ssrf", "ssrf-blind"} & classes and "ssrf" in pattern["technique"]:
            boost = 0.05
        if {"oauth-bypass", "oauth", "open-redirect"} & classes and "oauth" in pattern["technique"]:
            boost = 0.05
        if {"graphql-introspection", "graphql", "idor"} & classes and "graphql" in pattern["technique"]:
            boost = 0.05
        return min(0.95, base * 0.9 + boost)


__all__ = [
    "SCHEMA",
    "CANONICAL_PROTOCOLS",
    "DESTRUCTIVE_VERBS",
    "FORBIDDEN_METHODS",
    "ChainStep",
    "CrossProtocolChain",
    "CrossTargetChain",
    "Chain",
    "Unavailable",
    "CrossProtocolChainBuilder",
]
