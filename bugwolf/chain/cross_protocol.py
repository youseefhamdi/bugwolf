## Source: BugWolf Phase 3.5 (in-house) — cross_protocol helpers
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.cross_protocol — high-level helpers for HTTP→gRPC→DB chains.

This module adds opinionated factories on top of
:class:`bugwolf.chain.builder.CrossProtocolChainBuilder` for the most
common cross-protocol transitions seen in H100 disclosed reports.

The module is STUB-SAFE. Every function returns the chain object on
success or an :class:`Unavailable` dataclass on failure. It never
raises.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from bugwolf.chain.builder import (
    CANONICAL_PROTOCOLS,
    CrossProtocolChain,
    CrossProtocolChainBuilder,
    ChainStep,
    SCHEMA,
    Unavailable,
)


# ---------------------------------------------------------------------------
# Public factory surface
# ---------------------------------------------------------------------------

def build_http_to_grpc_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                             references: Sequence[str] = (),
                             ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP → gRPC translation chain."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="grpc",
        findings=findings,
        references=references,
    )


def build_http_to_db_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                           references: Sequence[str] = (),
                           ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP → DB via SQLi or graphQL-resolved SQLi."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="db",
        findings=findings,
        references=references,
    )


def build_graphql_to_db_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                              references: Sequence[str] = (),
                              ) -> Union[CrossProtocolChain, Unavailable]:
    """GraphQL → DB chain (introspection → missing authZ → DB read)."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="graphql",
        target_protocol="db",
        findings=findings,
        references=references,
    )


def build_http_to_cloud_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                              references: Sequence[str] = (),
                              ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP SSRF → cloud IMDS chain."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="cloud",
        findings=findings,
        references=references,
    )


def build_http_to_iam_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                            references: Sequence[str] = (),
                            ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP OAuth → IAM bearer token chain."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="iam",
        findings=findings,
        references=references,
    )


def build_http_to_ci_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                           references: Sequence[str] = (),
                           ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP SSRF → CI/CD chain (destructive verb pre-gated)."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="ci-cd",
        findings=findings,
        references=references,
    )


def build_http_to_registry_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                                 references: Sequence[str] = (),
                                 ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP SSRF → internal registry chain."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="registry",
        findings=findings,
        references=references,
    )


def build_graphql_to_http_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                                references: Sequence[str] = (),
                                ) -> Union[CrossProtocolChain, Unavailable]:
    """GraphQL → HTTP chain (field resolver → IDOR backend)."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="graphql",
        target_protocol="http",
        findings=findings,
        references=references,
    )


def build_http_to_websocket_chain(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                                  references: Sequence[str] = (),
                                  ) -> Union[CrossProtocolChain, Unavailable]:
    """HTTP → WebSocket hijack chain."""
    builder = CrossProtocolChainBuilder()
    return builder.build_cross_protocol_chain(
        source_protocol="http",
        target_protocol="websocket",
        findings=findings,
        references=references,
    )


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def list_supported_transitions() -> Tuple[Tuple[str, str], ...]:
    """Return the canonical (source, target) pairs known to the builder."""
    return tuple(
        (p["source"], p["target"])
        for p in CrossProtocolChainBuilder().list_known_patterns()
    )


def build_all_known_transitions(*, findings: Optional[Sequence[Dict[str, Any]]] = None,
                                ) -> List[Union[CrossProtocolChain, Unavailable]]:
    """Build every known cross-protocol transition.

    Returns a list (possibly empty) of chain or :class:`Unavailable`
    results. The list preserves pattern-table order.
    """
    builder = CrossProtocolChainBuilder()
    out: List[Union[CrossProtocolChain, Unavailable]] = []
    for p in builder.list_known_patterns():
        result = builder.build_cross_protocol_chain(
            source_protocol=p["source"],
            target_protocol=p["target"],
            findings=findings,
        )
        out.append(result)
    return out


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def validate_protocol(p: str) -> bool:
    """Return ``True`` if ``p`` is in the canonical protocol set."""
    if not isinstance(p, str):
        return False
    return p.strip().lower() in CANONICAL_PROTOCOLS


def has_destructive_step(chain: CrossProtocolChain) -> bool:
    """Return ``True`` if any step in ``chain`` is marked destructive."""
    return any(bool(s.destructive) for s in chain.steps)


def step_protocols(chain: CrossProtocolChain) -> Tuple[str, ...]:
    """Return the ordered tuple of unique protocols touched by ``chain``."""
    seen: List[str] = []
    for s in chain.steps:
        if s.protocol not in seen:
            seen.append(s.protocol)
    return tuple(seen)


__all__ = [
    "SCHEMA",
    "build_http_to_grpc_chain",
    "build_http_to_db_chain",
    "build_graphql_to_db_chain",
    "build_http_to_cloud_chain",
    "build_http_to_iam_chain",
    "build_http_to_ci_chain",
    "build_http_to_registry_chain",
    "build_graphql_to_http_chain",
    "build_http_to_websocket_chain",
    "list_supported_transitions",
    "build_all_known_transitions",
    "validate_protocol",
    "has_destructive_step",
    "step_protocols",
]
