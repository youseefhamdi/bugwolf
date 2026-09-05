## Source: BugWolf Phase 3.5 (in-house) — chain package
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain — Phase 3.5 cross-protocol chain synthesis.

This package exposes the public surface for building, validating, and
generating PoCs for chains that cross protocol or target boundaries.

Re-exports the primary classes so callers can do:

    from bugwolf.chain import (
        CrossProtocolChainBuilder,
        CrossTargetChainBuilder,
        ChainValidator,
        ChainPoCGenerator,
    )

STUB-SAFE everywhere — no public function raises.
"""
from __future__ import annotations

from bugwolf.chain.builder import (
    CANONICAL_PROTOCOLS,
    CrossProtocolChain,
    CrossProtocolChainBuilder,
    CrossTargetChain,
    Chain,
    ChainStep,
    DESTRUCTIVE_VERBS,
    FORBIDDEN_METHODS,
    SCHEMA,
    Unavailable,
)
from bugwolf.chain.cross_protocol import (
    build_all_known_transitions,
    build_graphql_to_db_chain,
    build_graphql_to_http_chain,
    build_http_to_ci_chain,
    build_http_to_cloud_chain,
    build_http_to_db_chain,
    build_http_to_grpc_chain,
    build_http_to_iam_chain,
    build_http_to_registry_chain,
    build_http_to_websocket_chain,
    has_destructive_step,
    list_supported_transitions,
    step_protocols,
    validate_protocol,
)
from bugwolf.chain.cross_target import CrossTargetChainBuilder
from bugwolf.chain.poc_chain import ChainPoCGenerator, PoCUnavailable
from bugwolf.chain.validator import ChainValidationResult, ChainValidator


__all__ = [
    "SCHEMA",
    "CANONICAL_PROTOCOLS",
    "DESTRUCTIVE_VERBS",
    "FORBIDDEN_METHODS",
    "Chain",
    "ChainStep",
    "CrossProtocolChain",
    "CrossTargetChain",
    "Unavailable",
    "CrossProtocolChainBuilder",
    "CrossTargetChainBuilder",
    "ChainValidator",
    "ChainValidationResult",
    "ChainPoCGenerator",
    "PoCUnavailable",
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
