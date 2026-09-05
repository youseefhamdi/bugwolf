"""BugWolf API scanners — Phase 1.5 + 2.1.

This subpackage hosts the API-level scanners.  Phase 1.5 introduced the
shim re-exports of the ``graphql_batch_analyzer``; Phase 2.1 adds the
five new ``bug_class``-driven scanners.
"""
from __future__ import annotations

from bugwolf.scanners.api.graphql import GraphqlScanner
from bugwolf.scanners.api.graphql_dos import GraphQLDoSScanner
from bugwolf.scanners.api.graphql_introspection import (
    GraphQLIntrospectionScanner,
)
from bugwolf.scanners.api.param_discovery import ParamDiscoveryScanner
from bugwolf.scanners.api.rate_limit_bypass import RateLimitBypassScanner
from bugwolf.scanners.api.rest_fuzzing import RESTFuzzingScanner


def all_api_scanners():
    return [
        GraphqlScanner(),
        GraphQLIntrospectionScanner(),
        GraphQLDoSScanner(),
        RESTFuzzingScanner(),
        ParamDiscoveryScanner(),
        RateLimitBypassScanner(),
    ]


__all__ = [
    "GraphqlScanner",
    "GraphQLIntrospectionScanner",
    "GraphQLDoSScanner",
    "RESTFuzzingScanner",
    "ParamDiscoveryScanner",
    "RateLimitBypassScanner",
    "all_api_scanners",
]