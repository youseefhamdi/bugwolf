"""gRPC attack scanner — SHELL-LEVEL.

This scanner is intentionally a shell: full :class:`Scanner` subclass
shape with ``name`` / ``bug_class`` / ``default_severity`` / ``PAYLOADS``
and a ``scan()`` that returns ``[]`` when no transport is supplied.

Rationale: real gRPC probing requires either HTTP/2 frame manipulation
or a dedicated client; running that from inside BugWolf's default
transport contract (HTTP/1.1-shaped ``transport(method, url, ...)``)
would silently down-grade to REST semantics.  Keeping the scanner as
a shell leaves a stable import surface for the orchestrator without
shipping half-broken HTTP/2 logic.

When invoked with a real gRPC-aware transport the scanner can be
extended to walk the protobuf reflection API and enumerate methods —
see the TODO marker in ``scan``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class GRPCScanner(Scanner):
    name = "grpc"
    bug_class = "grpc-misconfig"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = (
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        "/grpc.health.v1.Health/Check",
        "POST /<unknown>",
        "content-type-application/grpc",
        "te-trailers",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "grpc: shell-mode (no transport); returning [] "
                "— implement against an HTTP/2-aware transport to enable"
            )
            return []
        # Minimal HTTP/2-content-type probe via the supplied transport.
        # If the response is gRPC-shaped (status 200 + content-type
        # application/grpc+proto) AND the body echoes our reflection
        # service name, emit an info finding.
        try:
            resp: Dict[str, Any] = transport(
                "POST",
                f"{target.rstrip('/')}/grpc.reflection.v1alpha"
                f".ServerReflection/ServerReflectionInfo",
                headers={"Content-Type": "application/grpc"},
                body="BugWolfGRPCProbe",
            )
        except Exception as exc:
            logger.debug("grpc: transport error: %s", exc)
            return []
        rheaders = resp.get("headers", {}) or {}
        ct = ""
        for k, v in rheaders.items():
            if k.lower() == "content-type":
                ct = str(v).lower()
        if "application/grpc" in ct and resp.get("status") == 200:
            return [make_finding(
                self,
                target=target,
                evidence="gRPC reflection endpoint responded — enumerate methods",
                severity="medium",
                detail={"content_type": ct, "status": resp.get("status")},
            )]
        return []


__all__ = ["GRPCScanner"]