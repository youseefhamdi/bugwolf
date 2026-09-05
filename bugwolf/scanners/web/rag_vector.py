"""RAG / vector-store attack scanner — SHELL-LEVEL.

RAG-specific attack surface (poisoning, prompt-injection via embedded
documents, similarity-search leakage) requires a vector-store client
and an embedding model.  Both are out-of-band for BugWolf's default
unit-test transport contract.

This scanner ships as a shell so the orchestrator can import it
without crashing and so the test suite can verify the ABC shape.  When
invoked with a real RAG-aware transport it can be extended to send
canary tokens through the embed/retrieve path and observe them in
returned documents — see TODO in :meth:`scan`.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_RAG_CANARIES: Tuple[str, ...] = (
    "BugWolfRAGCanaryA1B2",
    "BugWolfRAGCanaryC3D4",
    "BugWolfRAGCanaryE5F6",
)


class RAGVectorScanner(Scanner):
    name = "rag-vector"
    bug_class = "rag-vector-attack"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = _RAG_CANARIES

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "rag-vector: shell-mode (no transport); returning [] "
                "— supply an embedding/retrieval-aware transport to enable"
            )
            return []
        # Generic embed/retrieve echo probe.
        try:
            resp: Dict[str, Any] = transport(
                "POST", target,
                headers={"Content-Type": "application/json"},
                body='{"query":"%s"}' % _RAG_CANARIES[0],
            )
        except Exception as exc:
            logger.debug("rag: transport error: %s", exc)
            return []
        rbody = resp.get("body", "") or ""
        if _RAG_CANARIES[0] in rbody:
            return [make_finding(
                self,
                target=target,
                evidence="canary token echoed back from RAG retrieval",
                severity="high",
                detail={"canary": _RAG_CANARIES[0],
                        "snippet": rbody[:160]},
            )]
        return []


__all__ = ["RAGVectorScanner"]