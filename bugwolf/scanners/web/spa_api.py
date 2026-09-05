"""SPA API discovery scanner.

Modern single-page apps frequently fetch JSON from a private API
endpoint that is not linked from any HTML.  This scanner enumerates
the canonical SPA-API locations (``/api``, ``/api/v1``, ``/graphql``,
``/internal``, ``/v2``, ``/_next/data``, etc.) and probes them.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_SPA_PATHS: Tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/internal",
    "/_next/data",
    "/_nuxt/data",
    "/_app",
    "/_private",
    "/__data.json",
    "/rest",
    "/v1",
    "/v2",
)


class SPAAPIScanner(Scanner):
    name = "spa-api"
    bug_class = "spa-api-exposure"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = _SPA_PATHS

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("spa-api: transport is None; returning []")
            return []
        findings: List[Finding] = []
        base = target.rstrip("/")
        for path in _SPA_PATHS:
            url = base + path
            try:
                resp: Dict[str, Any] = transport("GET", url)
            except Exception as exc:
                logger.debug("spa-api: transport error: %s", exc)
                continue
            status = resp.get("status")
            rheaders = resp.get("headers", {}) or {}
            rbody = (resp.get("body", "") or "")
            ct = ""
            for k, v in rheaders.items():
                if k.lower() == "content-type":
                    ct = str(v).lower()
            if status in (200, 401, 403) and (
                "json" in ct or "html" in ct or rbody.startswith(("{", "["))
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"SPA API endpoint reachable at {path}",
                    severity="medium",
                    detail={"path": path, "status": status,
                            "content_type": ct,
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["SPAAPIScanner"]