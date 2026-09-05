"""Shadow-API detection scanner.

A "shadow API" is an undocumented HTTP endpoint that has drifted from
the public spec (legacy version paths, internal staging endpoints,
debug handlers, forgotten ``/v0`` routes).  This scanner enumerates a
small static list of paths against the target and flags any non-404
response with a 2xx/4xx other than 401/403/405 — those suggest a
hidden-but-live handler.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_SHADOW_PATHS: Tuple[str, ...] = (
    "/v0",
    "/v1",
    "/internal",
    "/debug",
    "/_debug",
    "/__debug__",
    "/admin",
    "/admin.php",
    "/admin/login",
    "/wp-admin",
    "/administrator",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/apidocs",
    "/api-docs",
    "/docs",
    "/redoc",
    "/metrics",
    "/healthz",
    "/readyz",
    "/status",
    "/ping",
    "/env",
    "/config",
    "/.env",
    "/.git",
    "/.git/HEAD",
    "/.svn",
    "/.hg",
)


class ShadowAPIScanner(Scanner):
    name = "shadow-api"
    bug_class = "shadow-api"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = _SHADOW_PATHS

    INTERESTING_STATUSES = (200, 201, 204, 301, 302, 400, 500, 502)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("shadow-api: transport is None; returning []")
            return []
        findings: List[Finding] = []
        base = target.rstrip("/")
        for path in _SHADOW_PATHS:
            url = base + path
            try:
                resp: Dict[str, Any] = transport("GET", url)
            except Exception as exc:
                logger.debug("shadow: transport error: %s", exc)
                continue
            status = resp.get("status")
            if status in self.INTERESTING_STATUSES and status not in (401, 403, 405):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"shadow endpoint at {path} returned {status}",
                    severity="medium",
                    detail={"path": path, "status": status,
                            "snippet": (resp.get("body", "") or "")[:160]},
                ))
        return findings


__all__ = ["ShadowAPIScanner"]