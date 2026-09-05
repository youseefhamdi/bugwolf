"""Subdomain enumeration scanner.

Uses a static wordlist against ``*.target`` to discover subdomains via
HTTP probe.  A 200/301/302 from a wildcard host indicates a live
subdomain.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_WORDS: Tuple[str, ...] = (
    "www", "api", "admin", "staging", "stage", "dev", "test",
    "beta", "internal", "intranet", "portal", "mail", "smtp",
    "imap", "vpn", "remote", "ssh", "git", "gitlab", "github",
    "ci", "cd", "jenkins", "k8s", "kubernetes", "blog", "shop",
    "store", "docs", "doc", "wiki", "cdn", "static", "assets",
    "media", "img", "image", "files", "upload", "download",
    "backup", "bak", "old", "new", "v1", "v2", "v3", "auth",
    "sso", "oauth", "login", "dashboard", "console", "grafana",
    "prometheus", "kibana", "elastic", "redis", "mysql", "postgres",
    "mongo", "rabbit", "kafka", "queue", "worker", "cron",
)


class SubdomainEnumScanner(Scanner):
    name = "subdomain-enum"
    bug_class = "subdomain-discovery"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = _WORDS

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "subdomain-enum: transport is None; returning []"
            )
            return []
        findings: List[Finding] = []
        base = target.replace("http://", "").replace("https://", "").split(
            "/", 1
        )[0]
        if not base:
            return findings
        # strip leading subdomain to get the eTLD+1
        parts = base.split(".")
        if len(parts) <= 2:
            apex = base
        else:
            apex = ".".join(parts[-2:])
        for word in _WORDS:
            host = f"{word}.{apex}"
            url = f"https://{host}"
            try:
                resp: Dict[str, Any] = transport("GET", url)
            except Exception as exc:
                logger.debug("sub: transport error: %s", exc)
                continue
            status = resp.get("status")
            if status in (200, 301, 302):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"subdomain reachable: {host}",
                    severity="informational",
                    detail={"host": host, "status": status},
                ))
        return findings


__all__ = ["SubdomainEnumScanner"]