"""Port-scanning scanner.

Sends a tiny probe against the canonical TCP-port list.  In a real
deployment the orchestrator substitutes a transport capable of
TCP-level probing; here we model the result via the
``transport`` contract.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000,
    3306, 3389, 4848, 5000, 5432, 5601, 5900, 5984, 6379, 7000,
    8000, 8080, 8081, 8443, 8500, 9000, 9042, 9090, 9092, 9200,
    9301, 9418, 10000, 11211, 15672, 27017, 27018, 27019,
)


class PortScanScanner(Scanner):
    name = "port-scan"
    bug_class = "port-exposure"
    default_severity = "medium"
    PAYLOADS: Tuple[str, ...] = tuple(str(p) for p in _PORTS)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("port-scan: transport is None; returning []")
            return []
        findings: List[Finding] = []
        host = target.replace("http://", "").replace("https://", "").split(
            "/", 1
        )[0]
        for port in _PORTS:
            try:
                resp: Dict[str, Any] = transport(
                    "GET", f"https://{host}:{port}/",
                )
            except Exception as exc:
                logger.debug("port: transport error: %s", exc)
                continue
            status = resp.get("status")
            if status in (200, 301, 302, 400, 401, 403):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"port {port} reachable on {host}",
                    severity="medium",
                    detail={"host": host, "port": port,
                            "status": status},
                ))
        return findings


__all__ = ["PortScanScanner"]