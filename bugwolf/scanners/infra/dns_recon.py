"""DNS recon scanner.

Probes a handful of DNS-related attack surfaces: zone-transfer,
SPF/DKIM/DMARC records, and the canonical DNS-over-HTTPS service
URLs.  This scanner only emits findings when the mock transport
echoes canary strings; it never issues a real DNS query.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_RECORDS: Tuple[str, ...] = (
    "AXFR",
    "SPF",
    "DKIM",
    "DMARC",
    "DNSKEY",
    "NSEC",
    "NSEC3",
    "CAA",
    "TLSA",
    "HTTPS",
)


class DNSReconScanner(Scanner):
    name = "dns-recon"
    bug_class = "dns-misconfig"
    default_severity = "low"
    PAYLOADS: Tuple[str, ...] = _RECORDS

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("dns-recon: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for record in _RECORDS:
            try:
                resp: Dict[str, Any] = transport(
                    "GET",
                    f"{target.rstrip('/')}/_dns/{record}",
                    headers={"Accept": "application/dns-message"},
                )
            except Exception as exc:
                logger.debug("dns: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            if resp.get("status") == 200 and f"BugWolfDNS{record}" in rbody:
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"DNS {record} record disclosed",
                    severity="low",
                    detail={"record": record,
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["DNSReconScanner"]