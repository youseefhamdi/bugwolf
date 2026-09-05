"""SAML XSW (XML Signature Wrapping) scanner.

Probes the classic SAML XSW variants: an attacker wraps a signed
``Assertion`` element inside an unsigned sibling, hoping the signature
validator passes while the relying party consumes the unsigned copy.

The scanner's ``PAYLOADS`` are pre-baked XML strings tagged with the
``BugWolfSAMLXSW`` canary so that a transport mock can be used to
verify the canary path end-to-end.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


def _xsw(body_substitute: str) -> str:
    """Return a minimal SAML XSW variant."""
    return (
        "<samlp:Response>"
        "<saml:Assertion ID='signed'>BugWolfSAMLXSW-signed</saml:Assertion>"
        f"<saml:Assertion ID='unsigned'>{body_substitute}</saml:Assertion>"
        "</samlp:Response>"
    )


class SAMLXSWScanner(Scanner):
    name = "saml-xsw"
    bug_class = "saml-xsw"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = (
        _xsw("BugWolfSAMLXSWRole=admin"),
        _xsw("BugWolfSAMLXSWSubject=victim"),
        _xsw("BugWolfSAMLXSWNameID=attacker"),
        _xsw("BugWolfSAMLXSWAttr=elevated"),
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("saml-xsw: transport is None; returning []")
            return []
        findings: List[Finding] = []
        for payload in self.PAYLOADS:
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={"Content-Type": "text/xml"},
                    body=payload,
                )
            except Exception as exc:
                logger.debug("saml: transport error: %s", exc)
                continue
            rbody = resp.get("body", "") or ""
            if "BugWolfSAMLXSW" in rbody and (
                resp.get("status") in (200, 202, 302)
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="SAML XSW canary reflected in response",
                    severity="critical",
                    detail={"payload": payload[:160],
                            "status": resp.get("status"),
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["SAMLXSWScanner"]