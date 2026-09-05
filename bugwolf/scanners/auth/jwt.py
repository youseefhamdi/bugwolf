"""JWT scanner — shim re-export of tools.domains.auth.jwt_forgery.

This module is a thin adapter: it does NOT duplicate the JWT forgery logic.
It imports the existing ``analyze()`` function and converts its
:class:`JwtFinding` dataclass into the Phase 1.5 :class:`LiveFinding` wire
format.  All crypto attack planning stays in tools/domains/auth/jwt_forgery.py.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.auth.jwt_forgery import analyze as _analyze_jwt


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_BY_CLASS = {
    "alg_none": "critical",
    "key_confusion": "critical",
    "weak_hmac": "high",
    "claim_tampering": "high",
    "expiry_bypass": "high",
    "kid_injection": "high",
}


class JWTScanner(Scanner):
    name = "jwt"
    description = "JWT crypto attacks (alg=none, key confusion, weak HMAC, kid injection)"
    bug_class = "jwt"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "token" in target and isinstance(target.get("token"), str)

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        token = target.get("token", "")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        finding = _analyze_jwt(token)
        if finding is None:
            return []
        plans = list(getattr(finding, "plans", []))
        out: List[LiveFinding] = []
        for plan in plans:
            cls = str(plan.get("class", ""))
            sev = _SEVERITY_BY_CLASS.get(cls, self.default_severity)
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"JWT plan: {plan.get('name', cls)} ({cls})",
                reproducer=f"alg={finding.alg!r}  plans={len(plans)}",
                remediation="Reject alg=none; pin expected algorithm; validate iss/aud/exp/nbf; use asymmetric keys where possible.",
                payload_id="jwt-" + cls,
                extra={"class": cls, "name": plan.get("name", "")},
            ))
        if not plans:
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity="low",
                endpoint=endpoint,
                method=method,
                evidence="JWT decodeable but produced no plans (insufficient signal)",
                reproducer="decode + analyse",
                remediation="Review JWT validation: algorithm pinning, signature verification, claim validation.",
                payload_id="jwt-empty",
                extra={"alg": finding.alg},
            ))
        return out


def export_jwt_scanner():
    """Phase 1.5 export shim — returns a fresh JWTScanner instance."""
    return JWTScanner()


__all__ = ["JWTScanner", "export_jwt_scanner"]
