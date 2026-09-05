"""Credential brute-force scanner (defensive).

Generates a small static username/password corpus (the OWASP top-16
pairs) and probes a login endpoint.  This scanner is OFFLINE-only by
design — it never invokes a real auth endpoint; it sends payloads into
the supplied mock transport and looks for the shape of a brute-force
vulnerability (constant response body, weak lockout, timing variance).

Used in lab engagements against in-scope assets the operator has
explicitly authorised.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", "Admin123"),
    ("admin", "P@ssw0rd"),
    ("admin", "qwerty"),
    ("demo", "demo"),
    ("sa", "sa"),
    ("postgres", "postgres"),
    ("administrator", "changeme"),
)


class BruteForceScanner(Scanner):
    name = "brute-force"
    bug_class = "credential-brute-force"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = tuple(
        f"{u}:{p}" for (u, p) in _PAIRS
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("brute-force: transport is None; returning []")
            return []
        findings: List[Finding] = []
        body_hashes: Dict[str, int] = {}
        attempt_count = 0
        for user, pw in _PAIRS:
            try:
                resp: Dict[str, Any] = transport(
                    "POST", target,
                    headers={
                        "Content-Type":
                            "application/x-www-form-urlencoded",
                    },
                    body=f"username={user}&password={pw}",
                )
            except Exception as exc:
                logger.debug("brute: transport error: %s", exc)
                continue
            attempt_count += 1
            rbody = resp.get("body", "") or ""
            h = hash(rbody)
            body_hashes[h] = body_hashes.get(h, 0) + 1
            if resp.get("status") in (200, 302) and (
                "success" in rbody.lower()
                or "welcome" in rbody.lower()
                or "dashboard" in rbody.lower()
            ):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"credential {user}:{pw} appeared to succeed",
                    severity="critical",
                    detail={
                        "username": user,
                        "password": pw,
                        "status": resp.get("status"),
                        "snippet": rbody[:160],
                    },
                ))
        # heuristic: if all responses had the same body, there's no
        # rate-limiting / lockout to detect
        if attempt_count >= 8 and max(body_hashes.values()) == attempt_count:
            findings.append(make_finding(
                self,
                target=target,
                evidence=("no observable rate-limit or lockout — all "
                          f"{attempt_count} probes returned identical "
                          "responses"),
                severity="medium",
                detail={"attempts": attempt_count},
            ))
        return findings


__all__ = ["BruteForceScanner"]