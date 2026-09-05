"""Canary-token detection scanner.

Scans a fetched response for known canary-token patterns (GUID /
UUID-shaped strings, AWS-style keys, Slack tokens, GitHub PAT
prefixes, etc.).  The scanner never reaches out to a canary service
itself — it only inspects the supplied page.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from bugwolf.scanners import Finding, Scanner, make_finding


logger = logging.getLogger(__name__)


_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Slack token", r"xox[abprs]-[0-9a-zA-Z-]{10,}"),
    ("GitHub PAT", r"ghp_[0-9A-Za-z]{36}"),
    ("GitHub OAuth", r"gho_[0-9A-Za-z]{36}"),
    ("Stripe secret", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Heroku API key", r"heroku[a-z0-9_]{8,}[0-9a-f]{32}"),
    ("Generic UUID", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}"),
)


class CanaryDetectorScanner(Scanner):
    name = "llm-canary-detector"
    bug_class = "canary-leak"
    default_severity = "high"
    PAYLOADS: Tuple[str, ...] = ("probe",)

    def scan(self, target: str, transport) -> List[Finding]:
        if transport is None:
            logger.warning(
                "llm-canary-detector: transport is None; returning []"
            )
            return []
        try:
            resp: Dict[str, Any] = transport("GET", target)
        except Exception as exc:
            logger.debug("canary: transport error: %s", exc)
            return []
        body = resp.get("body", "") or ""
        findings: List[Finding] = []
        for label, pattern in _PATTERNS:
            for m in re.finditer(pattern, body):
                findings.append(make_finding(
                    self,
                    target=target,
                    evidence=(f"canary token ({label}) leaked: "
                              f"{m.group(0)[:24]}…"),
                    severity="high",
                    detail={"kind": label, "match": m.group(0)[:64]},
                ))
                break  # one finding per kind
        return findings


__all__ = ["CanaryDetectorScanner"]