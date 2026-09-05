"""WAF bypass encoder — emits payload variants to evade naive WAF signatures."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


SEED_PAYLOADS = (
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../../etc/passwd",
)

ENCODINGS = (
    "identity",
    "urlencode-full",
    "urlencode-special-only",
    "double-urlencode",
    "html-entity-decimal",
    "html-entity-hex",
    "unicode-escape",
    "mixed-case",
    "comment-injection",
    "null-byte-prefix",
    "utf8-overlong",
)


def _pid(payload: str, encoding: str) -> str:
    return "waf-enc-" + hashlib.sha256(
        (encoding + "|" + payload).encode()).hexdigest()[:10]


def encode(payload: str, encoding: str) -> str:
    """Pure-python payload encoder — no network, no third-party libs."""
    if encoding == "identity":
        return payload
    if encoding == "urlencode-full":
        from urllib.parse import quote
        return quote(payload, safe="")
    if encoding == "urlencode-special-only":
        from urllib.parse import quote
        specials = set("<>\"'`;|&$(){} ")
        return "".join(quote(c) if c in specials else c for c in payload)
    if encoding == "double-urlencode":
        from urllib.parse import quote
        return quote(quote(payload, safe=""), safe="")
    if encoding == "html-entity-decimal":
        return "".join("&#" + str(ord(c)) + ";" for c in payload)
    if encoding == "html-entity-hex":
        return "".join("&#x" + format(ord(c), "x") + ";" for c in payload)
    if encoding == "unicode-escape":
        return "".join("\\u" + format(ord(c), "04x") for c in payload)
    if encoding == "mixed-case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    if encoding == "comment-injection":
        out_chars = []
        for i, c in enumerate(payload):
            out_chars.append(c)
            if c in "<>'\"" and i + 1 < len(payload):
                out_chars.append("/**/")
        return "".join(out_chars)
    if encoding == "null-byte-prefix":
        return "\x00" + payload
    if encoding == "utf8-overlong":
        return "".join(c if ord(c) < 128 else c for c in payload)
    return payload


class WAFEncoderScanner(Scanner):
    name = "waf_encoder"
    description = "Produces encoded payload variants to bypass naive WAF signatures"
    bug_class = "waf_encoding"
    default_severity = "informational"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        method = str(target.get("method", "GET")).upper()
        for seed in SEED_PAYLOADS:
            for encoding in ENCODINGS:
                encoded = encode(seed, encoding)
                try:
                    resp = transport(method, url,
                                     headers={"X-Test-Payload": encoded},
                                     body=encoded)
                except Exception:
                    continue
                rheaders = (resp.get("headers") or {}) if isinstance(resp, dict) else {}
                status = resp.get("status") if isinstance(resp, dict) else None
                if status and 200 <= status < 300:
                    findings.append(LiveFinding(
                        scanner=self.name,
                        bug_class=self.bug_class,
                        severity=self.default_severity,
                        endpoint=url,
                        method=method,
                        evidence=f"encoded payload ({encoding}) returned {status}",
                        reproducer=f"{method} {url}  X-Test-Payload: {encoded[:80]!r}",
                        remediation="WAF signature set is incomplete — broaden the rule with the encoded forms.",
                        payload_id=_pid(seed, encoding),
                        extra={"encoding": encoding, "status": status},
                    ))
        return findings


__all__ = ["WAFEncoderScanner", "encode", "ENCODINGS", "SEED_PAYLOADS"]
