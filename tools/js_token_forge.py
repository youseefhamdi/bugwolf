#!/usr/bin/env python3
"""Offline static analysis for client-side token forging (HMAC/secret reuse).

A recurring high-impact bug is embedding a signing secret in client JavaScript
and using it to mint authentication tokens from client-controlled fields. Since
the secret ships to every visitor, anyone can forge tokens for arbitrary
user / device / role claims — the classic ``getSDToken(deviceId, userId, …)``
HMAC pattern from a JS bundle.

This module detects the ingredients of that bug class and emits a forgeability
hypothesis plus a remediation plan. It is a *static* analyzer: it never runs
the code, never prints or persists the raw secret (evidence is a SHA-256
fingerprint of the matched line only), and never mints or validates a token.

Usage:
  python3 tools/js_token_forge.py --path recon/T/js --output-dir recon/T/token-forge --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

SCHEMA_VERSION = "bugwolf-js-token-forge-v1"

# (pattern, category, title, severity, rationale)
RULES: Sequence[Tuple[str, str, str, str, str]] = (
    (
        r"""(?i)\b(?:\w*secret\w*|\w*token\w*|signing\w*key|api\w*key|hmac\w*key|passphrase|salt|private\w*key)\s*[:=]\s*["'`][^"'`\n]{4,}["'`]""",
        "hardcoded_secret",
        "Hardcoded signing secret in client code",
        "critical",
        "A signing-secret literal ships with the client bundle; anyone can recover it.",
    ),
    (
        r"""(?i)(CryptoJS\.Hmac[A-Za-z0-9]+|crypto\.subtle\.sign|createHmac\s*\(|HmacSHA(?:1|256|384|512)|HmacMD5|\.update\([^)]*\)\s*\.digest\s*\()""",
        "client_signature_sink",
        "Client-side HMAC/signature primitive",
        "high",
        "A signature/HMAC primitive runs in the browser, implying the secret is also client-side.",
    ),
    (
        r"""(?i)\b(deviceId|device_id|userId|user_id|accountId|account_id|clientId|client_id|sessionId|session_id|username|email|phone|role|is[_ ]?admin)\b\s*\+""",
        "token_claim_input",
        "Client-controlled claim fed into the token",
        "high",
        "User/device/role fields are concatenated into the signed payload, so those claims are forgeable.",
    ),
    (
        r"""(?i)(jwt\.sign\s*\(|jsonwebtoken|signToken|mintToken|createToken|issueToken|generateToken|getSDToken|HmacSHA256\s*\([^)]*,\s*(?:secret|token|key))""",
        "token_mint_function",
        "Client-side token minting function",
        "critical",
        "Token generation logic lives in client code where its secret and inputs are attacker-visible.",
    ),
)


@dataclass
class TokenForgeFinding:
    finding_id: str
    category: str
    title: str
    source: str
    line_number: int
    severity: str
    rationale: str
    evidence_hash: str      # sha256 of the matched line — the raw line/secret is never stored
    status: str = "static_signal_human_review_required"

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


@dataclass
class TokenForgePlan:
    plan_id: str
    title: str
    source: str
    findings: List[str]
    forgeability: str       # high | medium | low
    rationale: str
    validation_questions: List[str]
    remediation: List[str]
    status: str = "offline_plan_only"

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["schema"] = SCHEMA_VERSION
        return data


def _finding_id(source: str, line: int, category: str, line_text: str) -> str:
    digest = hashlib.sha256(line_text.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.sha256(
        f"{source}:{line}:{category}:{digest}".encode()
    ).hexdigest()[:16]


def analyze_text(text: str, source: str = "artifact") -> List[TokenForgeFinding]:
    """Scan source text for the token-forging ingredients (offline)."""
    findings: List[TokenForgeFinding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for pattern, category, title, severity, rationale in RULES:
            if re.search(pattern, line):
                digest = hashlib.sha256(
                    line.encode("utf-8", errors="replace")
                ).hexdigest()
                findings.append(TokenForgeFinding(
                    finding_id=_finding_id(source, line_number, category, line),
                    category=category,
                    title=title,
                    source=source,
                    line_number=line_number,
                    severity=severity,
                    rationale=rationale,
                    evidence_hash=digest,
                ))
    return findings


def _forgeability(categories: set) -> str:
    has_secret = "hardcoded_secret" in categories
    has_sink = ("client_signature_sink" in categories
                or "token_mint_function" in categories)
    has_claims = "token_claim_input" in categories
    if has_secret and has_sink:
        return "high"
    if (has_secret and has_claims) or (has_sink and has_claims):
        return "medium"
    return "low"


def build_plans(findings: Iterable[TokenForgeFinding]) -> List[TokenForgePlan]:
    """Group findings per source file and grade forgeability.

    Only files that show a secret or a signing primitive produce a plan; a
    claim input alone is too common to flag on its own.
    """
    by_source: Dict[str, List[TokenForgeFinding]] = {}
    for finding in findings:
        by_source.setdefault(finding.source, []).append(finding)

    plans: List[TokenForgePlan] = []
    for source, items in sorted(by_source.items()):
        categories = {item.category for item in items}
        if "hardcoded_secret" not in categories and not (
                "client_signature_sink" in categories
                or "token_mint_function" in categories):
            continue
        forgeability = _forgeability(categories)
        plan_id = hashlib.sha256(
            f"token-forge:{source}".encode()
        ).hexdigest()[:16]
        plans.append(TokenForgePlan(
            plan_id=plan_id,
            title="Client-side token forging: signing secret embedded in client code",
            source=source,
            findings=[item.finding_id for item in items],
            forgeability=forgeability,
            rationale=(
                "A signing secret shipped in the client plus a client-side "
                "HMAC/sign primitive means any visitor can mint tokens for "
                "arbitrary user, device, or role claims — the server cannot "
                "tell a legitimate token from a forged one if it trusts the "
                "same embedded secret."
            ),
            validation_questions=[
                "Can a token be minted for a different userId/deviceId/role from a second authorized test account or a synthetic fixture?",
                "Is the signing secret recoverable from the client bundle (it is, by construction)?",
                "Does the server re-derive or verify the signature using the same embedded secret?",
                "Are role/admin/account claims part of the signed payload?",
            ],
            remediation=[
                "Move token signing server-side; the client should only receive opaque, short-lived tokens.",
                "Rotate the exposed secret and treat it as compromised.",
                "Remove user/device/role claims from client-minted tokens; resolve identity server-side from the session.",
                "Prefer asymmetric signing (Ed25519/RS256) with the private key held server-side only.",
            ],
        ))
    return plans


def analyze_paths(paths: Iterable[Path]) -> Tuple[List[TokenForgeFinding], List[TokenForgePlan]]:
    """Analyze files/directories; files are read as UTF-8 (errors replaced)."""
    findings: List[TokenForgeFinding] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    findings.extend(_analyze_file(child))
        elif path.is_file():
            findings.extend(_analyze_file(path))
    return findings, build_plans(findings)


def _analyze_file(path: Path) -> List[TokenForgeFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return analyze_text(text, str(path))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BugWolf offline client-side token-forging analyzer")
    parser.add_argument("--path", action="append", default=[],
                        help="File or directory to analyze (repeatable)")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings, plans = analyze_paths(Path(p) for p in args.path)

    for filename, rows in (("token-forge-findings.jsonl", findings),
                           ("token-forge-plans.jsonl", plans)):
        with (output / filename).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row.to_dict(), sort_keys=True) + "\n")

    manifest = {
        "schema": SCHEMA_VERSION,
        "findings": len(findings),
        "plans": len(plans),
        "execution": "offline_static_only",
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps({
            **manifest,
            "plans": [p.to_dict() for p in plans],
        }, indent=2, sort_keys=True))
    else:
        print(f"[*] Token-forge findings: {len(findings)}  plans: {len(plans)}")
        for plan in plans:
            print(f"    [{plan.forgeability}] {plan.source}")


if __name__ == "__main__":
    main()
