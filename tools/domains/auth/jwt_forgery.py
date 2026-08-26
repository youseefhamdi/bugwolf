#!/usr/bin/env python3
"""BugWolf JWT Forgery Analyzer (P0, Week 1).

Static/offline JWT analysis: decode a token, inventory the ``alg`` header and
claims, and generate *plans* for the classic forgery classes — ``alg=none``,
RS256→HS256 algorithm confusion, ``jwk`` header injection, ``kid`` path
traversal, and key-confusion via public key as HMAC secret.

Design (deterministic core, uncensored, workflow-aware):

  * Fully offline and deterministic: decode is local, and the plans describe
    what *would* be tested.  No signature forgery is executed and no network
    call is made — validation of a forged token is the operator's live step
    (through the pass-through execution layer).
  * Output: ``research/<target>/auth/jwt-forgery-plans.json`` — recognized as
    a supplementary artifact of the ``research`` stage and an input to
    ``triage`` / ``chain_orchestrator``.
  * Emits an ``AUTH_CANDIDATE`` event on the signal bus so triage/chaining
    can react.

Usage:
  python3 tools/domains/auth/jwt_forgery.py --target acme --token <jwt>
  python3 tools/domains/auth/jwt_forgery.py --target acme --tokens-file recon/acme/jwts.txt
  python3 tools/domains/auth/jwt_forgery.py --target acme --token <jwt> --json
"""

import base64
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current

_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus, AUTH_CANDIDATE
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, AUTH_CANDIDATE

SCHEMA = "bugwolf/jwt-forgery/v1"

# Algorithm confusion / abuse classes this analyzer plans for.
FORGERY_PLANS: Dict[str, Dict[str, Any]] = {
    "alg_none": {
        "name": "alg=none (unsigned token)",
        "description": "Server accepts a token with no signature when the alg "
                       "header is 'none'.",
        "condition": "server does not reject unsupported alg values",
        "steps": [
            "Re-encode header {'alg': 'none'} + unchanged payload",
            "Set signature segment to empty string",
            "Submit with standard Authorization: Bearer header",
        ],
        "success_signal": "endpoint accepts the token as valid",
    },
    "rs256_hs256_confusion": {
        "name": "RS256 -> HS256 algorithm confusion",
        "description": "Server verifies HS256 with the RSA public key as the "
                       "HMAC secret; attacker forges with the public key.",
        "condition": "server accepts HS256 tokens and the RSA public key is "
                     "obtainable (JWKS endpoint, certificate, source)",
        "steps": [
            "Fetch the RSA public key (JWKS / cert / bundled config)",
            "Re-encode header {'alg': 'HS256'} + payload",
            "Sign with the public key bytes as the HMAC secret",
        ],
        "success_signal": "server verifies the HS256-signed token",
    },
    "jwk_injection": {
        "name": "JWK header injection (embedded key)",
        "description": "Server trusts a public key embedded in the token's "
                       "jwk header instead of its own key store.",
        "condition": "server honors the jwk header and does not pin keys",
        "steps": [
            "Generate an attacker RSA key pair",
            "Embed the public key in header {'jwk': {..., 'alg': 'RS256'}}",
            "Sign the token with the matching private key",
        ],
        "success_signal": "server accepts a token signed by the attacker key",
    },
    "kid_path_traversal": {
        "name": "kid header path traversal / file read",
        "description": "Server uses the kid header to pick a verification key "
                       "file; ../ paths read arbitrary files as the key.",
        "condition": "server derives the key file path from kid unsafely",
        "steps": [
            "Set kid to a traversed path (e.g. ../../../../etc/passwd)",
            "Sign with a known value derived from the read file (or empty)",
            "Observe whether the server accepts / errors differently",
        ],
        "success_signal": "server accepts a token whose kid points outside the "
                          "key store",
    },
    "public_key_as_hmac": {
        "name": "Public key as HMAC secret (key confusion, explicit)",
        "description": "Server verifies HS256 tokens using the literal public "
                       "key value as the shared secret.",
        "condition": "server accepts HS256 and the public key is available",
        "steps": [
            "Obtain the public key PEM",
            "Use the PEM bytes as the HMAC secret with alg=HS256",
            "Sign and submit",
        ],
        "success_signal": "server accepts the forged HS256 token",
    },
}


@dataclass
class JwtFinding:
    token_hash: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    alg: str
    plans: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JwtAnalysis:
    target: str
    generated_at: str
    findings: List[JwtFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _b64_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT into header/payload (None for malformed tokens)."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64_decode(parts[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload}


def analyze(token: str) -> Optional[JwtFinding]:
    """Produce a deterministic JwtFinding (plans + header/payload) or None."""
    decoded = _decode_token(token)
    if decoded is None:
        return None
    import hashlib
    header, payload = decoded["header"], decoded["payload"]
    alg = str(header.get("alg", ""))

    plans: List[Dict[str, Any]] = []
    # alg=none: always worth planning (cheap, deterministic).
    plans.append({"class": "alg_none", **FORGERY_PLANS["alg_none"]})
    if alg and alg.upper().startswith("RS"):
        plans.append({"class": "rs256_hs256_confusion",
                      **FORGERY_PLANS["rs256_hs256_confusion"]})
        plans.append({"class": "public_key_as_hmac",
                      **FORGERY_PLANS["public_key_as_hmac"]})
    if "jwk" in header or alg.upper().startswith("RS"):
        plans.append({"class": "jwk_injection",
                      **FORGERY_PLANS["jwk_injection"]})
    if header.get("kid"):
        plans.append({"class": "kid_path_traversal",
                      **FORGERY_PLANS["kid_path_traversal"]})
    # Deduplicate by class name.
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for plan in plans:
        if plan["class"] not in seen:
            seen.add(plan["class"])
            unique.append(plan)

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return JwtFinding(token_hash=token_hash, header=header, payload=payload,
                      alg=alg, plans=unique)


def analyze_many(tokens: List[str]) -> List[JwtFinding]:
    findings: List[JwtFinding] = []
    seen_tokens: set = set()
    for token in tokens:
        finding = analyze(token)
        if finding is None:
            continue
        if finding.token_hash in seen_tokens:
            continue
        seen_tokens.add(finding.token_hash)
        findings.append(finding)
    return findings


def write_analysis(analysis: JwtAnalysis, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/auth/jwt-forgery-plans.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", analysis.target) or "default"
    out_dir = root / "research" / target_slug / "auth"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "jwt-forgery-plans.json"
    out_path.write_text(json.dumps(analysis.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf JWT Forgery Analyzer (P0)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--token", default="", help="Single JWT to analyze")
    parser.add_argument("--tokens-file", default="",
                        help="File of JWTs (one per line)")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    tokens: List[str] = []
    if args.token:
        tokens.append(args.token)
    if args.tokens_file:
        path = Path(args.tokens_file)
        if not path.is_file():
            path = workspace_root(args.project_root) / "recon" / \
                re.sub(r"[^\w.-]+", "_", args.target) / "jwts.txt"
        if path.is_file():
            tokens.extend(line.strip() for line in path.read_text().splitlines()
                          if line.strip())
    if not tokens:
        print(json.dumps({"ok": False,
                          "error": "no JWTs; pass --token or --tokens-file"},
                         indent=2))
        return 2

    findings = analyze_many(tokens)
    analysis = JwtAnalysis(
        target=args.target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings)
    out_path = write_analysis(analysis, project_root=args.project_root)

    if findings:
        try:
            bus = SignalBus(args.target, project_root=args.project_root)
            for finding in findings:
                bus.publish(AUTH_CANDIDATE, source="jwt_forgery",
                            payload={"token_hash": finding.token_hash,
                                     "alg": finding.alg,
                                     "plan_classes": [p["class"]
                                                      for p in finding.plans]})
        except Exception:
            pass  # event bus is advisory

    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "tokens_analyzed": len(tokens),
        "findings": len(findings),
        "plan_classes": sorted({p["class"] for f in findings for p in f.plans}),
        "output_file": str(out_path),
        "analysis": analysis.to_dict(),
        "next_command": ("plans are offline forgeries to validate; run the "
                         "validation steps through the pass-through execution "
                         "layer when the operator authorizes live testing"),
    }
    print(json.dumps(output, indent=2) if args.json else
          (f"[+] {args.target}: {len(findings)} JWT findings, "
           f"{len(output['plan_classes'])} forgery classes -> {out_path}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
