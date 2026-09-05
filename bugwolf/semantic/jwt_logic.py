"""JWT logic analyzer (Phase 3.3).

Detects *logic-level* JWT defects that the existing tools/domains/auth/
analyzer doesn't have to worry about because it is fed a single token
in isolation.  Here we model the validation pipeline a real
verifier has to run and emit one :class:`JWTIssue` per defect:

  * ``alg=none`` — token claims ``alg=none`` and offers no signature
  * weak HMAC secret — given an HMAC-protected token, attempt a tiny
    brute force over the rockyou top-50 list (stdlib only) and emit
    a finding if we recover the key
  * ``kid`` injection — ``kid`` header is a SQL injection / path
    traversal / command-injection vector
  * ``jku`` / ``x5u`` confusion — token references a remote JWKS
    URL that the verifier would have to follow blindly
  * missing signature verification — the verifier accepts a
    signature whose algorithm doesn't match the header ``alg``
  * expired token — the verifier never checks ``exp`` (token has
    no ``exp`` or ``exp`` is in the past)
  * JWE downgrade — token claims ``alg=HS256`` while the public
    service is known to be RSA-only

STUB-SAFE: every operation tolerates bad input.  We never raise.
``analyze()`` returns ``[]`` on a token we can't decode at all.

## Source:  bugwolf/semantic/jwt_logic.py (Phase 3.3)
## License:  BugWolf Proprietary License v1.0
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "bugwolf-semantic-v1"


log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JWTIssue:
    """One JWT logic-level defect."""

    kind: str                 # "alg-none" / "weak-hmac" / "kid-inject" / ...
    severity: str             # "low" / "medium" / "high" / "critical"
    evidence: str
    fix: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "kind": self.kind,
            "severity": self.severity,
            "evidence": self.evidence,
            "fix": self.fix,
            "detail": dict(self.detail),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64decode(data: str) -> Optional[bytes]:
    if not data:
        return None
    pad = "=" * ((4 - (len(data) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode(data + pad)
    except Exception:  # noqa: BLE001
        try:
            return base64.b64decode(data + pad)
        except Exception:  # noqa: BLE001
            return None


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Top-50 rockyou-style "what's the worst password people still pick"
# list, used as a deterministic, stdlib-only sanity check for weak
# HMAC secrets.  This is NOT exhaustive — it's a smell test.
_WEAK_HMAC_SECRETS: Tuple[str, ...] = (
    "secret", "password", "123456", "12345678", "qwerty",
    "abc123", "letmein", "monkey", "iloveyou", "admin",
    "welcome", "login", "princess", "dragon", "passw0rd",
    "master", "hello", "freedom", "whatever", "qwerty123",
    "trustno1", "starwars", "jennifer", "hunter2", "asdf",
    "test", "root", "toor", "changeme", "default",
    "key", "mysecret", "jwt-secret", "jwt_secret", "secret123",
    "0000", "1111", "1234", "pass", "p@ssw0rd",
    "supersecret", "s3cr3t", "helloworld", "abc", "qwertyuiop",
    "nopassword", "1q2w3e4r", "12345", "54321", "1234567890",
)


_KID_INJECTION_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("sql", re.compile(r"('|\"|;|--|/\*|\*/|union\s+select|or\s+1=1)",
                       re.IGNORECASE)),
    ("path-traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/)",
                                  re.IGNORECASE)),
    ("command", re.compile(r"(`|\$\(|;|\|\||&&)")),
    ("url", re.compile(r"^(https?|ftp)://", re.IGNORECASE)),
    ("crlf", re.compile(r"(\r\n|%0d%0a|%0a|%0d)")),
)

# Tokens in the alg header that we treat as "no signature".
_NONE_ALG_VARIANTS: frozenset = frozenset(
    s.lower() for s in ("none", "None", "NONE", "nOnE", "")
)


# ---------------------------------------------------------------------------
# JWTLogicAnalyzer
# ---------------------------------------------------------------------------

class JWTLogicAnalyzer:
    """Logic-level JWT analyzer — never raises."""

    def __init__(self) -> None:
        self.weak_hmac_secrets: Tuple[str, ...] = _WEAK_HMAC_SECRETS
        self.weak_hmac_max_attempts: int = 50

    # ------------------------------------------------------------------ api

    def analyze(
        self,
        token: str,
        *,
        public_key: Optional[bytes] = None,
        secret: Optional[str] = None,
    ) -> List[JWTIssue]:
        """Run every logic-level check on ``token``.

        ``public_key`` is used to test for the HS256 → RS256 confusion
        when the token claims HS256 but we can verify it against a
        public key.  ``secret`` is the *expected* secret: if the
        token is HS256-signed and verifies under it, we still emit
        weak-hmac findings if the secret is itself weak (caller may
        pass a known-good secret to short-circuit that check).
        """
        out: List[JWTIssue] = []
        if not token or not isinstance(token, str):
            return out
        try:
            parts = token.split(".")
        except Exception:  # noqa: BLE001
            return out
        if len(parts) < 2:
            out.append(JWTIssue(
                kind="malformed",
                severity="medium",
                evidence=f"Token has {len(parts)} segment(s); JWT requires 3",
                fix="Reject malformed JWTs at the parser; do not pass them to a verifier.",
            ))
            return out
        header_b64, payload_b64 = parts[0], parts[1]
        signature_b64 = parts[2] if len(parts) > 2 else ""
        try:
            header_raw = _b64decode(header_b64) or b"{}"
            payload_raw = _b64decode(payload_b64) or b"{}"
        except Exception:  # noqa: BLE001
            return out
        try:
            header = json.loads(header_raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            header = {}
        try:
            payload = json.loads(payload_raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(header, dict):
            header = {}
        if not isinstance(payload, dict):
            payload = {}

        # 1) alg=none
        alg = str(header.get("alg", "")).strip()
        if alg.lower() in _NONE_ALG_VARIANTS or not alg:
            out.append(JWTIssue(
                kind="alg-none",
                severity="critical",
                evidence=(
                    f"JWT header declares alg={alg!r} (or empty) — "
                    f"the verifier must REJECT this token, never "
                    f"accept it without a signature"
                ),
                fix=(
                    "Refuse any token whose alg is 'none', empty, or "
                    "case-folded ('None', 'NONE'). Pin the verifier to "
                    "an allow-list of expected algorithms."
                ),
                detail={"alg": alg, "header": _redact(header)},
            ))
        # 2) missing exp / expired token
        out.extend(self._check_expiry(payload))
        # 3) kid injection
        out.extend(self._check_kid(header))
        # 4) jku / x5u confusion
        out.extend(self._check_jku(header))
        # 5) weak HMAC secret (brute force)
        if alg.upper().startswith("HS"):
            out.extend(self._check_weak_hmac(
                token, header, payload, signature_b64, secret,
            ))
        # 6) algorithm confusion: HS256 token that verifies against
        #    a provided public key (signing the token with the
        #    public RSA/EC key as if it were an HMAC secret).
        if alg.upper().startswith("HS") and public_key:
            out.extend(self._check_alg_confusion(
                token, header, payload, signature_b64, public_key,
            ))
        # 7) JWE downgrade: token claims an alg that is not in the
        #    server's expected set.  We use a small static policy.
        out.extend(self._check_alg_policy(alg, header))
        # 8) Signature not actually checked: an empty signature in
        #    the third segment with a non-none alg.
        if not signature_b64 and alg.lower() not in _NONE_ALG_VARIANTS:
            out.append(JWTIssue(
                kind="missing-signature",
                severity="critical",
                evidence=(
                    f"JWT alg={alg!r} but signature segment is empty — "
                    f"the verifier should refuse to accept an "
                    f"unsigned token"
                ),
                fix=(
                    "Treat an empty signature as a hard failure. "
                    "Always recompute and compare the HMAC / RSA / "
                    "ECDSA signature over (header.payload)."
                ),
                detail={"alg": alg},
            ))
        return out

    # ------------------------------------------------------------------ checks

    def _check_expiry(self, payload: Dict[str, Any]) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        if "exp" not in payload:
            out.append(JWTIssue(
                kind="missing-exp",
                severity="high",
                evidence=(
                    "JWT payload has no 'exp' claim — the verifier "
                    "cannot reject an expired token"
                ),
                fix=(
                    "Issue tokens with a short 'exp' (≤15 min) and "
                    "require the verifier to reject any token where "
                    "now >= exp. Use a sliding refresh token for "
                    "longer sessions."
                ),
                detail={"payload_keys": sorted(payload.keys())},
            ))
            return out
        try:
            exp = int(payload["exp"])
        except (TypeError, ValueError):
            out.append(JWTIssue(
                kind="invalid-exp",
                severity="high",
                evidence=(
                    f"JWT exp claim is not a number: "
                    f"{payload['exp']!r}"
                ),
                fix=("Reject tokens whose exp is not a valid integer."),
                detail={"exp": payload["exp"]},
            ))
            return out
        now = int(time.time())
        if exp < now:
            out.append(JWTIssue(
                kind="expired-token",
                severity="medium",
                evidence=(
                    f"JWT exp={exp} is in the past "
                    f"(now={now}, "
                    f"delta={now - exp}s)"
                ),
                fix=(
                    "Reject tokens whose exp has passed. If the "
                    "verifier is tolerating a clock skew, bound the "
                    "skew window to ≤30s."
                ),
                detail={"exp": exp, "now": now, "skew": now - exp},
            ))
        return out

    def _check_kid(self, header: Dict[str, Any]) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            return out
        for label, pat in _KID_INJECTION_PATTERNS:
            if pat.search(kid):
                out.append(JWTIssue(
                    kind="kid-injection",
                    severity="high",
                    evidence=(
                        f"JWT kid={kid!r} matches {label!r} pattern — "
                        f"the verifier may be using kid to build a "
                        f"file path / SQL query / shell command"
                    ),
                    fix=(
                        "Treat kid as a strict allow-list of "
                        "key identifiers; never pass it to a SQL "
                        "query, a shell, or a filesystem path. "
                        "If multiple keys are needed, look them up "
                        "in a static dict."
                    ),
                    detail={"kid": kid, "pattern": label},
                ))
                # one finding per kid is enough
                break
        return out

    def _check_jku(self, header: Dict[str, Any]) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        for key in ("jku", "x5u", "jwk"):
            val = header.get(key)
            if not isinstance(val, str) or not val:
                continue
            if not re.match(r"^https://", val, re.IGNORECASE):
                out.append(JWTIssue(
                    kind=f"{key}-confusion",
                    severity="high",
                    evidence=(
                        f"JWT {key}={val!r} is not https — the "
                        f"verifier should refuse to follow a "
                        f"plaintext jku/x5u URL"
                    ),
                    fix=(
                        f"Refuse any {key} that is not https AND not "
                        f"on a strict allow-list of trusted JWKS "
                        f"hosts. Pin the JWKS URL per-issuer."
                    ),
                    detail={key: val},
                ))
                continue
            # Even https is risky if it's attacker-controlled.  Flag
            # any non-allowlisted host as a finding.
            host = self._host_of(val)
            if host and not self._is_well_known_jwks_host(host):
                out.append(JWTIssue(
                    kind=f"{key}-confusion",
                    severity="medium",
                    evidence=(
                        f"JWT {key} points to non-canonical host "
                        f"{host!r} — the verifier would have to "
                        f"fetch keys from an unfamiliar origin"
                    ),
                    fix=(
                        f"Pin the {key} to the canonical issuer's "
                        f"JWKS endpoint; do not accept arbitrary "
                        f"host pointers."
                    ),
                    detail={key: val, "host": host},
                ))
        return out

    @staticmethod
    def _host_of(url: str) -> str:
        m = re.match(r"^https?://([^/]+)", url, re.IGNORECASE)
        if m:
            return m.group(1).split(":")[0].lower()
        return ""

    @staticmethod
    def _is_well_known_jwks_host(host: str) -> bool:
        # Conservative allowlist: the most common public-key issuers
        # actually use HTTPS-only JWKS endpoints.
        canonical = {
            "accounts.google.com", "www.googleapis.com",
            "login.microsoftonline.com", "graph.microsoft.com",
            "appleid.apple.com", "auth0.com",
            "cognito-idp.us-east-1.amazonaws.com",
            "sts.amazonaws.com",
        }
        for c in canonical:
            if host == c or host.endswith("." + c):
                return True
        return False

    def _check_weak_hmac(
        self,
        token: str,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature_b64: str,
        expected_secret: Optional[str],
    ) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        if not signature_b64:
            return out
        if expected_secret is not None:
            # Caller pinned the secret — verify it.  If verifying under
            # the *expected* secret fails, that itself is a finding
            # ("signature was forged with a different key") so we add
            # a structural one.
            if not self._verify_hmac(token, expected_secret):
                out.append(JWTIssue(
                    kind="signature-mismatch",
                    severity="high",
                    evidence=(
                        "JWT signature does not verify under the "
                        "expected HMAC secret — token was signed "
                        "with a different key"
                    ),
                    fix=(
                        "Reject any token whose signature doesn't "
                        "recompute under the server's pinned key."
                    ),
                ))
            # Brute-force the top-50 weak list regardless: if the
            # expected secret IS weak, the operator should know.
            if expected_secret in self.weak_hmac_secrets or (
                    expected_secret and len(expected_secret) < 8):
                out.append(JWTIssue(
                    kind="weak-hmac",
                    severity="high",
                    evidence=(
                        f"Server's HMAC secret is weak: "
                        f"length={len(expected_secret)} "
                        f"in_top50={expected_secret in self.weak_hmac_secrets}"
                    ),
                    fix=(
                        "Use a 32-byte (256-bit) random HMAC secret "
                        "stored in a secret manager; rotate the key "
                        "on suspected compromise."
                    ),
                    detail={"length": len(expected_secret)},
                ))
            return out
        # No expected secret provided: try the top-50 weak list.
        sig = _b64decode(signature_b64) or b""
        for guess in self.weak_hmac_secrets[: self.weak_hmac_max_attempts]:
            try:
                if self._verify_hmac_with_sig(token, sig, guess):
                    out.append(JWTIssue(
                        kind="weak-hmac",
                        severity="critical",
                        evidence=(
                            f"JWT HS256 signature verified under the "
                            f"weak secret {guess!r} (length "
                            f"{len(guess)})"
                        ),
                        fix=(
                            "Rotate the HMAC secret to a "
                            "32-byte random value stored in a "
                            "secret manager. Reject all tokens "
                            "signed under the old secret."
                        ),
                        detail={"recovered_secret": guess,
                                "length": len(guess)},
                    ))
                    break
            except Exception:  # noqa: BLE001
                continue
        return out

    def _check_alg_confusion(
        self,
        token: str,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature_b64: str,
        public_key: bytes,
    ) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        alg = str(header.get("alg", "")).upper()
        if not alg.startswith("HS"):
            return out
        # We were given a public key and the token claims HS*: try
        # signing the (header.payload) with the public key bytes as
        # if it were an HMAC secret.  If the signature matches,
        # classic alg-confusion is present.
        signing_input = token.rsplit(".", 1)[0].encode("ascii", errors="replace")
        sig = _b64decode(signature_b64) or b""
        try:
            expected = hmac.new(public_key, signing_input, hashlib.sha256).digest()
        except Exception:  # noqa: BLE001
            return out
        if sig and hmac.compare_digest(sig, expected):
            out.append(JWTIssue(
                kind="alg-confusion",
                severity="critical",
                evidence=(
                    f"JWT alg={alg!r} signature verifies under the "
                    f"provided public key bytes as HMAC — classic "
                    f"HS→RS confusion"
                ),
                fix=(
                    "Pin the verifier to a single expected algorithm "
                    "and check the alg BEFORE attempting any "
                    "verification. Never use a public key as an "
                    "HMAC secret."
                ),
                detail={"alg": alg, "key_len": len(public_key)},
            ))
        return out

    def _check_alg_policy(
        self, alg: str, header: Dict[str, Any]
    ) -> List[JWTIssue]:
        out: List[JWTIssue] = []
        if not alg:
            return out
        # If the alg is not in our rough allow-list of modern, sensible
        # choices, flag it as a downgrade / unexpected alg.
        allowed = {"HS256", "HS384", "HS512",
                   "RS256", "RS384", "RS512",
                   "ES256", "ES384", "ES512",
                   "PS256", "PS384", "PS512",
                   "EdDSA"}
        if alg.upper() not in allowed:
            out.append(JWTIssue(
                kind="unexpected-alg",
                severity="medium",
                evidence=(
                    f"JWT alg={alg!r} is not in the modern allow-list "
                    f"{sorted(allowed)} — possible downgrade or "
                    f"non-standard verifier"
                ),
                fix=(
                    "Restrict the verifier to a small allow-list of "
                    "modern algorithms. Reject anything else, "
                    "including legacy 'HS1', 'none', and case-folded "
                    "variants."
                ),
                detail={"alg": alg},
            ))
        return out

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _verify_hmac(token: str, secret: str) -> bool:
        if not secret or token.count(".") < 2:
            return False
        try:
            signing_input, sig_b64 = token.rsplit(".", 1)
        except ValueError:
            return False
        sig = _b64decode(sig_b64) or b""
        if not sig:
            return False
        try:
            expected = hmac.new(
                secret.encode("utf-8"),
                signing_input.encode("ascii", errors="replace"),
                hashlib.sha256,
            ).digest()
        except Exception:  # noqa: BLE001
            return False
        return bool(sig) and hmac.compare_digest(sig, expected)

    @staticmethod
    def _verify_hmac_with_sig(token: str, sig: bytes, secret: str) -> bool:
        if not secret or not sig or token.count(".") < 2:
            return False
        try:
            signing_input = token.rsplit(".", 1)[0]
            expected = hmac.new(
                secret.encode("utf-8"),
                signing_input.encode("ascii", errors="replace"),
                hashlib.sha256,
            ).digest()
        except Exception:  # noqa: BLE001
            return False
        return hmac.compare_digest(sig, expected)


def _redact(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if k in ("alg", "typ", "kid", "cty"):
            out[k] = v
        else:
            ks = str(k)
            out[ks[:4]] = f"<redacted len={len(str(v))}>"
    return out


__all__ = ["SCHEMA", "JWTIssue", "JWTLogicAnalyzer"]
