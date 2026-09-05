#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/payload/headers_url.go (Host header CNAME fuzz)
## Source: gobypass403 core/engine/payload/url.go (subdomain brute list helpers)
## Source: NoMoreForbidden nomoreforbidden/core/host_fuzz.py (CNAME list generators)
## License: MIT (gobypass403, NoMoreForbidden)
## Port: 2026-09-05

CNAME-based Host header fuzzing.

Many CDNs (Cloudflare, Akamai, Fastly) terminate a single IP on
multiple customer domains via SNI / Host header matching. If the target
application sits behind a CDN that doesn't validate the Host, an
attacker can rewrite the Host header to a sibling CNAME the CDN
happens to terminate -- slipping past ACL rules keyed on the original
Host.

The class generates CNAME candidates by appending common subdomains to
the apex. The DNS lookup itself happens in the caller's transport --
this module emits *strings*, never sockets.
"""

from __future__ import annotations

from typing import Dict, List


class CnameHostBypass:
    """CNAME-style Host header fuzz generator."""

    # Common subdomains observed on bug-bounty programs. The list is
    # ordered by hit-rate (descending); callers may slice.
    COMMON_SUBDOMAINS: List[str] = [
        "www",
        "api",
        "cdn",
        "cloud",
        "static",
        "assets",
        "media",
        "origin",
        "internal",
        "staging",
        "stage",
        "dev",
        "test",
        "beta",
        "old",
        "legacy",
        "v1",
        "v2",
        "lb",
        "edge",
        "admin",
        "auth",
        "sso",
        "oauth",
    ]

    # Region suffixes used by multi-region CDN PoPs.
    REGION_SUFFIXES: List[str] = [
        "us",
        "eu",
        "asia",
        "ap",
        "uk",
        "de",
        "fr",
        "jp",
    ]

    def __init__(self, *, apex: str = "example.com"):
        self._apex = apex

    def apex(self) -> str:
        return self._apex

    def set_apex(self, apex: str) -> None:
        if not apex or "." not in apex:
            raise ValueError(f"apex must be a dotted host, got {apex!r}")
        self._apex = apex

    def host_candidates(self) -> List[str]:
        """Return the full CNAME-fuzz host list (subdomain + region variants)."""
        candidates: List[str] = [self._apex]
        for sub in self.COMMON_SUBDOMAINS:
            candidates.append(f"{sub}.{self._apex}")
        for region in self.REGION_SUFFIXES:
            candidates.append(f"{self._apex}.{region}")
            for sub in ("api", "cdn", "edge"):
                candidates.append(f"{sub}.{self._apex}.{region}")
        return candidates

    def payload(self, path: str = "/") -> List[Dict[str, str]]:
        """Return the [{Host: ...}, ...] header list to fuzz.

        ``path`` is kept for compatibility with the other bypass modules
        but is not embedded -- the caller controls the request URL.
        """
        return [{"Host": host} for host in self.host_candidates()]

    def name(self) -> str:
        return "cname_host_bypass"

    def technique(self) -> str:
        return "CNAME-sibling Host header fuzz"