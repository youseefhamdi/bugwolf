#!/usr/bin/env python3
"""Composable value-encoding pipelines (Phase 1.3).

Mirrors the documented CODEC vocabulary (master plan): a mutation value can
pass through a pipeline of codecs before it is set into the message —
``["url", "url"]`` double-encodes, ``["base64url"]`` embeds, and so on.
WAF filter bypasses live exactly in this space; string concatenation cannot
express it.

Deterministic tier: pure functions, no I/O.
"""

from __future__ import annotations

from typing import List

SCHEMA = "bugwolf-replay-encode/v1"

CODECS = ("url", "url-all", "url-double", "base64", "base64url", "hex",
          "html-dec", "html-hex", "unicode", "upper", "lower")


def _url(value: str, *, safe: str = "") -> str:
    from urllib.parse import quote
    return quote(value, safe=safe)


def _url_all(value: str) -> str:
    return _url(value, safe="")


def apply_pipeline(value: str, codecs: List[str]) -> str:
    """Apply codecs left-to-right to ``value``; unknown codec raises."""
    current = value
    for codec in codecs:
        codec = codec.strip().lower()
        if codec == "url":
            current = _url(current, safe="/?&=:@")
        elif codec == "url-all":
            current = _url_all(current)
        elif codec == "url-double":
            current = _url(_url(current, safe=""), safe="")
        elif codec == "base64":
            import base64
            current = base64.b64encode(current.encode("utf-8")).decode("ascii")
        elif codec == "base64url":
            import base64
            current = base64.urlsafe_b64encode(
                current.encode("utf-8")).rstrip(b"=").decode("ascii")
        elif codec == "hex":
            current = current.encode("utf-8").hex()
        elif codec == "html-dec":
            current = "".join(f"&#{ord(ch)};" for ch in current)
        elif codec == "html-hex":
            current = "".join(f"&#x{ord(ch):x};" for ch in current)
        elif codec == "unicode":
            current = "".join(f"\\u{ord(ch):04x}" for ch in current)
        elif codec == "upper":
            current = current.upper()
        elif codec == "lower":
            current = current.lower()
        else:
            raise ValueError(f"unknown codec {codec!r} (known: {CODECS})")
    return current
