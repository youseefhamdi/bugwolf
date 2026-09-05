#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter waf_encoder.py:1-300 (1.5.b)
## Source: HackGATE encoders/builtin.py:14-220
## License: MIT (sister projects)
## Port: 2026-09-05

11 pure-stdlib WAF bypass encoders.

Each technique produces a different output that may bypass common WAF
signatures.  All transforms are pure functions over text and do not
perform any network IO.

Techniques (11):
  url, double_url, unicode_escape, html_entity, comment_injection,
  case_mix, whitespace_pad, null_byte, path_traversal, base64, hex_escape

The :class:`WAFEncoder` API is::

    enc = WAFEncoder()
    out = enc.encode("<script>alert(1)</script>", technique="double_url")

A caller can list all available techniques via :attr:`WAFEncoder.TECHNIQUES`.
"""
from __future__ import annotations

import base64
import binascii
import html
import urllib.parse
from typing import Dict, List


SCHEMA = "bugwolf-waf-encoder/v1"


_TECHNIQUE_NAMES = (
    "url", "double_url", "unicode_escape", "html_entity", "comment_injection",
    "case_mix", "whitespace_pad", "null_byte", "path_traversal",
    "base64", "hex_escape",
)


def _url(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def _double_url(payload: str) -> str:
    once = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(once, safe="")


def _unicode_escape(payload: str) -> str:
    out_chars: List[str] = []
    for ch in payload:
        if ch.isascii():
            out_chars.append(ch)
        else:
            out_chars.append(f"\\u{ord(ch):04x}")
    return "".join(out_chars)


def _html_entity(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)


def _comment_injection(payload: str) -> str:
    """Inject ``/**/`` between characters of every token-like word.

    Many WAFs tokenise on whitespace; by splitting words we defeat naive
    string matching without changing the runtime semantics for browsers.
    """
    parts = payload.split(" ")
    return " ".join("/**/".join(p) for p in parts)


def _case_mix(payload: str) -> str:
    out: List[str] = []
    flip = False
    for ch in payload:
        if ch.isalpha():
            out.append(ch.upper() if flip else ch.lower())
            flip = not flip
        else:
            out.append(ch)
    return "".join(out)


def _whitespace_pad(payload: str) -> str:
    # Replace every space with a tab+space+newline combo (still a single
    # whitespace-equivalent token for most parsers).
    return payload.replace(" ", "\t \n")


def _null_byte(payload: str) -> str:
    return payload.replace("<", "\x00<").replace(">", ">\x00")


def _path_traversal(payload: str) -> str:
    # Sprinkle "../" segments; harmless when the payload is treated as a
    # string but commonly confuses path-based signature engines.
    return "../" + payload.replace("/", "/./")


def _base64(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def _hex_escape(payload: str) -> str:
    return "\\x" + "\\x".join(f"{ord(c):02x}" for c in payload)


_TECHNIQUES: Dict[str, callable] = {
    "url": _url,
    "double_url": _double_url,
    "unicode_escape": _unicode_escape,
    "html_entity": _html_entity,
    "comment_injection": _comment_injection,
    "case_mix": _case_mix,
    "whitespace_pad": _whitespace_pad,
    "null_byte": _null_byte,
    "path_traversal": _path_traversal,
    "base64": _base64,
    "hex_escape": _hex_escape,
}


class WAFEncoder:
    """Apply one of 11 WAF bypass encodings to a payload string.

    All transforms are deterministic and side-effect free; multiple
    encodes of the same input always yield the same output.
    """

    SCHEMA = SCHEMA
    TECHNIQUES: List[str] = list(_TECHNIQUE_NAMES)

    def encode(self, payload: str, technique: str) -> str:
        """Encode ``payload`` with ``technique``.

        Raises :class:`ValueError` for unknown techniques.  Empty payloads
        return ``""``.
        """
        if payload == "":
            return ""
        fn = _TECHNIQUES.get(technique)
        if fn is None:
            raise ValueError(
                f"unknown WAF technique {technique!r}; "
                f"valid={self.TECHNIQUES}")
        return fn(payload)

    def encode_all(self, payload: str) -> Dict[str, str]:
        """Apply every technique to ``payload``.  Useful for fuzz grids."""
        return {t: self.encode(payload, t) for t in self.TECHNIQUES}


__all__ = ["SCHEMA", "WAFEncoder"]