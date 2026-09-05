#!/usr/bin/env python3
"""
## Source: gobypass403 core/engine/payload/url.go (Unicode NFKC transforms)
## Source: gobypass403 core/engine/payload/url.go (zero-width + bidi truncation chars)
## Source: NoMoreForbidden nomoreforbidden/core/transforms.py (Unicode NFKC mapping table)
## License: MIT (gobypass403, NoMoreForbidden)
## Port: 2026-09-05

Two Unicode-based bypass maps.

1. ``UnicodeNormalization`` -- the canonical NFKC map that converts
   full-width / fraction / circled / squared codepoints into their
   ASCII forms. ``/`` (U+002F) becomes ``\xef\xbc\x8f`` (U+FF0F) on the
   wire; the *URL parser* sees a separator, but the *string matcher*
   sees a literal ``/`` after NFKC round-trip.

2. ``UnicodeTruncation`` -- bidi-control and zero-width characters
   inserted mid-path to confuse substring-match ACLs while preserving
   the URL's *intent* to most clients.

The two maps are intentionally separate: the normalization map is a
*bijective* transform on a closed set of codepoints, whereas the
truncation map is a *generative* injection of control bytes. Mixing
them produces ambiguous output.
"""

from __future__ import annotations

import unicodedata
from typing import Dict, List


# ---------------------------------------------------------------------------
# Unicode normalization map (NFKC + NFKD + NFKC_Casefold)
# ---------------------------------------------------------------------------


class UnicodeNormalization:
    """NFKC / NFKD / NFKC_Casefold bypass map.

    :meth:`map_char` returns a *list* of bypass candidates for a single
    ASCII character: the original plus every NFKC-equivalent form. The
    caller composes these into a path-level transform via
    :meth:`transform_string`.
    """

    # Codepoints that NFKC-normalize to a printable ASCII char (or to
    # another codepoint on this list). Source: Unicode UAX #15 + the
    # gobypass403 / NoMoreForbidden canonical tables.
    NFKC_TABLE: Dict[str, str] = {
        "/": "\uff0f",                # FULLWIDTH SOLIDUS
        "\\": "\uff3c",                # FULLWIDTH REVERSE SOLIDUS
        ".": "\uff0e",                # FULLWIDTH FULL STOP
        "-": "\u2010",                # HYPHEN
        " ": "\u2000",                # EN QUAD
        "a": "\u0061",                # ASCII 'a' -- NFKC identity
        "A": "\uff21",                # FULLWIDTH LATIN CAPITAL LETTER A
        "0": "\uff10",                # FULLWIDTH DIGIT ZERO
        "1": "\uff11",                # FULLWIDTH DIGIT ONE
    }

    FORMS: List[str] = ["NFKC", "NFKD", "NFC", "NFD"]

    @classmethod
    def map_char(cls, c: str) -> List[str]:
        """Return the bypass candidate list for one ASCII char.

        The first element is always the original char (for downstream
        short-circuiting). Subsequent elements are NFKC alternatives from
        :attr:`NFKC_TABLE` plus the three normalization forms applied to
        a single-char string.
        """
        candidates: List[str] = [c]
        if c in cls.NFKC_TABLE:
            candidates.append(cls.NFKC_TABLE[c])
        for form in cls.FORMS:
            normalized = unicodedata.normalize(form, c)
            if normalized not in candidates:
                candidates.append(normalized)
        return candidates

    @classmethod
    def transform_string(cls, s: str, *, form: str = "NFKC") -> str:
        """Apply one NFKC form to the whole string."""
        try:
            return unicodedata.normalize(form, s)
        except (TypeError, ValueError):    # pragma: no cover - defensive
            return s

    @classmethod
    def casefold(cls, s: str) -> str:
        """NFKC_Casefold emulation (NFKC + str.casefold)."""
        try:
            return unicodedata.normalize("NFKC", s).casefold()
        except (TypeError, ValueError, AttributeError):    # pragma: no cover
            return s

    @classmethod
    def transform_all(cls, s: str) -> List[str]:
        """Apply every supported NFKC form -- returns a list of bypass
        candidate strings (original + every normalized form).
        """
        out: List[str] = [s]
        for form in cls.FORMS:
            n = cls.transform_string(s, form=form)
            if n not in out:
                out.append(n)
        return out


# ---------------------------------------------------------------------------
# Unicode truncation map (bidi + zero-width)
# ---------------------------------------------------------------------------


# Codepoints the gobypass403 truncation map emits. Each one is a
# *zero-width* or *directional-control* character that many path
# matchers strip -- but the URL parser preserves in the request line.
_TRUNCATION_TABLE: Dict[str, List[str]] = {
    "/": [
        "\u200d",                    # ZERO WIDTH JOINER
        "\u200c",                    # ZERO WIDTH NON-JOINER
        "\u200b",                    # ZERO WIDTH SPACE
        "\u202e",                    # RIGHT-TO-LEFT OVERRIDE
        "\u202d",                    # LEFT-TO-RIGHT OVERRIDE
        "\u2066",                    # LEFT-TO-RIGHT ISOLATE
        "\ufeff",                    # BYTE ORDER MARK
    ],
    ".": [
        "\u200d",
        "\u202e",
    ],
    "-": [
        "\u200d",
        "\ufeff",
    ],
}


class UnicodeTruncation:
    """Zero-width + bidi-control truncation map.

    :meth:`map_char` returns a list of *injection candidates* for one
    ASCII char. The caller composes them into a path-level transform via
    :meth:`transform_string`.
    """

    TABLE: Dict[str, List[str]] = _TRUNCATION_TABLE

    @classmethod
    def map_char(cls, c: str) -> List[str]:
        """Return the zero-width / bidi injections for one char.

        Unlike :meth:`UnicodeNormalization.map_char`, the *original*
        char is NOT included -- these are pure injections, not
        alternatives.
        """
        return list(cls.TABLE.get(c, []))

    @classmethod
    def transform_string(cls, s: str, *, position: str = "after") -> str:
        """Insert one truncation char after every separator byte.

        ``position`` accepts ``"after"`` (default), ``"before"``, or
        ``"both"``. The caller chooses the most useful insertion pattern.
        """
        if position not in ("after", "before", "both"):
            raise ValueError(
                f"position must be after|before|both, got {position!r}")
        out: List[str] = []
        for ch in s:
            injections = cls.map_char(ch)
            if not injections:
                out.append(ch)
                continue
            inj = injections[0]
            if position == "after":
                out.append(ch + inj)
            elif position == "before":
                out.append(inj + ch)
            else:    # both
                out.append(inj + ch + inj)
        return "".join(out)

    @classmethod
    def transforms(cls, s: str) -> List[str]:
        """Return every variant (after / before / both) plus the raw
        input -- handy for callers that want a flat candidate list.
        """
        return [
            s,
            cls.transform_string(s, position="after"),
            cls.transform_string(s, position="before"),
            cls.transform_string(s, position="both"),
        ]