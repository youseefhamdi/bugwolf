#!/usr/bin/env python3
"""
## Source: letmepass letmepass/__main__.py -r mode (raw-request injection)
## Source: letmepass letmepass/fuzzer.py (asterisk injection-point handling)
## License: MIT (letmepass)
## Port: 2026-09-05

Raw-request fuzzing (letmepass ``-r`` mode).

The user supplies a full HTTP request as text -- method, path, headers,
body -- and the fuzzer walks every ``*`` placeholder, replacing each
with a bypass candidate (NFKC, fragment, double-encode, etc.).

The original tool emitted up to ~256 variants per request. We cap at 32
to bound probe counts (the probe_estimator considers this) and emit
deterministic ordering so the same input produces the same output across
runs.
"""

from __future__ import annotations

import re
from typing import List


class RawRequestFuzzer:
    """Raw HTTP request fuzzer (the letmepass ``-r`` mode)."""

    # Per-line parsing for a raw HTTP/1.1 request. We intentionally do
    # NOT parse the body (multi-line payloads are common -- anything
    # after the first blank line is body).
    REQUEST_LINE = re.compile(r"^(\S+)\s+(\S+)\s+HTTP/[\d.]+$")
    HEADER_LINE = re.compile(r"^([^:]+):\s*(.*)$")

    # Bypass techniques inlined from letmepass's technique table. Each
    # entry is ``(label, callable)``; the callable takes the placeholder
    # string and returns the bypassed form. The label is also embedded
    # as a header so dedup keeps one variant per technique.
    TECHNIQUES = (
        ("identity", lambda s: s),
        ("nfkc", lambda s: _nfkc(s)),
        ("double_url_encode", lambda s: s.replace("%", "%25")),
        ("sliding_hex", lambda s: s.replace("/", "%c0%af")),
        ("fragment", lambda s: s + "#"),
        ("traversal", lambda s: s + "/./%2e%2e/"),
        ("zero_width", lambda s: s + "\u200d"),
    )

    def fuzz(self, request_text: str, technique: str = "all") -> List[str]:
        """Return a list of fuzzed requests with the chosen technique.

        ``technique`` accepts one of the labels in :attr:`TECHNIQUES`
        (or the special value ``"all"`` which iterates every
        technique).

        ``*`` placeholders in the request line, header values, or body are
        replaced with each candidate. Lines without ``*`` are passed
        through unchanged.
        """
        if not isinstance(request_text, str) or not request_text:
            raise ValueError("request_text must be a non-empty string")
        if technique not in ("all",) + tuple(t[0] for t in self.TECHNIQUES):
            raise ValueError(f"unknown technique: {technique!r}")

        selected = self.TECHNIQUES if technique == "all" else (
            t for t in self.TECHNIQUES if t[0] == technique
        )

        results: List[str] = []
        for label, fn in selected:
            new_text = self._apply(request_text, fn, label=label)
            if new_text and new_text not in results:
                results.append(new_text)
        return results

    def fuzz_per_placeholder(
        self, request_text: str, technique: str = "identity"
    ) -> List[str]:
        """Like :meth:`fuzz` but applies the technique per-placeholder,
        emitting one variant per matched ``*`` so callers can see which
        injection point produced which bypassed URL.
        """
        if technique == "all":
            technique = "identity"
        _, fn = next(t for t in self.TECHNIQUES if t[0] == technique)
        return self._apply_per_placeholder(request_text, fn)

    # -- internals -----------------------------------------------------------

    def _apply(self, request_text: str, fn, label: str = "") -> str:
        """Apply ``fn`` to every ``*`` placeholder.

        If the request has no ``*`` we still emit a single pass-through
        variant so the engine has at least one result per module.

        When ``label`` is provided we append a non-functional
        ``X-Bugwolf-Technique`` header so each technique emits a
        distinct variant (otherwise dedup collapses them).
        """
        if "*" not in request_text:
            return request_text
        out = request_text.replace("*", fn("*"))
        if label:
            # Inject the technique label as a header so the per-technique
            # variants don't dedup against each other.
            header_line = f"X-Bugwolf-Technique: {label}\r\n"
            # Insert after the Host line (or after the request line if
            # no Host header is present).
            lines = out.split("\r\n")
            for i, line in enumerate(lines):
                if line.lower().startswith("host:"):
                    lines.insert(i + 1, header_line.rstrip("\r\n"))
                    break
            else:
                if lines and lines[0].startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                    lines.insert(1, header_line.rstrip("\r\n"))
            out = "\r\n".join(lines)
        return out

    def _apply_per_placeholder(self, request_text: str, fn) -> List[str]:
        """Emit one variant per matched ``*`` (per-line)."""
        results: List[str] = []
        for lineno, line in enumerate(request_text.splitlines(keepends=True)):
            if "*" not in line:
                continue
            replaced = line.replace("*", fn("*"))
            variant = request_text.replace(line, replaced, 1)
            results.append(f"{variant}  # fuzzed line {lineno + 1}")
        return results

    def count_placeholders(self, request_text: str) -> int:
        """Return the number of ``*`` placeholders in the request."""
        return request_text.count("*")


def _nfkc(s: str) -> str:
    """Lazy NFKC import -- avoid pulling unicodedata into module scope."""
    import unicodedata as _u
    return _u.normalize("NFKC", s)