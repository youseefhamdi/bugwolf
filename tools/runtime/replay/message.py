#!/usr/bin/env python3
"""Byte-exact HTTP/1.1 message parsing and serialization (Phase 1.1).

The send engine's foundation: ``Request`` and ``Response`` preserve the
bytes on the wire — header case, whitespace between name and value,
duplicate headers, and malformed framing are all round-tripped exactly.
String tools (``urllib``, ``requests``, curl text templates) normalize this
away, which is precisely what request-smuggling and desync attacks need to
survive. A desync exists only when two HTTP implementations disagree about
message boundaries; catching it requires sending bytes, not "requests".

Design contract:

  * ``Request.from_bytes`` parses start line, raw header lines (split at the
    FIRST colon, name and value kept verbatim including case and OWS), and
    the body.  ``to_bytes()`` reconstructs the message byte-for-byte when no
    mutation happened.
  * Framing is *observed*, never resolved silently: if Content-Length and
    Transfer-Encoding coexist (the CL.TE ambiguity), or Content-Length is
    duplicated with conflicting values, the message is flagged as a
    smuggling candidate.  The engine sends what the operator asked for.
  * Mutations (Phase 1.2) operate on this structure; header edits preserve
    position and original spelling unless explicitly changed.

No network, no dependencies (deterministic tier).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

SCHEMA = "bugwolf-replay-message/v1"

CRLF = b"\r\n"


@dataclass
class HeaderLine:
    """One raw header line, preserved exactly as received/constructed."""

    raw_name: bytes          # original case, e.g. b"Transfer-Encoding"
    raw_value: bytes         # value WITHOUT leading OWS (leading whitespace stripped)
    ows: bytes = b""         # whitespace that followed the colon (preserved)
    trailing: bytes = b""    # trailing whitespace/OBS fold artifacts (preserved)

    @property
    def lower_name(self) -> str:
        return self.raw_name.decode("latin-1").strip().lower()

    def render(self) -> bytes:
        return self.raw_name + b":" + self.ows + self.raw_value + self.trailing


class HttpMessage:
    """Shared header/body machinery for Request and Response."""

    def __init__(self) -> None:
        self.headers: List[HeaderLine] = []
        self.body: bytes = b""
        self._raw: Optional[bytes] = None   # original bytes if unmutated

    # -- header access -------------------------------------------------------

    def get_all(self, name: str) -> List[str]:
        key = name.lower()
        return [h.raw_value.decode("latin-1").strip()
                for h in self.headers if h.lower_name == key]

    def get(self, name: str) -> Optional[str]:
        values = self.get_all(name)
        return values[0] if values else None

    def has(self, name: str) -> bool:
        return bool(self.get_all(name))

    def set_header(self, name: str, value: str) -> None:
        """Set (replace all occurrences or append) a header, preserving the
        original line position of the first occurrence."""
        key = name.lower()
        for idx, h in enumerate(self.headers):
            if h.lower_name == key:
                h.raw_value = value.encode("latin-1")
                # drop duplicates beyond the first
                self.headers = [h2 for i, h2 in enumerate(self.headers)
                                if i == idx or h2.lower_name != key]
                return
        self.headers.append(HeaderLine(raw_name=name.encode("latin-1"),
                                       raw_value=value.encode("latin-1")))

    def add_header(self, name: str, value: str) -> None:
        """Append a header line, preserving duplicates deliberately."""
        self.headers.append(HeaderLine(raw_name=name.encode("latin-1"),
                                       raw_value=value.encode("latin-1")))

    def remove_header(self, name: str) -> int:
        key = name.lower()
        before = len(self.headers)
        self.headers = [h for h in self.headers if h.lower_name != key]
        return before - len(self.headers)

    # -- framing analysis ----------------------------------------------------

    def _cl_values(self) -> List[str]:
        return self.get_all("content-length")

    def _te_values(self) -> List[str]:
        return self.get_all("transfer-encoding")

    @property
    def framing_conflict(self) -> Optional[str]:
        """Return a reason string when framing is ambiguous (smuggling
        territory), else None.  Observed, never auto-resolved."""
        cls = self._cl_values()
        tes = self._te_values()
        if cls and tes:
            return "CL+TE coexist"
        if len(cls) > 1 and len({v.strip() for v in cls}) > 1:
            return "conflicting duplicate Content-Length"
        if len(cls) > 1:
            return "duplicate Content-Length (identical)"
        if len(tes) > 1:
            return "duplicate Transfer-Encoding"
        for te in tes:
            if te.strip().lower() not in ("chunked", "identity"):
                return f"unusual Transfer-Encoding: {te!r}"
            if te != te.strip().lower() and te.strip().lower() == "chunked":
                return f"mixed-case Transfer-Encoding: {te!r}"
        return None

    @property
    def is_chunked(self) -> bool:
        return any(v.strip().lower() == "chunked" for v in self._te_values())

    @property
    def content_length(self) -> Optional[int]:
        values = self._cl_values()
        if not values:
            return None
        try:
            return int(values[0].strip())
        except ValueError:
            return None

    # -- serialization -------------------------------------------------------

    def _render_headers(self) -> bytes:
        return b"".join(h.render() + CRLF for h in self.headers)

    def mutated(self) -> bool:
        return self._raw is None


class Request(HttpMessage):
    """A byte-exact HTTP/1.1 request."""

    def __init__(self, method: str = "GET", target: str = "/",
                 version: bytes = b"HTTP/1.1") -> None:
        super().__init__()
        self.method = method
        self.target = target
        self.version = version

    # -- parsing -------------------------------------------------------------

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Request":
        msg = cls.__new__(cls)
        msg.__init__()
        msg._raw = raw
        # start line
        head, sep, rest = raw.partition(CRLF)
        if not sep:
            raise ValueError("request has no complete start line")
        parts = head.split(b" ")
        if len(parts) < 3:
            raise ValueError(f"malformed request line: {head!r}")
        msg.method = parts[0].decode("latin-1")
        msg.version = parts[-1]
        msg.target = b" ".join(parts[1:-1]).decode("latin-1")
        rest = msg._parse_headers(rest)
        # body: take the remainder as-is. Framing ambiguity is *flagged*
        # (framing_conflict), never silently resolved -- raw sends depend on
        # sending exactly these bytes.
        cl = msg.content_length
        if cl is not None and cl <= len(rest):
            msg.body = rest[:cl]
            msg._trailer = rest[cl:]        # pipelined second message (desync evidence)
        else:
            msg.body = rest
            msg._trailer = b""
        return msg

    def _parse_headers(self, rest: bytes) -> bytes:
        while True:
            line, sep, rest = rest.partition(CRLF)
            if not sep or line == b"":
                return rest
            name, colon, value = line.partition(b":")
            if not colon:
                # continuation fold or garbage; preserve as a valueless line
                self.headers.append(HeaderLine(raw_name=line, raw_value=b"",
                                               trailing=b""))
                continue
            stripped = value.lstrip(b" \t")
            inner = stripped.rstrip(b" \t")      # value WITHOUT trailing OWS
            self.headers.append(HeaderLine(
                raw_name=name,
                raw_value=inner,
                ows=value[:len(value) - len(stripped)],
                trailing=stripped[len(inner):],
            ))

    # -- serialization -------------------------------------------------------

    def to_bytes(self, include_body: bool = True) -> bytes:
        start = f"{self.method} {self.target} ".encode("latin-1") + self.version
        out = start + CRLF + self._render_headers() + CRLF
        if include_body:
            out += self.body
            # pipelined bytes captured after the framed body (desync
            # evidence) must survive the round trip too
            out += getattr(self, "_trailer", b"")
        return out

    def renders_identically(self) -> bool:
        """True when no mutation has changed the wire bytes."""
        return self._raw is not None and self.to_bytes() == self._raw

    # convenience ------------------------------------------------------------

    @property
    def host(self) -> Optional[str]:
        return self.get("host")

    def with_header(self, name: str, value: str) -> "Request":
        """Functional-style copy with one header set (for compare sides)."""
        clone = Request.from_bytes(self.to_bytes())
        clone._raw = None
        clone.set_header(name, value)
        return clone


class Response(HttpMessage):
    """A byte-exact HTTP/1.1 response (observation side)."""

    def __init__(self, version: bytes = b"HTTP/1.1",
                 status: int = 200, reason: bytes = b"OK") -> None:
        super().__init__()
        self.version = version
        self.status = status
        self.reason = reason

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Response":
        msg = cls.__new__(cls)
        msg.__init__()
        msg._raw = raw
        head, sep, rest = raw.partition(CRLF)
        if not sep:
            raise ValueError("response has no complete status line")
        parts = head.split(b" ", 2)
        msg.version = parts[0]
        try:
            msg.status = int(parts[1])
        except (IndexError, ValueError):
            raise ValueError(f"malformed status line: {head!r}")
        msg.reason = parts[2] if len(parts) > 2 else b""
        rest = Request._parse_headers(msg, rest)
        if msg.is_chunked:
            msg.body = _decode_chunked(rest)
        else:
            msg.body = rest
        return msg

    def to_bytes(self, include_body: bool = True) -> bytes:
        status_line = (self.version + b" " + str(self.status).encode()
                       + b" " + self.reason)
        out = status_line + CRLF + self._render_headers() + CRLF
        if include_body:
            out += self.body
            out += getattr(self, "_trailer", b"")
        return out


def _decode_chunked(raw: bytes) -> bytes:
    """Decode a chunked body for observation. Malformed input degrades to
    the raw bytes (evidence, not an exception)."""
    out = bytearray()
    rest = raw
    while True:
        line, sep, rest = rest.partition(CRLF)
        if not sep:
            return bytes(out) + rest if out or rest else bytes(out)
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(out)
        if size == 0:
            return bytes(out)
        out += rest[:size]
        rest = rest[size:]
        if rest.startswith(CRLF):
            rest = rest[len(CRLF):]
