#!/usr/bin/env python3
"""HPACK: header compression for HTTP/2 (master plan Phase 1.1b).

The header-block layer of RFC 7541, stdlib-only: the RFC-correct 61-entry
static table, dynamic-table contexts (insertion, eviction, size updates),
indexed and literal representations, and the raw/non-conformant postures
desync work runs on.

Deliberate scope: string literals are emitted **without Huffman coding**
(the H bit is always 0).  Huffman is an optional layer inside HPACK, the
classes bugwolf hunts are built from verbatim header bytes — a compression
step that re-encodes them is exactly the normalization smuggling probes
must avoid — and an honest implementation beats a bit-rotted copy of
appendix B.  Decoding a Huffman-coded block raises ``HpackError`` with
that stated reason (bugwolf's own H2 peers never emit one).

Two decoder postures:

  * conformant (default) — indexes, dynamic table, size updates; reads
    HPACK from conforming peers (the H2Frontend's replies);
  * raw — no table state, no H-bit interpretation; every header is a
    7-bit-length literal pair.  Desync tooling states exactly which bytes
    cross the wire; shared table state is a fidelity hazard.

Two encoder postures:

  * default — literal-without-indexing, name-by-static-index when the
    name is in the table: small, valid, stateless across connections;
  * raw — deliberately non-conformant literals (the incremental-indexing
    bit pattern applied *without* any table insertion, so stateful
    decoders diverge — the divergence IS the desync surface) plus
    ``raw_header_block`` for exact-verbatim header blocks with forbidden
    casing, spacing, and duplicate names.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Static table (RFC 7541, appendix A) — 61 entries, 1-indexed; position 0 is
# the illegal index placeholder so table positions equal RFC indices.
# ---------------------------------------------------------------------------

STATIC_TABLE: Tuple[Tuple[str, str], ...] = (
    ("", ""),
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
)

_STATIC_NAME_INDEX = {
    name: idx for idx, (name, _value) in enumerate(STATIC_TABLE) if name
}


class HpackError(ValueError):
    """Malformed HPACK block, or a Huffman string (unsupported by design)."""


# ---------------------------------------------------------------------------
# Integer primitive (RFC 7541 §5.1/§6.1)
# ---------------------------------------------------------------------------

def encode_int(value: int, prefix_bits: int, first_byte: int = 0) -> bytes:
    """RFC 7541 integer with ``prefix_bits`` usable bits of ``first_byte``."""
    if value < 0:
        raise HpackError("negative integer")
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([first_byte | value])
    out = bytearray([first_byte | limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


class _Reader:
    """Cursor over an HPACK block with RFC integer parsing."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def peek_hbit(self) -> int:
        """The 0x80 bit of the byte at the cursor (string H flag)."""
        return self.data[self.pos] & 0x80 if self.pos < len(self.data) else 0

    def read_int(self, prefix_bits: int) -> int:
        if self.pos >= len(self.data):
            raise HpackError("truncated integer")
        limit = (1 << prefix_bits) - 1
        value = self.data[self.pos] & limit
        self.pos += 1
        if value < limit:
            return value
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise HpackError("truncated integer continuation")
            byte = self.data[self.pos]
            self.pos += 1
            value += (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value
            if shift > 63:
                raise HpackError("integer overflow")


# ---------------------------------------------------------------------------
# Dynamic-table context (RFC 7541 §4)
# ---------------------------------------------------------------------------

class HpackContext:
    """One direction's HPACK state: dynamic table + size accounting."""

    def __init__(self, table_size: int = 4096):
        self.table_size = table_size
        self._dynamic: List[Tuple[str, str]] = []   # newest first
        self._size = 0

    @staticmethod
    def entry_size(name: str, value: str) -> int:
        return len(name.encode("latin-1")) + len(value.encode("latin-1")) + 32

    def _evict(self) -> None:
        while self._size > self.table_size and self._dynamic:
            name, value = self._dynamic.pop()
            self._size -= self.entry_size(name, value)

    def add(self, name: str, value: str) -> None:
        size = self.entry_size(name, value)
        if size > self.table_size:
            return
        self._dynamic.insert(0, (name, value))
        self._size += size
        self._evict()

    def lookup(self, index: int) -> Optional[Tuple[str, str]]:
        """RFC index space: 1..61 static, 62+ dynamic (newest first)."""
        if index <= 0:
            return None
        if index < len(STATIC_TABLE):
            return STATIC_TABLE[index]
        dyn = index - len(STATIC_TABLE)
        if 0 <= dyn < len(self._dynamic):
            return self._dynamic[dyn]
        return None


# ---------------------------------------------------------------------------
# Header block encode
# ---------------------------------------------------------------------------

def encode_headers(headers: List[Tuple[str, str]], *,
                   context: Optional[HpackContext] = None,
                   raw: bool = False) -> bytes:
    """Encode ``headers`` into an HPACK header block.

    Default: literal-without-indexing (0x00 prefix), name-by-static-index
    when the name is in the table.  ``raw=True`` emits deliberately
    non-conformant literals: the 0x40 incremental-indexing bit pattern
    WITHOUT inserting into any table, so a stateful decoder's dynamic
    table diverges from the encoder's — precisely the disagreement
    H2.CL desync work studies.  No Huffman in either posture.
    """
    out = bytearray()
    for name, value in headers:
        name_bytes = name.encode("latin-1")
        value_bytes = value.encode("latin-1")
        if raw:
            # The literal 0x40 byte itself — an index that does not fit a
            # 6-bit prefix encoded legitimately would continuation-extend;
            # the single forbidden byte is what stateful decoders read as
            # "literal with incremental indexing, index 0".
            out.append(0x40)
            out += encode_int(len(name_bytes), 7) + name_bytes
            out += encode_int(len(value_bytes), 7) + value_bytes
            continue
        name_index = _STATIC_NAME_INDEX.get(name.lower())
        if name_index:
            out += encode_int(name_index, 4, 0x00)
        else:
            out += encode_int(0, 4, 0x00)
            out += encode_int(len(name_bytes), 7) + name_bytes
        out += encode_int(len(value_bytes), 7) + value_bytes
    return bytes(out)


def raw_header_block(headers: List[Tuple[str, str]]) -> bytes:
    """Verbatim header block: 7-bit-length literals, no table, no flags —
    the exact-bytes contract for smuggled header material."""
    out = bytearray()
    for name, value in headers:
        nb, vb = name.encode("latin-1"), value.encode("latin-1")
        out += encode_int(len(nb), 7) + nb
        out += encode_int(len(vb), 7) + vb
    return bytes(out)


# ---------------------------------------------------------------------------
# Header block decode
# ---------------------------------------------------------------------------

def decode_headers(data: bytes, *,
                   context: Optional[HpackContext] = None,
                   raw: bool = False) -> List[Tuple[str, str]]:
    """Decode an HPACK header block.

    Conformant (default): indexed, literal (with/without incremental
    indexing), and dynamic-table-size-update instructions.  ``raw=True``:
    pure 7-bit-length literal pairs (the ``raw_header_block`` format) —
    no table, no instruction bytes.
    """
    if raw:
        reader = _Reader(data)
        headers: List[Tuple[str, str]] = []
        while reader.pos < len(data):
            name_len = reader.read_int(7)
            name = data[reader.pos:reader.pos + name_len].decode("latin-1")
            reader.pos += name_len
            value_len = reader.read_int(7)
            value = data[reader.pos:reader.pos + value_len].decode("latin-1")
            reader.pos += value_len
            headers.append((name, value))
        return headers

    context = context or HpackContext()
    reader = _Reader(data)
    headers = []
    while reader.pos < len(data):
        byte = data[reader.pos]
        if byte & 0x80:                            # 1xxxxxxx: indexed field
            index = reader.read_int(7)
            entry = context.lookup(index)
            if entry is None:
                raise HpackError(f"bad index {index}")
            headers.append(entry)
        elif byte & 0xC0 == 0x40:                  # 01xxxxxx: literal w/ incr indexing
            headers.append(_read_literal(reader, context, 6, add=True))
        elif byte & 0xE0 == 0x20:                  # 001xxxxx: size update
            # The update is not cosmetic: it changes the table's capacity
            # immediately and evicts from the top (RFC 7541 §4.2).
            context.table_size = reader.read_int(5)
            context._evict()
        else:                                      # 0000xxxx: literal w/o indexing
            headers.append(_read_literal(reader, context, 4, add=False))
    return headers


def _read_literal(reader: _Reader, context: HpackContext,
                  prefix_bits: int, *, add: bool) -> Tuple[str, str]:
    index = reader.read_int(prefix_bits)
    if index:
        base = context.lookup(index)
        if base is None:
            raise HpackError(f"bad name index {index}")
        name = base[0]
    else:
        name = _read_string(reader)
    value = _read_string(reader)
    if add:
        context.add(name, value)
    return name, value


def _read_string(reader: _Reader) -> str:
    huffman = reader.peek_hbit()
    length = reader.read_int(7)
    raw = reader.data[reader.pos:reader.pos + length]
    if len(raw) != length:
        raise HpackError("truncated string")
    reader.pos += length
    if huffman:
        raise HpackError(
            "huffman-coded string: bugwolf emits raw literals by design")
    return raw.decode("latin-1")
