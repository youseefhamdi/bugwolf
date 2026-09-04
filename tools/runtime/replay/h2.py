#!/usr/bin/env python3
"""HTTP/2 framing layer + H2.CL desync frontend (master plan Phase 1.1b).

Frames (RFC 7540 §4/§6): the 9-octet header (length, type, flags, R+stream)
and the client connection preface.  The client side (:func:`build_headers_frame`,
:func:`build_data_frame`, :func:`client_preface`) emits governed probe
traffic; the server side (:class:`H2Frontend`) is the desync observable: a
minimal, deliberately flawed HTTP/2→HTTP/1.1 gateway whose backend
connection pool makes the classic H2.CL desync *testable end-to-end*.

Why the flaw is deliberate (and bounded): real H2.CL bugs are frontends
that forward forbidden ``Transfer-Encoding`` headers (RFC 7540 §8.1.2
forbids them; a conformance-checking frontend strips them) and that
compute no Content-Length of their own when one was supplied.  The stub
frontend reproduces exactly that pair, only for requests whose decoded
headers carry it — ``H2Frontend.forward_transfer_encoding = True`` — and
refuses to run without an explicit opt-in flag, mirroring the replay
engine's "vulnerabilities are configured, never accidental" doctrine.

Desync mechanics implemented here end-to-end:

  1. attacker sends H2 POST whose headers carry ``transfer-encoding:
     chunked`` plus a ``content-length: 0``, body = chunked bytes followed
     by the smuggled HTTP/1.1 request;
  2. the frontend decodes HPACK (no normalization), forwards the
     forbidden TE verbatim and does not synthesize its own C-L;
  3. the HTTP/1.1 backend honors TE over C-L (RFC 7230 §3.3.3), decodes
     one chunk, and the bytes after the chunked terminator become a NEW
     request on the *pooled* backend connection;
  4. the frontend reads only the first response and returns the (now
     dirty) connection to its pool;
  5. the next client on that pooled connection reads the SMUGGLED
     request's response — the desync, observed as a 200 from a route
     that answers the victim 403/404.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
from collections import deque
from typing import Dict, List, Optional, Tuple

from tools.runtime.replay.hpack import (
    HpackContext, decode_headers, encode_headers, raw_header_block,
)

SCHEMA = "bugwolf-replay-h2/v1"

# ---------------------------------------------------------------------------
# Frame layer (RFC 7540 §4, §6)
# ---------------------------------------------------------------------------

FT_DATA = 0x0
FT_HEADERS = 0x1
FT_PRIORITY = 0x2
FT_RST_STREAM = 0x3
FT_SETTINGS = 0x4
FT_PUSH_PROMISE = 0x5
FT_PING = 0x6
FT_GOAWAY = 0x7
FT_WINDOW_UPDATE = 0x8
FT_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1

FRAME_HEADER_LEN = 9                          # length(3) type(1) flags(1) stream(3)
MAX_FRAME_SIZE = 16384

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class H2Error(ValueError):
    """Malformed HTTP/2 framing."""


def encode_frame(frame_type: int, flags: int, stream_id: int,
                 payload: bytes = b"") -> bytes:
    """One frame: 9-octet header + payload (payload split is the caller's).

    Stream 0 is the connection itself (SETTINGS/GOAWAY/PING) and is
    valid here; request frames carry streams >= 1.
    """
    if stream_id < 0 or stream_id > 0x7FFFFFFF:
        raise H2Error(f"bad stream id {stream_id}")
    if len(payload) > 0xFFFFFF:
        raise H2Error("frame payload exceeds 24-bit length")
    head = (struct.pack(">I", len(payload))[1:]      # 24-bit big-endian length
            + bytes([frame_type & 0xFF, flags & 0xFF])
            + struct.pack(">I", stream_id & 0x7FFFFFFF))  # R bit + 31-bit id
    return head + payload


def parse_frame_header(header: bytes) -> Tuple[int, int, int, int]:
    """9 bytes -> (length, type, flags, stream_id)."""
    if len(header) != 9:
        raise H2Error("frame header must be 9 bytes")
    length = int.from_bytes(header[0:3], "big")
    return length, header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7FFFFFFF


def split_frames(payload: bytes, *,
                 preface: bool = False) -> List[Tuple[int, int, int, bytes]]:
    """Convenience decoder for test/analysis buffers: whole buffer -> frames.

    ``preface=True`` skips the 24-octet client connection preface first
    (client-side buffers start with it; server responses do not).
    """
    frames: List[Tuple[int, int, int, bytes]] = []
    offset = len(CLIENT_PREFACE) if preface else 0
    if preface and payload[:24] != CLIENT_PREFACE:
        raise H2Error("buffer does not start with the client preface")
    while offset + 9 <= len(payload):
        length, ftype, flags, stream = parse_frame_header(
            payload[offset:offset + 9])
        end = offset + 9 + length
        if end > len(payload):
            raise H2Error("truncated frame payload")
        frames.append((ftype, flags, stream, payload[offset + 9:end]))
        offset = end
    if offset != len(payload):
        raise H2Error("trailing garbage after last frame")
    return frames


def client_preface(*, settings: Optional[Dict[int, int]] = None) -> bytes:
    """The 24-octet preface followed by the client's SETTINGS frame."""
    payload = b"".join(
        struct.pack(">HI", setting, value)
        for setting, value in (settings or {0x3: 100}).items())  # max frame size
    return CLIENT_PREFACE + encode_frame(FT_SETTINGS, 0, 0, payload)


def build_headers_frame(stream_id: int, headers: List[Tuple[str, str]], *,
                        context: Optional[HpackContext] = None,
                        end_stream: bool = False,
                        raw_block: Optional[bytes] = None) -> bytes:
    """HEADERS frame with an HPACK block (conformant or verbatim-raw)."""
    block = raw_block if raw_block is not None else encode_headers(
        headers, context=context)
    flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
    return encode_frame(FT_HEADERS, flags, stream_id, block)


def build_data_frame(stream_id: int, data: bytes, *,
                     end_stream: bool = True) -> bytes:
    """DATA frame (one frame; payloads beyond MAX_FRAME_SIZE must be split)."""
    if len(data) > MAX_FRAME_SIZE:
        raise H2Error("DATA payload exceeds MAX_FRAME_SIZE; split it")
    return encode_frame(FT_DATA, FLAG_END_STREAM if end_stream else 0,
                        stream_id, data)


def build_h2_request(stream_id: int, method: str, path: str, authority: str,
                     *, headers: Optional[List[Tuple[str, str]]] = None,
                     body: bytes = b"", context: Optional[HpackContext] = None,
                     raw_block: Optional[bytes] = None) -> bytes:
    """A complete client request: preface + HEADERS (+ DATA when body).

    Pseudo-headers (:method/:scheme/:authority/:path) are prepended; any
    extra ``headers`` follow verbatim — including the ones RFC 7540
    forbids, which is the point.
    """
    pseudo = [(":method", method), (":scheme", "http"),
              (":authority", authority), (":path", path)]
    out = client_preface()
    out += build_headers_frame(
        stream_id, pseudo + list(headers or []), context=context,
        end_stream=not body, raw_block=raw_block)
    if body:
        out += build_data_frame(stream_id, body, end_stream=True)
    return out


# ---------------------------------------------------------------------------
# H2Frontend — the minimal (and, on opt-in, desync-prone) HTTP/2 gateway
# ---------------------------------------------------------------------------

class _NotH2(Exception):
    """The client's first bytes are not the HTTP/2 preface."""


class _H2ClientHandler:
    """Per-connection behavior; mixed into the server's handler class."""

    def setup(self) -> None:                     # socketserver hook
        super().setup()
        try:
            self.connection.settimeout(15)
        except OSError:
            pass

    def handle(self) -> None:
        # 24-octet preface or HTTP/1.1 passthrough (dual-protocol probe
        # surface: desync victims do not speak H2).
        head = self.rfile.read(24)
        if head != CLIENT_PREFACE:
            self._serve_http11(head)
            return
        try:
            self._read_and_drain_settings()
            self._serve_h2_requests()
        except Exception as exc:                 # noqa: BLE001 - error is data
            try:
                self.server.h2_errors.append(
                    f"{type(exc).__name__}: {exc}")
            except AttributeError:
                pass
            try:
                self.wfile.write(encode_frame(FT_GOAWAY, 0, 0,
                                              struct.pack(">II", 0, 1)))
            except OSError:
                pass

    # -- H2 serving -------------------------------------------------------

    def _read_and_drain_settings(self) -> None:
        length, ftype, _flags, _stream = self._read_frame_header()
        if ftype != FT_SETTINGS:
            raise H2Error(f"expected SETTINGS after preface, got {ftype}")
        self.rfile.read(length)
        self.wfile.write(encode_frame(FT_SETTINGS, FLAG_ACK, 0))

    def _read_frame_header(self) -> Tuple[int, int, int, int]:
        header = self.rfile.read(9)
        if len(header) < 9:
            raise ConnectionError("eof in frame header")
        return parse_frame_header(header)

    def _serve_h2_requests(self) -> None:
        context = self.server.h2_context
        while True:
            length, ftype, flags, stream = self._read_frame_header()
            payload = self.rfile.read(length) if length else b""
            if ftype != FT_HEADERS:
                # SETTINGS/WINDOW_UPDATE/PING between requests: drain.
                if ftype == FT_PING and not flags & FLAG_ACK:
                    self.wfile.write(encode_frame(FT_PING, FLAG_ACK, 0,
                                                  payload))
                continue
            if flags & 0x20:                     # PRIORITY flag: strip pad
                payload = payload[5:]
            headers = decode_headers(payload, context=context)
            if not flags & FLAG_END_STREAM:
                body = self._read_data(stream)
            else:
                body = b""
            self._dispatch(headers, body, stream)

    def _read_data(self, stream: int) -> bytes:
        body = bytearray()
        while True:
            length, ftype, flags, sid = self._read_frame_header()
            payload = self.rfile.read(length) if length else b""
            if ftype == FT_DATA and sid == stream:
                body.extend(payload)
                if flags & FLAG_END_STREAM:
                    return bytes(body)
            elif ftype == FT_RST_STREAM and sid == stream:
                raise H2Error("stream reset before body completed")
            # other frame types during DATA: drained

    def _dispatch(self, headers: List[Tuple[str, str]], body: bytes,
                  stream: int) -> None:
        method = path = ""
        hop: List[Tuple[bytes, bytes]] = []
        te_values: List[bytes] = []
        for name, value in headers:
            if name == ":method":
                method = value
            elif name == ":path":
                path = value
            elif name.startswith(":"):
                continue
            else:
                lname = name.lower().encode("latin-1")
                lvalue = value.encode("latin-1")
                if lname == b"transfer-encoding":
                    te_values.append(lvalue)
                hop.append((lname, lvalue))
        self.server.h2_requests.append({
            "method": method, "path": path,
            "te": [t.decode("latin-1") for t in te_values],
            "body_bytes": len(body),
        })

        # The desync fork: forward the forbidden TE verbatim (opt-in), and
        # never synthesize a C-L when the client supplied one — the two
        # behaviors whose absence makes real frontends safe.
        forward_te = self.server.forward_transfer_encoding and te_values
        client_cl = [v for n, v in hop if n == b"content-length"]
        lines = [f"{method} {path} HTTP/1.1".encode("latin-1")]
        lines.extend(n + b": " + v for n, v in hop)
        if forward_te:
            lines.extend(b"transfer-encoding: " + t for t in te_values)
        else:
            # Conformant translation: the frontend OWNS framing — no TE is
            # forwarded and the body length it re-computes overrides any
            # client C-L (RFC 7540 §8.1.2.6: a conforming frontend rejects
            # or resynthesizes; forwarding the client's lie is the bug).
            # WITHOUT this synthesis the unframed body would pipeline on
            # the backend and poison the pool even without TE — which is
            # exactly what the safe-mode control test must not observe.
            # The TE pair itself is stripped too: forwarding it verbatim
            # while synthesizing a C-L reintroduces ambiguity (backend
            # honors TE per RFC 7230 §3.3.3 and the smuggled remainder
            # is consumed as chunked body — desync with the switch off).
            hop = [(n, v) for n, v in hop
                   if n not in (b"content-length", b"transfer-encoding")]
            lines = [f"{method} {path} HTTP/1.1".encode("latin-1")]
            lines.extend(n + b": " + v for n, v in hop)
            lines.append(f"Content-Length: {len(body)}".encode())

        request = b"\r\n".join(lines) + b"\r\n\r\n" + body
        status, resp_head_pairs, resp_body = self._backend_roundtrip(request)

        out = [(b":status", str(status).encode())]
        if forward_te:
            # The frontend BELIEVES the response is chunk-framed — forward
            # that belief as the response's framing header.
            out.append((b"transfer-encoding", b"chunked"))
        for name, value in resp_head_pairs:
            lname = name.lower()
            if forward_te and lname == b"content-length":
                continue
            if lname in (b"content-type", b"x-stub-h2-marker"):
                out.append((bytes(name), value))
        self.wfile.write(encode_frame(
            FT_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream,
            encode_headers([(n.decode("latin-1"), v.decode("latin-1"))
                            for n, v in out], context=self.server.h2_context)))
        if resp_body:
            self.wfile.write(encode_frame(FT_DATA, FLAG_END_STREAM, stream,
                                          resp_body))

    # -- backend connection pool (the desync vehicle) ----------------------

    def _backend_roundtrip(self, request: bytes) -> Tuple[int, List[Tuple[bytes, bytes]], bytes]:
        """One request/response over a pooled backend connection.

        Pool entries carry a per-connection read buffer: recv() can
        over-deliver past a message boundary, and on a DESYNCED connection
        the queued (smuggled) response lives exactly in that overrun —
        consuming it silently hides the desync.  Exact-buffer reads are
        what makes the poisoned-connection observation possible.

        Hygiene: a pooled socket that turns out dead is dropped and the
        send retried once on a fresh connection.
        """
        last_exc: Optional[Exception] = None
        for attempt in range(2):
            sock, buf = self.server._backend_pool_pop()
            try:
                sock.sendall(request)
                head, body = self._read_http11(sock, buf)
            except Exception as exc:          # noqa: BLE001 - retry hygiene
                self.server._backend_pool_drop(sock)
                last_exc = exc
                continue
            self.server._backend_pool_push(sock, buf)
            pairs: List[Tuple[bytes, bytes]] = []
            status = 0
            head_lines = head.split(b"\r\n")
            for line in head_lines[1:]:
                name, _, value = line.partition(b":")
                if _:
                    pairs.append((name.strip(), value.strip()))
            parts = head_lines[0].split(b" ", 2)
            if len(parts) >= 2:
                try:
                    status = int(parts[1])
                except ValueError:
                    status = 0
            return status, pairs, body
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _read_http11(sock: socket.socket,
                     buf: bytearray) -> Tuple[bytes, bytes]:
        """One HTTP/1.1 message with honest framing (C-L; TE fallback).

        Reads come from ``buf`` first (the per-connection carry-over), so
        bytes past this message's boundary remain buffered for the next
        read — on a desynced connection that leftover IS the evidence.
        """
        sock.settimeout(15)

        def _fill() -> bytes:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("eof in response")
            buf.extend(chunk)
            return chunk

        while b"\r\n\r\n" not in buf:
            _fill()
        head_bytes, _, rest = bytes(buf).partition(b"\r\n\r\n")
        consumed = len(head_bytes) + 4
        lowered = head_bytes.lower()
        if b"transfer-encoding" in lowered and b"chunked" in lowered:
            body = bytearray()
            while True:
                while b"\r\n" not in buf[consumed:]:
                    _fill()
                window = bytes(buf[consumed:])
                size_line, _, after = window.partition(b"\r\n")
                size = int(size_line.partition(b";")[0].strip() or b"0", 16)
                consumed += len(size_line) + 2
                if size == 0:
                    del buf[:consumed]
                    return head_bytes, bytes(body)
                while len(buf) - consumed < size + 2:
                    _fill()
                body.extend(buf[consumed:consumed + size])
                consumed += size + 2
        length = 0
        for line in head_bytes.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.partition(b":")[2].strip() or 0)
        while len(buf) - consumed < length:
            _fill()
        body = bytes(buf[consumed:consumed + length])
        del buf[:consumed + length]
        return head_bytes, body

    # -- plain HTTP/1.1 passthrough (the desync "victim") -------------------

    def _serve_http11(self, first_bytes: bytes) -> None:
        # read1() not read(): BufferedReader.read(n) blocks until n bytes
        # or EOF, deadlocking any request smaller than the read size.
        head = bytearray(first_bytes)
        while b"\r\n\r\n" not in head:
            chunk = self.rfile.read1(4096)
            if not chunk:
                return
            head.extend(chunk)
        head_bytes, _, rest = bytes(head).partition(b"\r\n\r\n")
        length = 0
        for line in head_bytes.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.partition(b":")[2].strip() or 0)
        body = rest
        while len(body) < length:
            chunk = self.rfile.read1(4096)
            if not chunk:
                break
            body += chunk
        request = head_bytes + b"\r\n\r\n" + body[:length]
        try:
            status, pairs, resp_body = self._backend_roundtrip(request)
        except Exception:                        # noqa: BLE001 - honest close
            return
        out = [f"HTTP/1.1 {status} OK".encode()]
        out.extend(n + b": " + v for n, v in pairs)
        out.append(b"Content-Length: " + str(len(resp_body)).encode())
        self.wfile.write(b"\r\n".join(out) + b"\r\n\r\n" + resp_body)


def _read_chunked(sock: socket.socket, initial: bytes) -> bytes:
    body = bytearray()
    buf = bytearray(initial)
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("eof in chunk size")
            buf.extend(chunk)
        size_line, _, buf = bytes(buf).partition(b"\r\n")
        size = int(size_line.partition(b";")[0].strip() or 0, 16)
        if size == 0:
            return bytes(body)
        while len(buf) < size + 2:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("eof in chunk data")
            buf.extend(chunk)
        body.extend(buf[:size])
        buf = bytearray(buf[size + 2:])          # strip chunk + CRLF


class H2Frontend:
    """A threading HTTP/2 gateway over a real HTTP/1.1 backend.

    ``forward_transfer_encoding`` is the desync switch (default False):
    with it off the frontend is a well-behaved minimal H2 gateway; with it
    on, requests whose H2 headers carry ``transfer-encoding`` are forwarded
    verbatim without a synthesized Content-Length — the H2.CL bug, live.
    """

    def __init__(self, backend_host: str, backend_port: int, *,
                 forward_transfer_encoding: bool = False):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.forward_transfer_encoding = bool(forward_transfer_encoding)
        self.h2_context = HpackContext()          # one direction's state
        self.h2_requests: List[Dict] = []         # audit: decoded requests
        self.h2_errors: List[str] = []
        self._pool: deque = deque()
        self._pool_lock = threading.Lock()
        self._handler_cls = type(
            "BoundH2Handler", (_H2ClientHandler,
                               socketserver.StreamRequestHandler), {})

        server = self

        class _Srv(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            # attribute shims so _H2ClientHandler can use self.server.*
            h2_context = server.h2_context
            h2_requests = server.h2_requests
            h2_errors = server.h2_errors
            forward_transfer_encoding = server.forward_transfer_encoding

            def _backend_pool_pop(sself):
                return server._backend_pool_pop()

            def _backend_pool_push(sself, sock, buf=None):
                server._backend_pool_push(sock, buf)

            def _backend_pool_drop(sself, sock):
                server._backend_pool_drop(sock)

        self._srv = _Srv((backend_host, 0), self._handler_cls)
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)

    # -- pool (entries: [socket, bytearray read-buffer]) ---------------------

    def _backend_pool_pop(self) -> Tuple[socket.socket, bytearray]:
        with self._pool_lock:
            if self._pool:
                return self._pool.popleft()
        sock = socket.create_connection(
            (self.backend_host, self.backend_port), timeout=10)
        return sock, bytearray()

    def _backend_pool_push(self, sock: socket.socket,
                           buf: Optional[bytearray] = None) -> None:
        with self._pool_lock:
            self._pool.append((sock, buf if buf is not None else bytearray()))

    def _backend_pool_drop(self, sock: socket.socket) -> None:
        try:
            sock.close()
        except OSError:
            pass

    # -- lifecycle ------------------------------------------------------------

    @property
    def port(self) -> int:
        return self._srv.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        while self._pool:
            sock, _buf = self._pool.popleft()
            self._backend_pool_drop(sock)
