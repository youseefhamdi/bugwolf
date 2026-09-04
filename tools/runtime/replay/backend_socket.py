#!/usr/bin/env python3
"""Raw-socket backend sender (Phase 1.4).

The only place BugWolf puts bytes on the wire for the replay engine.  The
socket is dumb on purpose: it transmits exactly the bytes it is given and
reads exactly what comes back — the desync classes (CL.TE, TE.CL) exist
only when implementations disagree about message boundaries, which means
every normalization layer must be absent.

Fail-closed order of operations, before any connection:

    1. scope gate authorizes the host (ScopeViolation propagates — the
       deny-by-default mission boundary holds at the lowest network layer);
    2. governor admits the send (budget/circuit/concurrency/rate).

Sockets are created fresh per send (no pooling) — predictable, and raw
smuggling probes WANT independent connections so the smuggled prefix lands
on a fresh server-side parser.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple
from urllib.parse import urlsplit

from tools.runtime.replay.governor import DEFAULTS as GOV_DEFAULTS, Governor

SCHEMA = "bugwolf-replay-backend/v1"

CRLF = b"\r\n"


class BackendRefused(Exception):
    """The governor refused the send (budget/circuit/rate/concurrency)."""


@dataclass
class SendResult:
    """What came back from one raw send — facts only, never verdicts."""

    status: Optional[int] = None
    reason: bytes = b""
    headers_raw: bytes = b""
    body: bytes = b""
    raw_response: bytes = b""
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    timed_out: bool = False
    truncated: bool = False           # body cap hit (bytes preserved, read stopped)
    connect_ms: float = 0.0
    attempts: int = 1

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "status": self.status,
            "reason": self.reason.decode("latin-1", "replace"),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "connect_ms": round(self.connect_ms, 2),
            "body_bytes": len(self.body),
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "error": self.error,
            "attempts": self.attempts,
        }


def split_host_port(host: str, default_port: int) -> Tuple[str, int, bool]:
    """host[:port] -> (hostname, port, is_tls) with scheme inference:
    https:// => 443/TLS, http:// => 80/plain; explicit port always wins."""
    tls = False
    if "://" in host:
        scheme, _, remainder = host.partition("://")
        tls = scheme.lower() == "https"
        host = remainder
    host = host.rstrip("/")
    if host.startswith("["):                      # IPv6 literal
        host_part, _, rest = host.partition("]")
        port_part = rest[1:] if rest.startswith(":") else ""
        hostname = host_part + "]"
    else:
        hostname, _, port_part = host.partition(":")
    port = int(port_part) if port_part else (443 if tls else default_port)
    return hostname, port, tls


def _read_response(sock: socket.socket, *,
                   total_timeout_s: float,
                   body_cap: int) -> tuple:
    """Read one response.  Returns (payload, truncated, saw_any_bytes).

    Termination heuristics, honest about which one fired:
      * EOF (server closed) or body cap -- normal completion;
      * idle gap after bytes were seen -- normal for keep-alive/slow-write
        servers, the response header phase is over;
      * idle gap with ZERO bytes seen -- the server never answered (it may
        still be waiting for request bytes we declared but did not send):
        the caller MUST record this as a timeout fact, never as success.
    """
    sock.settimeout(total_timeout_s)
    chunks = []
    total = 0
    truncated = False
    saw_any = False
    deadline = time.monotonic() + total_timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            truncated = True
            break
        sock.settimeout(min(remaining, 2.0))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break                                  # idle gap: response complete
        if not chunk:
            break                                  # EOF: server closed
        saw_any = True
        chunks.append(chunk)
        total += len(chunk)
        if total >= body_cap:
            truncated = True
            break
    return b"".join(chunks), truncated, saw_any


def send_raw(host: str, raw_bytes: bytes, *,
             governor: Optional[Governor] = None,
             connect_timeout_s: float = GOV_DEFAULTS["connect_timeout_s"],
             total_timeout_s: float = GOV_DEFAULTS["total_timeout_s"],
             body_cap: int = GOV_DEFAULTS["response_body_cap_bytes"],
             retries: int = GOV_DEFAULTS["max_retries"],
             now: Optional[float] = None) -> SendResult:
    """Send ``raw_bytes`` to ``host`` verbatim and read one response.

    Authorization happens FIRST (fail-closed): the scope gate raises
    ScopeViolation on out-of-scope hosts; the governor refusal raises
    BackendRefused with its recorded reason.  Transport-level retries apply
    only to connect failures — a response (any status) is final.
    """
    from tools.runtime.scope import check_url  # fail-closed mission boundary

    hostname, port, tls = split_host_port(host, default_port=80)
    scheme = "https" if tls else "http"
    url = f"{scheme}://{hostname}:{port}/"
    check_url(url)  # raises ScopeViolation when out of scope

    gov = governor
    if gov is not None:
        clock = now if now is not None else time.monotonic() * 1000.0
        if not gov.allow(hostname, clock):
            raise BackendRefused(gov.blocked_reason or "governor refused")
        gov.budget.record()

    result = SendResult()
    last_error: Optional[str] = None
    attempts_allowed = 1 + max(0, retries)

    for attempt in range(1, attempts_allowed + 1):
        result.attempts = attempt
        started = time.monotonic()
        sock: Optional[socket.socket] = None
        try:
            connect_started = time.monotonic()
            sock = socket.create_connection((hostname, port),
                                            timeout=connect_timeout_s)
            result.connect_ms = (time.monotonic() - connect_started) * 1000.0
            if tls:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=hostname)
            sock.sendall(raw_bytes)
            payload, truncated, saw_any = _read_response(
                sock, total_timeout_s=total_timeout_s, body_cap=body_cap)
            result.raw_response = payload
            result.truncated = truncated
            result.elapsed_ms = (time.monotonic() - started) * 1000.0
            if not payload and not saw_any:
                # FACT, not silence: the server never sent a byte within the
                # window (e.g. it is still waiting for body bytes we declared
                # but did not send -- a framing mismatch in itself).
                result.timed_out = True
                result.error = result.error or \
                    "no response bytes within timeout window"
            if payload:
                head, _, _rest = payload.partition(CRLF + CRLF)
                status_line = head.split(CRLF, 1)[0]
                parts = status_line.split(b" ", 2)
                try:
                    result.status = int(parts[1])
                except (IndexError, ValueError):
                    result.status = None
                result.reason = parts[2] if len(parts) > 2 else b""
                result.headers_raw = head
                try:
                    result.body = payload.partition(CRLF + CRLF)[2]
                except IndexError:
                    result.body = b""
            if gov is not None:
                gov.record_success(hostname)
            return result
        except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if gov is not None:
                gov.record_failure(hostname, time.monotonic() * 1000.0)
            result.error = last_error
            if attempt >= attempts_allowed:
                result.timed_out = isinstance(exc, socket.timeout)
                result.elapsed_ms = (time.monotonic() - started) * 1000.0
                return result
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return result


def send_desync_pair(host: str, front_bytes: bytes, smuggled_bytes: bytes, *,
                     pause_s: float = 0.3, **kwargs) -> Tuple[SendResult, SendResult]:
    """The CL.TE / TE.CL detection pattern (Phase 1.9 acceptance):

    1. send ``front_bytes`` whose framing is ambiguous (the frontend and
       backend will disagree about where the first message ends);
    2. pause (the frontend forwards what it parsed);
    3. send ``smuggled_bytes`` — if a desync exists, this lands on the
       backend as the START of a NEW request and its response is the
       smuggled request's, not a normal pipeline answer.
    """
    first = send_raw(host, front_bytes, **kwargs)
    time.sleep(pause_s)
    second = send_raw(host, smuggled_bytes, **kwargs)
    return first, second
