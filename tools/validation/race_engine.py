#!/usr/bin/env python3
"""BugWolf single-window race engine (plan section 5.6 S5 + section 2.5).

TOCTOU entries in the FIN matrix bind this engine.  The technique: hold N
pre-built HTTP/1.1 requests one byte short of complete (the last byte of the
body), then release every final byte inside one synchronized window.  A
check-then-act server that validates state before acting sees N "first"
requests arrive together; a non-atomic guard is defeated by the window.

Safety contract (plan section 2.5 — non-negotiable):
  * single window per call — no retries, no loops;
  * window size hard-capped at RACE_MAX_WINDOW (30, the plan ceiling);
  * connect abort: if the first connections all fail, the race aborts
    instead of hammering a struggling server;
  * per-request timeout; sockets closed in ``finally``;
  * state-changing races use operator-owned objects only (the caller's
    canary payload — the safety ceiling still applies above this engine).

HTTP/1.1 last-byte sync is the default dispatcher (stdlib sockets, no
dependencies).  HTTP/2 single-packet (frame withhold + flush) requires an
h2 stack and is exposed behind ``dispatcher`` injection — tests and future
transports implement the same ``Dispatcher`` protocol.
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

SCHEMA = "bugwolf-race/v1"

RACE_MAX_WINDOW = 30          # plan section 2.5 ceiling
_CONNECT_ABORT_AFTER = 3      # sustained connect failures abort the race


@dataclass
class RaceRequest:
    url: str
    method: str = "POST"
    body: Optional[Any] = None            # dict -> JSON, str -> verbatim
    headers: Optional[Dict[str, str]] = None
    count: int = 8
    timeout: float = 5.0
    verify_tls: bool = True               # certificate validation ON by
                                          # default: a MITM who wins the
                                          # race handshake owns the race.
                                          # Operators pinning unusual certs
                                          # may opt out explicitly.


@dataclass
class RaceResult:
    attempted: int
    statuses: List[int] = field(default_factory=list)
    successes: int = 0
    client_errors: int = 0
    server_errors: int = 0
    transport_errors: int = 0
    window_ms: int = 0
    schema: str = SCHEMA
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema, "attempted": self.attempted,
            "statuses": list(self.statuses), "successes": self.successes,
            "client_errors": self.client_errors,
            "server_errors": self.server_errors,
            "transport_errors": self.transport_errors,
            "window_ms": self.window_ms, "error": self.error,
        }


Dispatcher = Callable[[RaceRequest], List[Tuple[int, str]]]
# Native dispatcher signature: (responses, window_ms). Injected test
# dispatchers return the response list only.
NativeDispatcher = Callable[[RaceRequest], Tuple[List[Tuple[int, str]], int]]


def _replace_count(req: "RaceRequest", count: int) -> "RaceRequest":
    """Return a copy of ``req`` with ``count`` clamped to ``count``."""
    import dataclasses
    return dataclasses.replace(req, count=count)


def _encode_body(body: Optional[Any]) -> bytes:
    if body is None:
        return b""
    if isinstance(body, dict):
        return json.dumps(body).encode()
    return str(body).encode()


def _build_request_bytes(request: RaceRequest) -> bytes:
    """Full HTTP/1.1 request; the dispatcher withholds the final byte."""
    parsed = urlparse(request.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"race url must be http(s): {request.url!r}")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    body = _encode_body(request.body)
    headers: Dict[str, str] = {
        "Host": parsed.netloc,
        "User-Agent": "bugwolf-race-engine/1.0",
        "Connection": "close",
    }
    if body:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    for key, value in (request.headers or {}).items():
        headers[key] = value
    head = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return (f"{request.method.upper()} {path} HTTP/1.1\r\n{head}\r\n"
            .encode() + body)


def _read_response(sock: socket.socket, timeout: float) -> Tuple[int, str]:
    """Read one HTTP/1.1 response (status line + headers + body)."""
    sock.settimeout(timeout)
    buf = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf:
            head, _, rest = buf.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        length = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        length = 0
            if length == 0 or len(rest) >= length:
                break
    status = 0
    body_text = ""
    if b"\r\n\r\n" in buf:
        head, _, body_text = buf.partition(b"\r\n\r\n")
        first = head.split(b"\r\n")[0]
        parts = first.split(None, 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
    return status, body_text.decode("utf-8", "replace")


def last_byte_dispatcher(request: RaceRequest
                         ) -> Tuple[List[Tuple[int, str]], int]:
    """HTTP/1.1 last-byte synchronization (plan: H1 fallback technique).

    Opens ``count`` connections, sends every request except its final byte,
    then releases all final bytes from synchronized threads — one window.
    Returns one (status, body) pair per request (status 0 = transport
    error carrying ``error: ...`` in the body).
    """
    count = max(1, min(int(request.count), RACE_MAX_WINDOW))
    # Request-form validation FIRST (a malformed request is not a scope
    # question), then the execution-boundary scope gate: raw-socket races
    # obey the same operator scope as every HTTP lane (readiness R1).  Both
    # follow the engine's transport-error convention (status 0 + error:).
    try:
        full = _build_request_bytes(request)
    except ValueError as exc:
        return [(0, f"error: {exc}")] * count, 0
    try:
        from tools.runtime.scope import ScopeViolation, check_url
        check_url(request.url)
    except ScopeViolation as exc:
        return [(0, f"error: scope-blocked: {exc}")] * count, 0
    prefix, final = full[:-1], full[-1:]

    parsed = urlparse(request.url)
    tls = parsed.scheme == "https"
    host, port = parsed.hostname, parsed.port or (443 if tls else 80)

    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        if not request.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    sockets: List[Optional[socket.socket]] = []
    try:
        # Phase 1 — connect + send all-but-last-byte, sequentially.
        failed = 0
        for _ in range(count):
            try:
                sock = socket.create_connection((host, port),
                                                timeout=request.timeout)
                if tls and ctx is not None:
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.sendall(prefix)
                sockets.append(sock)
            except OSError:
                failed += 1
                sockets.append(None)
                if failed >= _CONNECT_ABORT_AFTER:
                    # Sustained connect failure: abort (plan section 2.5).
                    break
        if not any(sockets):
            return [(0, "error: all connections failed")] * count

        # Phase 2 — one window: every thread releases its final byte.
        results: List[Optional[Tuple[int, str]]] = [None] * count
        barrier = threading.Barrier(len([s for s in sockets if s]))
        lock = threading.Lock()

        def _fire(index: int) -> None:
            sock = sockets[index]
            if sock is None:
                results[index] = (0, "error: connect failed")
                return
            try:
                barrier.wait(timeout=request.timeout)
                sock.sendall(final)
                results[index] = _read_response(sock, request.timeout)
            except Exception as exc:  # noqa: BLE001 - failure is data
                with lock:
                    results[index] = (0, f"error: {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=_fire, args=(i,), daemon=True)
                   for i, s in enumerate(sockets) if s is not None]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(request.timeout * 2)
        window_ms = int((time.monotonic() - started) * 1000)

        out: List[Tuple[int, str]] = []
        for i in range(count):
            if sockets[i] is None:
                out.append((0, "error: connect failed"))
            else:
                out.append(results[i] or (0, "error: no response"))
        return out, window_ms  # type: ignore[return-value]
    finally:
        for sock in sockets:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def run_race(request: RaceRequest, *,
             dispatcher: Optional[Dispatcher] = None,
             transport: str = "auto") -> RaceResult:
    """Run ONE race window and account the results.

    ``dispatcher`` injects alternative transports (HTTP/2 single-packet,
    test fakes).  ``transport`` selects the default dispatcher when
    ``dispatcher`` is None:
      - ``"http1"`` (default for http://) — last-byte sync
      - ``"h2"`` or ``"h2-single-packet"`` — James Kettle H2 single-packet
      - ``"auto"`` — pick h2 for https, http1 for http
    """
    count = max(1, min(int(request.count), RACE_MAX_WINDOW))
    if dispatcher is None:
        if transport == "auto":
            from urllib.parse import urlparse
            transport = "h2" if urlparse(request.url).scheme == "https" else "http1"
        if transport in ("h2", "h2-single-packet", "h2c"):
            try:
                from tools.validation.h2_race_dispatcher import (
                    h2_single_packet_dispatcher, is_h2_available,
                )
                if is_h2_available():
                    started = time.monotonic()
                    raw = h2_single_packet_dispatcher(
                        dataclasses.replace(request, count=count)
                        if False else _replace_count(request, count)
                    )
                    window_ms = int((time.monotonic() - started) * 1000)
                else:
                    raise RuntimeError("H2 dispatcher not available")
            except Exception as exc:  # noqa: BLE001
                return RaceResult(attempted=count,
                                  error=f"H2: {type(exc).__name__}: {exc}")
        else:
            try:
                raw, window_ms = last_byte_dispatcher(request)  # type: ignore[misc]
            except Exception as exc:  # noqa: BLE001
                return RaceResult(attempted=count,
                                  error=f"{type(exc).__name__}: {exc}")
    else:
        # The window ceiling is an ENGINE property (plan section 2.5): it
        # holds for every transport, so injected dispatchers also receive
        # a clamped request.
        import dataclasses
        clamped = _replace_count(request, count)
        started = time.monotonic()
        try:
            raw = dispatcher(clamped)
        except Exception as exc:  # noqa: BLE001
            return RaceResult(attempted=count,
                              error=f"{type(exc).__name__}: {exc}")
        window_ms = int((time.monotonic() - started) * 1000)

    statuses = [int(s) for s, _body in raw]
    # All-transport-failure: surface the body's error text as the result
    # error (diagnostics without parsing bodies out of the caller's hands).
    error = ""
    if statuses and all(s == 0 for s in statuses):
        for _s, body in raw:
            text = str(body)
            if text.startswith("error:"):
                error = text
                break
    return RaceResult(
        attempted=len(statuses),
        statuses=statuses,
        successes=sum(1 for s in statuses if 200 <= s < 300),
        client_errors=sum(1 for s in statuses if 400 <= s < 500),
        server_errors=sum(1 for s in statuses if s >= 500),
        transport_errors=sum(1 for s in statuses if s == 0),
        window_ms=window_ms,
        error=error,
    )


def read_state(url: str, *, headers: Optional[Dict[str, str]] = None,
               reads: int = 5, timeout: float = 5.0
               ) -> List[Tuple[int, str]]:
    """Read-race-read proof tail: sequential GETs after the window.

    The caller diffs these snapshots against pre-race state to prove the
    action applied more (or fewer) times than the guard allows.
    """
    import urllib.error
    import urllib.request

    out: List[Tuple[int, str]] = []
    for _ in range(max(1, reads)):
        req = urllib.request.Request(url, headers=dict(headers or {}),
                                     method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out.append((resp.status, resp.read(4096).decode("utf-8",
                                                                "replace")))
        except urllib.error.HTTPError as exc:
            out.append((exc.code,
                        (exc.read(4096) if exc.fp else b"").decode(
                            "utf-8", "replace")))
        except OSError as exc:
            out.append((0, f"error: {type(exc).__name__}: {exc}"))
    return out
