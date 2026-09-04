#!/usr/bin/env python3
"""Engine facade (Phase 1.8): the replay engine's public surface.

    replay_request  -- structured mode: parse a captured/constructed request,
                       apply field-level mutations, send through the
                       governed raw backend, return facts + the delta.
    replay_raw      -- raw mode: send exact bytes verbatim (smuggling,
                       malformed framing, odd-case headers, Host override).

Both modes authorize fail-closed (scope gate) and send governed (governor);
both return FACTS (status/timing/reflection/errors/delta) — verdicts stay
with the F0.5 gate.  This module is what the CLI, the MCP bridge, and the
agents' http_replay / http_replay_raw tool surface call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from tools.runtime.replay.message import Request
from tools.runtime.replay.apply import apply_mutations, ApplyError
from tools.runtime.replay.backend_socket import (
    SendResult, send_raw, send_desync_pair, BackendRefused, split_host_port)
from tools.runtime.replay.observe import diff, observe
from tools.runtime.replay.governor import DEFAULTS as GOV_DEFAULTS, Governor

SCHEMA = "bugwolf-replay-engine/v1"


@dataclass
class ReplayReport:
    """Facts from one replay — the agent-facing payload."""

    mode: str                                    # "request" | "raw"
    host: str
    status: Optional[int] = None
    elapsed_ms: float = 0.0
    body_bytes: int = 0
    body_preview: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    reflection_markers: List[str] = field(default_factory=list)
    error_classes: List[str] = field(default_factory=list)
    delta: Optional[Dict[str, Any]] = None       # present when baseline+mutation
    transport_error: Optional[str] = None
    truncated: bool = False
    sent_bytes: str = ""                         # exactly what left the socket
    framing_conflict: Optional[str] = None       # request-level ambiguity fact
    curl_equivalent: str = ""                    # reproducibility hint

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "mode": self.mode,
            "host": self.host,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "body_bytes": self.body_bytes,
            "body_preview": self.body_preview[:400],
            "headers": self.headers,
            "reflections": self.reflection_markers,
            "error_classes": self.error_classes,
            "delta": self.delta,
            "transport_error": self.transport_error,
            "truncated": self.truncated,
            "sent_bytes": self.sent_bytes[:2000],
            "framing_conflict": self.framing_conflict,
            "curl_equivalent": self.curl_equivalent,
        }


def _headers_of(result: SendResult) -> Dict[str, str]:
    out: Dict[str, str] = {}
    head = result.raw_response.partition(b"\r\n\r\n")[0]
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            out[name.decode("latin-1").strip().lower()] = \
                value.decode("latin-1").strip()
    return out


def _body_preview(result: SendResult) -> str:
    return result.body.decode("latin-1", "replace")


def _curl_for(request: Request, host: str) -> str:
    """A curl approximation of the STRUCTURED send (raw mode intentionally
    has none — its whole point is that curl cannot express the bytes)."""
    _, port, tls = split_host_port(host, 80)
    scheme = "https" if tls else "http"
    parts = [f"curl -s -X {request.method} '{scheme}://{host}{request.target}'"]
    for h in request.headers:
        parts.append(f" -H '{h.render().decode('latin-1')}'")
    if request.body:
        parts.append(f" --data-binary '{request.body.decode('latin-1')}'")
    return " \\\n".join(parts)


def replay_request(raw_request: str, *,
                   host: Optional[str] = None,
                   mutations: Optional[List[Dict[str, Any]]] = None,
                   compare_baseline: bool = False,
                   markers: Optional[List[str]] = None,
                   governor: Optional[Governor] = None,
                   **send_kwargs) -> ReplayReport:
    """Structured replay: request text -> mutations -> governed send.

    With ``compare_baseline`` (and mutations present), a baseline send is
    made first and the report carries the deterministic delta — the
    three-gate confirm protocol's engine half.
    """
    request = Request.from_bytes(raw_request.encode("latin-1"))
    target_host = host or request.host
    if not target_host:
        raise ValueError("no host: pass host= or include a Host header")

    baseline_result: Optional[SendResult] = None
    if compare_baseline and mutations:
        baseline_result = send_raw(target_host, request.to_bytes(),
                                   governor=governor, **send_kwargs)

    variant = apply_mutations(request, mutations or []) \
        if mutations else request
    result = send_raw(target_host, variant.to_bytes(),
                      governor=governor, **send_kwargs)

    obs = observe(result, markers=markers)
    report = ReplayReport(
        mode="request",
        host=target_host,
        status=result.status,
        elapsed_ms=result.elapsed_ms,
        body_bytes=len(result.body),
        body_preview=_body_preview(result),
        headers=_headers_of(result),
        reflection_markers=obs.reflections,
        error_classes=obs.error_classes,
        transport_error=result.error,
        truncated=result.truncated,
        sent_bytes=variant.to_bytes().decode("latin-1"),
        framing_conflict=variant.framing_conflict,
        curl_equivalent=_curl_for(variant, target_host),
    )
    if baseline_result is not None:
        report.delta = diff(baseline_result, result,
                            markers=markers).to_dict()
    return report


def replay_raw(raw_request: bytes, *, host: str,
               markers: Optional[List[str]] = None,
               governor: Optional[Governor] = None,
               **send_kwargs) -> ReplayReport:
    """Raw replay: send these bytes verbatim. No parsing, no repair, no
    normalization — malformed framing is a FEATURE here (that is how
    desyncs are tested). The scope gate still authorizes the host."""
    result = send_raw(host, raw_request, governor=governor, **send_kwargs)
    obs = observe(result, markers=markers)
    # Best-effort framing analysis of the bytes we sent (fact, not verdict).
    conflict = None
    try:
        conflict = Request.from_bytes(raw_request).framing_conflict
    except ValueError:
        conflict = "unparseable request (sent verbatim)"
    return ReplayReport(
        mode="raw",
        host=host,
        status=result.status,
        elapsed_ms=result.elapsed_ms,
        body_bytes=len(result.body),
        body_preview=_body_preview(result),
        headers=_headers_of(result),
        reflection_markers=obs.reflections,
        error_classes=obs.error_classes,
        transport_error=result.error,
        truncated=result.truncated,
        sent_bytes=raw_request.decode("latin-1"),
        framing_conflict=conflict,
    )


def desync_probe(host: str, front_bytes: bytes, smuggled_bytes: bytes, *,
                 governor: Optional[Governor] = None,
                 **send_kwargs) -> Dict[str, Any]:
    """Two-send desync pattern (front then smuggled); returns both sends'
    facts. Verdicts (smuggled vs pipelined interpretation) stay upstream."""
    first, second = send_desync_pair(
        host, front_bytes, smuggled_bytes,
        governor=governor, **send_kwargs)
    return {
        "schema": SCHEMA,
        "mode": "desync-pair",
        "host": host,
        "front": {
            "status": first.status,
            "elapsed_ms": round(first.elapsed_ms, 2),
            "transport_error": first.error,
        },
        "smuggled": {
            "status": second.status,
            "elapsed_ms": round(second.elapsed_ms, 2),
            "body_preview": _body_preview(second)[:400],
            "headers": _headers_of(second),
            "transport_error": second.error,
        },
        "front_framing_conflict": Request.from_bytes(front_bytes).framing_conflict
        if _parsable(front_bytes) else "unparseable front bytes",
    }


def _parsable(raw: bytes) -> bool:
    try:
        Request.from_bytes(raw)
        return True
    except ValueError:
        return False
