#!/usr/bin/env python3
"""mitmproxy addon: capture target traffic to bugwolf's captures.jsonl
(master plan Phase 2.4 — the capture half of the capture→replay loop).

    mitmproxy -s tools/runtime/capture_addon.py \
        --set bugwolf_out=captures.jsonl \
        --set bugwolf_allow=+.target.example

Every request/response that crosses the proxy becomes one JSONL line:

    {"schema": "bugwolf-capture/v1", "id": 1, "kind": "request-response",
     "timestamp": "...", "method": "GET", "path": "/api/users/1",
     "host": "target.example", "port": 443, "scheme": "https",
     "status": 200,
     "request_raw":  "<byte-exact HTTP/1.1 wire text>",
     "response_raw": "<byte-exact HTTP/1.1 response>",
     "request_len":  N, "response_len": M,
     "framing_notes": ["..."],
     "transport_error": null}

The file is the whole contract: ``tools/runtime/capture_replay.py`` loads
it and replays each request through the governed raw-socket engine.  This
addon is deliberately SELF-CONTAINED — it imports nothing from bugwolf —
because it runs inside mitmproxy's interpreter, not ours.

Why the raw text is byte-exact: string tools normalize header case,
whitespace, and framing away — precisely what desync and cache-key
attacks need to survive.  Captures that cannot be replayed byte-exact
are noise; captures that can are evidence.

Hop-by-hop framing headers (Content-Length, Transfer-Encoding, Connection,
Host, ...) are WITHHELD from the emitted wire text: the replay engine's
``send_raw`` re-derives honest framing from the body it actually sends.
Their PRESENCE upstream is recorded as a ``framing_notes`` fact (e.g.
``transfer-encoding`` on an H2 stream is never valid per RFC 7540
§8.1.2.2 — the H2.CL pre-condition — and its withholding is documented).
"""

from __future__ import annotations

import datetime
import json
import time
from typing import Any, Dict, List, Optional

SCHEMA = "bugwolf-capture/v1"

# Hop-by-hop + framing + pseudo headers: withheld from the emitted wire
# text (send_raw owns framing).  Case-insensitive; h2 pseudo-headers
# included so an h2 flow's downgraded head cannot smuggle :authority.
_BLOCKED_HEADERS = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "proxy-connection", "te", "trailer", "upgrade", "host",
    ":authority", ":method", ":path", ":scheme", ":protocol",
}

_FRAMING_HEADERS = {"content-length", "transfer-encoding"}


class _CaptureWriter:
    """Appends one JSON object per line; crash-safe per record."""

    def __init__(self, path: str):
        self._path = path
        self._fh = None                     # open lazily, on first record
        self.count = 0

    def write(self, record: Dict[str, Any]) -> None:
        if self._fh is None:
            self._fh = open(self._path, "a", encoding="utf-8")  # noqa: SIM115
        self._fh.write(json.dumps(record, sort_keys=True,
                                  ensure_ascii=True, default=str) + "\n")
        self._fh.flush()
        self.count += 1

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            finally:
                self._fh = None


def _framing_notes(headers: Any) -> List[str]:
    """Facts about the ORIGINAL headers (before blocking).  Not verdicts."""
    names = [k.lower() for k in headers.keys()]
    notes: List[str] = []
    if "transfer-encoding" in names:
        notes.append("transfer-encoding present upstream; withheld from "
                     "replay wire text (framing re-derived by send_raw)")
    if "content-length" in names and "transfer-encoding" in names:
        notes.append("content-length and transfer-encoding both present "
                     "upstream (RFC 7230 3.3.3 ambiguity candidate)")
    return notes


def _blocked_present(headers: Any) -> set:
    return {k.lower() for k in headers.keys()} & _BLOCKED_HEADERS


class CaptureAddon:
    """mitmproxy addon: flow -> captures.jsonl (one line per exchange)."""

    def __init__(self) -> None:
        self._writer: Optional[_CaptureWriter] = None
        self._out_path = "captures.jsonl"
        self._allow: List[str] = []
        self._seq = 0

    # -- mitmproxy option plumbing (only called by real mitmproxy) --------

    def load(self, loader) -> None:  # noqa: ANN001 - mitmproxy API
        loader.add_option(
            name="bugwolf_out", typespec=str, default="captures.jsonl",
            help="captures.jsonl output path")
        loader.add_option(
            name="bugwolf_allow", typespec=[str], default=[],
            help="capture only hosts matching these suffix/wildcard "
                 "entries (empty: capture everything)")

    def configure(self, updated) -> None:  # noqa: ANN001
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        # Re-read options lazily via mitmproxy ctx when present.
        try:
            from mitmproxy import ctx as _ctx  # noqa: PLC0415
            self._out_path = _ctx.options.bugwolf_out
            self._allow = list(_ctx.options.bugwolf_allow)
        except Exception:                    # noqa: BLE001 - embedded use
            pass

    # -- allow-list (suffix match; "*.target.example" and "+.target.example"
    #    both reduce to the suffix form) ------------------------------------

    def _allowed(self, host: str) -> bool:
        if not self._allow:
            return True
        host = (host or "").lower()
        for entry in self._allow:
            suffix = str(entry).strip().lower()
            for token in ("+.", "*.", "."):
                if suffix.startswith(token):
                    suffix = suffix[len(token):]
                    break
            if not suffix:
                continue
            if host == suffix or host.endswith("." + suffix):
                return True
        return False

    def _writer_for(self) -> _CaptureWriter:
        if self._writer is None:
            self._writer = _CaptureWriter(self._out_path)
        return self._writer

    # -- flow -> record ----------------------------------------------------

    def _request_wire(self, request) -> str:  # noqa: ANN001
        """Byte-exact downgraded HTTP/1.1 request text.

        Headers are emitted verbatim (original case, original order)
        except the blocked framing/hop-by-hop set; the body is the raw
        upstream bytes.  Latin-1 round-trip: every byte value survives.
        """
        lines = [f"{request.method} {request.path} HTTP/1.1"]
        for name, value in request.headers.items():
            if name.lower() in _BLOCKED_HEADERS:
                continue
            lines.append(f"{name}: {value}")
        head = "\r\n".join(lines) + "\r\n\r\n"
        body = request.raw_content or b""
        return head + body.decode("latin-1")

    def _response_wire(self, response) -> str:  # noqa: ANN001
        reason = getattr(response, "reason", "") or ""
        lines = [f"HTTP/1.1 {response.status_code} {reason}".rstrip()]
        for name, value in response.headers.items():
            if name.lower() in _BLOCKED_HEADERS:
                continue
            lines.append(f"{name}: {value}")
        head = "\r\n".join(lines) + "\r\n\r\n"
        body = response.raw_content or b""
        return head + body.decode("latin-1")

    def _base_record(self, request, kind: str) -> Dict[str, Any]:  # noqa: ANN001
        self._seq += 1
        return {
            "schema": SCHEMA,
            "id": self._seq,
            "kind": kind,
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "method": str(request.method),
            "path": str(request.path),
            "host": str(request.host),
            "port": int(request.port or 0),
            "scheme": str(request.scheme),
            "request_raw": self._request_wire(request),
            "framing_notes": _framing_notes(request.headers),
            "transport_error": None,
        }

    # -- mitmproxy event handlers ------------------------------------------

    def request(self, flow) -> None:  # noqa: ANN001
        """Request-only record (connection errors: no response arrives)."""
        if not self._allowed(flow.request.host):
            return
        record = self._base_record(flow.request, "request-only")
        record["status"] = None
        record["response_raw"] = ""
        record["request_len"] = len(flow.request.raw_content or b"")
        record["response_len"] = 0
        self._writer_for().write(record)

    def response(self, flow) -> None:  # noqa: ANN001
        if not self._allowed(flow.request.host):
            return
        request = flow.request
        response = flow.response
        record = self._base_record(request, "request-response")
        record["status"] = int(response.status_code)
        record["response_raw"] = self._response_wire(response)
        record["request_len"] = len(request.raw_content or b"")
        record["response_len"] = len(response.raw_content or b"")
        self._writer_for().write(record)

    def error(self, flow) -> None:  # noqa: ANN001
        if flow is None or flow.request is None:
            return
        if not self._allowed(flow.request.host):
            return
        if flow.response is not None:        # response() already recorded it
            return
        record = self._base_record(flow.request, "request-only")
        record["status"] = None
        record["response_raw"] = ""
        record["request_len"] = len(flow.request.raw_content or b"")
        record["response_len"] = 0
        message = flow.error if isinstance(flow.error, str) else getattr(
            flow.error, "message", "") or "connection error"
        record["transport_error"] = str(message)
        self._writer_for().write(record)

    def done(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None


# Module-level addon instance: `mitmproxy -s capture_addon.py` finds it.
addons = [CaptureAddon()]


# -- standalone smoke mode (no mitmproxy): synthesize two sample lines -----
if __name__ == "__main__":                 # pragma: no cover
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "captures.sample.jsonl"
    writer = _CaptureWriter(out)
    started = time.time()
    writer.write({
        "schema": SCHEMA, "id": 1, "kind": "request-response",
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "method": "GET", "path": "/api/users/1", "host": "target.example",
        "port": 80, "scheme": "http", "status": 200,
        "request_raw": "GET /api/users/1 HTTP/1.1\r\n"
                       "accept: application/json\r\n\r\n",
        "response_raw": "HTTP/1.1 200 OK\r\ncontent-type: "
                        "application/json\r\n\r\n{\"id\": 1}",
        "request_len": 0, "response_len": 9,
        "framing_notes": [], "transport_error": None,
    })
    writer.close()
    print(f"wrote 1 sample record to {out} in {time.time() - started:.3f}s")
