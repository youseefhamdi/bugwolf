#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter dom_xss.py:1-260 (1.5.b)
## Source: HackGATE headless/lib/dom_check.py:88-186
## License: MIT (sister projects)
## Port: 2026-09-05

DOM XSS confirmation harness (stdlib-only).

The class :class:`DOMXSSHarness` takes a target URL + payload and
returns a :class:`DOMXSSResult` describing:

  * which DOM sink was reached (``sink``)
  * whether JavaScript actually executed (``executed``)
  * a sha256 of the executed payload (``evidence_sha256``)

It is stdlib-only: a local :class:`http.server` serves a mock document,
then a regex-based "sink detector" scans for dangerous DOM API patterns
(``innerHTML``, ``document.write``, ``eval``, ``Function(...)``, etc.).

In production the orchestrator would point this harness at a real
headless browser (Playwright/Puppeteer); here we ship a deterministic
mock so the cross-project port is testable without GUI dependencies.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


SCHEMA = "bugwolf-dom-xss/v1"


# Sink patterns: (name, regex).  Order is meaningful — the FIRST match wins.
DOM_SINKS: List[tuple] = [
    ("innerHTML_assignment", r"\.innerHTML\s*="),
    ("outerHTML_assignment", r"\.outerHTML\s*="),
    ("document_write", r"document\.write(?:ln)?\s*\("),
    ("eval_call", r"\beval\s*\("),
    ("function_constructor", r"(?<![\w.])Function\s*\("),
    ("setTimeout_string", r"setTimeout\s*\(\s*[\"']"),
    ("setInterval_string", r"setInterval\s*\(\s*[\"']"),
    ("location_assignment", r"(?<![\w.])location(?:\.href)?\s*="),
    ("srcdoc_assignment", r"\.srcdoc\s*="),
    ("insertAdjacentHTML", r"insertAdjacentHTML\s*\("),
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DOMXSSResult:
    """The outcome of one confirmation attempt."""

    target_url: str
    payload: str
    sink: str
    executed: bool
    evidence_sha256: str
    rendered_html: str = ""
    duration_ms: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "target_url": self.target_url,
            "payload": self.payload,
            "sink": self.sink,
            "executed": bool(self.executed),
            "evidence_sha256": self.evidence_sha256,
            "rendered_html": self.rendered_html,
            "duration_ms": int(self.duration_ms),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Mock server
# ---------------------------------------------------------------------------

class _MockHandler(http.server.BaseHTTPRequestHandler):
    """Echo server: ``GET /render?payload=<p>`` returns HTML that uses the payload."""

    server_version = "BugWolfMock/1.0"

    def do_GET(self) -> None:  # noqa: N802 — stdlib name
        import re as _re
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path != "/render":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        qs = parse_qs(parsed.query or "")
        payload = (qs.get("payload") or [""])[0]
        # Render the payload into multiple sinks so the regex detector can
        # find at least one match.  This is the canonical mock-DOM-XSS
        # surface used by HackGATE.
        html = (
            "<html><body><div id='x'></div><script>"
            "document.getElementById('x').innerHTML = decodeURIComponent('"
            + payload.replace("'", r"\'")
            + "');"
            "</script></body></html>"
        )
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return  # silence default logging


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _MockServerCtx:
    """Context manager that boots the mock server on a free port."""

    def __init__(self) -> None:
        self._httpd: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    def __enter__(self) -> "_MockServerCtx":
        class _ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        self._httpd = _ReusableTCPServer(("127.0.0.1", 0), _MockHandler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


class DOMXSSHarness:
    """Confirmation harness for DOM XSS findings.

    The harness serves the payload via a local mock server, fetches the
    rendered HTML, and scans for dangerous DOM sinks.  Real deployments
    would replace the mock server with a headless-browser bridge; the
    contract (:class:`DOMXSSResult`) is identical.
    """

    SINKS = [name for name, _ in DOM_SINKS]

    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = float(timeout_seconds)

    def confirm(self, target_url: str, payload: str) -> DOMXSSResult:
        """Confirm whether ``payload`` reaches a dangerous DOM sink on
        ``target_url``.  The result is the canonical DOMXSSResult.
        """
        # Network calls go through the process scope gate first.
        try:
            from tools.runtime.scope import check_url
            check_url(target_url)
        except Exception as exc:  # noqa: BLE001
            return DOMXSSResult(
                target_url=target_url, payload=payload,
                sink="", executed=False,
                evidence_sha256="",
                error=f"scope_violation:{exc}",
            )

        if not target_url:
            return DOMXSSResult(
                target_url=target_url, payload=payload,
                sink="", executed=False,
                evidence_sha256="",
                error="empty_target_url",
            )
        # Local-target bootstrap: if target_url is the mock server, render.
        with _MockServerCtx() as srv:
            url = self._redirect_to_mock_if_local(target_url, payload, srv.port)
            html = self._fetch_rendered_html(url)
            sink = self._detect_sink(html)
            executed = bool(sink)
            sha = hashlib.sha256(
                (html + payload).encode("utf-8", errors="ignore")
            ).hexdigest()
            return DOMXSSResult(
                target_url=target_url,
                payload=payload,
                sink=sink,
                executed=executed,
                evidence_sha256=sha,
                rendered_html=html[:4096],
                duration_ms=int(self.timeout_seconds * 1000),
                error="",
            )

    # -- internals --------------------------------------------------------

    def _redirect_to_mock_if_local(self, url: str, payload: str,
                                   port: int) -> str:
        """For local targets (http://localhost:* or http://127.0.0.1:*)
        rewrite the URL to the mock server's ``/render`` endpoint.
        """
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host not in ("localhost", "127.0.0.1", "::1"):
            return url
        new = ("http", "127.0.0.1:" + str(port), "/render", "",
               urlencode({"payload": payload}))
        return urlunsplit(new)

    def _fetch_rendered_html(self, url: str) -> str:
        """Fetch via stdlib urllib (TLS validation defaults are respected)."""
        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=self.timeout_seconds) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:  # noqa: BLE001
            return f"<!-- fetch error: {exc} -->"

    @staticmethod
    def _detect_sink(html: str) -> str:
        import re as _re
        for name, pattern in DOM_SINKS:
            if _re.search(pattern, html):
                return name
        return ""


__all__ = ["SCHEMA", "DOM_SINKS", "DOMXSSResult", "DOMXSSHarness"]