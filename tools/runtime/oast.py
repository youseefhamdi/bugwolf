#!/usr/bin/env python3
"""BugWolf OAST service (orchestrator plan v2, section 5.6 S1).

Self-hosted out-of-band testing service, the elite-loop parity layer:

    * every hypothesis/lead gets its own canary token ({LEAD-ID}-shaped
      label), so callbacks self-identify the lead that fired the probe;
    * the service persists interactions to disk (the durable registry) and
      publishes ``OAST_CALLBACK`` on the signal bus -- the event the plan's
      auto-lead rule binds to;
    * attribution: a callback carrying an unregistered canary is still
      recorded (evidence), but never attributed to a lead;
    * protocol note: the listener accepts plain HTTP canary hits
      (``GET /<token>`` or ``GET /<token>/<anything>``).  DNS-level
      interactions (interactsh-style) are the operator's deployed
      interactsh deployment -- this service is the in-process,
      dependency-free layer the mission runner owns end to end.

Deterministic tier: no model calls.  The poller re-reads the registry, so
attribution survives process restarts (the registry is the source of
truth, not memory).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.core.signal_bus import publish_or_warn
try:
    from tools.core.medium_safety import path_open_text
except Exception:  # pragma: no cover - tools.* not always importable
    def path_open_text(path, mode="r", **kw):  # type: ignore[no-redef]
        return open(path, mode, encoding=kw.get("encoding", "utf-8"),
                     errors=kw.get("errors", "replace"))

SCHEMA = "bugwolf-oast/v1"

_TOKEN_RE = re.compile(r"^[a-z0-9]{6,64}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canary_token(lead_id: str, project_root: Optional[str] = None) -> str:
    """Stable per-lead canary token: ``oast<12 hex of sha256(lead)>``."""
    digest = hashlib.sha256(
        f"{lead_id}:{project_root or ''}".encode()).hexdigest()[:12]
    return f"oast{digest}"


class OastRegistry:
    """Durable canary -> lead mapping + interaction log (JSONL, append-only).

    Lives under ``<project_root>/state/oast/``: ``registry.jsonl`` maps
    canary tokens to lead IDs; ``interactions.jsonl`` is the append-only
    interaction log.  Both survive restarts; the poller replays the tail.
    """

    def __init__(self, *, project_root: Optional[str] = None):
        root = Path(project_root or os.environ.get("BUGWOLF_PROJECT_ROOT", "."))
        self.dir = root / "state" / "oast"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.dir / "registry.jsonl"
        self.interactions_path = self.dir / "interactions.jsonl"
        self._lock = threading.Lock()

    # -- registration ---------------------------------------------------------

    def register(self, lead_id: str) -> str:
        """Bind one canary token to a lead; returns the token."""
        token = _canary_token(lead_id, str(self.dir.parent.parent))
        entry = {"token": token, "lead_id": lead_id, "ts": _now_iso()}
        with self._lock:
            with path_open_text(self.registry_path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        return token

    def lookup(self, token: str) -> Optional[str]:
        """Lead ID for a canary token, or None (unregistered = evidence only)."""
        if not self.registry_path.exists():
            return None
        found: Optional[str] = None
        with path_open_text(self.registry_path) as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if entry.get("token") == token:
                    found = entry.get("lead_id")
        return found

    # -- interactions -----------------------------------------------------------

    def record(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Persist one interaction (attribution included) and return it."""
        record = {"ts": _now_iso(), **interaction}
        with self._lock:
            with path_open_text(self.interactions_path, "a") as fh:
                fh.write(json.dumps(record) + "\n")
        return record

    def interactions(self, *, lead_id: Optional[str] = None) -> List[Dict]:
        """Replay the interaction log (optionally for one lead)."""
        if not self.interactions_path.exists():
            return []
        out: List[Dict] = []
        with path_open_text(self.interactions_path) as fh:
            for line in fh:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if lead_id is None or item.get("lead_id") == lead_id:
                    out.append(item)
        return out


class OastListener:
    """Minimal HTTP canary listener (ThreadingHTTPServer).

    Every ``GET /<token>[...]`` records an interaction; the response is a
    fixed body with no target-derived content.  Unregistered tokens are
    recorded as evidence with ``lead_id: None`` -- attribution requires
    registration, never guessed.
    """

    def __init__(self, registry: OastRegistry, host: str = "127.0.0.1",
                 port: int = 0, public_base_url: Optional[str] = None):
        """``host``/``port`` control the BIND (default loopback + ephemeral;
        never expose the listener beyond the operator's machine by default).
        ``public_base_url`` is what canary URLs ADVERTISE -- for a remote
        target the callback must traverse a tunnel/reverse proxy the
        operator owns (set BUGWOLF_OAST_PUBLIC_URL); advertising the raw
        bind address would make attribution silently impossible.
        """
        self.registry = registry
        self._public_base_url = (public_base_url or "").rstrip("/")
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # keep test output quiet
                pass

            def do_GET(self):
                # Route = path WITHOUT the query string (real callbacks
                # carry query params); the full path is preserved in the
                # interaction record as evidence.
                route = self.path.split("?", 1)[0]
                raw = route.strip("/").split("/")[0]
                if not _TOKEN_RE.match(raw):
                    self.send_response(404)
                    self.end_headers()
                    return
                lead_id = outer.registry.lookup(raw)
                outer.registry.record({
                    "token": raw, "lead_id": lead_id,
                    "transport": "http",
                    "source": self.client_address[0],
                    "path": self.path,
                })
                body = b'{"oast":"ack"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.host, self.port = self.httpd.server_address[:2]
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        daemon=True)

    @property
    def base_url(self) -> str:
        """The URL embedded in canaries: the public route when declared,
        else the local bind (loopback testing / local targets)."""
        if self._public_base_url:
            return self._public_base_url
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def canary_url(base: str, lead_id: str, *, project_root: Optional[str] = None,
               registry: Optional[OastRegistry] = None) -> str:
    """Build the per-lead canary URL for ``base`` (the OAST listener root).

    Registers the lead's canary when a registry is supplied (or resolvable
    from project_root) and returns ``<base>/<token>`` -- the URL to embed
    in probes (SSRF fetch, header value, payload echo).
    """
    reg = registry or OastRegistry(project_root=project_root)
    token = reg.register(lead_id)
    return f"{base.rstrip('/')}/{token}"


def poll_callbacks(registry: OastRegistry, *, since_count: int = 0,
                   project_root: Optional[str] = None,
                   publish: bool = True,
                   ) -> Tuple[List[Dict], int]:
    """Replay new interactions; publish OAST_CALLBACK per attributed hit.

    Returns (attributed_interactions, new_total).  Attribution: only
    interactions whose token resolves to a lead are published; unregistered
    canaries stay in the log as evidence (never attributed -- the plan's
    "no silent attribution" rule).  ``since_count`` is the caller's cursor
    into the append-only log (restart-safe).
    """
    all_hits = registry.interactions()
    new_hits = all_hits[since_count:]
    attributed: List[Dict] = []
    for hit in new_hits:
        lead_id = hit.get("lead_id")
        if not lead_id:
            continue
        attributed.append(hit)
        if publish:
            publish_or_warn(
                lead_id, "OAST_CALLBACK", "oast",
                {"lead_id": lead_id, "token": hit.get("token"),
                 "source": hit.get("source"), "path": hit.get("path"),
                 "ts": hit.get("ts")},
                project_root=project_root)
    return attributed, len(all_hits)


def wait_for_callbacks(registry: OastRegistry, lead_id: str, *,
                       timeout: float = 5.0, cursor: int = 0,
                       publish: bool = True) -> List[Dict]:
    """Block until ``lead_id``'s canary fires (or timeout).  Restart-safe:
    the cursor indexes the durable log, not memory."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        attributed, _total = poll_callbacks(registry, since_count=cursor,
                                            publish=publish)
        hits = [h for h in attributed if h.get("lead_id") == lead_id]
        if hits:
            return hits
        time.sleep(0.1)
    return []
