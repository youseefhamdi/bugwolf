"""Dynamic taint probe — collects taint events from a running process.

A *probe* listens on a socket (or ptrace channel) for taint events
emitted by the instrumentation layer and forwards them to a
:class:`ShadowMemory` instance.

This implementation is **stub-safe**: when the runtime is unavailable,
all public methods return the constant ``"unavailable"``.

**Production deployment path**:

  * eBPF program attached via ``bpf()`` syscall that emits per-event
    payloads through a perf ring buffer.
  * Go / Rust / Java probes connect over a UNIX socket and stream JSONL
    payloads (see ``probes.jsonl.schema``).
  * Solidity probes use the ``debug_traceCall`` JSON-RPC method.

Schema: ``bugwolf-taint-v1``
"""

## Source: dynamic taint probe (Phase 3.2 — stub-safe)
## License: bugwolf-MIT

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-taint-v1"


UNAVAILABLE = "unavailable"


class DynamicTaintProbe:
    """Collect taint events from an attached probe endpoint."""

    def __init__(self, endpoint: str = "", poll_interval: float = 0.05) -> None:
        self.endpoint = str(endpoint)
        self.poll_interval = float(poll_interval)
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._socket: Optional[socket.socket] = None

    # Public API --------------------------------------------------------------

    def start(self) -> str:
        """Start polling.  ``"unavailable"`` when no endpoint is configured."""

        if not self.endpoint:
            return UNAVAILABLE
        if self._running:
            return "already-running"
        self._running = True
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()
        return "started"

    def stop(self) -> str:
        """Stop polling.  Always safe."""

        if not self._running:
            return UNAVAILABLE
        self._running = False
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        return "stopped"

    def collect(self) -> List[Dict[str, Any]]:
        """Snapshot and clear the collected events."""

        with self._lock:
            events = list(self._events)
            self._events.clear()
            return events

    def push(self, event: Dict[str, Any]) -> str:
        """Inject a single event.  Used in tests."""

        if not isinstance(event, dict):
            return UNAVAILABLE
        with self._lock:
            self._events.append(dict(event))
        return "received"

    def count(self) -> int:
        """Number of buffered events."""

        with self._lock:
            return len(self._events)

    def status(self) -> Dict[str, Any]:
        """Return a status snapshot."""

        with self._lock:
            return {
                "schema": SCHEMA,
                "endpoint": self.endpoint,
                "running": self._running,
                "buffered": len(self._events),
            }

    # Internals ---------------------------------------------------------------

    def _poll(self) -> None:
        """Background poll loop — connects and reads until stopped."""

        while self._running:
            try:
                self._read_once()
            except OSError:
                # Connection died; back off and retry.
                time.sleep(self.poll_interval)
            else:
                time.sleep(self.poll_interval)

    def _read_once(self) -> None:
        """Open the socket once and read a single JSON line."""

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.poll_interval)
            sock.connect(self.endpoint)
            self._socket = sock
            chunk = sock.recv(65536)
        except OSError:
            return
        if not chunk:
            return
        try:
            line = chunk.decode("utf-8", errors="replace").strip().splitlines()
            for raw in line:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    with self._lock:
                        self._events.append(obj)
        except (ValueError, json.JSONDecodeError):
            return
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._socket = None


def probe_for_file(filepath: str) -> DynamicTaintProbe:
    """Build a probe for a UNIX socket named after ``filepath``."""

    name = Path(filepath).name if filepath else "probe"
    endpoint = f"/tmp/bugwolf-taint-{name}.sock"
    return DynamicTaintProbe(endpoint=endpoint)


__all__ = [
    "DynamicTaintProbe",
    "probe_for_file",
    "UNAVAILABLE",
    "drain",
    "push_all",
]


def drain(probe: DynamicTaintProbe) -> List[Dict[str, Any]]:
    """Drain all buffered events from ``probe``."""

    return probe.collect()


def push_all(probe: DynamicTaintProbe, events: List[Dict[str, Any]]) -> int:
    """Push every event in ``events`` to ``probe``.  Returns the count."""

    count = 0
    for event in events:
        if probe.push(event) == "received":
            count += 1
    return count
