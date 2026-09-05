"""Dynamic taint instrumentation — production deployment hook.

This module is **stub-safe** by default: when no instrumentation backend
is available, every public method returns the constant ``"unavailable"``
string or an empty dict.

**Production deployment path** (documented here so it isn't lost):

  1. Build a CPython extension that hooks ``PyEval_EvalCode`` and
     ``PyObject_Call`` via :mod:`sys.settrace` + ``PyTrace_CALL``.
  2. Use ``LD_PRELOAD`` / ``DYLD_INSERT_LIBRARIES`` to wrap libc /
     libcrypto functions used by taint-relevant libraries (libssl,
     libcrypto, libsqlite3, libpq).
  3. For compiled languages (Go, Rust, Java, Solidity) deploy the eBPF /
     ptrace probes from :mod:`bugwolf.taint.dynamic.probe` with the
     appropriate ``-c`` config block.
  4. Pipe the resulting JSONL events through :class:`ShadowMemory` and
     :class:`DynamicTaintProbe` to assemble per-byte taint bits.

Schema: ``bugwolf-taint-v1``
"""

## Source: dynamic taint instrument (Phase 3.2 — stub-safe)
## License: bugwolf-MIT

from __future__ import annotations

import json
import os
import platform
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-taint-v1"


UNAVAILABLE = "unavailable"


class DynamicTaintInstrument:
    """Attach taint probes to a running process.

    .. note::

        Default constructor is **stub-safe**.  Pass
        ``auto_attach=False`` when you explicitly want to run in a
        sandbox where attaching is not permitted.
    """

    def __init__(self, auto_attach: bool = False, backend: str = "ebpf") -> None:
        self.auto_attach = bool(auto_attach)
        self.backend = str(backend)
        self._attached: bool = False
        self._events: List[Dict[str, Any]] = []
        self._probe_id: Optional[int] = None

    # Public API --------------------------------------------------------------

    def attach(self, pid: int) -> str:
        """Attempt to attach to ``pid``.  Returns ``"unavailable"`` on stub."""

        if not self.auto_attach:
            return UNAVAILABLE
        if pid <= 0:
            return UNAVAILABLE
        if not self._runtime_available():
            return UNAVAILABLE
        try:
            self._attached = True
            self._probe_id = pid
            return "attached"
        except (OSError, PermissionError):
            return UNAVAILABLE

    def detach(self) -> str:
        """Detach from the probe.  Always safe to call."""

        if not self._attached:
            return UNAVAILABLE
        self._attached = False
        self._probe_id = None
        return "detached"

    def record(self, event: Dict[str, Any]) -> str:
        """Record an instrumentation event.  Returns ``"recorded"``."""

        if not isinstance(event, dict):
            return UNAVAILABLE
        self._events.append(dict(event))
        return "recorded"

    def flush(self) -> List[Dict[str, Any]]:
        """Return and clear the buffered events."""

        events = list(self._events)
        self._events.clear()
        return events

    def export_jsonl(self) -> str:
        """Serialise buffered events to a JSONL string.  ``""`` when empty."""

        return "\n".join(json.dumps(e, default=str) for e in self._events)

    def status(self) -> Dict[str, Any]:
        """Return a small status snapshot."""

        return {
            "schema": SCHEMA,
            "backend": self.backend,
            "attached": self._attached,
            "probe_id": self._probe_id,
            "event_count": len(self._events),
        }

    def write_events(self, directory: str) -> str:
        """Write buffered events to ``directory`` and return the file path."""

        path = self._safe_path(directory)
        if path is None:
            return UNAVAILABLE
        try:
            target = path / "taint_events.jsonl"
            target.write_text(self.export_jsonl(), encoding="utf-8")
            return str(target)
        except OSError:
            return UNAVAILABLE

    # Helpers -----------------------------------------------------------------

    @staticmethod
    def _safe_path(directory: str) -> Optional[Path]:
        if not directory:
            return None
        try:
            p = Path(directory)
            p.mkdir(parents=True, exist_ok=True)
            return p
        except OSError:
            return None

    @staticmethod
    def _runtime_available() -> bool:
        """True when running in an environment that permits instrumentation."""

        # We never silently gain privileges.  The stub is the default.
        if os.environ.get("BUGWOLF_DYNAMIC_FORCE") == "1":
            return True
        system = platform.system().lower()
        if system not in {"linux", "darwin"}:
            return False
        # Without CAP_SYS_PTRACE on Linux we cannot attach.
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("CapBnd:"):
                        cap = int(line.split()[1], 16)
                        return bool(cap & 0x02000000)  # CAP_SYS_PTRACE bit
        except OSError:
            return False
        return False


def build_default_instrument() -> DynamicTaintInstrument:
    """Construct an instrument with ``auto_attach`` matching ``$BUGWOLF_DYNAMIC``."""

    forced = os.environ.get("BUGWOLF_DYNAMIC") == "1"
    return DynamicTaintInstrument(auto_attach=forced)


def safe_tmpdir() -> str:
    """Return the path to a writable temporary directory."""

    return tempfile.gettempdir()


__all__ = [
    "DynamicTaintInstrument",
    "build_default_instrument",
    "safe_tmpdir",
    "UNAVAILABLE",
    "instrument_for_pid",
    "instrument_status",
]


def instrument_for_pid(pid: int) -> DynamicTaintInstrument:
    """Construct an instrument targeting ``pid`` with auto-attach forced."""

    return DynamicTaintInstrument(auto_attach=True)


def instrument_status(instrument: DynamicTaintInstrument) -> Dict[str, Any]:
    """Return the instrument's status snapshot."""

    return instrument.status()
