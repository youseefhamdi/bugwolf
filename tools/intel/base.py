#!/usr/bin/env python3
"""Intel lane base (INTEGRATION_PLAN Phase E, v1.28).

Architecture ported from Agent-Reach's ``Channel`` ABC (MIT, attributed):
ordered backend candidates with a user override that can never hide
working backends, a ``check()`` that must REALLY probe ("which() alone is
NOT proof of health"), and a doctor that degrades per channel and scrubs
credentials from every message.

BugWolf's additions (the opsec gates the lane exists under):

  * the lane is DEFAULT-OFF: nothing here runs unless the mission spec
    or the understand CLI enables it explicitly;
  * ZERO credentials: channels authenticate with nothing — a channel that
    needs login/cookies is out of scope for v1 (AR's own cookie
    discipline, cited as the reason);
  * third-party backends (r.jina.ai) are fallback-only and documented in
    ``docs/INTEL_TRANSPARENCY.md``;
  * results are FACTS with provenance — they may raise a surface rank by
    a bounded weight but can never park/unpark a coverage class, alter
    the scope gate, or touch the governor.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bugwolf-intel/v1"

# Third-party backends documented in docs/INTEL_TRANSPARENCY.md.  A
# backend not listed here and not "direct" must be added to that doc
# before it can serve (enforced by the release test).
THIRD_PARTY_BACKENDS = {"jina"}
JINA_PREFIX = "https://r.jina.ai/"

_SECRET_RE = re.compile(
    r"(?:bearer\s+|token[=:\s]+|api[_-]?key[=:\s]+|authorization[=:\s]+)"
    r"([A-Za-z0-9._\-]{8,})", re.IGNORECASE)


def scrub_message(message: str) -> str:
    """Credential scrubbing for doctor/user-facing messages (AR pattern:
    the output boundary scrubs EVERY message before render)."""
    return _SECRET_RE.sub(lambda m: m.group(0)[:12] + "...", str(message))


class IntelResult(dict):
    """One fetched external fact with provenance."""

    @classmethod
    def make(cls, *, channel: str, backend: str, url: str,
             status: int, body: str, fetched_at: str) -> "IntelResult":
        return cls(channel=channel, backend=backend, url=url,
                   status=status, body=body[:20000],
                   fetched_at=fetched_at, source="external-intel")


class IntelChannel(ABC):
    """One external-intel platform.  See module docstring for the opsec
    gates.  Backends are ORDERED: ``backends[0]`` is preferred, the rest
    are fallbacks."""

    name: str = ""
    description: str = ""
    tier: int = 2                 # 0 = zero-config, 1 = free key, 2 = setup
    backends: List[str] = ["direct"]

    #: Backend actually serving right now; set by check(), None if dead.
    active_backend: Optional[str] = None

    @abstractmethod
    def can_handle(self, url: str) -> bool:
        """Does this URL belong to this channel?"""

    def ordered_backends(self, config: Optional[Dict[str, Any]] = None
                         ) -> List[str]:
        """Candidate backends in probe order, honoring the user override
        (config key ``<name>_backend`` / env ``<NAME>_BACKEND``).  An
        unknown override is ignored so a stale setting can never hide
        working backends (AR's rule)."""
        candidates = list(self.backends)
        override = None
        if config:
            override = config.get(f"{self.name}_backend")
        if override and override in candidates:
            candidates.remove(override)
            candidates.insert(0, override)
        return candidates

    @abstractmethod
    def fetch_backend(self, url: str, backend: str) -> Tuple[int, str]:
        """Fetch via one named backend.  Returns (status, body).

        Implementations MUST be stdlib-only and credential-free.  A
        backend failure raises or returns a non-200; the channel falls
        through to the next backend."""

    def check(self, config: Optional[Dict[str, Any]] = None
              ) -> Tuple[str, str]:
        """Health check via a REAL probe of the preferred backend (AR's
        rule: a which()-style existence check is not proof of health).
        Returns (status, message) with status in ok/warn/off/error."""
        last = "no backends"
        for backend in self.ordered_backends(config):
            try:
                status, body = self.fetch_backend(self.probe_url(), backend)
            except Exception as exc:  # noqa: BLE001 - degrade, don't die
                last = f"{backend}: {type(exc).__name__}"
                continue
            if status == 200:
                self.active_backend = backend
                return "ok", scrub_message(
                    f"{backend} serving ({len(body)}B probe)")
            last = f"{backend}: status {status}"
        self.active_backend = None
        return "warn", scrub_message(f"no backend answered ({last})")

    def probe_url(self) -> str:
        """The URL used by check()'s real probe (defaults to example.com)."""
        return "https://example.com/"

    def fetch(self, url: str,
              config: Optional[Dict[str, Any]] = None) -> IntelResult:
        """Fetch with ordered-backend failover.  Raises on total failure
        (the caller records the dead channel as a fact, not a crash)."""
        import time
        last_error = "no backends"
        for backend in self.ordered_backends(config):
            try:
                status, body = self.fetch_backend(url, backend)
            except Exception as exc:  # noqa: BLE001 - try next backend
                last_error = f"{backend}: {type(exc).__name__}"
                continue
            if status == 200 and body:
                self.active_backend = backend
                return IntelResult.make(
                    channel=self.name, backend=backend, url=url,
                    status=status, body=body,
                    fetched_at=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime()))
            last_error = f"{backend}: status {status}"
        raise RuntimeError(f"intel channel {self.name!r} failed: "
                           f"{last_error}")


def iter_channels() -> List[IntelChannel]:
    """The shipped channel registry (singleton-ish: fresh instances)."""
    from tools.intel.channels import build_channels
    return build_channels()


def doctor(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """AR's doctor semantics: check every channel, degrade per channel,
    scrub every message, report the active backend."""
    results: Dict[str, Any] = {}
    for channel in iter_channels():
        try:
            status, message = channel.check(config)
            active = channel.active_backend
        except Exception as exc:  # noqa: BLE001 - one dead channel never
            status, active = "error", None        # kills the report
            message = f"check failed: {type(exc).__name__}"
        results[channel.name] = {
            "status": status, "description": channel.description,
            "message": scrub_message(message), "tier": channel.tier,
            "backends": list(channel.backends), "active_backend": active,
        }
    return {"schema": SCHEMA, "channels": results}
