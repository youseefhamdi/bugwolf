"""Operational security helpers (plan R-OPSEC + R-15 — Phase 1.4).

The plan's R-OPSEC rule mandates:

  * a rotating User-Agent pool so probes do not stamp every outbound
    request with a BugWolf-identifying UA;
  * strict file permissions on the local proxy / cookie cache
    (chmod 0o600, fail-closed if chmod fails);
  * a Tor control-port safety check that refuses empty-auth control
    channels;
  * a UA redaction helper used before the runner sends headers to any
    third-party API (Burp Collaborator, OAST listener, etc.).

All helpers are stdlib-only.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from pathlib import Path
from typing import Dict, List, Optional, Sequence

SCHEMA = "bugwolf-opsec-v1"

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# User-Agent pool.
# ---------------------------------------------------------------------------


# Common, non-identifying desktop browser UAs.  Order matters — the
# deterministic pick walks this list.  Adding more is fine; we keep
# >= 10 entries per plan R-OPSEC.
_USER_AGENTS: tuple = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
)


class UAPool:
    """Deterministic rotating User-Agent pool."""

    def __init__(self, *, agents: Optional[Sequence[str]] = None) -> None:
        self._agents: tuple = tuple(agents) if agents else _USER_AGENTS
        if len(self._agents) < 10:
            raise ValueError(
                f"UAPool requires at least 10 User-Agent strings; "
                f"got {len(self._agents)}")
        self._index = 0

    @property
    def agents(self) -> tuple:
        return self._agents

    def pick(self, *, seed: Optional[str] = None) -> str:
        """Return the next UA, optionally seeded for determinism.

        ``seed`` defaults to ``os.environ['BUGWOLF_UA_SEED']``; if that
        env var is unset, a time-derived hash is used so two picks at the
        same wall-clock second return the same UA but picks spaced apart
        return different ones.  ``seed`` may be overridden by the caller
        (used by tests).
        """
        if seed is None:
            env = os.environ.get("BUGWOLF_UA_SEED")
            if env is not None:
                seed = env
            else:
                # time-based hash; same second ⇒ same UA
                import time as _time
                seed = str(int(_time.time()))
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "big") % len(self._agents)
        return self._agents[idx]

    def rotate(self) -> str:
        """Return the next UA in insertion order, advancing the cursor."""
        ua = self._agents[self._index]
        self._index = (self._index + 1) % len(self._agents)
        return ua


# ---------------------------------------------------------------------------
# File permissions for the local proxy / cookie cache.
# ---------------------------------------------------------------------------


def proxies_cache_permissions(path: Path) -> bool:
    """chmod 0o600 ``path``; fail-closed on permission errors.

    The plan requires the proxies cache file to be readable ONLY by the
    current user.  If ``path`` does not exist yet, it is created empty
    first.  If ``chmod`` raises (rare on POSIX; common on non-POSIX
    platforms such as Windows) the function returns ``False`` so the
    caller can abort the mission.
    """
    if not isinstance(path, Path):
        path = Path(path)
    try:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            # Touch the file so chmod has something to act on.
            fd = os.open(str(path),
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                         0o600)
            os.close(fd)
        os.chmod(str(path), 0o600)
    except (OSError, PermissionError) as exc:
        _logger.warning("proxies_cache_permissions failed for %s: %r",
                        path, exc)
        return False
    # Verify the resulting mode (defence-in-depth — chmod can be a no-op
    # on some filesystems).
    try:
        st = os.stat(str(path))
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            # World or group readable — fail closed.
            _logger.warning("proxies_cache_permissions: residual mode %#o "
                            "on %s", mode, path)
            return False
    except OSError as exc:
        _logger.warning("proxies_cache_permissions: stat failed on %s: %r",
                        path, exc)
        return False
    return True


# ---------------------------------------------------------------------------
# Tor control-port safety check.
# ---------------------------------------------------------------------------


class TorControlAuthError(PermissionError):
    """Raised when the Tor control port refuses to authenticate."""


def tor_control_port_check(cookie_path: Path, *,
                           host: str = "127.0.0.1",
                           port: int = 9051) -> bool:
    """Verify that the Tor control port is NOT open with empty auth.

    The plan R-15 rule requires the operator to either present a valid
    cookie OR an explicit ``HASHEDPASSWORD`` line.  An empty-auth control
    port is a protocol violation that the safe-by-default policy must
    REFUSE.

    Returns ``True`` only if the control port is reachable AND requires
    non-empty authentication.  Returns ``False`` (and logs) when the
    port is unreachable — that is not, on its own, a violation; the
    caller decides whether to retry.
    """
    if not isinstance(cookie_path, Path):
        cookie_path = Path(cookie_path)
    try:
        import socket as _socket
        with _socket.create_connection((host, port), timeout=2.0) as sock:
            sock.sendall(b"AUTHENTICATE\r\n")
            data = sock.recv(512)
            if not data:
                return False
            head = data[:64]
            # RFC: 250 = OK, 510 = Auth required, 512 = Incorrect creds.
            # Empty-auth control ports return ``250 OK`` straight away;
            # we REFUSE that path.
            if head.startswith(b"250 "):
                _logger.warning(
                    "tor_control_port_check: empty-auth control port "
                    "rejected at %s:%s", host, port)
                return False
            if head.startswith(b"510 ") or head.startswith(b"512 "):
                # Server requires authentication — verify cookie exists.
                if not cookie_path.exists():
                    _logger.warning(
                        "tor_control_port_check: cookie missing at %s",
                        cookie_path)
                    return False
                try:
                    content = cookie_path.read_bytes()
                except OSError as exc:
                    _logger.warning(
                        "tor_control_port_check: cookie read failed: %r",
                        exc)
                    return False
                if not content:
                    return False
                return True
            return False
    except (OSError, TimeoutError) as exc:
        _logger.debug("tor_control_port_check: control port unreachable: %r",
                      exc)
        return False


# ---------------------------------------------------------------------------
# UA redaction.
# ---------------------------------------------------------------------------


# UA tokens that identify BugWolf / outrider frameworks and MUST be
# stripped before a request leaves the process.  Matched case-insensitive.
_REDACT_UA_TOKENS = (
    "bugwolf",
    "outrider",
    "bug-wolf",
    "bugwolf/",
    "outrider/",
    "x-bugwolf",
)


def redact_ua(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of ``headers`` with framework-identifying UAs stripped.

    The redaction is case-insensitive and partial: any UA header whose
    value contains one of :data:`_REDACT_UA_TOKENS` is replaced with the
    empty string ``""`` (NOT deleted — many HTTP servers reject empty
    UA values, so this is the safer minimal scrub).
    """
    if not isinstance(headers, dict):
        raise TypeError(
            f"headers must be a dict; got {type(headers).__name__}")
    out: Dict[str, str] = {}
    for k, v in headers.items():
        key = str(k)
        val = v if isinstance(v, str) else str(v)
        low = val.lower()
        if any(tok in low for tok in _REDACT_UA_TOKENS):
            out[key] = ""
            continue
        out[key] = val
    return out


__all__ = [
    "SCHEMA",
    "UAPool",
    "proxies_cache_permissions",
    "TorControlAuthError",
    "tor_control_port_check",
    "redact_ua",
]