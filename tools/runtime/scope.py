#!/usr/bin/env python3
"""BugWolf operator scope gate (plan v2 section 2.4; readiness R1 fix).

Closes the first readiness warning: **authorization is now enforced at the
execution boundary.**  The gate is deny-by-default:

  * the mission target's own host is always authorized (declared by the
    operator in the MissionSpec);
  * loopback (localhost / 127.0.0.0/8 / ::1) is authorized when the target
    itself is local -- local campaigns must reach local stubs and the
    self-hosted OAST listener;
  * everything else requires an explicit operator scope file
    (``--scope scope.txt``, one host suffix per line, ``#`` comments);
  * the check runs inside :func:`tools.runtime.mission_runner.http_probe`
    -- the single choke point every HTTP lane shares -- so a payload that
    tricks a probe into fetching an out-of-scope host fails closed with a
    ``ScopeViolation`` (probe status 0, reason recorded) instead of one
    silent outbound request.

Design rules:
  * fail CLOSED: an unset gate denies everything except the bound target;
  * registrations are exact-host or dot-boundary suffix (``.example.com``
    matches ``api.example.com`` but never ``notexample.com``);
  * the gate is process-global but idempotent to re-bind: rebinding with
    the same target is a no-op, rebinding with a different target raises
    (one mission per process -- mixing targets is how scope accidents
    happen);
  * scope state is exported into the preflight/mission record so the
    operator can audit what was authorized at any point in time.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse

SCHEMA = "bugwolf-scope/v1"


class ScopeViolation(PermissionError):
    """Raised when a request would leave the operator-declared scope."""

    def __init__(self, url: str, host: str):
        self.url = url
        self.host = host
        super().__init__(
            f"out-of-scope request blocked: {host!r} is not authorized "
            f"(target-only + operator scope file); url={url!r}")


@dataclass
class ScopeGate:
    """Deny-by-default outbound authorization for one mission process."""

    target: str = ""
    extra_hosts: set = field(default_factory=set)
    _bound: bool = False
    _explicit: bool = False   # bound by the mission runner (not auto-bind)

    # -- binding -------------------------------------------------------------

    def bind(self, target: str, extra_hosts=None, *, force: bool = False) -> None:
        """Bind the gate to a mission target (+ optional extra allowed hosts).

        Idempotent for the same target.  ``force=True`` replaces a previous
        AUTO-bind (standalone probe default) but never an explicit mission
        bind -- mixing declared targets is the classic scope accident.
        """
        host = _host_of(target)
        if not host:
            raise ValueError(f"cannot bind scope gate: no host in {target!r}")
        if self._bound:
            if host == self.target:
                self._explicit = self._explicit or not force
                return
            if force and not self._explicit:
                self._bound = False
            else:
                raise RuntimeError(
                    f"scope gate already bound to {self.target!r}; refusing to "
                    f"rebind to {host!r} (one mission per process)")
        self.target = host
        for entry in extra_hosts or ():
            norm = _host_of(str(entry)) or str(entry).strip().lower()
            if norm:
                self.extra_hosts.add(norm)
        self._bound = True
        # bind() is the DECLARED-scope API; only check()'s inline auto-bind
        # is non-explicit (it sets the fields itself).
        self._explicit = True

    @property
    def bound(self) -> bool:
        return self._bound

    # -- the check -----------------------------------------------------------

    def check(self, url: str) -> str:
        """Return the authorized host for ``url`` or raise ScopeViolation.

        An UNBOUND gate auto-binds to the first host it sees and marks the
        authorization non-explicit: a standalone probe of X authorizes X
        (there is no declared mission to violate).  The mission runner binds
        EXPLICITLY before dispatch, so in-mission requests are strictly
        scoped to the operator declaration.
        """
        host = _host_of(url)
        if not host:
            raise ScopeViolation(url, "(no host)")
        if not self._bound:
            # Auto-bind (standalone probe default): authorize the first host
            # seen, NON-explicit -- a later declared mission may replace it;
            # an explicit mission bind may never be silently replaced.
            self.target = host
            self._bound = True
            self._explicit = False
            return host
        if self._authorized_host(host):
            return host
        raise ScopeViolation(url, host)

    def _authorized_host(self, host: str) -> bool:
        if host == self.target:
            return True
        # Dot-boundary suffix: operator-declared parent authorizes children.
        if host.endswith("." + self.target) or (
                self.target.startswith(".") and host.endswith(self.target)):
            return True
        for entry in self.extra_hosts:
            if host == entry or host.endswith("." + entry):
                return True
        # Loopback is authorized only for local campaigns: a remote target
        # never needs to make us fetch localhost, and SSRF payloads pointing
        # at 127.0.0.1 must not become our own outbound traffic.
        if _is_loopback(host) and _is_loopback(self.target):
            return True
        return False

    # -- audit ---------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "extra_hosts": sorted(self.extra_hosts),
            "bound": self._bound,
            "explicit": self._explicit,
            "mode": "deny-by-default" if self._explicit else "auto-bind",
        }


# ---------------------------------------------------------------------------
# Module-level gate (the process boundary http_probe consults)
# ---------------------------------------------------------------------------

_GATE = ScopeGate()


def bind_target(target: str, extra_hosts=None, *, force: bool = False) -> ScopeGate:
    """Bind the process gate (idempotent). Returns the gate for auditing."""
    _GATE.bind(target, extra_hosts, force=force)
    return _GATE


def reset() -> None:
    """Test/CLI escape hatch: unbind the process gate."""
    global _GATE
    _GATE = ScopeGate()


def check_url(url: str) -> str:
    """Authorize ``url`` against the process gate (raises ScopeViolation)."""
    return _GATE.check(url)


def gate_state() -> dict:
    """Audit snapshot of the process gate (preflight/mission records)."""
    return _GATE.to_dict()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def load_scope_file(path: str) -> list:
    """Parse an operator scope file: one host per line, ``#`` comments."""
    entries = []
    p = Path(path)
    if not p.exists():
        return entries
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host = _host_of(line) or line.lower().rstrip(".")
        if host:
            entries.append(host)
    return entries


def _host_of(url: str) -> str:
    """Extract the lowercase hostname from a URL or bare host string."""
    value = str(url).strip()
    if "://" not in value:
        value = "//" + value
    try:
        host = (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    # Defend the IDN/decimal-IP confusion surface: keep the literal host,
    # but resolve bare IPs to their canonical form.
    return _canonical(host)


def _canonical(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        # Not an IP literal.  Bracketed IPv6 was already stripped by
        # urlparse's hostname.  Drop a trailing dot fully.
        return host


def _is_loopback(host: str) -> bool:
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolves_inside_scope(host: str) -> bool:
    """DNS-pin helper (defense in depth): True if every resolved address for
    ``host`` is loopback/private -- used by preflight to flag targets whose
    DNS rebinding could swing the gate.  Never blocks by itself."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_private):
            return False
    return True
