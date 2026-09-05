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
import json
import os
import socket
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse

SCHEMA = "bugwolf-scope/v1"


class ScopeViolation(PermissionError):
    """Raised when a request would leave the operator-declared scope."""

    def __init__(self, url: str, host: str, *, policy: str = "deny-by-default"):
        self.url = url
        self.host = host
        self.policy = policy
        super().__init__(
            f"{policy} request blocked: {host!r} is not authorized "
            f"(target-only + operator scope file); url={url!r}")


class ScopeContractError(Exception):
    """Raised when a scope-contract operation targets the wrong mission."""


@dataclass
class ScopeGate:
    """Deny-by-default outbound authorization for one mission process."""

    target: str = ""
    extra_hosts: set = field(default_factory=set)
    deny_entries: set = field(default_factory=set)   # excluded hosts (program
                                                     # policy, e.g. beta./community.)
    _bound: bool = False
    _explicit: bool = False   # bound by the mission runner (not auto-bind)

    # -- binding -------------------------------------------------------------

    def bind(self, target: str, extra_hosts=None, *, force: bool = False,
             deny_entries=None) -> None:
        """Bind the gate to a mission target (+ allowed/excluded hosts).

        Idempotent for the same target.  ``force=True`` replaces a previous
        AUTO-bind (standalone probe default) but never an explicit mission
        bind -- mixing declared targets is the classic scope accident.

        ``deny_entries`` are EXPLICITLY EXCLUDED hosts (bug-bounty program
        carve-outs like ``beta.example.com``): exclusion ALWAYS wins over
        any allow rule, including the target wildcard -- the single most
        important rule for real engagements.
        """
        host = _host_of(target)
        if not host:
            raise ValueError(f"cannot bind scope gate: no host in {target!r}")
        if self._bound:
            if host == self.target:
                self._explicit = self._explicit or not force
                self._merge_denies(deny_entries)
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
        self._merge_denies(deny_entries)
        self._bound = True
        # bind() is the DECLARED-scope API; only check()'s inline auto-bind
        # is non-explicit (it sets the fields itself).
        self._explicit = True

    def _merge_denies(self, deny_entries) -> None:
        for entry in deny_entries or ():
            norm = _host_of(str(entry)) or str(entry).strip().lower()
            if norm:
                self.deny_entries.add(norm)

    def add_denies(self, deny_entries) -> None:
        """Extend exclusions on a bound gate (explicit operator action)."""
        if not self._bound:
            raise RuntimeError("cannot add exclusions to an unbound gate")
        self._merge_denies(deny_entries)

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
        # EXCLUSION FIRST: a host the operator carved out (beta., community.,
        # internal admin) is denied even when a wildcard allow would match.
        if self._denied_host(host):
            raise ScopeViolation(url, host, policy="excluded-by-policy")
        if self._authorized_host(host):
            return host
        raise ScopeViolation(url, host)

    def _denied_host(self, host: str) -> bool:
        for entry in self.deny_entries:
            if host == entry or host.endswith("." + entry):
                return True
        return False

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
            "deny_entries": sorted(self.deny_entries),
            "bound": self._bound,
            "explicit": self._explicit,
            "mode": "deny-by-default" if self._explicit else "auto-bind",
        }


# ---------------------------------------------------------------------------
# Module-level gate (the process boundary http_probe consults)
# ---------------------------------------------------------------------------

_GATE = ScopeGate()


def bind_target(target: str, extra_hosts=None, *, force: bool = False,
                deny_entries=None) -> ScopeGate:
    """Bind the process gate (idempotent). Returns the gate for auditing."""
    _GATE.bind(target, extra_hosts, force=force, deny_entries=deny_entries)
    return _GATE


def reset() -> None:
    """Test/CLI escape hatch: unbind the process gate."""
    global _GATE
    _GATE = ScopeGate()


def check_url(url: str) -> str:
    """Authorize ``url`` against the process gate (raises ScopeViolation)."""
    return _GATE.check(url)


def add_denies(deny_entries) -> None:
    """Extend exclusions on the bound process gate (operator action)."""
    _GATE.add_denies(deny_entries)


def gate_state() -> dict:
    """Audit snapshot of the process gate (preflight/mission records)."""
    return _GATE.to_dict()


def __getattr__(name: str):  # PEP 562 — module attribute access
    """``scope_mod.GATE`` — the live process gate. Always resolves the CURRENT
    gate, so ``reset()`` swaps remain visible to holders of the module
    reference (the bridge, the replay CLI, and live-lane tests bind here)."""
    if name == "GATE":
        return _GATE
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Harness-level scope contract (master plan Phase 3.1)

# The PreToolUse hook (hooks/bugwolf_pretool_scope_hook.py) enforces the
# SAME boundary in Claude Code's hook pipeline — outside the model.  The
# contract is the bridge between the in-engine gate (this module) and the
# harness gate (the hook): the runner writes it on bind, clears on close.

_CONTRACT_SCHEMA = "bugwolf-scope-contract/v1"


def _contract_path(root=None):
    # Same workspace resolution the hook shim uses (env var wins, cwd default)
    # so writer and enforcer always agree on the contract's location.
    base = Path(root) if root else Path(
        os.environ.get("BUGWOLF_PROJECT_ROOT") or ".")
    return base / "state" / "scope_contract.json"


def write_scope_contract(mission_id: str, *, root=None) -> dict:
    """Publish the CURRENT gate state as the harness contract.

    Called by the mission runner right after ``bind_target``: from this
    moment the PreToolUse hook denies out-of-scope/excluded hosts for
    every Bash/WebFetch — even ones the model improvises outside BugWolf's
    tools.  A workspace may have only one active mission contract: replacing
    another mission's contract would create a time-of-check/time-of-use
    scope split between the engine and the hook.
    """
    mission_id = str(mission_id or "").strip()
    if not mission_id:
        raise ValueError("scope contract requires a mission_id")
    path = _contract_path(root)
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("refusing to replace unreadable scope contract") from exc
        if (isinstance(existing, dict)
                and existing.get("schema") == _CONTRACT_SCHEMA
                and str(existing.get("mission_id") or "") not in ("", mission_id)):
            raise RuntimeError(
                "scope contract already belongs to another active mission: "
                + str(existing.get("mission_id")))
    contract = {
        "schema": _CONTRACT_SCHEMA,
        "mission_id": mission_id,
        "target": _GATE.target,
        "extra_hosts": sorted(_GATE.extra_hosts),
        "deny_entries": sorted(_GATE.deny_entries),
        "mode": "deny-by-default",
        "written_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(contract, indent=2))
        stream.flush()
        os.fsync(stream.fileno())
    tmp.replace(path)
    return contract


def clear_scope_contract(*, root=None, mission_id: str = "") -> bool:
    """Remove the harness contract (mission closed) — the hook goes inert.

    When ``mission_id`` is supplied, do not let one mission tear down a
    different mission's active contract.  The no-argument form remains an
    explicit operator/test escape hatch for backwards compatibility.
    """
    try:
        path = _contract_path(root)
        if mission_id and path.is_file():
            current = json.loads(path.read_text(encoding="utf-8"))
            if (isinstance(current, dict)
                    and str(current.get("mission_id") or "") not in
                    ("", str(mission_id))):
                return False
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def clear_scope_contract_strict(mission_id: str, *, root=None) -> bool:
    """Strict mission-aware clear (Phase 0 H-3): raises on mission mismatch.

    The active contract's ``mission_id`` MUST equal ``mission_id`` — otherwise
    one mission cannot tear down a different mission's hook authority.
    Callers without an active contract (file absent) clear it successfully.
    Production callers should prefer this over :func:`clear_scope_contract`.
    """
    if not mission_id:
        raise ValueError("mission_id is required to clear the scope contract")
    try:
        path = _contract_path(root)
        if path.is_file():
            current = json.loads(path.read_text(encoding="utf-8"))
            if (isinstance(current, dict)
                    and str(current.get("mission_id") or "") != str(mission_id)):
                raise ScopeContractError(
                    f"scope contract belongs to mission "
                    f"{current.get('mission_id')!r}; refusing to clear with "
                    f"mission_id={mission_id!r}")
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def force_clear_scope_contract(*, root=None) -> bool:
    """Operator escape hatch: clear the contract regardless of mission.

    The non-strict variant preserved for emergency teardown and lab-profile
    operations. Production callers should use ``clear_scope_contract_strict``.
    """
    try:
        path = _contract_path(root)
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


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
    """Extract the lowercase hostname from a URL or bare host string.

    v1.24.1+: defends against:
      - decimal-IP (``http://2130706433/`` = 127.0.0.1)
      - octal-IP   (``http://0177.0.0.1/``)
      - hex-IP     (``http://0x7f000001/``)
      - mixed-encoding
      - IDN/Unicode hostnames (``http://xn--...`` or raw Unicode)
      - URL-embedded userinfo (``http://attacker@target/``)
    All such encodings are normalized to their canonical form before
    any scope comparison, so the gate cannot be bypassed by encoding tricks.
    """
    value = str(url).strip()
    if "://" not in value:
        value = "//" + value
    try:
        host = (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return _canonical(host)


def _decode_alt_ip(host: str) -> Optional[str]:
    """Decode decimal / octal / hex / mixed-encoding IP literals to IPv4.

    Python's ``ipaddress.ip_address`` accepts dotted-quad only, so a payload
    like ``http://2130706433/`` (= 127.0.0.1) passes through unchanged. This
    helper handles the legacy inet_aton encoding.

    Returns the canonical dotted-quad, or None if the host is not a numeric IP.
    """
    import re as _re
    # Strip IPv6 brackets already handled by urlparse.  Quick reject for
    # anything that contains a letter (other than hex 0-9a-f).
    if not _re.fullmatch(r"[0-9a-fA-Fx.]+", host):
        return None
    parts = host.split(".")
    if len(parts) > 4:
        return None
    try:
        if len(parts) == 1:
            # Single 32-bit number (decimal, octal with 0o, or hex with 0x).
            raw = parts[0]
            if raw.startswith("0x") or raw.startswith("0X"):
                n = int(raw, 16)
            elif raw.startswith("0o") or raw.startswith("0O"):
                n = int(raw, 8)
            elif raw.startswith("0") and len(raw) > 1 and raw[1:].isdigit():
                n = int(raw, 8)  # legacy octal
            else:
                n = int(raw, 10)
            if not 0 <= n <= 0xFFFFFFFF:
                return None
            return str(ipaddress.IPv4Address(n))
        # Multi-part: each part can be decimal, hex (0x), or octal (0).
        octets = []
        for p in parts:
            if not p:
                return None
            if p.startswith("0x") or p.startswith("0X"):
                v = int(p, 16)
            elif p.startswith("0") and len(p) > 1 and p[1:].isdigit():
                v = int(p, 8)
            else:
                v = int(p, 10)
            if not 0 <= v <= 0xFF:
                return None
            octets.append(v)
        if len(octets) < 4:
            # Last part can be 8/16/24 bits in legacy inet_aton
            last = octets.pop()
            for _ in range(4 - len(octets) - 1):
                octets.append(last & 0xFF)
                last >>= 8
            octets.append(last)
        return ".".join(str(o) for o in octets[:4])
    except (ValueError, IndexError):
        return None


def _canonical(host: str) -> str:
    # 1. Numeric IP encodings (decimal / octal / hex / mixed)
    decoded = _decode_alt_ip(host)
    if decoded is not None:
        try:
            return str(ipaddress.ip_address(decoded))
        except ValueError:
            pass
    # 2. Standard IPv4 / IPv6
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    # 3. IDN/punycode normalization.  Bare Unicode hosts (e.g. ``\u0440\u044b\u0431\u0430.com``)
    #    are converted to their ASCII (xn--) form so the gate can compare
    #    against operator-declared scope entries.  Already-encoded hosts pass
    #    through unchanged.
    if host and ("xn--" not in host):
        try:
            labels = host.split(".")
            normalized = []
            for label in labels:
                if not label:
                    continue
                if label.startswith("xn--"):
                    normalized.append(label)
                else:
                    try:
                        # Will raise on all-ASCII labels — that's fine.
                        normalized.append(label.encode("idna").decode("ascii"))
                    except (UnicodeError, UnicodeDecodeError):
                        normalized.append(label)
            cand = ".".join(normalized)
            if cand and cand != host:
                return cand
        except Exception:  # noqa: BLE001
            pass
    # 4. Not an IP literal. Bracketed IPv6 was already stripped by
    #    urlparse's hostname.  Drop a trailing dot fully.
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


# ---------------------------------------------------------------------------
# Phase 1.4 governance binding shim (additive; no existing logic changed)
# ---------------------------------------------------------------------------

def bind_governance(*, root=None):
    """Phase 1.4 shim — re-export the new governance scope binding.

    Returns the :class:`bugwolf.governance.scope.GovernanceHandle` wired
    to the current process scope gate.  Existing callers that import
    ``tools.runtime.scope.bind_governance`` continue to work; the
    underlying implementation lives in :mod:`bugwolf.governance.scope`.
    """
    from bugwolf.governance.scope import bind_governance as _bind
    return _bind(root=root)
