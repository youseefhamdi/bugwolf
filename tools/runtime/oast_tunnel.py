#!/usr/bin/env python3
"""BugWolf OAST public tunnel (plan v2 S1 completion for REMOTE targets).

The OAST listener binds loopback (product-audit rule).  For a LOCAL target
the target itself can reach ``127.0.0.1:<port>`` and attribution works.
For a REMOTE real-world target the callback must traverse a public route
the OPERATOR owns -- ``BUGWOLF_OAST_PUBLIC_URL``.  This module automates
the common zero-credential path:

    BUGWOLF_OAST_TUNNEL=1 python3 -m tools.runtime.mission_runner ...

which opens an SSH reverse tunnel (localhost.run by default, overridable
via ``BUGWOLF_OAST_TUNNEL_HOST``) from the loopback listener to a public
HTTPS URL, then sets the advertised base URL so every canary embeds the
public route and 100% of callbacks attribute.

HONEST TRANSPORT CAVEAT: localhost.run is a THIRD-PARTY tunnel.  The plan's
transport rule is "self-hosted, you own the callbacks" -- for engagements
with strict evidence-chain requirements, run your own interactsh-server or
an SSH reverse tunnel to a VPS YOU control and set
``BUGWOLF_OAST_PUBLIC_URL`` explicitly instead.  This convenience path
trades that ownership for zero-credential setup; the audit log records the
tunnel host either way.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

SCHEMA = "bugwolf-oast-tunnel/v1"

DEFAULT_TUNNEL_HOST = "serveo.net"
# serveo prints "Forwarding HTTP traffic from https://<hash>-<ip>.serveousercontent.com"
# on session start (requires ssh -t even without a real TTY).
_SERVEO_URL_RE = re.compile(
    r"Forwarding HTTP traffic from (https://[A-Za-z0-9.-]+)", re.IGNORECASE)
_ANY_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+\.(?:serveousercontent|lhr\.life)\.?", re.IGNORECASE)


class OastTunnel:
    """One SSH reverse tunnel: public HTTPS -> loopback OAST port."""

    def __init__(self, local_port: int, *,
                 tunnel_host: Optional[str] = None):
        self.local_port = int(local_port)
        self.tunnel_host = (tunnel_host
                            or os.environ.get("BUGWOLF_OAST_TUNNEL_HOST")
                            or DEFAULT_TUNNEL_HOST)
        self.public_url: Optional[str] = None
        self._proc: Optional[subprocess.Popen] = None
        self._master: Optional[int] = None
        self._stderr_tail: str = ""

    # -- lifecycle -----------------------------------------------------------

    def start(self, timeout: float = 25.0) -> Tuple[bool, str]:
        """Open the tunnel and discover the assigned public URL."""
        if self._proc is not None:
            return True, self.public_url or ""
        # serveo prints its "Forwarding HTTP traffic from <url>" banner only
        # on an INTERACTIVE session request (-t, NO -N): with -N it forwards
        # silently and the URL is unobtainable.  The session stays open and
        # carries the tunnel for the mission's lifetime.
        cmd = ["ssh", "-t", "-o", "StrictHostKeyChecking=no",
               "-o", "ServerAliveInterval=30", "-o", "ExitOnForwardFailure=yes",
               "-R", f"80:127.0.0.1:{self.local_port}",
               self.tunnel_host]
        # serveo only prints its URL banner when ssh requests a TTY (-t);
        # we hand it a pty so the banner lands on the master we read.
        import pty
        self._master, slave = pty.openpty()
        # Sandbox gate: the tunnel's ssh spawn obeys the kill switch + env
        # scrub like every engine-internal spawn (universal-coverage rule).
        from tools.runtime.sandbox import (
            sandboxed_run, scrub_env, kill_switch_engaged, SandboxViolation)
        if kill_switch_engaged():
            os.close(self._master)
            self._master = None
            return False, "kill switch engaged: tunnel ssh blocked"
        try:
            self._proc = subprocess.Popen(
                cmd, stdin=slave, stdout=slave, stderr=slave,
                env=scrub_env(), start_new_session=True)
        except OSError as exc:
            os.close(self._master)
            self._master = None
            return False, f"ssh spawn failed: {exc}"
        os.close(slave)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.3)
            if self._proc.poll() is not None:
                return False, (f"tunnel ssh exited rc={self._proc.returncode}: "
                               f"{self._stderr_tail[:200]}")
            buf = self._drain()
            match = _SERVEO_URL_RE.search(buf) or _ANY_URL_RE.search(buf)
            if match:
                url = match.group(1) if match.lastindex else match.group(0)
                self.public_url = url.rstrip("/").rstrip("\\")
                return True, self.public_url
            if buf:
                self._stderr_tail = buf[-400:]
        self.stop()
        return False, f"no public URL within {timeout}s; tail: {self._stderr_tail[:200]}"

    def _drain(self) -> str:
        """Read whatever the ssh session printed, via the pty master."""
        if self._master is None:
            return ""
        import select
        buf = getattr(self, "_buffer", "")
        deadline = time.monotonic() + 0.05
        while time.monotonic() < deadline:
            r, _, _ = select.select([self._master], [], [], 0.05)
            if not r:
                break
            try:
                chunk = os.read(self._master, 4096).decode("utf-8", "replace")
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        self._buffer = buf
        return buf

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: BLE001 - kill is best effort
                try:
                    self._proc.kill()
                except Exception:  # noqa: BLE001
                    pass
            self._proc = None
        if self._master is not None:
            try:
                os.close(self._master)
            except OSError:
                pass
            self._master = None

    def __enter__(self):
        ok, detail = self.start()
        if not ok:
            raise RuntimeError(f"OAST tunnel failed to start: {detail}")
        return self

    def __exit__(self, *exc):
        self.stop()
        return False


def arm_from_env(registry, listener, *, log=None) -> Optional[OastTunnel]:
    """Convenience used by MissionRunner: when ``BUGWOLF_OAST_TUNNEL=1``,
    open a tunnel for the running loopback listener and re-aim its
    advertised base URL at the public route.  Returns the tunnel (caller
    must ``stop()`` it, e.g. via ``close()``) or None when not requested.
    """
    if str(os.environ.get("BUGWOLF_OAST_TUNNEL", "")).lower() not in ("1", "true", "yes"):
        return None
    if str(os.environ.get("BUGWOLF_OAST_PUBLIC_URL", "")).strip():
        return None   # explicit operator URL wins; nothing to automate
    tunnel = OastTunnel(listener.port)
    ok, detail = tunnel.start()
    if log is not None:
        log("oast_tunnel", {"ok": ok, "detail": detail,
                            "host": tunnel.tunnel_host})
    if not ok:
        tunnel.stop()
        return None
    listener._public_base_url = tunnel.public_url  # re-aim advertised route
    return tunnel


def selftest(public_check_timeout: float = 25.0) -> tuple:
    """End-to-end proof: listener + tunnel -> fetch the PUBLIC canary URL
    from OUTSIDE the tunnel (this box's default route) -> assert the
    callback attributes to the registered lead.  No target needed."""
    import urllib.request
    from tools.runtime.oast import OastListener, OastRegistry, canary_url

    with tempfile_dir() as root:
        registry = OastRegistry(project_root=root)
        listener = OastListener(registry)
        listener.start()
        tunnel = None
        try:
            tunnel = arm_from_env(registry, listener, log=lambda *a: None)
            if tunnel is None:
                return False, ("BUGWOLF_OAST_TUNNEL not set -- selftest must "
                               "run with the env var armed")
            url = canary_url(listener.base_url, "selftest-lead",
                             registry=registry)
            req = urllib.request.Request(url, headers={"User-Agent": "bw-selftest"})
            try:
                urllib.request.urlopen(req, timeout=public_check_timeout)
            except Exception as exc:  # noqa: BLE001 - HTTP error is still a hit
                if "HTTP" not in type(exc).__name__:
                    return False, f"public fetch failed: {exc}"
            time.sleep(1.0)
            hits = registry.interactions(lead_id="selftest-lead")
            if not hits:
                return False, "public fetch did not attribute to the lead"
            return True, (f"attributed via {tunnel.public_url} "
                          f"({hits[0].get('transport', '?')})")
        finally:
            listener.stop()
            if tunnel is not None:
                tunnel.stop()


def tempfile_dir():
    import tempfile
    return tempfile.TemporaryDirectory()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf OAST tunnel utility")
    parser.add_argument("--selftest", action="store_true",
                        help="end-to-end attribution proof through the tunnel")
    parser.add_argument("--port", type=int, default=0,
                        help="local OAST port (selftest: 0 = ephemeral)")
    args = parser.parse_args()
    if args.selftest:
        os.environ["BUGWOLF_OAST_TUNNEL"] = "1"   # the selftest IS the armed path
        ok, detail = selftest()
        print(f"oast tunnel selftest: {'PASS' if ok else 'FAIL'} -- {detail}")
        raise SystemExit(0 if ok else 1)
    parser.error("nothing to do; try --selftest")
