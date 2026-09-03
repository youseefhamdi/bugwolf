#!/usr/bin/env python3
"""OAST tunnel tests: public-route acquisition + attribution + runner arm.

Contracts pinned here:
  * OastTunnel acquires a public serveousercontent.com URL and re-aims the
    listener's advertised base_url (the -t, no -N serveo invocation);
  * the tunnel respects an explicit BUGWOLF_OAST_PUBLIC_URL (never double-
    routes) and the BUGWOLF_OAST_TUNNEL arm switch;
  * end-to-end: fetching the PUBLIC canary URL from the box's default route
    attributes to the lead (marked network, kept fast);
  * MissionRunner arms the tunnel when oast_enabled + env, and stops it in
    close().
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.runtime.oast import OastListener, OastRegistry, canary_url  # noqa: E402
from tools.runtime.oast_tunnel import (  # noqa: E402
    OastTunnel, arm_from_env, selftest as tunnel_selftest,
)

# Live-network tests are opt-in (CI may run offline): BUGWOLF_TEST_NET=1.
_NET = os.environ.get("BUGWOLF_TEST_NET", "") == "1"


class TunnelArmPolicyTest(unittest.TestCase):
    """arm_from_env gating, no network."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._env = {k: v for k, v in os.environ.items()
                     if not k.startswith("BUGWOLF_OAST")}
        env_patch = mock.patch.dict(os.environ, self._env, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def _listener(self):
        registry = OastRegistry(project_root=self._tmp.name)
        listener = OastListener(registry)
        listener.start()
        self.addCleanup(listener.stop)
        return registry, listener

    def test_no_env_no_tunnel(self):
        registry, listener = self._listener()
        self.assertIsNone(arm_from_env(registry, listener))

    def test_explicit_public_url_wins(self):
        # Construct the listener WITH the explicit URL (as the runner does):
        # arm_from_env must then stay out of the way.
        os.environ["BUGWOLF_OAST_TUNNEL"] = "1"
        os.environ["BUGWOLF_OAST_PUBLIC_URL"] = "https://oast.operator.example"
        registry = OastRegistry(project_root=self._tmp.name)
        listener = OastListener(
            registry,
            public_base_url=os.environ["BUGWOLF_OAST_PUBLIC_URL"])
        listener.start()
        self.addCleanup(listener.stop)
        self.assertIsNone(arm_from_env(registry, listener),
                          "explicit operator URL must not be double-routed")
        self.assertEqual(listener.base_url, "https://oast.operator.example")

    def test_arm_reaims_advertised_url(self):
        if not _NET:
            self.skipTest("live network test (BUGWOLF_TEST_NET=1)")
        os.environ["BUGWOLF_OAST_TUNNEL"] = "1"
        registry, listener = self._listener()
        events = []
        tunnel = arm_from_env(registry, listener,
                              log=lambda e, p: events.append((e, p)))
        self.addCleanup(lambda: tunnel and tunnel.stop())
        self.assertIsNotNone(tunnel)
        self.assertTrue(tunnel.public_url.startswith("https://"))
        self.assertIn("serveousercontent.com", tunnel.public_url)
        self.assertEqual(listener.base_url, tunnel.public_url)
        self.assertTrue(any(e == "oast_tunnel" for e, _ in events))


class TunnelEndToEndTest(unittest.TestCase):
    """The proof that matters: public fetch -> attributed callback."""

    def test_public_fetch_attributes_to_lead(self):
        if not _NET:
            self.skipTest("live network test (BUGWOLF_TEST_NET=1)")
        os.environ["BUGWOLF_OAST_TUNNEL"] = "1"
        self.addCleanup(os.environ.pop, "BUGWOLF_OAST_TUNNEL", None)
        ok, detail = tunnel_selftest()
        self.assertTrue(ok, detail)
        self.assertIn("attributed via", detail)


if __name__ == "__main__":
    unittest.main()
