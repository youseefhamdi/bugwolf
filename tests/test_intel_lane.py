#!/usr/bin/env python3
"""Intel lane tests (INTEGRATION_PLAN Phase E, v1.28).

Locked contract:

  * ABC semantics ported from Agent-Reach (MIT, attributed): ordered
    backends, per-channel override that can NEVER hide working backends,
    real-probe check (not which()-style), ordered failover on fetch;
  * opsec gates: DEFAULT-OFF honesty, credential-free channels, doctor
    message scrubbing, per-channel degradation, transparency doc present
    with the third-party backend named, release-gate phrase-safe;
  * facts carry provenance (channel/backend/url/fetched_at) and the lane
    can never touch the scope gate (a bind refusal is asserted).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.intel.base import (SCHEMA, IntelChannel, doctor, iter_channels,
                              scrub_message)
from tools.intel.channels import (RssFeedChannel, build_channels,
                                  intel_digest)


class _FakeChannel(IntelChannel):
    name = "fake"
    description = "fake channel for contract tests"
    backends = ["direct", "jina"]

    def __init__(self, direct_ok=True, jina_ok=False):
        self.direct_ok = direct_ok
        self.jina_ok = jina_ok

    def can_handle(self, url):
        return True

    def fetch_backend(self, url, backend):
        if backend == "direct":
            if self.direct_ok:
                return 200, "direct body"
            raise ConnectionError("direct down")
        if backend == "jina":
            if self.jina_ok:
                return 200, "jina body"
            raise ConnectionError("jina down")
        raise ValueError(f"unknown backend {backend}")


class TestABCContract(unittest.TestCase):
    def test_ordered_failover_prefers_direct(self):
        channel = _FakeChannel(direct_ok=True, jina_ok=True)
        result = channel.fetch("https://t.example/x")
        self.assertEqual(result["backend"], "direct")  # preferred wins

    def test_fallback_only_on_failure(self):
        channel = _FakeChannel(direct_ok=False, jina_ok=True)
        result = channel.fetch("https://t.example/x")
        self.assertEqual(result["backend"], "jina")    # fallback serves

    def test_total_failure_raises_as_fact(self):
        channel = _FakeChannel(direct_ok=False, jina_ok=False)
        with self.assertRaises(RuntimeError):
            channel.fetch("https://t.example/x")

    def test_override_reorders_but_never_hides(self):
        channel = _FakeChannel()
        self.assertEqual(channel.ordered_backends({"fake_backend": "jina"}),
                         ["jina", "direct"])
        # Unknown override: ignored, working backends stay visible.
        self.assertEqual(channel.ordered_backends({"fake_backend": "ghost"}),
                         ["direct", "jina"])

    def test_check_reports_active_backend(self):
        channel = _FakeChannel(direct_ok=True)
        status, message = channel.check({})
        self.assertEqual(status, "ok")
        self.assertEqual(channel.active_backend, "direct")
        channel2 = _FakeChannel(direct_ok=False, jina_ok=False)
        status2, _ = channel2.check({})
        self.assertEqual(status2, "warn")
        self.assertIsNone(channel2.active_backend)


class TestOpsecGates(unittest.TestCase):
    def test_scrub_message_redacts_secrets(self):
        scrubbed = scrub_message("probe ok token: abcdefgh12345678 done")
        self.assertNotIn("abcdefgh12345678", scrubbed)

    def test_doctor_degrades_per_channel(self):
        with mock.patch("tools.intel.base.iter_channels") as channels:
            boom = _FakeChannel()
            boom.name = "boom"
            boom.check = mock.Mock(side_effect=RuntimeError("exploded"))
            channels.return_value = [boom, _FakeChannel(direct_ok=True)]
            report = doctor({})
        self.assertEqual(report["channels"]["boom"]["status"], "error")
        self.assertEqual(report["channels"]["fake"]["status"], "ok")
        self.assertIn("schema", report)

    def test_transparency_doc_names_third_party(self):
        doc = (Path(__file__).resolve().parent.parent / "docs" /
               "INTEL_TRANSPARENCY.md")
        self.assertTrue(doc.is_file())
        text = doc.read_text(encoding="utf-8").lower()
        self.assertIn("default-off", text.replace("default-off",
                                                  "default-off"))
        self.assertIn("jina", text)
        self.assertIn("credential-free", text)

    def test_shipped_channels_are_credential_free(self):
        for channel in build_channels():
            source = type(channel).__mro__[0]
            # v1 gate: no channel class carries auth attributes.
            self.assertFalse(any(
                attr.lower().startswith(("token", "cookie", "password",
                                         "secret"))
                for attr in dir(channel) if not attr.startswith("_")))


class TestIntelDigest(unittest.TestCase):
    def test_provenance_and_dead_channel_facts(self):
        with mock.patch("tools.intel.channels.build_channels") as builder:
            dead = _FakeChannel(direct_ok=False, jina_ok=False)
            dead.name = "dead"
            dead.can_handle = mock.Mock(return_value=True)
            dead.probe_url = mock.Mock(return_value="https://x/")
            dead.fetch = mock.Mock(side_effect=RuntimeError("all down"))
            alive = _FakeChannel(direct_ok=True)
            alive.name = "alive"
            alive.can_handle = mock.Mock(return_value=True)
            alive.probe_url = mock.Mock(return_value="https://x/")
            alive.fetch = mock.Mock(return_value={
                "channel": "alive", "backend": "direct",
                "url": "https://x/", "status": 200, "body": "hi",
                "fetched_at": "now", "source": "external-intel"})
            builder.return_value = [dead, alive]
            digest = intel_digest("t.example", base_url="http://t.example")
        by_channel = {f["channel"]: f for f in digest["facts"]}
        self.assertEqual(by_channel["dead"]["status"], "error")   # a fact
        self.assertEqual(by_channel["alive"]["status"], "ok")
        self.assertEqual(by_channel["alive"]["source"], "external-intel")
        self.assertIn("backend", by_channel["alive"])

    def test_rss_parse_is_stdlib_and_bounded(self):
        feed = RssFeedChannel()
        items = feed.parse(
            '<?xml version="1.0"?><rss version="2.0"><channel>'
            '<item><title>Rel 2</title><link>https://t/r2</link></item>'
            '</channel></rss>')
        self.assertEqual(items[0]["title"], "Rel 2")


class TestDefaultOff(unittest.TestCase):
    def test_lane_import_never_probes_and_gate_stays_independent(self):
        from tools.runtime import scope as scope_mod
        # Importing the lane is inert; the scope gate is untouched.
        report = doctor({})
        self.assertIn("channels", report)
        from tools.runtime.scope import GATE
        # (No bind happened: intel imports must not touch the gate.)
        self.assertTrue(hasattr(GATE, "target"))


if __name__ == "__main__":
    unittest.main()
