#!/usr/bin/env python3
"""Antibot honesty tests (INTEGRATION_PLAN Phase F, v1.29).

Locked contract:

  * challenge pages (Cloudflare/captcha/Jina-warning formats) are
    DETECTED even when they arrive 200-with-content;
  * a rich real page that merely MENTIONS captcha passes through (the
    volume guard reads the whole body, not just the marker sample);
  * the U-layer fetcher excludes challenged pages from U1 intake and
    records them as facts ({fact, kind, path});
  * detection is a fact, never a crash; empty/junk input passes through.
"""

import importlib.util
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from tools.runtime.understanding.antibot import is_antibot_page, ANTIBOT_FACT

ROOT = Path(__file__).resolve().parent.parent


def _boot_stub():
    spec = importlib.util.spec_from_file_location(
        "stub_target_antibot", ROOT / "tests" / "_stub_target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TestHeuristics(unittest.TestCase):
    def test_cloudflare_challenge_detected(self):
        body = ("<html><head><title>Attention Required</title></head>"
                "<body>Checking your browser before accessing. cloudflare"
                + "<p>x</p>" * 30 + "</body></html>")
        self.assertTrue(is_antibot_page(body))

    def test_captcha_challenge_detected(self):
        body = "<html><body>verify you are human<script>captcha()</script></body></html>"
        self.assertTrue(is_antibot_page(body))

    def test_jina_warning_detected(self):
        body = ("Warning: the target page is protected by a solution "
                "requiring captcha. Title: Access denied")
        self.assertTrue(is_antibot_page(body))

    def test_rich_page_mentioning_captcha_passes(self):
        body = ("<html><body><h1>On captcha bypass research</h1><p>"
                + "Detailed discussion of challenge design and its "
                  "security implications. " * 60
                + "</p></body></html>")
        self.assertFalse(is_antibot_page(body))

    def test_no_marker_passes(self):
        self.assertFalse(is_antibot_page("<html><body><h1>Pricing</h1>"
                                         "<p>Seats $12/mo</p></body></html>"))
        self.assertFalse(is_antibot_page(""))
        self.assertFalse(is_antibot_page(None))  # type: ignore

    def test_fact_shape(self):
        fact = dict(ANTIBOT_FACT, path="/x")
        self.assertEqual(fact["fact"], "surface behind bot-wall")
        self.assertEqual(fact["kind"], "antibot")


class TestFetcherIntegration(unittest.TestCase):
    def test_challenged_page_excluded_and_recorded(self):
        server = _boot_stub()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            from tools.runtime import scope as scope_mod
            scope_mod.reset()
            scope_mod.bind_target(base)
            from tools.runtime.understanding.__main__ import _fetch_pages
            # Simulate a bot-walled target: the detector flags every body
            # (the stub serves clean pages; we exercise the exclusion path).
            with mock.patch(
                    "tools.runtime.understanding.antibot.is_antibot_page",
                    return_value=True):
                pages, openapi, antibot = _fetch_pages(base, ["/"])
            self.assertEqual(pages, {})
            self.assertTrue(antibot)
            self.assertEqual(antibot[0]["path"], "/")
            self.assertEqual(antibot[0]["kind"], "antibot")
        finally:
            server.shutdown()
            server.server_close()

    def test_clean_pages_flow_unchanged(self):
        server = _boot_stub()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            from tools.runtime import scope as scope_mod
            scope_mod.reset()
            scope_mod.bind_target(base)
            from tools.runtime.understanding.__main__ import _fetch_pages
            pages, openapi, antibot = _fetch_pages(base, ["/", "/pricing"])
            self.assertTrue(pages)
            self.assertEqual(antibot, [])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
