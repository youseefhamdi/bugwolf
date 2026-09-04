#!/usr/bin/env python3
"""Playwright browser-driver binding tests (master plan Phase 2.1 + 2.5).

Acceptance: browser-confirmed client-side verdicts — EXECUTION-CONFIRMED
requires the payload signature in a REAL browser console/DOM; body
reflection alone sets reflection_only and never confirms; no usable
browser means an honest blocked fact, never a fabricated verdict; the
scope gate holds at the navigation layer (an out-of-scope URL can never
spawn a browser process).

Layers:
  * deterministic: binding loader, driver_status, bridge tool with fake
    drivers (no browser process);
  * live (skipped when Playwright is absent): the full chain against the
    stub target's executable /api/notes surface — including the
    per-navigation console-buffer regression (stale evidence must never
    confirm a later candidate).
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.browser_driver import (  # noqa: E402
    validate_client_side, make_signature, load_default_driver,
    set_default_driver, driver_status)
from tools.runtime.browser_driver_playwright import (  # noqa: E402
    PlaywrightBrowserDriver)
from tools.runtime import scope as scope_mod  # noqa: E402


def _load_bridge():
    spec = importlib.util.spec_from_file_location(
        "bugwolf_mcp_bridge", ROOT / "bridge" / "bugwolf-mcp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BRIDGE = _load_bridge()


class _FakeDriver:
    """Structural driver: deterministic HTML/console/DOM, no browser."""

    def __init__(self, html: str = "", console=None, dom=None):
        self.html = html
        self._console = list(console or [])
        self._dom = dom
        self.navigate_calls: list = []

    def navigate(self, url: str) -> str:
        self.navigate_calls.append(url)
        return self.html

    def console(self):
        return list(self._console)

    def evaluate(self, expression):
        return self._dom


def _setUpModuleScope():
    scope_mod.reset()


class TestDefaultDriverLoader(unittest.TestCase):
    def setUp(self):
        _setUpModuleScope()
        set_default_driver(None)          # isolate from other tests

    def tearDown(self):
        set_default_driver(None)
        scope_mod.reset()

    def test_load_returns_real_binding_or_none(self):
        driver = load_default_driver()
        if PlaywrightBrowserDriver.available():
            self.assertIsInstance(driver, PlaywrightBrowserDriver)
        else:
            self.assertIsNone(driver)     # honest unavailability

    def test_pinned_driver_wins(self):
        fake = _FakeDriver()
        set_default_driver(fake)
        self.assertIs(load_default_driver(), fake)
        status = driver_status()
        self.assertTrue(status["bound"])
        self.assertEqual(status["driver"], "_FakeDriver")

    def test_driver_status_is_an_honest_fact(self):
        status = driver_status()
        self.assertFalse(status["bound"])
        self.assertIn("available", status)
        if not status["available"]:
            self.assertIn("playwright install", status.get("hint", ""))


class TestBridgeToolWithFakeDrivers(unittest.TestCase):
    def setUp(self):
        _setUpModuleScope()
        set_default_driver(None)

    def tearDown(self):
        set_default_driver(None)
        scope_mod.reset()

    def test_browser_confirm_confirmed_with_executing_signature(self):
        sig = make_signature("lead-x")
        set_default_driver(_FakeDriver(
            html=f"<div>{sig}</div>", console=[f"[error] {sig} hit"]))
        out = BRIDGE.tool_browser_confirm(
            {"url": "http://target.example/notes",
             "lead_id": "lead-x", "signature": sig})
        self.assertEqual(out["schema"], "bugwolf-browser-mcp/v1")
        self.assertTrue(out["execution_confirmed"])
        self.assertFalse(out["reflection_only"])
        self.assertEqual(out["signature"], sig)

    def test_browser_confirm_reflection_never_confirms(self):
        sig = make_signature("lead-y")
        set_default_driver(_FakeDriver(html=f"<p>{sig}</p>"))
        out = BRIDGE.tool_browser_confirm(
            {"url": "http://target.example/echo?q=" + sig,
             "lead_id": "lead-y", "signature": sig})
        self.assertFalse(out["execution_confirmed"])
        self.assertTrue(out["reflection_only"])

    def test_browser_confirm_scope_block_is_a_policy_fact(self):
        scope_mod.bind_target("http://target.example", force=True)
        fake = _FakeDriver()
        set_default_driver(fake)
        out = BRIDGE.tool_browser_confirm(
            {"url": "http://evil.example/x", "signature": "bwexec-00000000"})
        self.assertTrue(str(out.get("blocker", "")).startswith("scope-blocked"))
        self.assertEqual(fake.navigate_calls, [])   # driver never touched

    def test_browser_confirm_honest_blocked_without_driver(self):
        with patch("tools.runtime.browser_driver.load_default_driver",
                   return_value=None):
            out = BRIDGE.tool_browser_confirm(
                {"url": "http://target.example/notes"})
        self.assertTrue(out["blocked"])
        self.assertIn("driver_status", out)


class TestLivePlaywright(unittest.TestCase):
    """Full chain against the stub's executable /api/notes surface."""

    @classmethod
    def setUpClass(cls):
        if not PlaywrightBrowserDriver.available():
            raise unittest.SkipTest(
                "playwright not installed (pip install playwright && "
                "playwright install chromium)")
        spec = importlib.util.spec_from_file_location(
            "stub_target_browser", ROOT / "tests" / "_stub_target.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.stub_module = module
        cls.server = module.ThreadingHTTPServer(("127.0.0.1", 0),
                                                module.Handler)
        import threading
        threading.Thread(target=cls.server.serve_forever,
                         daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        scope_mod.reset()
        scope_mod.bind_target(cls.base)
        cls.signature = "bwexec-deadbeef"
        payload = ("note:<img src=x onerror="
                   f"\"console.error('{cls.signature}')\">")
        urllib.request.urlopen(
            cls.base + "/api/ingest?q=" + urllib.parse.quote(payload),
            timeout=5).read()

    @classmethod
    def tearDownClass(cls):
        scope_mod.reset()

    def test_execution_confirmed_via_console(self):
        with PlaywrightBrowserDriver() as driver:
            ev = validate_client_side(
                {"url": self.base + "/api/notes", "lead_id": "lead-live"},
                driver, signature=self.signature)
        self.assertTrue(ev.execution_confirmed, ev.to_dict())
        self.assertFalse(ev.reflection_only)
        self.assertTrue(any(self.signature in m
                            for m in ev.console_messages))

    def test_reflection_is_not_execution(self):
        with PlaywrightBrowserDriver() as driver:
            ev = validate_client_side(
                {"url": self.base + f"/api/param-echo?one={self.signature}",
                 "lead_id": "lead-reflect"},
                driver, signature=self.signature)
        self.assertTrue(ev.reflection_only)
        self.assertFalse(ev.execution_confirmed)

    def test_console_buffer_resets_per_navigation(self):
        """Regression: a reused driver validates many leads sequentially —
        evidence from an earlier page must never confirm a later one."""
        with PlaywrightBrowserDriver() as driver:
            first = validate_client_side(
                {"url": self.base + "/api/notes"},
                driver, signature=self.signature)
            self.assertTrue(first.execution_confirmed)
            second = validate_client_side(
                {"url": self.base + "/api/param-echo?one=clean"},
                driver, signature=self.signature)
        self.assertEqual(second.console_messages, [])
        self.assertFalse(second.execution_confirmed)

    def test_clean_page_is_inconclusive_not_confirmed(self):
        with PlaywrightBrowserDriver() as driver:
            ev = validate_client_side(
                {"url": self.base + "/api/param-echo?one=hello"},
                driver, signature="bwexec-00000000")
        self.assertFalse(ev.execution_confirmed)
        self.assertFalse(ev.reflection_only)
        self.assertIsNone(ev.blocker)

    def test_works_inside_asyncio_host(self):
        """Regression: Claude Code hosts (MCP bridge, harness) run on an
        asyncio event loop, and Playwright's sync API refuses event-loop
        threads.  The driver marshals every call onto its own worker
        thread, so validation from inside a coroutine must succeed."""
        import asyncio

        async def _validate():
            with PlaywrightBrowserDriver() as driver:
                return validate_client_side(
                    {"url": self.base + "/api/notes", "lead_id": "lead-async"},
                    driver, signature=self.signature)

        ev = asyncio.run(_validate())
        self.assertTrue(ev.execution_confirmed, ev.to_dict())
        self.assertNotIn("asyncio", str(ev.blocker or ""))

    def test_screenshot_evidence_artifact(self):
        with PlaywrightBrowserDriver() as driver:
            driver.navigate(self.base + "/api/notes")
            shot = driver.screenshot()
        self.assertTrue(Path(shot).is_file())

    def test_out_of_scope_never_starts_browser(self):
        scope_mod.reset()
        scope_mod.bind_target("http://in-scope.example", force=True)
        try:
            with PlaywrightBrowserDriver() as driver:
                ev = validate_client_side(
                    {"url": "http://evil.example/x"},
                    driver, signature="bwexec-00000000")
                self.assertIsNone(driver._page)   # no browser process spawned
        finally:
            scope_mod.reset()
            scope_mod.bind_target(self.base)
        self.assertTrue(str(ev.blocker or "").startswith("scope-blocked"))


if __name__ == "__main__":
    unittest.main()
