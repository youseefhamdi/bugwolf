#!/usr/bin/env python3
"""Playwright binding for the BrowserDriver protocol (master plan Phase 2.1).

The first real browser behind the "reflection is not execution" lane.  The
protocol lives in ``tools.runtime.browser_driver``; this module implements
it with Playwright's synchronous API:

    * navigate    -- goto + settle, returns the rendered HTML;
    * console     -- every console message AND uncaught page errors,
                     captured from page creation, reset per navigation;
    * evaluate    -- arbitrary JS in the page (the DOM-sink query);
    * screenshot  -- evidence artifact under the workspace state dir.

Threading model — the binding OWNS a worker thread:

Playwright's sync API refuses to run inside an asyncio event loop, and
BugWolf's hosts (Claude Code MCP bridge, the mission runner, OAST tests)
live on or beside one.  Every public call therefore marshals onto a single
dedicated worker thread where the sync API and its greenlets live; the
calling thread blocks on the result.  One code path, no environment
detection, works everywhere.

Fail-closed contract:

    * Playwright missing  =>  ``availability()`` reports an honest fact and
      ``load_default_driver()`` (browser_driver.py) returns None — the lead
      goes to ``blocked-browser``, never to a fabricated result;
    * the browser starts LAZILY on first ``navigate``: a constructed driver
      costs nothing until it is actually used;
    * navigation passes the scope gate BEFORE anything else happens — an
      out-of-scope URL can never spawn a browser process;
    * ``alert()``/``confirm()`` dialogs are auto-dismissed (recorded), so a
      blocking dialog cannot hang the lane.

Optional dependency: nothing here is imported unless a caller asks for the
Playwright binding.  Deterministic tier: no model calls.
"""

from __future__ import annotations

import queue
import threading
import time
from pathlib import Path
from typing import Any, List, Optional

from tools.runtime_paths import runtime_path, target_slug

SCHEMA = "bugwolf-browser-driver-playwright/v1"

_DEFAULT_TIMEOUT_MS = 15_000
_DEFAULT_SETTLE_MS = 300          # let deferred sinks (setTimeout/async) fire
_CALL_TIMEOUT_S = 90.0            # hard ceiling per marshalled call


class PlaywrightNotAvailable(RuntimeError):
    """Playwright (or its browser) is not installed in this environment."""


class PlaywrightBrowserDriver:
    """Playwright-backed ``BrowserDriver`` — lazy, scope-gated, threaded.

    Implements the structural protocol (navigate/console/evaluate); adds
    ``screenshot`` and context-manager semantics for one-shot validations.
    All Playwright work happens on an internal worker thread (see module
    docstring); public methods are safe to call from any thread.
    """

    def __init__(self, *, headless: bool = True,
                 browser_type: str = "chromium",
                 timeout_ms: int = _DEFAULT_TIMEOUT_MS,
                 settle_ms: int = _DEFAULT_SETTLE_MS,
                 viewport: Optional[dict] = None) -> None:
        self.headless = headless
        self.browser_type = browser_type
        self.timeout_ms = timeout_ms
        self.settle_ms = settle_ms
        self.viewport = viewport or {"width": 1280, "height": 800}
        self.last_status: Optional[int] = None
        self.last_url: Optional[str] = None
        self.dialogs: List[str] = []
        self._queue: "queue.Queue" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        # Playwright objects live ONLY on the worker thread.
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._console: List[str] = []

    # -- availability --------------------------------------------------------

    @classmethod
    def availability(cls) -> dict:
        """Honest environment fact: is the binding usable right now?"""
        try:
            import playwright.sync_api  # noqa: F401 — import IS the probe
        except Exception as exc:  # noqa: BLE001 - missing = an honest fact
            return {"available": False,
                    "driver": "playwright",
                    "detail": f"{type(exc).__name__}: {exc}",
                    "hint": "pip install playwright && playwright install chromium"}
        return {"available": True, "driver": "playwright", "detail": "ok"}

    @classmethod
    def available(cls) -> bool:
        return bool(cls.availability()["available"])

    # -- worker thread marshalling ---------------------------------------------

    def _submit(self, fn, *args) -> Any:
        """Run ``fn(*args)`` on the worker thread and wait for the result."""
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(
                target=self._worker_main, daemon=True,
                name="bugwolf-playwright")
            self._worker.start()
        done = threading.Event()
        box: dict = {}
        self._queue.put((fn, args, box, done))
        if not done.wait(timeout=_CALL_TIMEOUT_S):
            raise TimeoutError(
                f"playwright worker did not answer within {_CALL_TIMEOUT_S}s "
                f"(call: {getattr(fn, '__name__', fn)})")
        if "exc" in box:
            raise box["exc"]
        return box.get("ret")

    def _worker_main(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                self._teardown_sync()
                return
            fn, args, box, done = item
            try:
                box["ret"] = fn(*args)
            except BaseException as exc:  # noqa: BLE001 - re-raised on caller
                box["exc"] = exc
            finally:
                done.set()

    # -- worker-thread-side lifecycle (sync API lives here) ---------------------

    def _ensure_started(self) -> None:
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # noqa: BLE001 - fail closed, honestly
            raise PlaywrightNotAvailable(
                "playwright is not installed (pip install playwright && "
                f"playwright install chromium): {type(exc).__name__}: {exc}"
            ) from exc
        self._pw = sync_playwright().start()
        launcher = getattr(self._pw, self.browser_type)
        self._browser = launcher.launch(headless=self.headless)
        self._context = self._browser.new_context(viewport=self.viewport)
        self._page = self._context.new_page()
        self._attach_capture(self._page)

    def _attach_capture(self, page: Any) -> None:
        """Console/pageerror capture from page creation; dialogs auto-
        dismissed so a blocking alert() cannot hang the validation lane."""
        self._console = []

        def _on_console(msg: Any) -> None:
            try:
                self._console.append(f"[{msg.type}] {msg.text}")
            except Exception:  # noqa: BLE001 - capture must never crash the lane
                pass

        def _on_pageerror(err: Any) -> None:
            try:
                self._console.append(f"[pageerror] {err}")
            except Exception:  # noqa: BLE001
                pass

        def _on_dialog(dialog: Any) -> None:
            try:
                self.dialogs.append(f"{dialog.type}: {dialog.message}"[:200])
                dialog.dismiss()
            except Exception:  # noqa: BLE001
                pass

        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("dialog", _on_dialog)

    def _teardown_sync(self) -> None:
        for attr in ("_context", "_browser"):
            obj = getattr(self, attr, None)
            if obj is not None:
                try:
                    obj.close()
                except Exception:  # noqa: BLE001 - best-effort teardown
                    pass
                setattr(self, attr, None)
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:  # noqa: BLE001
                pass
            self._pw = None
        self._page = None

    # -- public surface (any thread) --------------------------------------------

    def navigate(self, url: str) -> str:
        """Navigate and return the rendered HTML.

        Scope gate FIRST (fail-closed, on the calling thread, before any
        browser process exists): the injected driver is a network capability
        like any other.
        """
        from tools.runtime.scope import check_url  # mission boundary
        check_url(url)
        return self._submit(self._navigate_sync, url)

    def _navigate_sync(self, url: str) -> str:
        self._ensure_started()
        # Evidence is PER-NAVIGATION: stale console messages/dialogs from an
        # earlier page must never confirm a later candidate (a reused driver
        # validates many leads sequentially — a leaked buffer would turn the
        # previous lead's execution into this lead's false CONFIRMED).
        self._console.clear()
        self.dialogs.clear()
        response = self._page.goto(url, wait_until="load",
                                   timeout=self.timeout_ms)
        if self.settle_ms:
            self._page.wait_for_timeout(self.settle_ms)
        self.last_status = response.status if response else None
        self.last_url = url
        return self._page.content()

    def console(self) -> List[str]:
        return self._submit(self._console_sync)

    def _console_sync(self) -> List[str]:
        return list(self._console)

    def evaluate(self, expression: str) -> Any:
        return self._submit(self._evaluate_sync, expression)

    def _evaluate_sync(self, expression: str) -> Any:
        self._ensure_started()
        return self._page.evaluate(expression)

    def screenshot(self, path: Optional[str | Path] = None) -> str:
        """Capture the current page as PNG evidence; returns the path."""
        return self._submit(self._screenshot_sync, path)

    def _screenshot_sync(self, path: Optional[str | Path]) -> str:
        self._ensure_started()
        if path is None:
            slug = target_slug(self.last_url or "page")[:60]
            path = runtime_path("state", "evidence", "browser",
                                f"{slug}-{int(time.time())}.png")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(path), full_page=True)
        return str(path)

    def close(self) -> None:
        """Idempotent teardown; safe even if the browser never started."""
        worker = self._worker
        if worker is not None and worker.is_alive():
            self._queue.put(None)          # sentinel: teardown + exit
            worker.join(timeout=15)
        self._worker = None

    def __enter__(self) -> "PlaywrightBrowserDriver":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
