# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-harness-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Harness for launching and exercising benchmark test apps on 127.0.0.1.

The harness spawns each test app as a subprocess, captures the port it
binds to by parsing startup output, and provides a small HTTP client
with hard timeouts. STUB-SAFE: any error from start / stop / request
is contained — nothing in here raises to the caller.
"""

SCHEMA = "bugwolf-benchmarks-harness-v1"

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _pick_free_port(retries: int = 5):
    """Bind to port 0 on 127.0.0.1 and return the assigned ephemeral port."""
    for _ in range(max(1, retries)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        finally:
            s.close()
        return port
    raise RuntimeError("could not pick a free port")


class BenchmarkApp:
    """Launch and exercise a benchmark test app on 127.0.0.1."""

    def __init__(self, name, app_module, app_attr="app", startup_timeout=10.0):
        self.name = name
        self.app_module = app_module
        self.app_attr = app_attr
        self.startup_timeout = startup_timeout
        self.port = None
        self.proc = None
        self._stdout_buf = []

    def start(self):
        """Launch the test app as a subprocess. Returns True on success."""
        if self.proc is not None:
            return self.port is not None
        cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cmd = [sys.executable, "-m", self.app_module]
        try:
            self.proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, ValueError):
            self.proc = None
            return False
        deadline = time.time() + self.startup_timeout
        port = None
        try:
            while time.time() < deadline:
                if self.proc.poll() is not None:
                    break
                line = self.proc.stdout.readline()
                if not line:
                    time.sleep(0.01)
                    continue
                self._stdout_buf.append(line)
                line = line.strip()
                if line.startswith("PORT="):
                    try:
                        port = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        port = None
                elif line == "READY" and port is not None:
                    self.port = port
                    return True
        except (OSError, ValueError):
            pass
        self.port = port
        return self.port is not None

    def stop(self):
        """Terminate the subprocess; kill on hang."""
        if self.proc is None:
            return
        try:
            self.proc.terminate()
        except (OSError, ProcessLookupError):
            self.proc = None
            return
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                self.proc.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        self.proc = None

    def base_url(self):
        return "http://127.0.0.1:{}".format(self.port or 0)

    def _request(self, method, path, data=None, content_type="application/x-www-form-urlencoded"):
        if self.port is None:
            return (0, {}, b"")
        url = self.base_url() + path
        body = data
        if isinstance(data, str):
            body = data.encode("utf-8")
        req = urllib.request.Request(url, data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", content_type)
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return (resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as e:
            try:
                body_bytes = e.read()
            except (OSError, urllib.error.URLError):
                body_bytes = b""
            return (e.code, dict(e.headers or {}), body_bytes)
        except (urllib.error.URLError, OSError, ValueError):
            return (0, {}, b"")

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, data, content_type="application/x-www-form-urlencoded"):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return self._request("POST", path, data=data, content_type=content_type)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


# ---------------------------------------------------------------------------
# Self-tests (also serve as the harness regression suite)
# ---------------------------------------------------------------------------

class _HarnessSelfTestHandler:
    """Trivial in-process handler used by harness self-tests."""

    def __init__(self):
        from http.server import BaseHTTPRequestHandler

        harness_self = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *args, **kwargs):
                return

            def do_GET(self):
                if self.path == "/ok":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("X-Harness", "self-test")
                    self.end_headers()
                    self.wfile.write(b"hello")
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                data = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"got:" + data)

        harness_self.handler_cls = _H


def _run_self_test_server():
    """Bind a self-test server on 127.0.0.1 and return (port, server, thread)."""
    import threading
    from http.server import HTTPServer

    helper = _HarnessSelfTestHandler()
    helper.handler_cls  # noqa: B018 — populated by helper ctor
    port = _pick_free_port()
    httpd = HTTPServer(("127.0.0.1", port), helper.handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return port, httpd, t


def _run_self_tests():
    import unittest

    class HarnessTests(unittest.TestCase):
        def test_pick_free_port(self):
            p = _pick_free_port()
            self.assertGreater(p, 0)

        def test_get_returns_200_from_fixture(self):
            port, httpd, _t = _run_self_test_server()
            try:
                ba = BenchmarkApp("selftest", "__main__")
                ba.port = port
                status, _h, body = ba.get("/ok")
                self.assertEqual(status, 200)
                self.assertEqual(body, b"hello")
            finally:
                httpd.shutdown()
                httpd.server_close()

        def test_post_works(self):
            port, httpd, _t = _run_self_test_server()
            try:
                ba = BenchmarkApp("selftest", "__main__")
                ba.port = port
                status, _h, body = ba.post("/echo", b"x=1")
                self.assertEqual(status, 200)
                self.assertIn(b"x=1", body)
            finally:
                httpd.shutdown()
                httpd.server_close()

        def test_get_missing_returns_zero(self):
            port, httpd, _t = _run_self_test_server()
            try:
                ba = BenchmarkApp("selftest", "__main__")
                ba.port = port
                status, _h, body = ba.get("/nope")
                # 404 from fixture is fine; what we test is no exception
                self.assertIn(status, (404, 0))
                self.assertIsInstance(body, bytes)
            finally:
                httpd.shutdown()
                httpd.server_close()

        def test_context_manager(self):
            port, httpd, _t = _run_self_test_server()
            try:
                ba = BenchmarkApp("selftest", "__main__")
                ba.port = port
                with ba as b:
                    self.assertIs(b, ba)
                    status, _, _ = b.get("/ok")
                    self.assertEqual(status, 200)
            finally:
                httpd.shutdown()
                httpd.server_close()

        def test_start_returns_false_when_module_missing(self):
            ba = BenchmarkApp("missing", "this_module_does_not_exist_xyz", startup_timeout=0.5)
            ok = ba.start()
            self.assertFalse(ok)
            ba.stop()

    return unittest.TestLoader().loadTestsFromTestCase(HarnessTests)


if __name__ == "__main__":
    import unittest
    unittest.TextTestRunner(verbosity=2).run(_run_self_tests())