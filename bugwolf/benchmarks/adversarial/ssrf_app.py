# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-ssrf-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial SSRF benchmark app — fetches arbitrary http(s) URLs.

Refuses `file://` (so this is not a LFI). The bug is unrestricted http(s)
target access, including internal 127.0.0.1 services.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-ssrf-v1"

import socket
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from bugwolf.benchmarks.harness import _pick_free_port
except Exception:
    def _pick_free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (ssrf)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body, content_type="text/plain"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/proxy":
            url = (q.get("url") or [""])[0]
            if not url:
                return self._send(400, "missing url")
            if url.startswith("file://"):
                return self._send(400, "file:// refused")
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    body = r.read(8192)
            except Exception as e:
                return self._send(502, "fetch failed: %s" % e)
            return self._send(200, body)

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, "need ?confirm=yes")
            time.sleep(3)
            return self._send(200, "RESET_OK")

        return self._send(404, "no such path")


def main():
    for _ in range(3):
        port = _pick_free_port()
        httpd = HTTPServer(("127.0.0.1", port), Handler)
        print("PORT=%d" % port, flush=True)
        print("READY", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            return
        except OSError:
            continue


if __name__ == "__main__":
    main()