# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-xss-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial XSS benchmark app — comment text embedded in HTML unescaped."""

SCHEMA = "bugwolf-benchmarks-adversarial-xss-v1"

import socket
import time
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
    server_version = "AdvBench/1.0 (xss)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body, content_type="text/html"):
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
        if u.path == "/comment":
            text = (q.get("text") or [""])[0]
            # BUG: text embedded raw — no escaping
            html = (
                "<html><body><h1>Comment posted</h1>"
                "<div class='comment'>%s</div>"
                "</body></html>" % text
            )
            return self._send(200, html)

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, "need ?confirm=yes")
            time.sleep(3)
            return self._send(200, "RESET_OK", "text/plain")

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