# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-idor-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial IDOR benchmark app — returns user data without auth check."""

SCHEMA = "bugwolf-benchmarks-adversarial-idor-v1"

import json
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


_USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@example.com", "role": "user"},
    2: {"id": 2, "name": "bob", "email": "bob@example.com", "role": "admin"},
    3: {"id": 3, "name": "carol", "email": "carol@example.com", "role": "user"},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (idor)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path.startswith("/api/users/"):
            try:
                uid = int(u.path.rsplit("/", 1)[-1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            user = _USERS.get(uid)
            if user is None:
                return self._send(404, {"error": "no such user"})
            # BUG: no auth check — returns any user's data to anyone
            return self._send(200, user)

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, {"error": "need ?confirm=yes"})
            time.sleep(3)
            return self._send(200, "RESET_OK")

        return self._send(404, {"error": "no such path"})


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