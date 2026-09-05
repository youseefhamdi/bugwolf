# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-graphql-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial GraphQL benchmark app — introspection enabled by default.

This is a minimal in-process GraphQL stub. It exposes an introspection
endpoint (the planted bug) and a `/users` query that returns everyone
without an auth check (a second planted bug). Bind is 127.0.0.1 only.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-graphql-v1"

import json
import socket
import threading
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


_USERS = [
    {"id": 1, "name": "alice", "role": "user"},
    {"id": 2, "name": "bob", "role": "admin"},
    {"id": 3, "name": "carol", "role": "user"},
]


_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT"},
                {"name": "User", "kind": "OBJECT"},
            ],
        }
    }
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (graphql)"

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

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/graphql":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                req = json.loads(raw)
            except Exception:
                return self._send(400, {"error": "bad json"})
            query = req.get("query", "")
            if "__schema" in query:
                # BUG: introspection enabled in production
                return self._send(200, _INTROSPECTION)
            if "users" in query:
                # BUG: returns ALL users without auth check
                return self._send(200, {"data": {"users": _USERS}})
            return self._send(200, {"data": None, "errors": [{"message": "unknown query"}]})

        return self._send(404, {"error": "no such path"})

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/graphql" and "__schema" in u.query:
            return self._send(200, _INTROSPECTION)
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