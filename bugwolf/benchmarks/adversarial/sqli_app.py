# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-sqli-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial SQLi benchmark app — f-string interpolation into raw SQL."""

SCHEMA = "bugwolf-benchmarks-adversarial-sqli-v1"

import os
import socket
import sqlite3
import sys
import threading
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


_DB = None
_DB_LOCK = threading.RLock()


def _db():
    global _DB
    if _DB is None:
        with _DB_LOCK:
            if _DB is None:
                _DB = sqlite3.connect(":memory:", check_same_thread=False)
                _DB.execute("CREATE TABLE users(username TEXT, password TEXT, role TEXT)")
                _DB.execute("INSERT INTO users VALUES('alice','alice-pw','user')")
                _DB.execute("INSERT INTO users VALUES('bob','bob-pw','admin')")
                _DB.execute("INSERT INTO users VALUES('carol','carol-pw','user')")
                _DB.commit()
    return _DB


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (sqli)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            import json
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        import sys
        print("[handler] do_GET path=%s" % self.path, file=sys.stderr, flush=True)
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/login":
            user = (q.get("user") or [""])[0]
            pw = (q.get("pass") or [""])[0]
            print("[handler] got user=%r pw=%r" % (user, pw), file=sys.stderr, flush=True)
            with _DB_LOCK:
                try:
                    print("[handler] before db", file=sys.stderr, flush=True)
                    cur = _db().execute(
                        "SELECT username, role FROM users WHERE username='%s' AND password='%s'" % (user, pw)
                    )
                    print("[handler] after query", file=sys.stderr, flush=True)
                    rows = cur.fetchall()
                    print("[handler] after fetchall", file=sys.stderr, flush=True)
                except Exception as e:
                    print("[handler] sql err: %s" % e, file=sys.stderr, flush=True)
                    return self._send(500, {"error": "sql", "detail": str(e)})
            print("[handler] sending response", file=sys.stderr, flush=True)
            return self._send(200, {"rows": rows, "count": len(rows)})

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, {"error": "need ?confirm=yes"})
            import time as _t
            _t.sleep(3)
            return self._send(200, "RESET_OK")

        return self._send(404, {"error": "no such path"})


def main():
    host = "127.0.0.1"
    for _ in range(3):
        port = _pick_free_port()
        httpd = HTTPServer((host, port), Handler)
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