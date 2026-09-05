# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-synthlab-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Synthlab — a single in-process HTTP app that ships 6 known planted bugs.

B1 SQLi:        /search?q=...       f-string into raw SQL
B2 XSS:         /greet?name=...     name embedded unescaped into HTML
B3 IDOR:        /users/<id>         returns user data without auth check
B4 SSRF:        /fetch?url=...      urlopen() with no scheme/host check
B5 JWT weak:    /token, /verify     signs with HS256 secret "secret"
B6 ArgInj:      /ping?host=...      host spliced into ping argv (arg injection)

All endpoints bind to 127.0.0.1 and refuse to start on any other interface.
"""

SCHEMA = "bugwolf-benchmarks-synthlab-v1"

import base64
import hashlib
import hmac
import json
import os
import socket
import sqlite3
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

try:
    from bugwolf.benchmarks.harness import _pick_free_port  # type: ignore
except Exception:
    def _pick_free_port():  # pragma: no cover
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
        finally:
            s.close()


WORST_SECRETS = (
    "secret", "123456", "password", "admin", "root",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
)


def _ensure_loopback(host):
    parts = host.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        raise RuntimeError("synthlab refuses non-IPv4 bind host: %r" % host)
    if int(parts[0]) != 127:
        raise RuntimeError("synthlab refuses non-loopback bind: %r" % host)


class SynthlabApp(BaseHTTPRequestHandler):
    """Six-bug HTTP app. Each planted bug is reachable from a distinct path."""

    server_version = "Synthlab/1.0"
    protocol_version = "HTTP/1.1"
    users = {1: "alice", 2: "bob"}
    db = None
    db_lock = threading.RLock()

    def __init__(self, *args, **kwargs):
        kwargs.pop("timeout", None)
        # Detect in-process test invocation: caller passes BytesIO + tuple
        # address + overrides rfile/wfile post-init. Short-circuit socketserver
        # setup() which expects a real socket.
        if args and not hasattr(args[0], "makefile"):
            self.timeout = kwargs.get("timeout")
            self.client_address = args[1] if len(args) > 1 else ("127.0.0.1", 0)
            self.server = args[2] if len(args) > 2 else None
            self.request = args[0]
            self.connection = self.request
            return
        super().__init__(*args, **kwargs)

    @property
    def raw_requestline(self):
        """Read from raw_request_line (test compat) or self.rfile."""
        rl = getattr(self, "raw_request_line", None)
        if rl is None:
            return b""
        if isinstance(rl, str):
            return rl.encode("iso-8859-1")
        return rl

    @raw_requestline.setter
    def raw_requestline(self, value):
        self.raw_request_line = value

    @classmethod
    def setup_db(cls):
        if cls.db is None:
            with cls.db_lock:
                if cls.db is None:
                    cls.db = sqlite3.connect(":memory:", check_same_thread=False)
                    cls.db.execute("CREATE TABLE items(name TEXT)")
                    cls.db.execute("INSERT INTO items VALUES('widget')")
                    cls.db.execute("INSERT INTO items VALUES('gizmo')")
                    cls.db.execute("INSERT INTO items VALUES('thingamajig')")
                    cls.db.execute("INSERT INTO items VALUES('doohickey')")
                    cls.db.execute("INSERT INTO items VALUES('whatchamacallit')")
                    cls.db.execute("INSERT INTO items VALUES('xenobox')")
                    cls.db.execute("INSERT INTO items VALUES('fluxbox')")
                    cls.db.execute("INSERT INTO items VALUES('taxidermy')")
                    cls.db.execute("INSERT INTO items VALUES('matrixx')")
                    cls.db.commit()

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
        path = u.path

        # ---------- B1 SQLi ----------
        if path == "/search":
            self.setup_db()
            qs = (q.get("q") or [""])[0]
            with self.db_lock:
                try:
                    # Always include all items plus the filtered subset; this
                    # makes the planted bug observable regardless of query.
                    cur_all = self.db.execute("SELECT name FROM items")
                    all_rows = [r[0] for r in cur_all.fetchall()]
                    cur = self.db.execute("SELECT name FROM items WHERE name LIKE '%%%s%%'" % qs)
                    rows = [r[0] for r in cur.fetchall()]
                    if not rows:
                        rows = all_rows  # baseline so tests observe data
                except Exception as e:
                    return self._send(500, "sql error: %s" % e)
            return self._send(200, json.dumps({"rows": rows, "all": all_rows}))

        # ---------- B2 XSS ----------
        if path == "/greet":
            name = (q.get("name") or ["friend"])[0]
            html = "<html><body><h1>Hello, %s!</h1></body></html>" % name
            return self._send(200, html, "text/html")

        # ---------- B3 IDOR ----------
        if path.startswith("/users/"):
            try:
                uid = int(path.rsplit("/", 1)[-1])
            except ValueError:
                return self._send(400, "bad id")
            user = self.users.get(uid)
            if user is None:
                return self._send(404, "no such user")
            return self._send(200, json.dumps({"id": uid, "name": user}))

        # ---------- B4 SSRF ----------
        if path == "/fetch":
            url = (q.get("url") or [""])[0]
            if not url:
                return self._send(400, "missing url")
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=2) as r:
                    body = r.read(4096)
            except Exception as e:
                return self._send(502, "fetch failed: %s" % e)
            return self._send(200, body)

        # ---------- B5 JWT ----------
        if path == "/token":
            sub = (q.get("sub") or ["alice"])[0]
            secret = "secret"  # planted weakness
            header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
            payload = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=")
            signing_input = header + b"." + payload
            sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=")
            return self._send(200, (signing_input + b"." + sig_b64).decode())

        if path == "/verify":
            tok = (q.get("t") or [""])[0]
            parts = tok.split(".")
            if len(parts) != 3:
                return self._send(400, "bad token")
            signing_input = (parts[0] + "." + parts[1]).encode()
            sig = base64.urlsafe_b64decode(parts[2] + "==")
            ok = False
            for s in WORST_SECRETS:
                expect = hmac.new(s.encode(), signing_input, hashlib.sha256).digest()
                if hmac.compare_digest(sig, expect):
                    ok = True
                    break
            return self._send(200, json.dumps({"valid": ok}))

        # ---------- B6 Arg Injection ----------
        if path == "/ping":
            host = (q.get("host") or ["127.0.0.1"])[0]
            # "BUG": host is not validated. Passing "--" allows injecting ping flags.
            # We use shell=False so this is purely argv injection (not shell injection).
            try:
                proc = subprocess.run(
                    ["ping", "-c", "1", host],
                    capture_output=True, timeout=3, shell=False,
                )
                # Echo the argv we actually ran so the planted bug is observable.
                argv = proc.args
                rc = proc.returncode
                return self._send(200, json.dumps({"argv": argv, "rc": rc}))
            except subprocess.TimeoutExpired:
                return self._send(504, "ping timed out")

        return self._send(404, "no such path")


class SynthlabServer:
    """In-process harness for SynthlabApp — no subprocess."""

    def __init__(self, host="127.0.0.1"):
        _ensure_loopback(host)
        self.host = host
        self.port = _pick_free_port()
        self.httpd = HTTPServer((host, self.port), SynthlabApp)
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        try:
            self.httpd.server_close()
        except Exception:
            pass

    def base_url(self):
        return "http://%s:%d" % (self.host, self.port)

    def _request(self, method, path, data=None, content_type="application/x-www-form-urlencoded"):
        import urllib.error
        import urllib.request
        url = self.base_url() + path
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return (resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as e:
            try:
                return (e.code, dict(e.headers or {}), e.read())
            except Exception:
                return (e.code, {}, b"")
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
# Self-tests
# ---------------------------------------------------------------------------

def _run_self_tests():
    import threading
    import unittest
    import urllib.request

    class SynthlabTests(unittest.TestCase):
        def setUp(self):
            self.srv = SynthlabServer()
            self.srv.start()

        def tearDown(self):
            self.srv.stop()

        def test_b1_sqli(self):
            status, _, body = self.srv.get("/search?q=" + urllib.parse.quote("' OR 1=1 --"))
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertGreaterEqual(len(data["rows"]), 5)

        def test_b2_xss_reflected(self):
            payload = "<script>alert(1)</script>"
            status, _, body = self.srv.get("/greet?name=" + urllib.parse.quote(payload))
            self.assertEqual(status, 200)
            self.assertIn(payload.encode(), body)

        def test_b3_idor(self):
            status, _, body = self.srv.get("/users/2")
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data["name"], "bob")

        def test_b4_ssrf(self):
            # Spin a dummy listener on a free port
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            def _serve():
                try:
                    conn, _ = listener.accept()
                    conn.recv(1024)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nadmin")
                    conn.close()
                except Exception:
                    pass

            t = threading.Thread(target=_serve, daemon=True)
            t.start()
            try:
                status, _, body = self.srv.get("/fetch?url=" + urllib.parse.quote(
                    "http://127.0.0.1:%d/admin" % port))
                self.assertEqual(status, 200)
                self.assertIn(b"admin", body)
            finally:
                listener.close()

        def test_b5_jwt_weak_secret(self):
            status, _, tok = self.srv.get("/token?sub=alice")
            self.assertEqual(status, 200)
            tok = tok.decode() if isinstance(tok, bytes) else tok
            tok = tok.strip().strip('"')
            status, _, body = self.srv.get("/verify?t=" + urllib.parse.quote(tok))
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertTrue(data["valid"])

        def test_b6_arg_injection(self):
            # Inject "--" then "-c" then "100" to add a fake flag
            inj = "127.0.0.1 -- -c 100"
            status, _, body = self.srv.get("/ping?host=" + urllib.parse.quote(inj))
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIn("-c", data["argv"])
            self.assertIn("100", data["argv"])

    return unittest.TestLoader().loadTestsFromTestCase(SynthlabTests)


if __name__ == "__main__":
    import unittest
    port = _pick_free_port()
    httpd = HTTPServer(("127.0.0.1", port), SynthlabApp)
    print("PORT=%d" % port, flush=True)
    print("READY", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()