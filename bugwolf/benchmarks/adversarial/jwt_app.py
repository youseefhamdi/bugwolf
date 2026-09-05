# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-jwt-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial JWT benchmark app — signs with HS256 weak secret.

`/issue` signs JWT with HS256 + secret "secret".
`/verify` accepts tokens signed with any of the 10 worst passwords.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-jwt-v1"

import base64
import hashlib
import hmac
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


WORST_SECRETS = (
    "secret", "123456", "password", "admin", "root",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
)


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def _hs256(secret: str, signing_input: bytes) -> bytes:
    return hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()


def _make_token(secret: str, sub: str) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": sub, "role": "user"}).encode())
    sig = _b64url(_hs256(secret, header + b"." + payload))
    return (header + b"." + payload + b"." + sig).decode()


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (jwt)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body, content_type="text/plain"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
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
        if u.path == "/issue":
            sub = (q.get("sub") or ["alice"])[0]
            tok = _make_token("secret", sub)
            return self._send(200, {"token": tok})

        if u.path == "/verify":
            tok = (q.get("t") or [""])[0]
            parts = tok.split(".")
            if len(parts) != 3:
                return self._send(400, {"error": "bad token"})
            try:
                signing_input = (parts[0] + "." + parts[1]).encode()
                sig = base64.urlsafe_b64decode(parts[2] + "==")
            except Exception as e:
                return self._send(400, {"error": "bad encoding", "detail": str(e)})
            for s in WORST_SECRETS:
                if hmac.compare_digest(sig, _hs256(s, signing_input)):
                    return self._send(200, {"valid": True, "secret_used": s})
            return self._send(200, {"valid": False})

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