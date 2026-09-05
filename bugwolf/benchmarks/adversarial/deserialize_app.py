# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-deserialize-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial deserialize benchmark app — pickle.loads on user-supplied bytes.

WARNING: This endpoint executes arbitrary Python when fed a valid pickle
payload. It is local-only (binds 127.0.0.1) and exists ONLY so that a
scanner can demonstrate the RCE pattern. Do NOT use this against any
non-test target.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-deserialize-v1"

import base64
import os
import pickle
import socket
import tempfile
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


_CANARY_PATH = os.path.join(tempfile.gettempdir(), "bugwolf_deser_canary.txt")


class _CanaryExec:
    """Pickle payload that writes a marker file when deserialized."""

    def __reduce__(self):
        import builtins
        return (
            builtins.exec,
            ("open(%r,'w').write('bugwolf_pwned')\n" % _CANARY_PATH,),
        )


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (deserialize)"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, body):
        if isinstance(body, (dict, list)):
            import json
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
        if u.path == "/load":
            data_b64 = (q.get("data") or [""])[0]
            try:
                raw = base64.b64decode(data_b64, validate=False)
            except Exception as e:
                return self._send(400, {"error": "bad base64", "detail": str(e)})
            try:
                # BUG: untrusted pickle
                result = pickle.loads(raw)
            except Exception as e:
                return self._send(400, {"error": "pickle failed", "detail": str(e)})
            return self._send(200, {"ok": True, "repr": repr(result)[:200]})

        if u.path == "/canary":
            exists = os.path.exists(_CANARY_PATH)
            return self._send(200, {"path": _CANARY_PATH, "exists": exists})

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, {"error": "need ?confirm=yes"})
            try:
                os.remove(_CANARY_PATH)
            except OSError:
                pass
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