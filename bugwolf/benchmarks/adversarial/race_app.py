# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-race-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial race-condition benchmark app — transfer-without-lock.

The BUG path (default) sleeps 0.1s between read and write of the
sender's balance. The /fixed path uses a threading.Lock.

Two endpoints expose the bug:
  * /transfer        — buggy (no lock)
  * /transfer_fixed  — fixed (uses threading.Lock)
"""

SCHEMA = "bugwolf-benchmarks-adversarial-race-v1"

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


_BALANCES = {"alice": 1000, "bob": 1000}
_BALANCES_LOCK = threading.Lock()


def _buggy_transfer(frm, to, amount):
    bal = _BALANCES.get(frm)
    if bal is None or bal < amount:
        return {"ok": False, "reason": "insufficient funds", "balance": bal}
    time.sleep(0.1)  # race window
    _BALANCES[frm] = bal - amount
    _BALANCES[to] = _BALANCES.get(to, 0) + amount
    return {"ok": True, "from": _BALANCES[frm], "to": _BALANCES[to]}


def _fixed_transfer(frm, to, amount):
    with _BALANCES_LOCK:
        bal = _BALANCES.get(frm)
        if bal is None or bal < amount:
            return {"ok": False, "reason": "insufficient funds", "balance": bal}
        time.sleep(0.1)
        _BALANCES[frm] = bal - amount
        _BALANCES[to] = _BALANCES.get(to, 0) + amount
        return {"ok": True, "from": _BALANCES[frm], "to": _BALANCES[to]}


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (race)"

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
        if u.path in ("/transfer", "/transfer_fixed"):
            frm = (q.get("from") or ["alice"])[0]
            to = (q.get("to") or ["bob"])[0]
            try:
                amount = int((q.get("amount") or ["0"])[0])
            except ValueError:
                return self._send(400, {"error": "bad amount"})
            fn = _fixed_transfer if u.path == "/transfer_fixed" else _buggy_transfer
            return self._send(200, fn(frm, to, amount))

        if u.path == "/balance":
            return self._send(200, {"balances": dict(_BALANCES)})

        if u.path == "/reset":
            if (q.get("confirm") or [""])[0] != "yes":
                return self._send(400, {"error": "need ?confirm=yes"})
            with _BALANCES_LOCK:
                _BALANCES["alice"] = 1000
                _BALANCES["bob"] = 1000
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