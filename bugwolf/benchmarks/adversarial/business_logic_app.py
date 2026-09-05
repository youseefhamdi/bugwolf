# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-business-logic-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
"""Adversarial business-logic benchmark app — 100%-off coupon bypass.

The BUG is that `TOTALFREE` accepts any cart_total and zeroes it. A
proper implementation would refuse to discount carts above some cap
(e.g. $100) and would refuse to make the final total negative.
"""

SCHEMA = "bugwolf-benchmarks-adversarial-business-logic-v1"

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


class Handler(BaseHTTPRequestHandler):
    server_version = "AdvBench/1.0 (business-logic)"

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
        if u.path == "/apply_coupon":
            code = (q.get("code") or [""])[0]
            try:
                cart_total = float((q.get("cart_total") or ["0"])[0])
            except ValueError:
                return self._send(400, {"error": "bad cart_total"})
            discount = 0.0
            if code == "TOTALFREE":
                # BUG: applies 100% off even for huge carts (negative-value attack)
                discount = cart_total
            elif code == "HALFOFF":
                if cart_total <= 100:
                    discount = cart_total * 0.5
                else:
                    discount = 50.0
            new_total = cart_total - discount
            return self._send(200, {"code": code, "discount": discount,
                                    "cart_total": cart_total, "new_total": new_total})

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