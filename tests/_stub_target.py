#!/usr/bin/env python3
"""Test-only deterministic stub target (NOT a shipped lab).

Production BugWolf hunting binds exclusively to operator-supplied targets and
attestations.  This module exists so the test-suite can exercise the live
lanes (recon, web/API, business-logic, verify, report) deterministically and
offline: every behavior is a fixed request -> response rule, no randomness,
no state beyond the request.  It ships only inside ``tests/`` and is never a
production boundary.

Behaviors mirror the vulnerability classes the lanes hunt:

  recon            GET /tech.json, /openapi.json
  BOLA             GET /api/users/{id}      (no authorization check)
  WAF bypass       GET /api/gateway         (403 unless X-Original-URL)
  fuzz             GET /api/ingest?q=...    (5xx on over-long / SQL-ish)
  generic          POST /graphql            (introspection schema)
  FIN money flows  /api/checkout, /api/payment/callback, /api/voucher/redeem,
                   /api/withdraw, /api/rates  (client-trusted price, replay,
                   voucher reuse, favor rounding, test-gateway forcing)

Boot pattern (same style as every live-lane test)::

    spec = importlib.util.spec_from_file_location("stub_target",
                                                  ROOT / "tests/_stub_target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
"""

import base64
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _issue_token(username: str) -> str:
    """Issue a structurally valid (deliberately weak) JWT, as a real target's
    login would: three base64url parts, HS256 header, no expiry.  Test stub
    only -- the weakness is the point the auth lane hunts."""
    header = _b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(
        {"username": username, "role": "user"}).encode())
    signature = _b64url(b"stub-signature-not-a-real-secret")
    return f"{header}.{payload}.{signature}"

USERS = {
    "1": {"id": "1", "username": "alice", "email": "alice@stub.local",
          "role": "user", "balance": 100},
    "2": {"id": "2", "username": "bob", "email": "bob@stub.local",
          "role": "user", "balance": 250},
    "42": {"id": "42", "username": "admin", "email": "admin@stub.local",
           "role": "admin", "balance": 99999},
}

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Stub Target API", "version": "1.0.0"},
    "paths": {
        "/api/users/{id}": {
            "get": {
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "user"}},
            }
        },
        "/api/checkout": {
            "post": {
                "requestBody": {"content": {"application/json": {
                    "schema": {"type": "object", "properties": {
                        "item_id": {"type": "string"},
                        "quantity": {"type": "integer"},
                        "price": {"type": "number"},
                        "currency": {"type": "string"},
                        "payment_type": {"type": "integer"},
                        "voucher_code": {"type": "string"},
                    }}}}},
                "responses": {"200": {"description": "order"}},
            }
        },
        "/api/payment/callback": {
            "post": {"responses": {"200": {"description": "callback ack"}}}
        },
        "/api/voucher/redeem": {
            "post": {"responses": {"200": {"description": "voucher applied"}}}
        },
        "/api/withdraw": {
            "post": {"responses": {"200": {"description": "withdrawal"}}}
        },
        "/api/rates": {"get": {"responses": {"200": {"description": "FX rates"}}}},
        "/graphql": {"post": {"responses": {"200": {"description": "graphql"}}}},
    },
}

TECH = {
    "service": "stub-target",
    "tech": ["nginx", "node", "graphql", "express"],
    "versions": {"nginx": "1.24.0", "node": "20.11.0", "express": "4.18.2"},
}

GRAPHQL_SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "user", "args": [
                {"name": "id", "type": {"kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"}}}],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
            {"name": "users", "args": [],
             "type": {"kind": "LIST",
                      "ofType": {"kind": "OBJECT", "name": "User"}}},
        ]},
        {"kind": "OBJECT", "name": "Mutation", "fields": [
            {"name": "updateUser", "args": [
                {"name": "id", "type": {"kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"}}}],
             "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
        ]},
        {"kind": "OBJECT", "name": "User", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
            {"name": "username", "type": {"kind": "SCALAR", "name": "String"}},
            {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
            {"name": "role", "type": {"kind": "SCALAR", "name": "String"}},
            {"name": "balance", "type": {"kind": "SCALAR", "name": "Float"}},
        ]},
    ],
}}}

# Fixed unit price so total-anomaly detection is deterministic.
_UNIT_PRICE = 100.0
_LAST_ORDER = {"order_id": None}


def _num(value):
    """Parse a client-supplied number the way the vulnerable stack does:
    trust it verbatim (float() accepts '1e99', 'NaN', 'Infinity', '0x0A'
    fails open to 1)."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 1.0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep test output quiet
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._json(200, {"service": "stub-target", "status": "ok"})
        elif path == "/openapi.json":
            self._json(200, OPENAPI)
        elif path == "/tech.json":
            self._json(200, TECH)
        elif path.startswith("/api/users/"):
            user = USERS.get(path.rsplit("/", 1)[-1])
            # BOLA: no session/authorization check on the object itself.
            self._json(200, user) if user else self._json(404, {"error": "not found"})
        elif path == "/api/ingest":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if len(q) > 64 or "' OR '1'='1" in q or "SLEEP(" in q:
                self._json(500, {"error": "ingest parser failure"})
            else:
                self._json(200, {"ok": True})
        elif path == "/api/gateway":
            if "X-Original-URL" in self.headers:
                self._json(200, {"id": "gw-1", "service": "internal-gateway",
                                 "role": "admin", "token": "gw-secret-token"})
                return
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if q:
                self._json(403, {"error": "access denied by gateway firewall"})
            else:
                self._json(200, {"gateway": "open", "status": "ok"})
        elif path == "/api/rates":
            self._json(200, {"EUR_USD": 1.5, "USD_EUR": 0.6667})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        if path == "/api/users":
            # Mass assignment: role/isAdmin from the request are trusted.
            if not body.get("username"):
                self._json(400, {"error": "username required"})
                return
            self._json(201, {"id": "3", "username": body["username"],
                             "email": body.get("email", ""),
                             "role": body.get("role", "user"),
                             "isAdmin": body.get("isAdmin", False),
                             "balance": body.get("balance", 0)})
        elif path == "/login":
            self._json(200, {"token": _issue_token(str(body.get("username", "alice"))),
                             "token_type": "Bearer"})
        elif path == "/api/checkout":
            quantity = _num(body.get("quantity", 1))
            price = _num(body.get("price", _UNIT_PRICE))
            # FIN-PARAM: the client-supplied price is trusted verbatim.
            total = price * quantity
            order_id = f"ord-{len(str(total))}-{quantity}"
            _LAST_ORDER["order_id"] = order_id
            gateway = ("test" if str(body.get("payment_type", "")) in
                       ("99", "test") else "live")
            self._json(200, {"order_id": order_id, "status": "pending",
                             "total": total, "currency": body.get("currency", "USD"),
                             "unit_price": price, "gateway": gateway})
        elif path == "/api/checkout/confirm":
            # FIN-TOCTOU: the confirm step re-accepts a changed price for an
            # order that already reached the payment stage.
            if body.get("order_id"):
                self._json(200, {"order_id": body["order_id"],
                                 "status": "paid",
                                 "total": _num(body.get("price", 0))})
            else:
                self._json(400, {"error": "order_id required"})
        elif path == "/api/payment/callback":
            # FIN-REPLAY: no nonce/state check; the same callback is acked
            # every time.
            self._json(200, {"callback": "acknowledged",
                             "amount": body.get("amount", 0)})
        elif path == "/api/voucher/redeem":
            # FIN-VOUCHER: single-use codes are never marked used.
            code = body.get("code") or body.get("voucher_code") or ""
            if re.fullmatch(r"[A-Z0-9]{4,32}", str(code)):
                self._json(200, {"code": code, "discount": 10,
                                 "applied": True})
            else:
                self._json(400, {"error": "invalid code"})
        elif path == "/api/withdraw":
            # FIN-ROUND: rounding always lands in the requester's favor
            # (ceil to cents); FIN-ARBITRAGE: the debit uses a stale rate.
            amount = _num(body.get("amount", 0))
            credited = -(-int(amount * 100) // 100) / 100.0  # ceil to cent
            self._json(200, {"credited": credited,
                             "currency": body.get("currency", "USD"),
                             "rate_used": 1.5})
        elif path == "/graphql":
            query = str(body.get("query", ""))
            if re.search(r"__schema|introspection", query, re.I):
                self._json(200, GRAPHQL_SCHEMA)
            else:
                self._json(200, {"data": {"users": USERS}})
        elif path in ("/account/email", "/account/reset"):
            self._json(200, {"changed": True})
        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":  # manual smoke only: python3 tests/_stub_target.py [port]
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"stub target on http://127.0.0.1:{srv.server_address[1]}")
    srv.serve_forever()
