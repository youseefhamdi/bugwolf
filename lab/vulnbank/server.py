#!/usr/bin/env python3
"""VulnBank — a small intentionally-vulnerable local demo app (Lab only).

Runs on stdlib http.server (no third-party deps). Exposes a deliberately
insecure API surface for exercising the BugWolf deep-hunt tool suite:

  GET  /                         — landing page
  GET  /api/users/<id>           — BOLA: object-level authz never checked
  POST /api/users                — mass assignment: `role`/`isAdmin` over-bound
  POST /graphql                  — GraphQL-ish endpoint (batching/aliasing)
  POST /login                    — issues HS256 JWT signed with a weak secret
  POST /account/email            — email-change endpoint (ATO lead)
  POST /account/reset            — password-reset endpoint (ATO lead)
  GET  /openapi.json             — OpenAPI 3.0 spec for schema-driven tools
  GET  /tech.json                — tech fingerprint (nginx, node, graphql, waf)
  GET  /api/ingest               — fuzz target: 500s on over-long or SQL-ish
                                   `q` input (deterministic crash the fuzz
                                   bridge finds and the loop reproduces)
  GET  /api/gateway               — WAF gateway: 403s fuzz-mutated `q`
                                   requests unless X-Original-URL bypass
                                   header present (operator-approval surface)

This is a LOCAL lab fixture for authorized testing only. It binds 127.0.0.1
and performs no network activity.
"""

import base64
import hashlib
import hmac
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8077

# A deliberately weak shared secret (lab fixture).
JWT_SECRET = "vulnbank-super-secret-2026"

USERS = {
    "1": {"id": "1", "username": "alice", "email": "alice@vulnbank.local",
          "role": "user", "balance": 100},
    "2": {"id": "2", "username": "bob", "email": "bob@vulnbank.local",
          "role": "user", "balance": 250},
    "42": {"id": "42", "username": "admin", "email": "admin@vulnbank.local",
           "role": "admin", "balance": 999999},
}

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "VulnBank API", "version": "1.0.0"},
    "paths": {
        "/api/users/{id}": {
            "get": {
                "parameters": [{"name": "id", "in": "path",
                                "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "user"}},
            }
        },
        "/api/users": {
            "post": {
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/User"}}}},
                "responses": {"201": {"description": "created"}},
            }
        },
        "/login": {
            "post": {
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {"type": "object",
                                   "properties": {"username": {"type": "string"},
                                                  "password": {"type": "string"}}}}}},
                "responses": {"200": {"description": "token"}},
            }
        },
    },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "isAdmin": {"type": "boolean", "readOnly": True},
                    "balance": {"type": "number"},
                },
            }
        }
    },
}

TECH = {
    "target": "vulnbank.local",
    "stack": ["nginx", "node", "graphql", "express"],
    "waf": True,
    "graphql": True,
    "endpoints": ["/api/users", "/graphql", "/login"],
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(header: dict, payload: dict) -> str:
    body = _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + _b64url(sig)


def _issue_jwt(username: str) -> str:
    return _sign(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": username, "role": "user", "iat": 1756000000, "exp": 1956000000},
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._json(200, {"service": "vulnbank", "status": "ok"})
        elif path == "/openapi.json":
            self._json(200, OPENAPI)
        elif path == "/tech.json":
            self._json(200, TECH)
        elif path.startswith("/api/users/"):
            user_id = path.rsplit("/", 1)[-1]
            # BOLA: no session/authorization check on the object itself.
            user = USERS.get(user_id)
            if not user:
                self._json(404, {"error": "not found"})
                return
            self._json(200, user)
        elif path == "/api/ingest":
            # Fuzz target: the "ingest parser" deterministically 5xxes on
            # over-long or SQL-ish input.  This is the crash surface the fuzz
            # bridge finds and the live loop re-probes + reproduces (E2E
            # fuzz -> spawn -> reproduce cycle / self-eval task 9).
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if len(q) > 64 or "' OR '1'='1" in q or "SLEEP(" in q:
                self._json(500, {"error": "ingest parser failure"})
                return
            self._json(200, {"ok": True})
        elif path == "/api/gateway":
            # WAF gateway: blocks fuzz-mutated requests (any `q` probe) with
            # a 403 unless the request carries the X-Original-URL bypass
            # header (the failure-learning catalog's header-based path
            # access technique).  This is the blocked -> operator approval ->
            # bypass exploitation surface (self-eval task 10 milestone).
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if "X-Original-URL" in self.headers:
                self._json(200, {"id": "gw-1", "service": "internal-gateway",
                                 "role": "admin", "token": "gw-secret-token"})
                return
            if q:
                self._json(403, {"error": "access denied by gateway firewall"})
                return
            self._json(200, {"gateway": "open", "status": "ok"})
        elif path == "/graphql":
            self._json(200, {"data": {"__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"kind": "OBJECT", "name": "Query",
                     "fields": [
                         {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                         {"name": "users", "args": [], "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}},
                     ]},
                    {"kind": "OBJECT", "name": "Mutation",
                     "fields": [
                         {"name": "updateUser", "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                     ]},
                    {"kind": "OBJECT", "name": "User",
                     "fields": [
                         {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                         {"name": "username", "type": {"kind": "SCALAR", "name": "String"}},
                         {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                         {"name": "role", "type": {"kind": "SCALAR", "name": "String"}},                             {"name": "avatarUrl", "type": {"kind": "SCALAR", "name": "String"}},
                         ]},
                    ]}}})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = self._read_body()
        if path == "/api/users":
            # Mass assignment: `role`/`isAdmin` from the request are trusted.
            if not body.get("username"):
                self._json(400, {"error": "username required"})
                return
            created = {"id": "3", "username": body["username"],
                       "email": body.get("email", ""),
                       "role": body.get("role", "user"),
                       "isAdmin": body.get("isAdmin", False),
                       "balance": body.get("balance", 0)}
            self._json(201, created)
        elif path == "/login":
            token = _issue_jwt(body.get("username", "alice"))
            self._json(200, {"token": token, "token_type": "Bearer"})
        elif path == "/account/email":
            # Email change: no re-auth of the current session (ATO lead).
            self._json(200, {"changed": True, "email": body.get("email", "")})
        elif path == "/account/reset":
            # Password reset: no token step (ATO lead).
            self._json(200, {"reset": True, "username": body.get("username", "")})
        elif path == "/graphql":
            query = body.get("query", "")
            if re.search(r"__schema|introspection", query, re.I):
                self._json(200, {"data": {"__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"kind": "OBJECT", "name": "Query",
                         "fields": [
                             {"name": "user", "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                             {"name": "users", "args": [], "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}},
                         ]},
                        {"kind": "OBJECT", "name": "Mutation",
                         "fields": [
                             {"name": "updateUser", "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}], "type": {"kind": "OBJECT", "name": "User", "ofType": None}},
                         ]},
                        {"kind": "OBJECT", "name": "User",
                         "fields": [
                             {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                             {"name": "username", "type": {"kind": "SCALAR", "name": "String"}},
                             {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                             {"name": "role", "type": {"kind": "SCALAR", "name": "String"}},
                             {"name": "avatarUrl", "type": {"kind": "SCALAR", "name": "String"}},
                         ]},
                    ]}}})
            else:
                self._json(200, {"data": {"users": USERS}})
        else:
            self._json(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[+] VulnBank listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
