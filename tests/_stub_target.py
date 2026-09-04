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
import hashlib
import json
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

# FIN-CRYPTO canary secret (CI regression only; models the classic
# ``secret || signature`` MAC construction the hash-length-extension and
# concatenated-signature techniques attack).  16 bytes, inside the prober's
# bounded secret-length sweep.
_SIGNING_SECRET = "s3cretk3ycanary"


def _pay_sig(params: str) -> str:
    """The vulnerable MAC: SHA256(secret || params) with no delimiter."""
    return hashlib.sha256((_SIGNING_SECRET + params).encode()).hexdigest()


def _pay_verify(params: str, sig: str) -> bool:
    return params and sig and sig == _pay_sig(params)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _cb_json(handler, code: int, payload: dict) -> None:
    """JSON helper for the OAST callback surface (handler has no _json in
    the do_GET early paths -- mirrors Handler._json exactly)."""
    body = json.dumps(payload).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# Stored notes for the client-side lane (CI regression only): "note:<text>"
# ingests are stored verbatim and replayed verbatim by GET /api/notes -- the
# classic stored-XSS sink for the reflection-is-not-execution check.
_NOTES: list = []

# Replay-engine caches (CI regression only): cache_key -> (body, unkeyed_debug)
_CACHE: dict = {}


def _issue_token(username: str, role: str = "user") -> str:
    """Issue a structurally valid (deliberately weak) JWT, as a real target's
    login would: three base64url parts, HS256 header, no expiry.  The role
    claim is signed-in data — the authz differential surfaces read it.
    Test stub only -- the weakness is the point the auth lane hunts."""
    header = _b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(
        {"username": username, "role": role}).encode())
    signature = _b64url(b"stub-signature-not-a-real-secret")
    return f"{header}.{payload}.{signature}"


def _token_role(auth_header: str) -> str:
    """Role carried by the request's Bearer token ('' when absent/invalid).
    Deliberately signature-less decode — the stub models a target whose
    authorization trusts the token's claims (that trust IS the bug class)."""
    if not auth_header:
        return ""
    token = auth_header.split(" ", 1)[1] if " " in auth_header else auth_header
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode()))
        return str(claims.get("role", "")) if isinstance(claims, dict) else ""
    except (ValueError, TypeError):
        return ""

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
        "/api/users": {
            # Declared because the stub IMPLEMENTS it (and trusts it):
            # the mass-assignment surface.  The schema documents the
            # vulnerable truth — role/isAdmin are client-settable.
            "post": {
                "requestBody": {"content": {"application/json": {
                    "schema": {"type": "object", "properties": {
                        "username": {"type": "string"},
                        "role": {"type": "string"},
                        "isAdmin": {"type": "boolean"},
                    }}}}},
                "responses": {"201": {"description": "created user"}},
            }
        },
        "/api/ingest": {
            "get": {
                "parameters": [{"name": "q", "in": "query", "required": False,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ingest result"}},
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

# ---------------------------------------------------------------------------
# U1 business surfaces (Understanding Layer inputs): pricing + ToS pages.
# ---------------------------------------------------------------------------

_PRICING_HTML = """<!DOCTYPE html>
<html><head><title>StubWare — Pricing &amp; Plans</title></head>
<body>
<h1>Pricing plans</h1>
<p>Start free. Upgrade to a paid subscription for premium features.</p>
<ul>
  <li>Free tier: 1 workspace, community support.</li>
  <li>Pro plan: $29/month per seat, billing monthly or yearly.</li>
  <li>Enterprise: custom pricing, SSO, audit logs, premium support.</li>
</ul>
<p>Coupons: apply a voucher code at checkout to receive a discount.</p>
<p><a href="/signup">Start your subscription</a> |
   <a href="/tos">Terms of service</a> |
   <a href="/api/checkout">Checkout API</a></p>
</body></html>"""

_TOS_HTML = """<!DOCTYPE html>
<html><head><title>StubWare — Terms of Service</title></head>
<body>
<h1>Terms of service</h1>
<p>Accounts: every user must verify their email address before their
   workspace is activated. Merchants selling on the marketplace must
   complete KYC verification before receiving payouts.</p>
<p>Billing: paid plans renew automatically; refunds within 14 days.
   Admin users manage team members and can approve or delete orders.</p>
<p>Acceptable use: no unauthorized security testing.</p>
<p><a href="/pricing">Back to pricing</a></p>
</body></html>"""

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
    protocol_version = "HTTP/1.1"   # keep-alive backend: the H2.CL pooled-
    # connection desync (Phase 1.1b) needs a backend that leaves the socket
    # open after each response.

    def log_message(self, fmt, *args):  # keep test output quiet
        pass

    def __getattr__(self, name):
        """Raw-mode acceptance surface: dispatch ANY 'do_*' method spelling
        to do_GET so odd-case verbs sent verbatim by the replay engine
        (e.g. ``gEt``) are handled instead of 501'd — Python's handler
        dispatch is case-sensitive by default; a raw byte-fidelity engine
        must be observable through a server that tolerates that."""
        if name.startswith("do_"):
            return self.do_GET
        raise AttributeError(name)

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # replay tests deliberately abandon half-read responses

    def _html(self, code, body):
        body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_body(self):
        # Desync fork (Phase 1.1b): when BOTH a Content-Length and a
        # Transfer-Encoding are present, RFC 7230 §3.3.3 says TE wins and
        # the C-L must be removed/ignored.  A frontend that forwards a
        # client C-L alongside the forbidden TE (the H2.CL bug) creates a
        # framing ambiguity only a TE-honoring backend exposes: honor TE
        # here, so the attacker's chunked body decodes and its post-
        # terminator bytes land on the connection as the next request.
        if ("Transfer-Encoding" in self.headers
                and "Content-Length" in self.headers):
            te = self.headers.get("Transfer-Encoding", "")
            if "chunked" in te.lower():
                return self._read_chunked_body()
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return {}

    def _read_chunked_body(self):
        """Honest chunked decoding for the TE-wins branch (Phase 1.1b)."""
        body = b""
        while True:
            size_line = self.rfile.readline(1024)
            if not size_line:
                return {}
            try:
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                return {}
            if size == 0:
                # consume trailer lines up to the blank line
                while True:
                    trailer = self.rfile.readline(1024)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                return {}
            data = self.rfile.read(size)
            body += data
            self.rfile.read(2)                     # chunk CRLF

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._json(200, {"service": "stub-target", "status": "ok"})
        elif path == "/openapi.json":
            self._json(200, OPENAPI)
        elif path == "/tech.json":
            self._json(200, TECH)
        elif path == "/pricing":
            self._html(200, _PRICING_HTML)
        elif path == "/tos":
            self._html(200, _TOS_HTML)
        elif path.startswith("/api/users/"):
            user = USERS.get(path.rsplit("/", 1)[-1])
            # BOLA: no session/authorization check on the object itself.
            self._json(200, user) if user else self._json(404, {"error": "not found"})
        elif path == "/api/ingest":
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if len(q) > 64 or "' OR '1'='1" in q or "SLEEP(" in q:
                self._json(500, {"error": "ingest parser failure"})
            elif q.startswith("http://") or q.startswith("https://"):
                # SSRF lane: the ingest parser fetches arbitrary URLs (a
                # classic enterprise feed-import bug).  Real fetch, no
                # allowlist -- the OAST canary attribution depends on it.
                try:
                    with urllib.request.urlopen(q, timeout=5) as resp:
                        self._json(200, {"fetched": True,
                                         "upstream": resp.status,
                                         "snippet": resp.read(120).decode(
                                             "utf-8", "replace")})
                except Exception as exc:  # noqa: BLE001 - failure is data
                    self._json(200, {"fetched": False,
                                     "error": f"{type(exc).__name__}"})
            elif q.startswith("note:"):
                # Client-side lane: store verbatim, replay verbatim.
                _NOTES.append(q[len("note:"):])
                self._json(200, {"stored": True, "total": len(_NOTES)})
            else:
                self._json(200, {"ok": True})
        elif path == "/api/notes":
            # Client-side lane replay surface: stored notes rendered into a
            # REAL HTML page with NO output encoding — the browser executes
            # them, which is the point.  The page embeds each note in a
            # <div data-note> attribute AND inline in a script sink, so both
            # DOM-sink queries and console/pageerror capture can observe a
            # payload signature (bwexec-XXXX) executing.
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            if q:
                # Reflected variant: query value echoed verbatim into the
                # same page — lets probes test reflected vs stored without
                # a second ingest.
                _NOTES.append(q)
            body = ("<!DOCTYPE html><html><head><title>Notes</title></head>"
                    "<body><h1>Notes</h1><div id=\"notes\">"
                    + "".join(
                        # CRLF guard: keep stored payloads from smuggling
                        # extra attributes out of the attribute context.
                        f'<div data-note="{note}" class="note">'
                        f'{note}</div>'
                        for note in _NOTES)
                    + "</div><script>"
                    "window.__notesLoaded = true;\n"
                    + "\n".join(
                        # JS-string-safe embedding: backslash doubled
                        # (chr(92)*2), double quotes become single quotes.
                        f'try {{ eval("{note.replace(chr(92), chr(92) * 2).replace(chr(34), chr(39))}") }}'
                        f' catch (e) {{ console.error("stub-note-error:", e.message) }}'
                        for note in _NOTES)
                    + "\n</script></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
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
        elif path == "/api/echo-headers":
            # Replay engine surface: return selected request headers as
            # JSON so compare/sweep modes can assert header mutations
            # deterministically (no guessing from status codes).
            wanted = parse_qs(urlparse(self.path).query).get("names", [""])[0]
            names = [n.strip().lower() for n in wanted.split(",") if n.strip()]
            picked = {n: self.headers.get(n) for n in names
                      if self.headers.get(n) is not None}
            self._json(200, {"headers": picked})
        elif path == "/api/param-echo":
            # Sweep surface: reflect every query param back so per-position
            # injections are observable as body reflections.
            params = {k: v[0] for k, v in
                      parse_qs(urlparse(self.path).query).items()}
            body = json.dumps({"params": params}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Stub-Param-Count", str(len(params)))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/cached/page":
            # Cache-poisoning surface: an UNKEYED header is reflected into
            # the cached representation (X-Stub-Debug). The response carries
            # X-Cache: HIT/MISS semantics keyed on path only, so a poisoned
            # entry is observable on the NEXT request without the header.
            debug = self.headers.get("X-Stub-Debug") or ""
            cache_key = f"GET {path}"
            cached = _CACHE.get(cache_key)
            if cached is not None:
                body, _ = cached
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Cache", "HIT")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                body = f"page-content debug={debug}".encode()
                _CACHE[cache_key] = (body, debug)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Cache", "MISS")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        elif path == "/abi/app.json":
            # Web3 lane stub: a minimal ABI (CI regression only).
            self._json(200, {
                "target": "stub-vault",
                "functions": [
                    {"name": "withdraw", "args": [{"name": "amount",
                                                   "type": "uint256"}],
                     "payable": True},
                    {"name": "transferOwnership", "args": [
                        {"name": "newOwner", "type": "address"}],
                     "payable": False},
                ],
                "invariants": [],
                "roles": ["attacker", "owner"],
            })
        elif path == "/iam/policy.json":
            # Cloud lane stub: a policy dump with a passrole privesc (CI only).
            self._json(200, {
                "Statement": [
                    {"Effect": "Allow", "Action": ["sts:AssumeRole",
                                                   "iam:PassRole"]},
                ],
            })
        elif path == "/dashboard":
            # Auth-crawl surface: identity-aware HTML page.  Any valid
            # session (or even none — the missing boundary is the point)
            # gets a dashboard; the page links the admin panel so the
            # crawler TRAVERSES into it and the differential is recorded.
            role = _token_role(self.headers.get("Authorization") or "")
            username = "anon" if not role else (
                "admin" if "admin" in role else "alice")
            body = (
                "<!DOCTYPE html><html><head><title>Dashboard</title></head>"
                f"<body><h1>Dashboard ({username})</h1>"
                f'<p role="session-role">{role or "none"}</p>'
                '<a href="/dashboard">Dashboard</a> '
                '<a href="/admin/panel">Admin Panel</a> '
                '<a href="/api/notes">Notes</a>'
                '<form action="/api/checkout" method="POST">'
                '<input name="item_id" type="text">'
                '<input name="price" type="number">'
                '<button type="submit">Buy</button></form>'
                "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif path == "/admin/panel":
            # Auth-crawl surface: the PRIVILEGED page.  200 only for a
            # token whose role claim contains 'admin' — every other
            # identity gets 403, so the access matrix has a real boundary
            # (and an operator's A-account probing it is the classic
            # privilege-escalation differential).
            role = _token_role(self.headers.get("Authorization") or "")
            if "admin" in role:
                body = (
                    "<!DOCTYPE html><html><head><title>Admin Panel</title></head>"
                    "<body><h1>Admin Panel</h1>"
                    '<a href="/dashboard">Dashboard</a>'
                    '<form action="/api/users" method="POST">'
                    '<input name="username" type="text">'
                    '<input name="role" type="text">'
                    '<button type="submit">Create user</button></form>'
                    "</body></html>").encode()
                code = 200
            else:
                body = ("<!DOCTYPE html><html><head><title>Forbidden"
                        "</title></head><body>403</body></html>").encode()
                code = 403
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
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
            username = str(body.get("username", "alice"))
            role = "admin" if username == "admin" else "user"
            self._json(200, {"token": _issue_token(username, role),
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
        elif path == "/api/payment/verify":
            # FIN-CRYPTO-01/02: the MAC is SHA256(secret || params) over the
            # raw concatenation with no delimiter -- the classic
            # length-extension construction.  Amount is parsed as a float
            # (0.1 + 0.2 != 0.3), so the rounding-abuse family also lands
            # on this surface.  JSON keys may serialize in any order; the
            # verifier canonicalizes sorted(key=value;) so probes stay
            # deterministic regardless of payload ordering.  ``raw`` support:
            # byte-fidelity verification of glue-padded continuations (the
            # prober's latin-1 round-trip preserves every byte).
            raw = body.get("raw")
            if isinstance(raw, str):
                params = raw.encode("latin-1")
                sig = str(body.get("sig", ""))
            else:
                params = "".join(
                    f"{key}={body[key]};" for key in sorted(body)).encode()
                sig = str(body.get("sig", ""))
            if params and sig and \
                    sig == hashlib.sha256(_SIGNING_SECRET.encode()
                                          + params).hexdigest():
                self._json(200, {"verified": True,
                                 "params": params.decode("latin-1"),
                                 "credited": float(re.search(
                                     r"amount=([^;]+)",
                                     params.decode("latin-1")).group(1))})
            else:
                self._json(403, {"error": "invalid signature"})
        elif path == "/api/payment/sign":
            # The operator's own signing flow for the canary order -- the
            # prober obtains ONE (params, sig) pair this way; no secret is
            # ever returned.
            clean = {k: v for k, v in body.items() if k != "sig"}
            params = "".join(f"{key}={clean[key]};" for key in sorted(clean))
            self._json(200, {"params": params, "sig": _pay_sig(params)})
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
        elif path == "/api/ai/chat":
            # LLM lane stub: deliberately vulnerable echo completion surface
            # (CI regression only).  The prompt is reflected verbatim, so
            # injection probes produce the echo differential.
            self._json(200, {"reply": f"echo: {body.get('prompt', '')}"})
        elif path in ("/account/email", "/account/reset"):
            self._json(200, {"changed": True})
        elif path == "/api/ingest":
            # POST alias for the SSRF/notes ingests (feed imports are POSTs
            # as often as GETs); same semantics as the GET branch.
            q = str(body.get("q", ""))
            if q.startswith("http://") or q.startswith("https://"):
                try:
                    with urllib.request.urlopen(q, timeout=5) as resp:
                        self._json(200, {"fetched": True,
                                         "upstream": resp.status,
                                         "snippet": resp.read(120).decode(
                                             "utf-8", "replace")})
                except Exception as exc:  # noqa: BLE001 - failure is data
                    self._json(200, {"fetched": False,
                                     "error": f"{type(exc).__name__}"})
            elif q.startswith("note:"):
                _NOTES.append(q[len("note:"):])
                self._json(200, {"stored": True, "total": len(_NOTES)})
            else:
                self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":  # manual smoke only: python3 tests/_stub_target.py [port]
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"stub target on http://127.0.0.1:{srv.server_address[1]}")
    srv.serve_forever()
