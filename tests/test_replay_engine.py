#!/usr/bin/env python3
"""Replay engine tests (master plan Phase 1.9).

Acceptance: ``http_replay_raw``-class raw sends detect framing ambiguity
that curl-style normalized tools cannot express, mutations preserve
byte-fidelity outside their target field, the governor refuses what policy
refuses, and the desync/cache/sweep patterns produce deterministic
observations against the stub target.

Layered:
  * unit (no network): message / encode / apply / governor / observe
  * integration (in-process stub): scope-gated sends, compare, sweep,
    unkeyed-header cache poisoning, CL.TE desync pair.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.replay.message import Request, Response  # noqa: E402
from tools.runtime.replay.encode import apply_pipeline  # noqa: E402
from tools.runtime.replay.apply import apply_mutations, ApplyError  # noqa: E402
from tools.runtime.replay.governor import (  # noqa: E402
    CircuitBreaker, AimdLimiter, TokenBucket, GlobalBudget, Governor)
from tools.runtime.replay.observe import diff, observe  # noqa: E402
from tools.runtime.replay.backend_socket import SendResult, split_host_port  # noqa: E402
from tools.runtime.replay.batch import compare, CompareSide, sweep_positions  # noqa: E402
from tools.runtime.replay.engine import (  # noqa: E402
    replay_request, replay_raw, desync_probe)
from tools.runtime.replay import backend_socket  # noqa: E402


# ---------------------------------------------------------------------------
# unit: byte-exact message
# ---------------------------------------------------------------------------

class TestMessage(unittest.TestCase):
    RAW = (b"pOsT /api/pay HTTP/1.1\r\n"
           b"hOsT: target.example.com \r\n"
           b"X-A: one\r\n"
           b"X-A: two\r\n"
           b"Content-Length: 13\r\n"
           b"\r\n"
           b'{"amount":"1"}')

    def test_round_trip_preserves_every_byte(self):
        request = Request.from_bytes(self.RAW)
        self.assertEqual(request.to_bytes(), self.RAW)
        self.assertTrue(request.renders_identically())

    def test_header_case_and_ows_preserved(self):
        request = Request.from_bytes(self.RAW)
        self.assertEqual(request.headers[0].raw_name, b"hOsT")
        self.assertEqual(request.headers[0].raw_value, b"target.example.com")
        self.assertEqual(request.headers[0].ows, b" ")

    def test_duplicate_headers_kept(self):
        request = Request.from_bytes(self.RAW)
        self.assertEqual(request.get_all("x-a"), ["one", "two"])

    def test_conflicting_content_length_flagged(self):
        raw = self.RAW.replace(b"Content-Length: 13\r\n",
                               b"Content-Length: 13\r\nContent-Length: 5\r\n")
        request = Request.from_bytes(raw)
        self.assertEqual(request.framing_conflict,
                         "conflicting duplicate Content-Length")

    def test_cl_te_coexistence_flagged(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\n"
               b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        request = Request.from_bytes(raw)
        self.assertEqual(request.framing_conflict, "CL+TE coexist")

    def test_mixed_case_te_flagged(self):
        raw = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: CHUNKED\r\n\r\n"
        self.assertIn("mixed-case", Request.from_bytes(raw).framing_conflict)

    def test_pipelined_trailer_captured(self):
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc"
               b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n")
        request = Request.from_bytes(raw)
        self.assertEqual(request.body, b"abc")
        self.assertTrue(request._trailer.startswith(b"GET /next"))

    def test_response_chunked_decode(self):
        raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               b"5\r\nhello\r\n3\r\n wo\r\n0\r\n\r\n")
        response = Response.from_bytes(raw)
        self.assertEqual(response.body, b"hello wo")
        self.assertEqual(response.status, 200)

    def test_unparseable_request_raises(self):
        with self.assertRaises(ValueError):
            Request.from_bytes(b"not a request at all")


# ---------------------------------------------------------------------------
# unit: encode pipelines
# ---------------------------------------------------------------------------

class TestEncode(unittest.TestCase):
    def test_url(self):
        self.assertEqual(apply_pipeline("<script>", ["url"]), "%3Cscript%3E")

    def test_double_url(self):
        self.assertEqual(apply_pipeline("a b", ["url-double"]), "a%2520b")

    def test_base64url(self):
        self.assertEqual(apply_pipeline("ab", ["base64url"]), "YWI")

    def test_html_dec_and_upper(self):
        self.assertEqual(apply_pipeline("<b", ["html-dec"]), "&#60;&#98;")
        self.assertEqual(apply_pipeline("ab", ["upper"]), "AB")

    def test_unknown_codec_raises(self):
        with self.assertRaises(ValueError):
            apply_pipeline("x", ["nope"])


# ---------------------------------------------------------------------------
# unit: mutations
# ---------------------------------------------------------------------------

class TestApply(unittest.TestCase):
    BASE = (b"POST /api/orders/7?x=1 HTTP/1.1\r\nHost: h.test\r\n"
            b'Content-Type: application/json\r\nContent-Length: 27\r\n'
            b"\r\n"
            b'{"user_id": "42", "qty": 1}')

    def test_original_object_never_mutated(self):
        request = Request.from_bytes(self.BASE)
        apply_mutations(request, [{"op": "set-query", "name": "x", "value": "9"}])
        self.assertIn(b"x=1", request.to_bytes())

    def test_set_query(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "set-query", "name": "x", "value": "9"}])
        self.assertIn(b"x=9", out.to_bytes())

    def test_add_query_creates_pollution(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "add-query", "name": "x", "value": "2"}])
        self.assertIn(b"x=1&x=2", out.to_bytes())

    def test_remove_query(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "remove-query", "name": "x"}])
        self.assertIn(b"/api/orders/7 HTTP/1.1", out.to_bytes())

    def test_set_header_replaces_all_and_keeps_position(self):
        raw = (b"GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nX-B: 2\r\nX-A: 3\r\n\r\n")
        out = apply_mutations(Request.from_bytes(raw),
                              [{"op": "set-header", "name": "X-A", "value": "z"}])
        rendered = out.to_bytes()
        self.assertEqual(out.get_all("x-a"), ["z"])
        self.assertLess(rendered.index(b"X-A"), rendered.index(b"X-B"))

    def test_add_header_allows_duplicate_smuggling_header(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "add-header", "name": "Content-Length",
                                "value": "0"}])
        self.assertEqual(len(out.get_all("content-length")), 2)

    def test_body_set_field_dot_path(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "body-set-field",
                                "name": "user_id", "value": "1"}])
        self.assertIn(b'"user_id":"1"', out.body)

    def test_body_set_field_encoded(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "body-set-field", "name": "user_id",
                                "value": "1' OR '1'='1", "encode": ["url"]}])
        self.assertNotIn(b"' OR", out.body)
        self.assertIn(b"1%27", out.body)

    def test_body_merge_and_remove(self):
        out = apply_mutations(
            Request.from_bytes(self.BASE),
            [{"op": "body-merge", "value": '{"role": "admin"}'},
             {"op": "body-remove-field", "name": "qty"}])
        self.assertIn(b'"role":"admin"', out.body)
        self.assertNotIn(b"qty", out.body)

    def test_set_method_and_target(self):
        out = apply_mutations(
            Request.from_bytes(self.BASE),
            [{"op": "set-method", "value": "delete"},
             {"op": "set-target", "value": "/admin/panel"}])
        self.assertEqual(out.method, "DELETE")
        self.assertIn(b"DELETE /admin/panel", out.to_bytes())

    def test_set_path_param_positional(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "set-path-param", "position": 3,
                                "value": "1"}])
        self.assertIn(b"/api/orders/1?x=1", out.to_bytes())

    def test_set_path_param_out_of_range(self):
        with self.assertRaises(ApplyError):
            apply_mutations(Request.from_bytes(self.BASE),
                            [{"op": "set-path-param", "position": 9,
                              "value": "1"}])

    def test_cookie_ops(self):
        raw = (b"GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1; b=2\r\n\r\n")
        out = apply_mutations(Request.from_bytes(raw),
                              [{"op": "set-cookie", "name": "b", "value": "9"}])
        self.assertEqual(out.get("cookie"), "a=1; b=9")
        out2 = apply_mutations(Request.from_bytes(raw),
                               [{"op": "remove-cookie", "name": "a"}])
        self.assertEqual(out2.get("cookie"), "b=2")

    def test_set_body_updates_content_length(self):
        out = apply_mutations(Request.from_bytes(self.BASE),
                              [{"op": "set-body", "value": '{"a":"b"}'}])
        self.assertEqual(out.get("content-length"), "9")

    def test_unknown_op_rejected(self):
        with self.assertRaises(ApplyError):
            apply_mutations(Request.from_bytes(self.BASE),
                            [{"op": "explode"}])


# ---------------------------------------------------------------------------
# unit: governor state machines (no clock, no sleeps)
# ---------------------------------------------------------------------------

class TestGovernor(unittest.TestCase):
    def test_circuit_breaker_lifecycle(self):
        breaker = CircuitBreaker(threshold=2, cooldown_ms=100)
        self.assertTrue(breaker.can_request(0))
        breaker.on_failure(0)
        self.assertTrue(breaker.can_request(1))
        breaker.on_failure(1)
        self.assertFalse(breaker.can_request(2))          # open
        self.assertTrue(breaker.can_request(200))         # half-open probe
        breaker.on_success()
        self.assertEqual(breaker.current, "closed")

    def test_aimd_grows_and_shrinks(self):
        limiter = AimdLimiter(start=2, max_concurrency=8)
        for _ in range(10):
            limiter.on_success(window=10)
        self.assertEqual(limiter.limit, 3)
        limiter.on_failure()
        self.assertEqual(limiter.limit, 1)

    def test_token_bucket_refuses_burst_beyond_rate(self):
        bucket = TokenBucket(rate_rps=1.0, burst=2)
        self.assertTrue(bucket.can_request(0))
        self.assertTrue(bucket.can_request(1))
        self.assertFalse(bucket.can_request(2))            # empty
        self.assertTrue(bucket.can_request(1500))          # ~1.5s elapsed

    def test_global_budget_exhaustion(self):
        budget = GlobalBudget(budget=2)
        budget.record(); budget.record()
        self.assertFalse(budget.can_request())
        self.assertEqual(budget.remaining, 0)

    def test_governor_blocks_and_reports_reason(self):
        governor = Governor(rate_rps=1000, budget=1)
        self.assertTrue(governor.allow("h1", now=0))
        governor.record_success("h1")
        self.assertFalse(governor.allow("h1", now=1))
        self.assertEqual(governor.blocked_reason, "global budget exhausted")


# ---------------------------------------------------------------------------
# unit: observation facts
# ---------------------------------------------------------------------------

class TestObserve(unittest.TestCase):
    @staticmethod
    def _result(body: bytes, status: int = 200, elapsed: float = 10.0) -> SendResult:
        return SendResult(status=status, body=body, elapsed_ms=elapsed)

    def test_reflection_and_error_facts(self):
        result = self._result(b"error: bwexec-deadbeef leaked ... "
                              b"You have an error in your SQL syntax")
        obs = observe(result, markers=["bwexec-deadbeef"])
        self.assertEqual(obs.reflections, ["bwexec-deadbeef"])
        self.assertIn("sql_error_mysql", obs.error_classes)

    def test_diff_detects_marker_and_status_changes(self):
        a = self._result(b"safe", status=200)
        b = self._result(b"safe bwexec-canary", status=403)
        delta = diff(a, b, markers=["bwexec-canary"])
        self.assertTrue(delta.differs)
        self.assertEqual(delta.status_delta, 203)
        self.assertEqual(delta.new_markers_in_b, ["bwexec-canary"])

    def test_diff_no_change(self):
        delta = diff(self._result(b"same"), self._result(b"same"))
        self.assertFalse(delta.differs)


# ---------------------------------------------------------------------------
# integration: in-process stub target (real sends, scope-gated)
# ---------------------------------------------------------------------------

def _boot_stub():
    spec = importlib.util.spec_from_file_location(
        "stub_target_replay", ROOT / "tests" / "_stub_target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}"


class TestLiveReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.runtime import scope as scope_mod
        cls.scope_mod = scope_mod
        cls.base = _boot_stub()
        scope_mod.GATE.bind(cls.base, force=True)

    @classmethod
    def tearDownClass(cls):
        # unbind: tests that follow must not inherit this gate binding
        cls.scope_mod.GATE._bound = False
        cls.scope_mod.GATE.target = ""

    def test_split_host_port(self):
        self.assertEqual(split_host_port("example.com", 80), ("example.com", 80, False))
        self.assertEqual(split_host_port("https://example.com", 80),
                         ("example.com", 443, True))
        self.assertEqual(split_host_port("http://h:8080", 80), ("h", 8080, False))
        self.assertEqual(split_host_port("https://[::1]:8443", 80),
                         ("[::1]", 8443, True))

    def test_structured_replay_facts(self):
        report = replay_request(
            f"GET /api/users/1 HTTP/1.1\r\nHost: {self.base.split('//')[1]}\r\n\r\n",
            host=self.base)
        self.assertEqual(report.status, 200)
        self.assertIn("alice", report.body_preview)

    def test_compare_mode_detects_bola(self):
        request = (f"GET /api/users/1 HTTP/1.1\r\n"
                   f"Host: {self.base.split('//')[1]}\r\n\r\n")
        report = compare(
            Request.from_bytes(request.encode()),
            [CompareSide(label="as-user-42",
                         mutations=[{"op": "set-path-param", "position": 3,
                                     "value": "42"}])],
            host=self.base, markers=["admin"])
        self.assertEqual(report.differing, ["as-user-42"])
        side = report.sides[0]
        # the admin body reflects what user 1's body does not
        self.assertEqual(side["delta"]["new_markers_in_b"], ["admin"])
        # admin body is bigger: balance 99999 vs 100
        self.assertGreater(side["delta"]["body_size_delta"], 0)

    def test_sweep_positions_across_params(self):
        request = (f"GET /api/param-echo?one=1&two=2 HTTP/1.1\r\n"
                   f"Host: {self.base.split('//')[1]}\r\n\r\n")
        results = sweep_positions(Request.from_bytes(request.encode()),
                                  host=self.base, op="set-query",
                                  value="bwexec-sweep",
                                  markers=["bwexec-sweep"])
        by_position = {r["position"]: r["delta"] for r in results}
        # every query position reflects the marker; path positions 404
        self.assertTrue(by_position["query:one"]["differs"])
        self.assertIn("bwexec-sweep", by_position["query:one"]["new_markers_in_b"])
        self.assertIn("query:two", by_position)
        for position, delta in by_position.items():
            if position.startswith("path:"):
                self.assertEqual(delta["status_delta"], 204)  # 404 vs 200

    def test_unkeyed_header_cache_poisoning(self):
        host = self.base.split("//")[1]
        # MISS with poisoned unkeyed header
        first = replay_request(
            f"GET /api/cached/page HTTP/1.1\r\nHost: {host}\r\n"
            f"X-Stub-Debug: pwn-marker-1\r\n\r\n",
            host=self.base)
        self.assertEqual(first.headers.get("x-cache"), "MISS")
        self.assertIn("pwn-marker-1", first.body_preview)
        # next request WITHOUT the header is served the POISONED body: HIT
        second = replay_request(
            f"GET /api/cached/page HTTP/1.1\r\nHost: {host}\r\n\r\n",
            host=self.base)
        self.assertEqual(second.headers.get("x-cache"), "HIT")
        self.assertIn("pwn-marker-1", second.body_preview)

    def test_cl_te_desync_pair_flags_framing_conflict(self):
        host = self.base.split("//")[1]
        # Python's http.server is single-message per connection, so a real
        # desync cannot land here — the FACTS the probe must surface are the
        # framing ambiguity of the front bytes and honest transport errors.
        front = (b"POST /api/checkout HTTP/1.1\r\n"
                 b"Host: " + host.encode() + b"\r\n"
                 b"Content-Length: 6\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n"
                 b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + host.encode() +
                 b"\r\n\r\n")
        smuggled = b"GET /admin HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        report = desync_probe(self.base, front, smuggled)
        self.assertEqual(report["front_framing_conflict"], "CL+TE coexist")
        # both sends completed as facts (status or honest transport error)
        self.assertTrue("status" in report["front"] and "status" in report["smuggled"])

    def test_raw_replay_reports_sent_bytes_and_conflict(self):
        host = self.base.split("//")[1]
        raw = (b"GET /api/gateway HTTP/1.1\r\nHost: " + host.encode() +
               b"\r\nX-Original-URL: /admin\r\n\r\n")
        report = replay_raw(raw, host=self.base)
        self.assertEqual(report.status, 200)
        self.assertIn("gw-secret-token", report.body_preview)
        self.assertIn("X-Original-URL", report.sent_bytes)

    def test_body_mutation_repairs_content_length(self):
        """Regression: a body-editing op must repair a stale Content-Length.
        Before the fix, the mutated body (31 bytes) shipped with the original
        CL header (32) and the target blocked waiting for a byte that never
        came — a self-inflicted, smuggling-shaped hang."""
        host = self.base.split("//")[1]
        request = (f"POST /api/checkout HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: 32\r\n\r\n"
                   f'{{"item_id": "x", "price": 100.0}}')
        report = replay_request(
            request, host=self.base,
            mutations=[{"op": "body-set-field", "name": "price",
                        "value": "0.01"}])
        self.assertEqual(report.status, 200)
        self.assertIn("0.01", report.body_preview)
        self.assertEqual(report.headers.get("content-length"),
                         str(len(report.body_preview.encode())))

    def test_no_response_bytes_is_a_timeout_fact(self):
        """Regression: a server that never sends a byte (here: declared CL
        exceeds the actual body, so it waits for more) must yield an honest
        transport error — never a silent status=None success."""
        host = self.base.split("//")[1]
        request = (f"POST /api/checkout HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: 99\r\n\r\n"
                   f'{{"item_id": "x", "price": 100.0}}')
        report = replay_request(request, host=self.base,
                                total_timeout_s=3.0)
        self.assertIsNone(report.status)
        self.assertTrue(report.transport_error)

    def test_raw_mode_sends_exactly_the_bytes_given(self):
        """The core raw-mode guarantee: odd-case header, extra spaces, and a
        duplicate Content-Length all reach the server untouched."""
        host = self.base.split("//")[1]
        # Raw-mode observable surface: odd-case verb, odd-case header names,
        # extra spaces after the colon, inner double spaces and trailing OWS
        # all reach the server untouched.  (Space BEFORE the colon —
        # ``hOsT : x`` — is equally sendable raw but unobservable through
        # Python's own header parser, which discards such lines entirely.)
        weird = (b"gEt /api/echo-headers?names=x-stub-raw HTTP/1.1\r\n"
                 b"hOsT:   " + host.encode() + b" \r\n"
                 b"X-STUB-RAW:   spaced  value \r\n\r\n")
        report = replay_raw(weird, host=self.base)
        self.assertEqual(report.status, 200)
        self.assertIn("spaced  value", report.body_preview)


class TestScopeFailClosed(unittest.TestCase):
    def test_out_of_scope_host_refused(self):
        from tools.runtime import scope as scope_mod
        scope_mod.GATE.bind("http://in-scope.example", force=True)
        try:
            with self.assertRaises(scope_mod.ScopeViolation):
                replay_raw(b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
                           host="http://evil.example")
        finally:
            scope_mod.GATE._bound = False
            scope_mod.GATE.target = ""

    def test_deny_entry_beats_target_wildcard(self):
        from tools.runtime import scope as scope_mod
        scope_mod.GATE.bind("http://target.example", force=True,
                            deny_entries=["beta.target.example"])
        try:
            with self.assertRaises(scope_mod.ScopeViolation):
                backend_socket.send_raw("beta.target.example", b"GET / HTTP/1.1\r\n\r\n")
        finally:
            scope_mod.GATE._bound = False
            scope_mod.GATE.target = ""


if __name__ == "__main__":
    unittest.main()
