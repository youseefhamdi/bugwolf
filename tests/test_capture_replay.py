#!/usr/bin/env python3
"""Capture→replay loop tests (master plan Phase 2.4, v1.21).

Locked contract:

  * addon: flow → JSONL record (byte-exact wire text, blocked framing
    headers withheld, framing notes as facts, allow-list suffix matching,
    error handler, no mitmproxy needed to unit-test the handlers);
  * loader: fail-closed validation (bad JSON / wrong schema / missing
    fields skipped WITH reasons), out-of-scope counted, never half-parsed;
  * replay: scope gate bound BEFORE any send, out-of-scope records
    skipped as facts, drift vs the captured response reported, artifacts
    written (capture_replays.jsonl + capture_report.json), the capture
    file itself never modified;
  * the live loop against the stub: captured GET replays to the same
    status through the governed engine.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime import capture_replay as cr  # noqa: E402
from tools.runtime import capture_addon as ca   # noqa: E402


def _capture(**over):
    record = {
        "schema": cr.SCHEMA, "id": 1, "kind": "request-response",
        "method": "GET", "path": "/api/users/1",
        "host": "target.example", "port": 80, "scheme": "http",
        "status": 200,
        "request_raw": "GET /api/users/1 HTTP/1.1\r\n"
                       "accept: application/json\r\n\r\n",
        "response_raw": "HTTP/1.1 200 OK\r\n"
                        "content-type: application/json\r\n\r\n"
                        '{"id": 1, "name": "alice"}',
        "request_len": 0, "response_len": 26,
        "framing_notes": [], "transport_error": None,
    }
    record.update(over)
    return record


# ---------------------------------------------------------------------------
# The addon, exercised WITHOUT mitmproxy (fake flow objects)
# ---------------------------------------------------------------------------

class _Headers(dict):
    def items(self):
        return super().items()


class _FakeRequest:
    def __init__(self, method="GET", path="/api/users/1",
                 host="target.example", port=80, scheme="http",
                 headers=None, content=b""):
        self.method = method
        self.path = path
        self.host = host
        self.port = port
        self.scheme = scheme
        self.headers = _Headers(headers or {"accept": "application/json"})
        self.raw_content = content


class _FakeResponse:
    def __init__(self, status=200, reason="OK", headers=None,
                 content=b'{"id": 1}'):
        self.status_code = status
        self.reason = reason
        self.headers = _Headers(headers or {"content-type":
                                            "application/json"})
        self.raw_content = content


class _FakeError:
    def __init__(self, message="connection killed"):
        self.message = message


class _FakeFlow:
    def __init__(self, request, response=None, error=None):
        self.request = request
        self.response = response
        self.error = error
        self.type = "http"


class TestAddon(unittest.TestCase):
    def setUp(self):
        self.addon = ca.CaptureAddon()
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "captures.jsonl")
        self.addon._out_path = self.out

    def _lines(self):
        if not os.path.exists(self.out):
            return []
        return [json.loads(l) for l in
                open(self.out, encoding="utf-8") if l.strip()]

    def test_response_flow_record_is_complete(self):
        flow = _FakeFlow(_FakeRequest(),
                         _FakeResponse(headers={"content-type": "app/json",
                                                "x-stub-marker": "v"}))
        self.addon.response(flow)
        (record,) = self._lines()
        self.assertEqual(record["schema"], cr.SCHEMA)
        self.assertEqual(record["kind"], "request-response")
        self.assertEqual(record["host"], "target.example")
        self.assertEqual(record["status"], 200)
        # byte-exact request head, framing headers withheld
        self.assertTrue(record["request_raw"].startswith(
            "GET /api/users/1 HTTP/1.1\r\naccept: application/json\r\n\r\n"))
        self.assertNotIn("content-length", record["request_raw"].lower())
        self.assertIn("x-stub-marker", record["response_raw"])

    def test_framing_headers_blocked_and_noted(self):
        request = _FakeRequest(
            headers={"accept": "*/*",
                     "Transfer-Encoding": "chunked",
                     "Content-Length": "5",
                     "Connection": "keep-alive",
                     "Host": "target.example"})
        flow = _FakeFlow(request, _FakeResponse())
        self.addon.response(flow)
        (record,) = self._lines()
        raw = record["request_raw"].lower()
        for blocked in ("transfer-encoding", "content-length",
                        "connection", "host"):
            self.assertNotIn(f"{blocked}:", raw)
        notes = " ".join(record["framing_notes"])
        self.assertIn("transfer-encoding", notes)
        self.assertIn("ambiguity candidate", notes)   # TE + C-L together

    def test_allow_list_is_suffix_semantics(self):
        self.addon._allow = ["+.target.example"]
        self.assertTrue(self.addon._allowed("target.example"))
        self.assertTrue(self.addon._allowed("api.target.example"))
        self.assertFalse(self.addon._allowed("eviltarget.example"))
        self.assertFalse(self.addon._allowed("other.example"))
        # wildcard + bare-dot forms reduce to the same suffix
        addon2 = ca.CaptureAddon()
        addon2._allow = ["*.api.target.example"]
        # suffix semantics: the exact form matches its own suffix
        self.assertTrue(addon2._allowed("api.target.example"))
        self.assertTrue(addon2._allowed("v1.api.target.example"))
        self.assertFalse(addon2._allowed("evilapi.target.example"))

    def test_error_flow_recorded_as_request_only(self):
        flow = _FakeFlow(_FakeRequest(), error=_FakeError("reset by peer"))
        self.addon.error(flow)
        (record,) = self._lines()
        self.assertEqual(record["kind"], "request-only")
        self.assertIsNone(record["status"])
        self.assertEqual(record["transport_error"], "reset by peer")

    def test_out_of_scope_host_not_captured(self):
        self.addon._allow = ["+.target.example"]
        self.addon.response(_FakeFlow(_FakeRequest(host="other.example"),
                                      _FakeResponse()))
        self.assertEqual(self._lines(), [])

    def test_writer_appends_and_counts(self):
        writer = ca._CaptureWriter(self.out)
        writer.write({"a": 1})
        writer.write({"a": 2})
        writer.close()
        self.assertEqual(writer.count, 2)
        self.assertEqual(len(self._lines()), 2)


# ---------------------------------------------------------------------------
# Loader: fail-closed validation
# ---------------------------------------------------------------------------

class TestLoader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "captures.jsonl")

    def _write(self, *lines):
        Path(self.path).write_text(
            "\n".join(json.dumps(l) if isinstance(l, dict) else str(l)
                      for l in lines) + "\n", encoding="utf-8")

    def test_valid_file_loads(self):
        self._write(_capture(), _capture(id=2, path="/api/rates"))
        result = cr.load_captures(self.path)
        self.assertEqual(result.schema_ok, 2)
        self.assertEqual(result.skipped, 0)
        self.assertEqual([r.path for r in result.records],
                         ["/api/users/1", "/api/rates"])

    def test_bad_json_skipped_with_line_number(self):
        self._write(_capture())
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("{not json\n")
        result = cr.load_captures(self.path)
        self.assertEqual(result.schema_ok, 1)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.skips[0].line_no, 2)
        self.assertTrue(result.skips[0].reason.startswith("invalid JSON"))

    def test_wrong_schema_and_missing_fields_skipped(self):
        self._write(_capture(schema="other/v1"),
                    _capture(id=3, request_raw=""))
        result = cr.load_captures(self.path)
        self.assertEqual(result.schema_ok, 0)
        self.assertEqual(result.skipped, 2)
        reasons = [s.reason for s in result.skips]
        self.assertTrue(reasons[0].startswith("schema mismatch"))
        self.assertIn("request_raw", reasons[1])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            cr.load_captures(os.path.join(self.tmp, "nope.jsonl"))

    def test_scope_filter_counts_without_sending(self):
        self._write(_capture(), _capture(id=2, host="elsewhere.example"),
                    _capture(id=3, host="sub.target.example"))
        result = cr.load_captures(
            self.path, scope_hosts={"target.example"})
        self.assertEqual(result.schema_ok, 2)          # 1 + subdomain
        self.assertEqual(result.out_of_scope, 1)       # elsewhere.example
        self.assertEqual(result.skips[-1].reason, "host out of scope")

    def test_host_matching_is_port_tolerant(self):
        self.assertTrue(cr._host_in_scope("target.example:8443",
                                          {"target.example"}))
        self.assertTrue(cr._host_in_scope("sub.target.example",
                                          {"target.example"}))
        self.assertFalse(cr._host_in_scope("eviltarget.example",
                                           {"target.example"}))


# ---------------------------------------------------------------------------
# The live loop against the stub
# ---------------------------------------------------------------------------

class _StubBackend:
    """Boots the shared stub target once for the whole class."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "stub_target_cr", ROOT / "tests" / "_stub_target.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls._server = module.ThreadingHTTPServer(("127.0.0.1", 0),
                                                 module.Handler)
        threading.Thread(target=cls._server.serve_forever,
                         daemon=True).start()
        cls.host = f"127.0.0.1:{cls._server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        cls._server.server_close()
        from tools.runtime import scope as scope_mod
        scope_mod.GATE._bound = False
        scope_mod.GATE.target = ""


class TestLiveReplay(_StubBackend, unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.captures = os.path.join(self.tmp, "captures.jsonl")
        self.artifacts = os.path.join(self.tmp, "mission", "captures")

    def _capture_for(self, **over):
        return _capture(host=self.host,
                        request_raw=f"GET /api/users/1 HTTP/1.1\r\n"
                                    f"Host: {self.host}\r\n\r\n",
                        **over)

    def test_captured_get_replays_to_same_status(self):
        Path(self.captures).write_text(
            json.dumps(self._capture_for()) + "\n", encoding="utf-8")
        before = open(self.captures, "rb").read()
        result = cr.load_captures(self.captures)
        summary = cr.replay_captures(
            result.records, target=f"http://{self.host}",
            artifacts_dir=self.artifacts, rate_rps=20.0)
        after = open(self.captures, "rb").read()
        self.assertEqual(before, after)            # capture file untouched
        self.assertEqual(summary["replayed"], 1)
        outcomes = [json.loads(l) for l in
                    open(Path(self.artifacts) /
                         "capture_replays.jsonl", encoding="utf-8")]
        self.assertEqual(outcomes[0]["status"], 200)
        self.assertEqual(outcomes[0]["captured_status"], 200)
        self.assertIsNone(outcomes[0]["drift"]["status"]
                          if outcomes[0]["drift"] and
                          "status" in outcomes[0]["drift"] else None)
        self.assertIn("alice", outcomes[0]["body_preview"])

    def test_status_drift_is_reported_as_fact(self):
        Path(self.captures).write_text(
            json.dumps(self._capture_for(status=403)) + "\n",
            encoding="utf-8")                       # captured a 403...
        result = cr.load_captures(self.captures)
        summary = cr.replay_captures(
            result.records, target=f"http://{self.host}",
            artifacts_dir=self.artifacts, rate_rps=20.0)
        self.assertEqual(summary["drift_count"], 1)
        outcomes = [json.loads(l) for l in
                    open(Path(self.artifacts) /
                         "capture_replays.jsonl", encoding="utf-8")]
        drift = outcomes[0]["drift"]
        self.assertEqual(drift["status"]["captured"], 403)
        self.assertEqual(drift["status"]["replayed"], 200)

    def test_out_of_scope_record_is_never_sent(self):
        Path(self.captures).write_text(
            json.dumps(_capture(id=7, host="elsewhere.example",
                                request_raw="GET / HTTP/1.1\r\n\r\n")) + "\n",
            encoding="utf-8")
        result = cr.load_captures(self.captures)
        summary = cr.replay_captures(
            result.records, target=f"http://{self.host}",
            artifacts_dir=self.artifacts, rate_rps=20.0)
        self.assertEqual(summary["replayed"], 0)
        self.assertEqual(summary["skipped_out_of_scope"], 1)
        outcomes = [json.loads(l) for l in
                    open(Path(self.artifacts) /
                         "capture_replays.jsonl", encoding="utf-8")]
        self.assertTrue(outcomes[0]["skipped"])
        self.assertIn("out of scope", outcomes[0]["skip_reason"])
        self.assertEqual(outcomes[0]["sent"], "")

    def test_report_artifact_shape(self):
        Path(self.captures).write_text(
            json.dumps(self._capture_for()) + "\n", encoding="utf-8")
        result = cr.load_captures(self.captures)
        summary = cr.replay_captures(
            result.records, target=f"http://{self.host}",
            artifacts_dir=self.artifacts, rate_rps=20.0)
        self.assertEqual(summary["schema"], cr.REPORT_SCHEMA)
        self.assertEqual(summary["hosts"], {self.host: 1})
        self.assertIn("statuses", summary)
        report = json.loads(open(Path(self.artifacts) /
                                 "capture_report.json",
                                 encoding="utf-8").read())
        self.assertEqual(report["schema"], summary["schema"])

    def test_gate_refuses_foreign_target_binding(self):
        """An explicitly-bound gate wins: force=True never overrides it."""
        from tools.runtime import scope as scope_mod
        scope_mod.GATE._bound = False               # deterministic start
        scope_mod.GATE.target = ""
        scope_mod.GATE.bind("http://mission-target.example", force=True)
        try:
            Path(self.captures).write_text(
                json.dumps(self._capture_for()) + "\n", encoding="utf-8")
            result = cr.load_captures(self.captures)
            with self.assertRaises(RuntimeError):
                cr.replay_captures(
                    result.records, target=f"http://{self.host}",
                    artifacts_dir=self.artifacts, rate_rps=20.0)
        finally:
            scope_mod.GATE._bound = False
            scope_mod.GATE.target = ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI(_StubBackend, unittest.TestCase):
    def test_main_replays_and_prints_summary(self):
        from io import StringIO
        import contextlib
        tmp = tempfile.mkdtemp()
        captures = os.path.join(tmp, "captures.jsonl")
        Path(captures).write_text(
            json.dumps(_capture(host=self.host,
                                request_raw=f"GET /api/rates HTTP/1.1\r\n"
                                            f"Host: {self.host}\r\n\r\n",
                                path="/api/rates")) + "\n",
            encoding="utf-8")
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cr.main([captures, "--target", f"http://{self.host}",
                          "--artifacts-dir", os.path.join(tmp, "a"),
                          "--rate", "20"])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("1 valid", out)
        self.assertIn("replayed: 1", out)


if __name__ == "__main__":
    unittest.main()
