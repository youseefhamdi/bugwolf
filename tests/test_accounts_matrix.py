#!/usr/bin/env python3
"""Operator account matrix (plan v2 section 5.6 S6) — unit contract.

Contract under test:
  * bindings come from operator specs only; malformed/duplicate specs are
    recorded and skipped (fail-open — the matrix degrades, never blocks);
  * bind() performs logins through an injected transport; pre-baked tokens
    bind without traffic; bind notes are redacted (never carry raw tokens);
  * three_way() produces the exact plan differentials — missing-auth,
    cross-account, privilege-boundary, inverted-boundary — each citing the
    observed statuses;
  * JWT helpers decode without verification and forge alg:none variants;
    non-JWT tokens simply do not apply.

No network: probe and login functions are fakes.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.accounts import (
    AccountMatrix, AccountBinding, is_auth_surface, redact,
    decode_jwt_claims, forge_alg_none,
)

ROOT = Path(__file__).resolve().parents[1]


def _saved_root_env():
    return os.environ.get("BUGWOLF_PROJECT_ROOT")


class _FakeResult:
    def __init__(self, status, body):
        self.status = status
        self.body = body


def _make_matrix(specs):
    """Matrix with pre-baked tokens (no network binding needed)."""
    matrix = AccountMatrix.from_specs("http://target.local", specs)
    notes = matrix.bind(login_fn=lambda url, payload: (400, ""))
    return matrix, notes


class TestAccountBinding(unittest.TestCase):
    def setUp(self):
        self._saved = _saved_root_env()
        os.environ["BUGWOLF_PROJECT_ROOT"] = tempfile.mkdtemp()

    def tearDown(self):
        # Restore before cleanup: tests after us must not inherit a
        # deleted temp dir (that poisoned the trigger-ledger suite).
        if self._saved is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved

    def test_prebaked_tokens_bind_without_traffic(self):
        matrix, notes = _make_matrix([
            {"label": "A", "username": "alice", "token": "tok-aaaa-0001",
             "identifiers": ["alice", "1"]},
            {"label": "B", "username": "bob", "token": "tok-bbbb-0002",
             "identifiers": ["bob", "2"]},
        ])
        self.assertEqual(matrix.bound_labels, ["A", "B"])
        self.assertTrue(matrix.bound)
        self.assertEqual(matrix.auth_headers("A"),
                         {"Authorization": "Bearer tok-aaaa-0001"})
        self.assertFalse(matrix.auth_headers("C"))  # never provided
        # Bind notes name accounts, never raw session values.
        joined = " | ".join(notes)
        self.assertNotIn("tok-aaaa-0001", joined)

    def test_malformed_and_duplicate_specs_skipped(self):
        matrix, notes = _make_matrix([
            {"label": "X", "username": "x"},          # bad label
            {"label": "A", "username": "a", "token": "t1"},
            {"label": "A", "username": "dup", "token": "t2"},  # duplicate
            "not-a-dict",                              # not an object
        ])
        self.assertEqual(matrix.bound_labels, ["A"])
        self.assertEqual(matrix.identity("A"), "a")
        self.assertTrue(any("skipped" in n for n in notes))
        self.assertTrue(any("duplicate" in n for n in notes))

    def test_login_binding_via_injected_transport(self):
        matrix = AccountMatrix.from_specs("http://target.local", [
            {"label": "A", "username": "alice", "password": "pw",
             "login_path": "/login"},
        ])

        def fake_login(url, payload):
            assert url.endswith("/login")
            assert payload["username"] == "alice"
            return 200, '{"token": "tok-new-1234567890abcdef"}'

        notes = matrix.bind(login_fn=fake_login)
        self.assertEqual(matrix.bound_labels, ["A"])
        self.assertIn("bound via /login", " ".join(notes))
        # The raw token never lands in notes -- only the redacted form.
        joined = " ".join(notes)
        self.assertNotIn("tok-new-1234567890abcdef", joined)
        self.assertIn(redact("tok-new-1234567890abcdef"), joined)

    def test_failed_login_recorded_not_fatal(self):
        matrix = AccountMatrix.from_specs("http://target.local", [
            {"label": "A", "username": "alice", "password": "bad",
             "login_path": "/login"},
        ])
        notes = matrix.bind(
            login_fn=lambda url, payload: (401, '{"error": "nope"}'))
        self.assertEqual(matrix.bound_labels, [])
        self.assertFalse(matrix.bound)
        self.assertTrue(any("bind failed" in n for n in notes))

    def test_identifier_set_includes_username(self):
        matrix = AccountMatrix.from_specs("http://target.local", [
            {"label": "A", "username": "alice", "token": "t",
             "identifiers": ["1"]},
            {"label": "B", "username": "bob", "token": "t"},
        ])
        self.assertEqual(matrix.identifier_set("A"), {"1", "alice"})
        self.assertEqual(matrix.identifier_set("B"), {"bob"})


class TestThreeWayDifferential(unittest.TestCase):
    """The four plan-S6 anomaly rules, each with its exact differential."""

    def _matrix(self):
        return AccountMatrix.from_specs("http://target.local", [
            {"label": "A", "username": "alice", "token": "tok-a",
             "identifiers": ["alice", "1"]},
            {"label": "B", "username": "bob", "token": "tok-b",
             "identifiers": ["bob", "2"]},
        ])

    def _probe(self, responses):
        def probe_fn(url, *, method="GET", body=None, headers=None):
            auth = (headers or {}).get("Authorization", "")
            key = (url, auth)
            if key in responses:
                return responses[key]
            return responses.get(("default", auth),
                                 _FakeResult(403, '{"error": "denied"}'))
        return probe_fn

    def test_missing_auth_rule(self):
        matrix = self._matrix()
        body = '{"id": "1", "username": "alice"}'
        probe = self._probe({
            ("http://target.local/api/users/1", ""): _FakeResult(200, body),
            ("http://target.local/api/users/1", "Bearer tok-a"):
                _FakeResult(200, body),
        })
        boundary = matrix.three_way(probe, "http://target.local/api/users/1")
        self.assertEqual(boundary.observations["anon"].status, 200)
        self.assertEqual(boundary.observations["A"].status, 200)
        self.assertTrue(any("missing-auth" in a for a in boundary.anomalies))

    def test_cross_account_rule(self):
        matrix = self._matrix()
        # A's session receives B's object (BOLA on identity surfaces).
        probe = self._probe({
            ("http://target.local/api/users/2", ""): _FakeResult(403, ""),
            ("http://target.local/api/users/2", "Bearer tok-a"):
                _FakeResult(200, '{"id": "2", "username": "bob"}'),
            ("http://target.local/api/users/2", "Bearer tok-b"):
                _FakeResult(200, '{"id": "2", "username": "bob"}'),
        })
        boundary = matrix.three_way(probe, "http://target.local/api/users/2")
        hit = [a for a in boundary.anomalies if "cross-account" in a]
        self.assertEqual(len(hit), 1)
        self.assertIn("'bob'", hit[0])

    def test_no_cross_account_for_own_object(self):
        matrix = self._matrix()
        probe = self._probe({
            ("http://target.local/api/users/1", "Bearer tok-a"):
                _FakeResult(200, '{"id": "1", "username": "alice"}'),
        })
        boundary = matrix.three_way(probe, "http://target.local/api/users/1")
        self.assertFalse(any("cross-account" in a
                             for a in boundary.anomalies))

    def test_privilege_boundary_rule(self):
        matrix = self._matrix()
        probe = self._probe({
            ("http://target.local/api/admin/panel", ""):
                _FakeResult(403, ""),
            ("http://target.local/api/admin/panel", "Bearer tok-a"):
                _FakeResult(200, '{"panel": "admin"}'),
        })
        boundary = matrix.three_way(
            probe, "http://target.local/api/admin/panel")
        hit = [a for a in boundary.anomalies if "privilege-boundary" in a]
        self.assertEqual(len(hit), 1)
        self.assertIn("A (non-admin) got 200", hit[0])

    def test_inverted_boundary_rule(self):
        matrix = self._matrix()
        probe = self._probe({
            ("http://target.local/api/profile", ""):
                _FakeResult(200, '{"anon": true}'),
            ("http://target.local/api/profile", "Bearer tok-a"):
                _FakeResult(403, ""),
        })
        boundary = matrix.three_way(probe, "http://target.local/api/profile")
        hit = [a for a in boundary.anomalies if "inverted-boundary" in a]
        self.assertEqual(len(hit), 1)
        self.assertIn("anon 200 but A 403", hit[0])

    def test_clean_boundary_yields_no_anomalies(self):
        matrix = self._matrix()
        probe = self._probe({
            ("http://target.local/api/users/1", ""): _FakeResult(401, ""),
            ("http://target.local/api/users/1", "Bearer tok-a"):
                _FakeResult(200, '{"id": "1", "username": "alice"}'),
        })
        boundary = matrix.three_way(probe, "http://target.local/api/users/1")
        self.assertEqual(boundary.anomalies, [])


class TestJwtHelpers(unittest.TestCase):
    def _issue(self, claims):
        import base64, json
        enc = lambda o: base64.urlsafe_b64encode(
            json.dumps(o).encode()).rstrip(b"=").decode()
        return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(claims)}.sig"

    def test_decode_without_verification(self):
        claims = decode_jwt_claims(self._issue(
            {"username": "alice", "role": "user"}))
        self.assertEqual(claims["username"], "alice")
        self.assertEqual(claims["role"], "user")

    def test_non_jwt_returns_none(self):
        self.assertIsNone(decode_jwt_claims("opaque-session-value"))
        self.assertIsNone(decode_jwt_claims("a.b"))  # wrong part count

    def test_forge_alg_none_overrides_claims(self):
        forged = forge_alg_none(
            self._issue({"username": "alice", "role": "user"}),
            {"role": "admin"})
        self.assertTrue(forged.endswith("."))
        self.assertEqual(decode_alg_none_header(forged), "none")
        payload = decode_jwt_claims(forged)
        self.assertEqual(payload["role"], "admin")
        self.assertEqual(payload["username"], "alice")

    def test_forge_passthrough_for_non_jwt(self):
        self.assertEqual(forge_alg_none("opaque", {"role": "admin"}),
                         "opaque")


def decode_alg_none_header(token):
    import base64, json
    head = json.loads(base64.urlsafe_b64decode(
        token.split(".")[0] + "=" * (-len(token.split(".")[0]) % 4)))
    return head["alg"]


class TestSurfaceClassification(unittest.TestCase):
    def test_auth_surface_keywords(self):
        for path in ("/api/users/1", "/api/admin/panel", "/account/email",
                     "/api/profile", "/settings"):
            self.assertTrue(is_auth_surface(path), path)
        for path in ("/api/ingest", "/api/checkout", "/graphql", "/"):
            self.assertFalse(is_auth_surface(path), path)

    def test_redaction_format(self):
        red = redact("tok-abcdefghij")
        self.assertTrue(red.startswith("tok:"))
        self.assertIn("...", red)
        self.assertNotIn("cdefghij", red)  # nothing beyond the 4-char head
        self.assertEqual(redact(""), "")


if __name__ == "__main__":
    unittest.main()
