#!/usr/bin/env python3
"""Session context store + authenticated crawl tests (master plan 2.2/2.3).

Acceptance: differential access becomes DATA — per-credential session
contexts (JWT claims, inferred roles, object-ID inventories) and a
per-label access matrix where the /admin boundary is a recorded
differential, not a guess.  Tokens are redacted in every export; the
crawl rides the replay engine (scope gate + governor inherited).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.session_context import (  # noqa: E402
    SessionContextStore, SessionContext, redact_claims)
from tools.runtime.authed_crawl import AuthedCrawler  # noqa: E402
from tools.runtime.accounts import AccountMatrix  # noqa: E402
from tools.runtime import scope as scope_mod  # noqa: E402


def _boot_stub():
    spec = importlib.util.spec_from_file_location(
        "stub_target_sessions", ROOT / "tests" / "_stub_target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return module, f"http://127.0.0.1:{server.server_address[1]}"


def _matrix_with_logins(base: str) -> AccountMatrix:
    """A = alice (user role), C = admin (admin role) via the stub's /login."""
    matrix = AccountMatrix.from_specs(base, [
        {"label": "A", "username": "alice", "password": "whatever",
         "login_path": "/login"},
        {"label": "C", "username": "admin", "password": "whatever",
         "login_path": "/login"},
    ])
    notes = matrix.bind()
    assert matrix.bound, notes
    return matrix


class TestSessionContextStore(unittest.TestCase):
    def test_jwt_role_inference_and_role_source(self):
        store = SessionContextStore("m-jwt")
        store.sessions["A"] = SessionContext(
            label="A", username="admin",
            raw_token=(_boot_stub()[0]._issue_token("admin", "admin")))
        store._hydrate_jwt(store.sessions["A"])
        ctx = store.sessions["A"]
        self.assertEqual(ctx.role, "admin")
        self.assertEqual(ctx.role_source, "jwt")
        self.assertTrue(ctx.role_is_admin())
        self.assertEqual(ctx.jwt_header.get("alg"), "HS256")
        self.assertIn("role", ctx.jwt_claims)

    def test_non_jwt_token_degrades_without_role(self):
        store = SessionContextStore("m-opaque")
        ctx = SessionContext(label="A", username="alice",
                             raw_token="tok-aaaa-0001")
        store.sessions["A"] = ctx
        store._hydrate_jwt(ctx)
        self.assertEqual(ctx.role, "")
        self.assertEqual(ctx.jwt_claims, {})

    def test_response_role_inference_when_jwt_is_silent(self):
        store = SessionContextStore("m-resp")
        ctx = SessionContext(label="A", username="alice",
                             raw_token="tok-not-a-jwt")
        store.sessions["A"] = ctx
        store.observe_response("A", "/api/users/1", status=200,
                               body=json.dumps({"id": "1", "role": "user",
                                                "balance": 100}))
        self.assertEqual(ctx.role, "user")
        self.assertEqual(ctx.role_source, "response")
        self.assertIn("1", ctx.object_ids)

    def test_object_id_inventory_accumulates(self):
        store = SessionContextStore("m-objs")
        store.sessions["A"] = SessionContext(label="A")
        store.observe_response("A", "/api/users/1", status=200,
                               body='{"id": "1", "balance": 100}')
        store.observe_response("A", "/api/users/42", status=200,
                               body='{"id": "42", "role": "admin"}')
        self.assertEqual(store.object_ids("A"), ["1", "42"])
        self.assertEqual(store.object_ids(), ["1", "42"])

    def test_identity_matrix_and_reachability(self):
        store = SessionContextStore("m-matrix")
        store.sessions["A"] = SessionContext(label="A")
        store.observe_response("A", "/dashboard", status=200, body="")
        store.observe_response("A", "/admin/panel", status=403, body="")
        self.assertEqual(store.identity_matrix()["A"],
                         {"/dashboard": 200, "/admin/panel": 403})
        self.assertEqual(store.reachable("A"), ["/dashboard"])

    def test_export_redacts_token_and_sensitive_claims(self):
        token = _boot_stub()[0]._issue_token("admin", "admin")
        store = SessionContextStore("m-redact")
        store.sessions["A"] = SessionContext(label="A", raw_token=token,
                                             username="admin")
        store._hydrate_jwt(store.sessions["A"])
        out = store.sessions["A"].to_dict()
        self.assertNotIn(token, json.dumps(out))
        self.assertIn("...", out["token"])
        self.assertNotIn("raw_token", out)

    def test_save_load_roundtrip_without_raw_tokens(self):
        with tempfile.TemporaryDirectory() as td:
            import os
            os.environ["BUGWOLF_PROJECT_ROOT"] = td
            try:
                store = SessionContextStore("m-round")
                ctx = SessionContext(label="A", username="alice",
                                     raw_token="tok-secret-xyz")
                store.sessions["A"] = ctx
                store.observe_response("A", "/dashboard", status=200, body="")
                store.save()
                reloaded = SessionContextStore("m-round").load()
                self.assertEqual(reloaded.sessions["A"].role, "")
                self.assertEqual(reloaded.sessions["A"].object_ids, [])
                self.assertEqual(reloaded.sessions["A"].username, "alice")
            finally:
                os.environ.pop("BUGWOLF_PROJECT_ROOT", None)

    def test_u4_model_artifact_shape(self):
        store = SessionContextStore("m-u4")
        store.sessions["A"] = SessionContext(label="A", role="user")
        store.sessions["C"] = SessionContext(label="C", role="admin")
        model = store.to_model_dict()
        self.assertEqual(model["roles"], {"A": "user", "C": "admin"})
        self.assertIn("identity_matrix", model)
        self.assertIn("role_sources", model)

    def test_claims_redaction_keeps_structure_hides_values(self):
        out = redact_claims({"role": "admin", "email": "a@b.c",
                             "exp": 1234567890, "admin": True})
        self.assertEqual(out["role"], "admin")       # not identity-bearing
        self.assertEqual(out["exp"], 1234567890)
        self.assertEqual(out["admin"], True)
        self.assertIn("...", out["email"])


class TestAuthedCrawl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module, cls.base = _boot_stub()
        scope_mod.reset()
        scope_mod.bind_target(cls.base)
        cls.matrix = _matrix_with_logins(cls.base)

    @classmethod
    def tearDownClass(cls):
        scope_mod.reset()

    def test_differential_access_is_recorded_data(self):
        with tempfile.TemporaryDirectory() as td:
            import os
            os.environ["BUGWOLF_PROJECT_ROOT"] = td
            try:
                store = SessionContextStore.from_matrix(
                    self.matrix, "m-crawl", project_root=td)
                crawler = AuthedCrawler(self.base, "m-crawl",
                                        matrix=self.matrix,
                                        session_store=store,
                                        max_pages=8, project_root=td)
                report = crawler.crawl(["/dashboard"])
                # The admin boundary is a recorded FACT:
                # anon/A see 403 on /admin/panel, C sees 200.
                panel = report.pages.get("/admin/panel")
                self.assertIsNotNone(panel,
                                     f"crawler never reached admin: {sorted(report.pages)}")
                self.assertEqual(panel.status_by_label.get("anon"), 403)
                self.assertEqual(panel.status_by_label.get("A"), 403)
                self.assertEqual(panel.status_by_label.get("C"), 200)
                self.assertIn("/admin/panel", report.differential_paths())
                # /dashboard is UNIFORM access by design (200 for every
                # identity; the identity lives in the rendered body — which
                # is where role inference reads it): not a status diff.
                self.assertNotIn("/dashboard", report.differential_paths())
                self.assertEqual(
                    set(report.pages["/dashboard"].status_by_label.values()),
                    {200})
                # Roles were inferred as a side effect of crawling.
                self.assertEqual(store.roles().get("A"), "user")
                self.assertEqual(store.roles().get("C"), "admin")
                # Form schema harvested from the dashboard form.
                dashboard = report.pages["/dashboard"]
                self.assertTrue(dashboard.forms, "no form schema harvested")
                names = {f["name"] for f in dashboard.forms[0]["fields"]}
                self.assertIn("item_id", names)
                artifacts = crawler.persist(report)
                matrix = json.loads(
                    Path(artifacts["access_matrix"]).read_text())
                self.assertEqual(matrix["access_matrix"]
                                 ["/admin/panel"]["C"], 200)
            finally:
                os.environ.pop("BUGWOLF_PROJECT_ROOT", None)

    def test_transport_errors_counted_not_fatal(self):
        crawler = AuthedCrawler("http://127.0.0.1:1", "m-dead",
                                matrix=self.matrix, max_pages=2)
        report = crawler.crawl(["/"])
        self.assertGreater(report.transport_errors, 0)
        self.assertEqual(report.pages["/"].status_by_label["anon"], 0)


if __name__ == "__main__":
    unittest.main()
