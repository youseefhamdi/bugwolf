#!/usr/bin/env python3
"""Understanding Layer tests (master plan Part VIII / §8.1–§8.3).

The thesis, locked in CI: **you cannot hunt what you haven't modeled.**

  * every stage engine's deterministic extraction is unit-tested;
  * the pipeline is strict-sequential (fail-closed on prerequisites),
    incremental (unchanged inputs ⇒ cached), and tamper-detecting;
  * the U8 ledger is the zero-day seed list: JSONL, ranked by fragility;
  * the U9 coverage gate PARKS classes with reason instead of spraying;
  * end-to-end against the live stub target: business model → money paths
    → workflows → identity boundaries → capabilities → Hunting Brief.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.understanding.base import (  # noqa: E402
    STAGES, Assumption, ModelStore, UArtifact,
)
from tools.runtime.understanding.pipeline import (  # noqa: E402
    StagePrerequisiteError, UnderstandingPipeline,
)
from tools.runtime.understanding import stages as U  # noqa: E402


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


class Page:
    def __init__(self, path, status_by_label, title="", links=None, forms=None):
        self.path, self.status_by_label, self.title = path, status_by_label, title
        self.links, self.forms = links or [], forms or []


class Crawl:
    pages = {
        "/": Page("/", {"anon": 200, "A": 200}, "Home — SaaS workspace pricing"),
        "/pricing": Page("/pricing", {"anon": 200, "A": 200},
                         "Pricing and plans — subscription billing",
                         links=["/signup", "/tos", "/api/checkout"],
                         forms=[{"action": "/api/checkout", "method": "POST",
                                 "fields": [{"name": "price"}, {"name": "item_id"}]}]),
        "/admin/panel": Page("/admin/panel", {"anon": 403, "A": 403, "C": 200},
                             "Admin panel"),
        "/api/checkout": Page("/api/checkout", {"anon": 200, "A": 200},
                              "checkout payment voucher"),
    }
    labels = ["anon", "A", "C"]

    def differential_paths(self):
        return ["/admin/panel"]

    def to_dict(self):
        return {"labels": self.labels}


class Ctx:
    role, role_source, jwt_header = "admin", "jwt", {"alg": "HS256"}
    jwt_claims = {"role": "admin", "exp": 123}
    object_ids, endpoints = ["1", "2", "42"], []


class Store:
    sessions = {"C": Ctx()}

    def identity_matrix(self):
        return {"C": {"/admin/panel": 200}}

    def object_ids(self, label=None):
        return ["1", "2", "42"]

    def to_model_dict(self):
        return {"roles": {"C": "admin"}}


OPENAPI = {
    "paths": {
        "/api/checkout": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "price": {}, "item_id": {}, "quantity": {}}}}}}}},
        "/api/voucher/redeem": {"post": {}},
        "/api/withdraw": {"post": {}},
    }
}

PAGES = {"/pricing": "SaaS subscription plans: workspaces, seats, teams, "
                    "and tenant billing. Upgrade your plan.",
         "/tos": "Users and merchants must verify their email and complete "
                 "KYC before payouts; billing renews monthly; workspace "
                 "admins approve seats"}


class TestStageEngines(unittest.TestCase):
    def test_u1_classifies_model_and_money_paths(self):
        out = []
        data = U.stage_u1(PAGES, out)
        self.assertEqual(data["model_type"], "saas")
        self.assertTrue(data["money_paths"])
        self.assertTrue(any(t["term"] == "verify" for t in data["trust_decisions"]))
        self.assertIn("merchant", data["entities"])
        # Assumptions carry origin + dispro plan (the U8 input contract).
        self.assertTrue(all(a.stage == "U1" and a.dispro_plan and a.challenge
                            for a in out))

    def test_u1_empty_pages_is_honest(self):
        data = U.stage_u1({})
        self.assertEqual(data["model_type"], "unknown")
        self.assertEqual(data["money_paths"], [])

    def test_u2_ranks_by_business_criticality(self):
        out = []
        data = U.stage_u2(Crawl(), OPENAPI, {"model_type": "saas"}, out)
        top = data["ranked_surface"][0]
        self.assertGreater(top["criticality"], 1)
        # The identity differential outranks a plain input page.
        weights = {r["path"]: r["criticality"] for r in data["ranked_surface"]}
        self.assertGreater(weights["/admin/panel"], weights["/"])

    def test_u3_workflows_from_forms_and_openapi(self):
        out = []
        data = U.stage_u3(Crawl(), OPENAPI, out)
        self.assertIn("purchase", data["workflows"])
        self.assertIn("redemption", data["workflows"])
        self.assertTrue(any(m["object"] == "/api/withdraw"
                            for m in data["state_machine_candidates"]))
        self.assertTrue(any(a.stage == "U3" for a in out))

    def test_u4_boundaries_from_differentials(self):
        out = []
        data = U.stage_u4(Store(), Crawl(), out)
        self.assertEqual(data["differential_count"], 1)
        self.assertEqual(data["roles"]["C"]["role"], "admin")
        self.assertEqual(data["roles"]["C"]["jwt_alg"], "HS256")
        self.assertTrue(any(b["path"] == "/admin/panel"
                            for b in data["authz_boundaries"]))

    def test_u5_id_formats_and_client_fields(self):
        out = []
        data = U.stage_u5(Store(), Crawl(), OPENAPI, out)
        self.assertIn("sequential-integer", data["object_id_format_counts"])
        self.assertTrue(any(f.endswith("::price")
                            for f in data["client_controlled_fields"]))
        self.assertTrue(any("sequential integer" in a.statement.lower()
                            for a in out))

    def test_u6_trust_map(self):
        out = []
        data = U.stage_u6(Crawl(), [{"header": "X-Forwarded-Host",
                                     "path": "/", "observed": "echoed"}], out)
        self.assertEqual(data["probe_count"], 1)
        self.assertTrue(data["trust_points"][0]["source"] == "probe")
        self.assertTrue(any(a.stage == "U6" for a in out))

    def test_u7_capabilities_ranked_by_impact(self):
        data = U.stage_u7(U.stage_u1(PAGES), U.stage_u4(Store(), Crawl()),
                          U.stage_u5(Store(), Crawl(), OPENAPI))
        self.assertGreater(data["capability_count"], 0)
        self.assertIn("dollars", data["impact_distribution"])
        # Ranked list: the first capability is dollars-or-privilege, never business.
        self.assertIn(data["capabilities"][0]["impact"],
                      ("dollars", "privilege", "ATO", "PII/ATO"))

    def test_u8_ledger_ranked_by_fragility(self):
        low = Assumption(stage="U5", statement="certain thing",
                         origin="observed", confidence=0.95,
                         dispro_plan="x")
        high = Assumption(stage="U3", statement="shaky workflow",
                          origin="inferred", confidence=0.3,
                          dispro_plan="y")
        data, ranked = U.stage_u8([low, high])
        self.assertEqual(data["ledger_size"], 2)
        self.assertEqual(ranked[0].statement, "shaky workflow")
        self.assertIn(ranked[0].assumption_id, data["fragile_top"])

    def test_u9_coverage_gate_parks_unsupported_classes(self):
        empty = {"U1": U.stage_u1({}), "U2": {}, "U3": {}, "U4": {}, "U5": {},
                 "U6": {}, "U7": {}}
        data, ranked = U.stage_u8([])
        u9 = U.stage_u9(empty, ranked, [])
        parked = {c["bug_class"] for c in u9["parked"]}
        self.assertIn("idor", parked)
        self.assertIn("authz-bypass", parked)
        self.assertTrue(all(c["reason"] for c in u9["parked"]))
        self.assertEqual(u9["hunts"], [])

    def test_u9_brief_renders_dispatch_contract(self):
        data, ranked = U.stage_u8([Assumption(
            stage="U3", statement="wf", origin="observed", confidence=0.4,
            dispro_plan="replay steps out of order")])
        u9 = U.stage_u9({"U1": U.stage_u1(PAGES), "U2": {}, "U3": {}, "U4": {},
                         "U5": {}, "U6": {}, "U7": {}}, ranked, [])
        brief = U.render_brief("t.test", u9, {})
        self.assertIn("# Hunting Brief — t.test", brief)
        self.assertIn("Parked with reason", brief)
        self.assertIn("dispro plan", brief)
        self.assertIn("/bugwolf-run", brief)


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.pipe = UnderstandingPipeline("pipe.test", project_root=self.root)
        self.kw = dict(pages=PAGES, crawl=Crawl(), session_store=Store(),
                       openapi=OPENAPI)

    def tearDown(self):
        self._tmp.cleanup()

    def test_all_nine_stages_artifacts_and_brief(self):
        result = self.pipe.run(**self.kw)
        self.assertEqual(result.stages_run, list(STAGES))
        for stage in STAGES:
            self.assertTrue(Path(result.artifacts[stage]).is_file(), stage)
        self.assertTrue(Path(result.brief_path).is_file())
        self.assertTrue(result.coverage_hunts)
        self.assertTrue(result.coverage_parked)
        self.assertGreater(result.ledger_size, 0)
        self.assertTrue(result.model_hash)

    def test_u8_jsonl_is_the_seed_list(self):
        self.pipe.run(**self.kw)
        path = self.pipe.store.stage_path("U8")
        lines = [json.loads(l) for l in
                 path.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertGreater(len(lines), 3)
        for record in lines:
            self.assertIn(record["origin"], U.ASSUMPTION_ORIGINS)
            self.assertTrue(record["dispro_plan"])
            self.assertTrue(record["challenge"])

    def test_strict_sequence_fail_closed(self):
        # (1) No facts at all => StagePrerequisiteError (hollow pipeline).
        with self.assertRaises(StagePrerequisiteError):
            UnderstandingPipeline("hollow.test",
                                  project_root=self.root / "hollow").run()
        # (2) The per-stage guard refuses out-of-order execution.
        pipe2 = UnderstandingPipeline("seq2.test",
                                      project_root=self.root / "seq2")
        with self.assertRaises(StagePrerequisiteError):
            pipe2._assert_sequence("U9", {})
        with self.assertRaises(StagePrerequisiteError):
            pipe2._assert_sequence("U4", {"stage:U1": "x"})  # U2/U3 missing
        # (3) A deleted mid-chain artifact self-heals by recompute (the
        #     pipeline always runs from U1), never by skipping.
        store = ModelStore("seq3.test", root=self.root / "seq3")
        store.save(UArtifact(stage="U3", target="seq3.test", data={}))
        (self.root / "seq3" / "u3-logic.json").unlink()
        pipe3 = UnderstandingPipeline("seq3.test", project_root=self.root,
                                      store=store)
        result = pipe3.run(pages=PAGES, crawl=Crawl(),
                           session_store=Store(), openapi=OPENAPI)
        self.assertIn("U3", result.stages_run)
        self.assertTrue(pipe3.store.stage_path("U3").is_file())

    def test_unchanged_inputs_are_fully_cached(self):
        first = self.pipe.run(**self.kw)
        second = self.pipe.run(**self.kw)
        self.assertEqual(second.stages_run, [])
        self.assertEqual(second.stages_cached, list(STAGES))
        self.assertEqual(first.model_hash, second.model_hash)

    def test_changed_input_recomputes_downstream_minimally(self):
        self.pipe.run(**self.kw)
        changed = {**PAGES, "/pricing": PAGES["/pricing"] + " voucher NEW"}
        third = self.pipe.run(pages=changed, crawl=Crawl(),
                              session_store=Store(), openapi=OPENAPI)
        self.assertEqual(third.stages_run, list(STAGES))  # pages feed U1..U9

    def test_tampered_artifact_is_detected_and_recomputed(self):
        first = self.pipe.run(**self.kw)
        path = Path(first.artifacts["U4"])
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["data"]["differential_count"] = 999
        path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        second = self.pipe.run(**self.kw)
        self.assertEqual(second.stages_run, ["U4"])
        self.assertFalse(
            json.loads(self.pipe.store.stage_path("U4").read_text(
                encoding="utf-8"))["data"]["differential_count"] == 999)

    def test_refresh_forces_recompute(self):
        self.pipe.run(**self.kw)
        refreshed = self.pipe.run(refresh=True, **self.kw)
        self.assertEqual(refreshed.stages_run, list(STAGES))


class TestBridgeTool(unittest.TestCase):
    def test_registered_with_schema(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bw_bridge", ROOT / "bridge" / "bugwolf-mcp.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIn("bugwolf_understand", module.TOOLS)
        description = module.TOOLS["bugwolf_understand"][1]
        self.assertIn("coverage gate", description)


class TestE2EStubTarget(unittest.TestCase):
    """Full chain against the live stub: fetch → model → brief."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import threading
        spec = importlib.util.spec_from_file_location(
            "stub_target_ul", ROOT / "tests" / "_stub_target.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls._server = module.ThreadingHTTPServer(("127.0.0.1", 0),
                                                  module.Handler)
        threading.Thread(target=cls._server.serve_forever,
                         daemon=True).start()
        cls.port = cls._server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()

    def test_full_pipeline_over_http(self):
        from tools.runtime.understanding.pipeline import UnderstandingPipeline
        from tools.runtime.replay.engine import replay_raw
        from tools.runtime.replay.governor import Governor
        base = f"http://127.0.0.1:{self.port}"
        host = f"127.0.0.1:{self.port}"
        governor = Governor(rate_rps=20.0, budget=100)

        pages = {}
        for path in ("/pricing", "/tos", "/openapi.json"):
            raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "Connection: close\r\n\r\n").encode("latin-1")
            report = replay_raw(raw, host=base, governor=governor)
            if report.status == 200:
                pages[path] = report.body_preview[:20000]

        self.assertIn("/pricing", pages)
        openapi = None
        try:
            doc = json.loads(pages["/openapi.json"])
            if isinstance(doc, dict) and "openapi" in doc:
                openapi = doc
        except (KeyError, ValueError):
            pass
        self.assertIsNotNone(openapi)

        with tempfile.TemporaryDirectory() as tmp:
            result = UnderstandingPipeline("stub.test", project_root=tmp).run(
                pages=pages, session_store=Store(), openapi=openapi)
            self.assertTrue(result.coverage_hunts)
            self.assertTrue(result.coverage_parked)
            self.assertGreater(result.ledger_size, 3)
            brief = Path(result.brief_path).read_text(encoding="utf-8")
            self.assertIn("# Hunting Brief — stub.test", brief)
            # The stub's pricing page really fed U1 (never "unknown").
            self.assertNotIn("Business model: **unknown**", brief)


if __name__ == "__main__":
    unittest.main()
