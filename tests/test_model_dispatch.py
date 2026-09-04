#!/usr/bin/env python3
"""Model-slice dispatch tests (master plan §8.3).

The model feeds the hunt: every dispatch carries the Target-Model slice
its bug class needs, and the coverage gate is enforced AT DISPATCH — a
PARKED class is skipped with a recorded fact; no model is a no-op.

  * slice selection per class (idor → U5+U4; business-logic → U3+U1; …);
  * prompt block: rendering, ordering, dispro plans, no-model = "";
  * gate semantics: absent / hunts / parked / unmodeled;
  * TeamEngine integration: intel payload carries the slice + block;
  * MissionRunner integration: parked family skipped + fact recorded.
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

from tools.runtime.understanding.base import ModelStore  # noqa: E402
from tools.runtime.understanding import dispatch as D  # noqa: E402
from tools.runtime.understanding.pipeline import UnderstandingPipeline  # noqa: E402


class Page:
    def __init__(self, path, status_by_label, title="", links=None, forms=None):
        self.path, self.status_by_label, self.title = path, status_by_label, title
        self.links, self.forms = links or [], forms or []


class Crawl:
    pages = {
        "/pricing": Page("/pricing", {"anon": 200, "A": 200},
                         "pricing subscription billing plans",
                         forms=[{"action": "/api/checkout", "method": "POST",
                                 "fields": [{"name": "price"}]}]),
        "/admin/panel": Page("/admin/panel", {"anon": 403, "A": 403, "C": 200},
                             "Admin"),
    }
    labels = ["anon", "A", "C"]

    def differential_paths(self):
        return ["/admin/panel"]

    def to_dict(self):
        return {"labels": self.labels}


class Ctx:
    role, role_source, jwt_header = "admin", "jwt", {"alg": "HS256"}
    jwt_claims = {"role": "admin", "exp": 1}
    object_ids, endpoints = ["1", "2", "42"], []


class Store:
    sessions = {"C": Ctx()}

    def identity_matrix(self):
        return {"C": {"/admin/panel": 200}}

    def object_ids(self, label=None):
        return ["1", "2", "42"]

    def to_model_dict(self):
        return {"roles": {"C": "admin"}}


OPENAPI = {"paths": {"/api/checkout": {"post": {"requestBody": {"content": {
    "application/json": {"schema": {"properties": {"price": {}}}}}}}}}}


def _build_model(root: Path) -> UnderstandingPipeline:
    pipe = UnderstandingPipeline("slice.test", project_root=root)
    pipe.run(pages={"/pricing": "SaaS subscription plans, seats, billing"},
             crawl=Crawl(), session_store=Store(), openapi=OPENAPI)
    return pipe


class TestGateAndAliases(unittest.TestCase):
    def test_alias_normalization(self):
        self.assertEqual(D.normalize_class("bola"), "idor")
        self.assertEqual(D.normalize_class("access_control"), "idor")
        self.assertEqual(D.normalize_class("waf_bypass"), "header-trust")
        self.assertEqual(D.normalize_class("client_side"), "xss-dom")

    def test_gate_absent_without_model(self):
        self.assertEqual(D.coverage_gate("idor", None)["status"], "absent")

    def test_gate_hunts_and_parks(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipe = _build_model(Path(tmp))
            model = pipe.store.load("U9").data
            self.assertEqual(D.coverage_gate("idor", model)["status"], "hunts")
            self.assertEqual(
                D.coverage_gate("ssrf", model)["status"], "parked")
            # v1.23.0 closed the gate gap: contract_logic normalizes to
            # fuzzing, which the gate now knows (support = U2's
            # ranked_surface).  The fixture model HAS a ranked surface,
            # so the honest verdict is "hunts" — previously the class was
            # invisible to the gate ("unmodeled").
            self.assertEqual(D.coverage_gate("contract_logic", model)["status"],
                             "hunts")


class TestSlices(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _build_model(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_model_returns_none(self):
        self.assertIsNone(D.model_slice(
            "idor", "nomodel.test", project_root=self.root / "none"))

    def test_idor_slice_carries_u5_inventory_and_u4_roles(self):
        sl = D.model_slice("idor", "slice.test", project_root=self.root)
        self.assertEqual(sl["status"], "hunts")
        self.assertIn("sequential-integer",
                      sl["slices"]["U5"]["object_id_format_counts"])
        self.assertIn("C", sl["slices"]["U4"]["roles"])
        self.assertTrue(sl["model_hash"])

    def test_business_logic_slice_carries_workflows_and_money(self):
        sl = D.model_slice("business-logic", "slice.test",
                           project_root=self.root)
        self.assertIn("purchase", sl["slices"]["U3"]["workflows"])
        self.assertTrue(sl["slices"]["U1"]["money_paths"])

    def test_parked_class_still_gets_gate_reason(self):
        sl = D.model_slice("ssrf", "slice.test", project_root=self.root)
        self.assertEqual(sl["status"], "parked")
        self.assertTrue(sl["reason"])


class TestPromptBlock(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _build_model(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_model_is_byte_identical_noop(self):
        self.assertEqual(D.render_prompt_block("idor", None), "")

    def test_block_carries_the_doctrine(self):
        ctx = D.dispatch_context("idor", "slice.test", project_root=self.root)
        block = ctx["model_prompt_block"]
        self.assertIn("## Target Model slice — idor", block)
        self.assertIn("OBSERVED by the deterministic", block)
        self.assertIn("sequential-integer", block)
        self.assertIn("Dispro plan:", block)
        self.assertIn("model_hash:", block)
        self.assertIn("don't re-derive it", block)

    def test_business_logic_block_orders_workflows(self):
        ctx = D.dispatch_context("business-logic", "slice.test",
                                 project_root=self.root)
        block = ctx["model_prompt_block"]
        self.assertIn("test step order, repetition, skip", block)
        self.assertIn("Money paths (U1)", block)

    def test_parked_block_carries_the_gate(self):
        ctx = D.dispatch_context("ssrf", "slice.test", project_root=self.root)
        self.assertIn("COVERAGE GATE: this class is PARKED",
                      ctx["model_prompt_block"])
        self.assertEqual(ctx["gate"]["status"], "parked")


class TestTeamIntegration(unittest.TestCase):
    def _engine(self, root: Path, bug_classes):
        from tools.runtime.team import TeamEngine
        from tools.runtime.contracts import MissionSpec
        mission = MissionSpec(mission_id="sl TeamEngine-1",
                              target="slice.test", domains=["web"])
        engine = TeamEngine(mission, project_root=root)
        engine.plan(bug_classes=list(bug_classes))
        return engine

    def test_member_intel_carries_model_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _build_model(root)
            engine = self._engine(root, ["idor"])
            member = next(m for m in engine.members.values()
                          if m.wave == "hunt")
            spec = engine._spec_for(member.role)
            classes = getattr(spec, "bug_classes", ()) or ("idor",)
            intel = engine._build_research_context(member.role, classes)
            self.assertIsNotNone(intel.get("target_model"))
            self.assertEqual(intel["target_model"]["bug_class"], "idor")
            self.assertIn("Target Model slice",
                          intel["model_prompt_block"])
            self.assertEqual(intel["coverage_gate"]["status"], "hunts")

    def test_no_model_leaves_payload_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(Path(tmp), ["idor"])
            member = next(m for m in engine.members.values()
                          if m.wave == "hunt")
            spec = engine._spec_for(member.role)
            classes = getattr(spec, "bug_classes", ()) or ("idor",)
            intel = engine._build_research_context(member.role, classes)
            self.assertIsNone(intel.get("target_model"))
            self.assertEqual(intel.get("model_prompt_block"), "")
            self.assertEqual(intel["coverage_gate"]["status"], "absent")


class TestMissionRunnerGate(unittest.TestCase):
    """Parked family skipped at dispatch + fact recorded; no model ⇒ all run."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import threading
        spec = importlib.util.spec_from_file_location(
            "stub_target_gate", ROOT / "tests" / "_stub_target.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls._server = module.ThreadingHTTPServer(("127.0.0.1", 0),
                                                  module.Handler)
        threading.Thread(target=cls._server.serve_forever, daemon=True).start()
        cls.port = cls._server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()

    def _mission(self, mission_id="gate-m1"):
        from tools.runtime.contracts import MissionSpec
        return MissionSpec(mission_id=mission_id,
                           target=f"127.0.0.1:{self.port}")
    def _build_model_parking_everything(self, root: Path):
        """A model whose gate parks every LANE_FAMILIES class."""
        from tools.runtime.understanding.base import STAGES, UArtifact
        store = ModelStore(f"127.0.0.1:{self.port}", project_root=root)
        for stage in STAGES:
            store.save(UArtifact(stage=stage, target=f"127.0.0.1:{self.port}",
                                 data={}))
        # Overwrite U9 with an empty-hunt gate: everything parked.
        u9 = store.load("U9")
        u9.data = {"hunts": [], "parked": [
            {"bug_class": "idor", "reason": "r"}, {"bug_class": "waf_bypass",
                                                   "reason": "r"},
            {"bug_class": "business_logic", "reason": "r"},
            {"bug_class": "fuzzing", "reason": "r"},
            {"bug_class": "generic", "reason": "r"},
            {"bug_class": "client_side", "reason": "r"}],
            "hypotheses": [], "model_chain": []}
        # Keep the recorded hash consistent with the patched data.
        from tools.runtime.understanding.base import canonical_hash
        u9.artifact_hash = canonical_hash({
            "stage": "U9", "target": u9.target, "data": u9.data,
            "assumptions": [a.to_dict() for a in u9.assumptions],
            "inputs": u9.inputs})
        store.save(u9)

    def test_parked_families_skipped_with_fact(self):
        from tools.runtime.mission_runner import MissionRunner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._build_model_parking_everything(root)
            runner = MissionRunner(self._mission(), project_root=str(root),
                                   base_url=f"http://127.0.0.1:{self.port}",
                                   paths=["/"], browser_driver=False)
            runner._run_web_lane()
            parks = [e for e in runner._events
                     if e.get("event") == "family_parked"]
            self.assertGreaterEqual(len(parks), 3)
            # No leads opened by parked families in this run.
            self.assertEqual(runner.leads.open_lead_ids(), [])

    def test_no_model_dispatches_everything(self):
        from tools.runtime.mission_runner import MissionRunner
        with tempfile.TemporaryDirectory() as tmp:
            runner = MissionRunner(self._mission("gate-m2"),
                                   project_root=str(tmp),
                                   base_url=f"http://127.0.0.1:{self.port}",
                                   paths=["/api/users/1", "/api/checkout",
                                          "/api/gateway"],
                                   browser_driver=False)
            runner._run_web_lane()
            self.assertGreater(len(runner.leads.open_lead_ids()), 0)


if __name__ == "__main__":
    unittest.main()
