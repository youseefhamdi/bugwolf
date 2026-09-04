#!/usr/bin/env python3
"""U7×U8 predicted-chain dispatch tests (master plan §8.3, v1.19).

CyberStrike correlates findings; bugwolf PREDICTS chains before probing:
a granted capability (U7) crossed with a fragile assumption (U8) becomes a
ranked, terminal-aware dispatch.  Locked contract:

  * predictor: pairing rule, priority order, stage→class map, terminal
    chaining, confidence window, status filter, cap, persistence;
  * team engine: predicted specialists staffed pre-hunt, gate refusals
    recorded, per-member ``predicted_chains`` priority intel;
  * mission runner: predicted families ordered first (stable otherwise);
  * pipeline: ``predicted-chains.json`` + brief section as U9 byproducts;
  * no model ⇒ exact no-op everywhere (byte-identical dispatch).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime.understanding.base import (  # noqa: E402
    Assumption, ModelStore, UArtifact,
)
from tools.runtime.understanding.chain_predict import (  # noqa: E402
    ChainPredictor, PredictedChain, registry_bug_class,
)


def _cap(obj="balance", impact="dollars", path="/api/checkout",
         role="user", verb="modify"):
    return {"role_label": role, "object": obj, "verb": verb,
            "path": path, "impact": impact, "reversible": impact != "dollars",
            "observable": True, "evidence": "test"}


def _asm(stage="U3", statement="the coupon applies once per balance purchase",
         confidence=0.3, status="open",
         dispro="Replay the purchase with a repeated coupon",
         aid="a1"):
    return {"stage": stage, "statement": statement, "origin": "inferred",
            "confidence": confidence, "dispro_plan": dispro,
            "evidence": "test", "status": status, "challenge": "c",
            "assumption_id": aid}


def _seed(store: ModelStore, capabilities, assumptions):
    if capabilities:
        store.save(UArtifact(stage="U7", target=store.target, data={
            "capability_count": len(capabilities),
            "capabilities": capabilities}))
    for stage in ("U3", "U4", "U5"):
        stage_asms = [Assumption(**a) for a in assumptions
                      if a["stage"] == stage]
        if stage_asms:
            store.save(UArtifact(stage=stage, target=store.target,
                                 data={}, assumptions=stage_asms))
    if any(a["stage"] == "U7" for a in assumptions):
        store.save(UArtifact(
            stage="U7", target=store.target,
            data={"capability_count": len(capabilities),
                  "capabilities": capabilities},
            assumptions=[Assumption(**a) for a in assumptions
                         if a["stage"] == "U7"]))


class TestPredictor(unittest.TestCase):
    def _store(self, tmp, capabilities=None, assumptions=None):
        store = ModelStore("pred.test", root=tmp)
        _seed(store, capabilities if capabilities is not None
              else [_cap()], assumptions or [_asm()])
        return store

    def test_no_u7_means_no_predictions(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ModelStore("pred.test", root=tmp)
            store.save(UArtifact(stage="U3", target="pred.test", data={},
                                 assumptions=[Assumption(**_asm())]))
            preds, lines = ChainPredictor(store).predict()
            self.assertEqual((preds, lines), ([], []))

    def test_pairing_requires_object_in_statement(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp, assumptions=[_asm(
                statement="signup requires email verification",
                aid="a2")])
            preds, _ = ChainPredictor(store).predict()
            self.assertEqual(preds, [])

    def test_prediction_names_class_capability_and_first_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            preds, lines = ChainPredictor(store).predict()
            self.assertEqual(len(preds), 1)
            p = preds[0]
            self.assertEqual(p.bug_class, "business-logic")
            self.assertEqual(p.capability["object"], "balance")
            self.assertEqual(p.assumption["dispro_plan"],
                             "Replay the purchase with a repeated coupon")
            self.assertEqual(p.chain, ["business-logic", "funds-drain"])
            self.assertTrue(p.terminal)
            self.assertIn("business-logic → funds-drain", "\n".join(lines))
            self.assertIn("First probe:", "\n".join(lines))

    def test_priority_ranks_dollars_above_business(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(
                tmp,
                capabilities=[_cap(obj="profile", impact="PII/ATO",
                                   path="/api/profile"),
                              _cap(obj="balance", impact="dollars")],
                assumptions=[_asm(statement="profile fields are server "
                                           "validated", aid="a2"),
                             _asm(statement="coupon applies once per "
                                           "balance purchase", aid="a1")])
            preds, _ = ChainPredictor(store).predict()
            self.assertEqual(len(preds), 2)
            self.assertEqual(preds[0].capability["impact"], "dollars")
            self.assertGreater(preds[0].priority, preds[1].priority)

    def test_confidence_window_and_status_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(
                tmp,
                assumptions=[_asm(confidence=0.95, aid="a-certain"),
                             _asm(confidence=0.0, aid="a-noise"),
                             _asm(status="disproven", aid="a-dead")])
            preds, _ = ChainPredictor(store).predict()
            self.assertEqual(preds, [])

    def test_stage_to_class_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(
                tmp,
                assumptions=[_asm(stage="U4",
                                  statement="admin balance override is "
                                            "role-gated", aid="a4"),
                             _asm(stage="U5",
                                  statement="balance amount is "
                                            "client-controlled",
                                  aid="a5"),
                             _asm(stage="U7",
                                  statement="balance capability requires "
                                            "its mapped role", aid="a7")])
            preds, _ = ChainPredictor(store).predict()
            classes = {p.bug_class for p in preds}
            self.assertEqual(classes, {"authz-bypass", "mass-assignment"})

    def test_unknown_stage_maps_to_no_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(
                tmp, assumptions=[_asm(stage="U6",
                                       statement="balance header is "
                                                 "trusted", aid="a6")])
            preds, _ = ChainPredictor(store).predict()
            self.assertEqual(preds, [])

    def test_persistence_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            predictor = ChainPredictor(store)
            preds, _ = predictor.predict()
            path = predictor.save(preds)
            self.assertEqual(path.name, "predicted-chains.json")
            loaded = ChainPredictor(store).load()
            self.assertEqual(len(loaded), len(preds))
            self.assertEqual(loaded[0].bug_class, preds[0].bug_class)
            self.assertEqual(loaded[0].priority, preds[0].priority)
            self.assertEqual(loaded[0].chain, preds[0].chain)

    def test_load_missing_file_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ChainPredictor(
                ModelStore("pred.test", root=tmp)).load(), [])

    def test_load_rejects_foreign_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ModelStore("pred.test", root=tmp)
            (store.dir / "predicted-chains.json").write_text(
                json.dumps({"schema": "other/v9", "predictions": []}))
            self.assertEqual(ChainPredictor(store).load(), [])

    def test_prediction_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            caps = [_cap(path=f"/api/x{i}", obj="balance") for i in range(40)]
            asms = [_asm(statement=f"balance assumption number {i}",
                         aid=f"a{i}") for i in range(40)]
            store = ModelStore("pred.test", root=tmp)
            _seed(store, caps, asms)
            preds, _ = ChainPredictor(store).predict()
            self.assertLessEqual(len(preds), 20)

    def test_registry_class_mapping(self):
        self.assertEqual(registry_bug_class("authz-bypass"), "auth_bypass")
        self.assertEqual(registry_bug_class("mass-assignment"),
                         "mass_assignment")
        self.assertEqual(registry_bug_class("business-logic"),
                         "business_logic")
        self.assertEqual(registry_bug_class("idor"), "idor")


class TestTeamIntegration(unittest.TestCase):
    """Fixtures seed via ``project_root=`` so the engine's ModelStore path
    (state/targets/pred.test/model/) resolves to the same directory."""

    def _seed_project(self, root: Path):
        store = ModelStore("pred.test", project_root=root)
        _seed(store, [_cap()], [_asm()])
        # The engine consumes the PERSISTED predictions file — produce it
        # the same way a pipeline run would.
        predictor = ChainPredictor(store)
        predictor.save(predictor.predict()[0])

    def _engine(self, root: Path):
        from tools.runtime.team import TeamEngine
        from tools.runtime.contracts import MissionSpec
        mission = MissionSpec(mission_id="pred-team-1",
                              target="pred.test", domains=["web"])
        engine = TeamEngine(mission, project_root=root)
        engine.plan(bug_classes=["idor"])
        return engine

    def test_predicted_specialist_staffed_pre_hunt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seed_project(root)
            engine = self._engine(root)
            dispatches = engine.state.get("predicted_dispatches") or {}
            self.assertIn("business-logic", dispatches.get("staffed", []))
            # The registry resolves the predicted class to its specialist.
            roles = {m.role for m in engine.members.values()}
            self.assertIn("business-logic", roles)

    def test_predictions_ride_member_intel_as_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._seed_project(root)
            engine = self._engine(root)
            member = next(m for m in engine.members.values()
                          if m.role == "business-logic")
            spec = engine._spec_for(member.role)
            intel = engine._build_research_context(
                member.role, tuple(spec.bug_classes))
            predicted = intel.get("predicted_chains") or []
            self.assertTrue(predicted)
            self.assertTrue(predicted[0]["priority_dispatch"])
            self.assertIn("dispro_plan", predicted[0]["assumption"])

    def test_gate_refusal_recorded_not_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = ModelStore("pred.test", project_root=root)
            _seed(store, [_cap()], [_asm()])
            predictor = ChainPredictor(store)
            predictor.save(predictor.predict()[0])
            # A U9 that PARKS business-logic: prediction must not override
            # the coverage gate.
            store.save(UArtifact(stage="U9", target="pred.test", data={
                "hunts": [], "parked": [
                    {"bug_class": "business-logic",
                     "reason": "no workflows observed"}]}))
            engine = self._engine(root)
            dispatches = engine.state.get("predicted_dispatches") or {}
            self.assertEqual(dispatches.get("staffed", []), [])
            refused = dispatches.get("gate_refusals") or []
            self.assertTrue(any(r["bug_class"] == "business-logic"
                                for r in refused))
            roles = {m.role for m in engine.members.values()}
            self.assertNotIn("business-logic", roles)

    def test_no_predictions_no_state_no_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(Path(tmp))
            self.assertIsNone(engine.state.get("predicted_dispatches"))
            before = {m.role for m in engine.members.values()}
            self.assertNotIn("business-logic", before)


class TestRunnerOrdering(unittest.TestCase):
    def test_predicted_family_sorts_first_stable(self):
        from tools.runtime.mission_runner import _order_families_by_predictions
        families = [("f1", "access_control", "t1"), ("f2", "waf_bypass", "t2"),
                    ("f3", "business_logic", "t3"), ("f4", "fuzzing", "t4")]
        preds = [PredictedChain(bug_class="business-logic", capability={},
                                assumption={}, fragility=0.5, priority=7.0)]
        ordered = _order_families_by_predictions(families, preds)
        self.assertEqual(ordered[0][1], "business_logic")
        # Stable: the unmapped keep their relative order.
        self.assertEqual([f[1] for f in ordered[1:]],
                         ["access_control", "waf_bypass", "fuzzing"])

    def test_no_predictions_is_exact_noop(self):
        from tools.runtime.mission_runner import _order_families_by_predictions
        families = [("f1", "access_control", "t1"), ("f2", "fuzzing", "t2")]
        self.assertEqual(_order_families_by_predictions(families, []),
                         families)

    def test_alias_vocabulary_matches(self):
        from tools.runtime.mission_runner import _order_families_by_predictions
        preds = [PredictedChain(bug_class="business-logic", capability={},
                                assumption={}, fragility=0.5, priority=7.0)]
        families = [("f1", "access_control", "t1"),
                    ("f2", "business_logic", "t3")]
        ordered = _order_families_by_predictions(families, preds)
        self.assertEqual([f[1] for f in ordered],
                         ["business_logic", "access_control"])


class TestPipelineByproduct(unittest.TestCase):
    """U9 run persists predicted-chains.json + appends the brief section.
    E2E against the live stub: fetch → model → predicted chains → brief."""

    @classmethod
    def setUpClass(cls):
        import threading
        spec = importlib.util.spec_from_file_location(
            "stub_target_pred", ROOT / "tests" / "_stub_target.py")
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

    def test_u9_byproducts(self):
        from tools.runtime.understanding.pipeline import UnderstandingPipeline
        from tools.runtime.replay.engine import replay_raw
        from tools.runtime.replay.governor import Governor
        base = f"http://127.0.0.1:{self.port}"
        host = f"127.0.0.1:{self.port}"
        governor = Governor(rate_rps=20.0, budget=50)

        pages = {}
        for path in ("/pricing", "/tos", "/openapi.json"):
            raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "Connection: close\r\n\r\n").encode("latin-1")
            report = replay_raw(raw, host=base, governor=governor)
            if report.status == 200:
                pages[path] = report.body_preview[:20000]
        self.assertIn("/pricing", pages)

        with tempfile.TemporaryDirectory() as tmp:
            pipe = UnderstandingPipeline("pred.e2e", project_root=tmp)
            pipe.run(pages=pages)
            # Without a crawl/session store every class PARKS (honest gate),
            # but U7 still maps U1 money paths into capabilities and U7/U1
            # assumptions still land in the pool — prediction fires on model
            # support alone, which is exactly what this test locks.
            self.assertGreaterEqual(pipe.result.predicted_chains, 1)
            path = Path(pipe.result.predicted_chains_path)
            payload = json.loads(path.read_text())
            self.assertEqual(payload["schema"],
                             "bugwolf-predicted-chains/v1")
            brief = pipe.store.brief_path().read_text()
            self.assertIn("Predicted chains", brief)
            self.assertIn("_Predicted ≠ confirmed", brief)


if __name__ == "__main__":
    unittest.main()
