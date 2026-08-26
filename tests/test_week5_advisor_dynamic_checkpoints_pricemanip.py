"""Week 5 tests: seed/mutation advisor, dynamic research checkpoints,
price/oracle manipulation analyzer."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.core import research_loop as rl
from tools.domains.smart_contracts import price_manipulation_analyzer as pma
from tools.intelligence import seed_advisor as sa

FAKE_FETCH = {
    "final_url": "file://bundled", "status": 200, "error": "",
    "text": "# bundled reference\nfallback content",
}


class TestDynamicCheckpoints(unittest.TestCase):
    def test_dynamic_triggers_registry(self):
        self.assertEqual(rl.DYNAMIC_TRIGGERS["post-chain"], "chain_candidates")
        self.assertEqual(rl.DYNAMIC_TRIGGERS["post-lab-verification"],
                         "lab_verification")
        self.assertEqual(rl.DYNAMIC_TRIGGERS["blocker-exhausted"],
                         "blocker_exhausted")

    def test_dynamic_checkpoints_for(self):
        self.assertEqual(
            rl.dynamic_checkpoints_for({"chain_candidates": True,
                                        "lab_verification": True}),
            ["post-chain", "post-lab-verification"])
        self.assertEqual(rl.dynamic_checkpoints_for({}), [])
        self.assertEqual(
            rl.dynamic_checkpoints_for({"blocker_exhausted": True}),
            ["blocker-exhausted"])

    def test_checkpoints_defined(self):
        for name in rl.DYNAMIC_TRIGGERS:
            self.assertIn(name, rl.CHECKPOINTS)

    def test_mandatory_sequence_untouched(self):
        self.assertEqual(len(rl.MANDATORY_RESEARCH_SEQUENCE), 7)
        # Dynamic checkpoints appended after the mandatory 7 still pass the
        # ordered-subsequence gate.
        seq = list(rl.MANDATORY_RESEARCH_SEQUENCE) + ["post-chain",
                                                      "post-lab-verification"]
        self.assertTrue(rl.mandatory_ordered_subsequence(seq))

    def test_sequential_execution_appends_dynamic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original_fetch = rl.fetch_url
            rl.fetch_url = lambda *a, **k: dict(FAKE_FETCH)
            try:
                result = rl.run_mandatory_research(
                    "dyn-test", "web", phase="full", base_dir=str(root),
                    context={"chain_candidates": True,
                             "lab_verification": True},
                    run_search=False, require_latest=True)
            finally:
                rl.fetch_url = original_fetch
            cur = result["current_execution"]
            seq = cur["sequence"]
            self.assertEqual(seq[:7], list(rl.MANDATORY_RESEARCH_SEQUENCE))
            self.assertIn("post-chain", seq)
            self.assertIn("post-lab-verification", seq)
            self.assertTrue(result["sequence_file"].endswith("sequence.json"))

    def test_verify_surfaces_dynamic(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original_fetch = rl.fetch_url
            rl.fetch_url = lambda *a, **k: dict(FAKE_FETCH)
            try:
                rl.run_mandatory_research(
                    "dyn-test2", "web", phase="full", base_dir=str(root),
                    context={"chain_candidates": True}, run_search=False,
                    require_latest=True)
            finally:
                rl.fetch_url = original_fetch
            report = rl.verify_sequence("dyn-test2", base_dir=str(root),
                                        require_latest=False)
            self.assertTrue(report["sequence_ok"])
            self.assertEqual(report["dynamic_checkpoints"], ["post-chain"])


class TestSeedAdvisor(unittest.TestCase):
    UNITS = [
        {"unit_id": "u-1", "mode": "web",
         "suggested_approaches": ["fuzz params"]},
        {"unit_id": "u-2", "mode": "smart-contract"},
    ]

    def test_proposals_per_unit(self):
        report = sa.advise("acme", self.UNITS)
        self.assertEqual(len(report.proposals), 5 + 4)
        u1 = [p for p in report.proposals if p.unit_id == "u-1"]
        self.assertEqual(u1[0].surface, "all parameters")
        self.assertEqual(u1[0].priority, 1)
        self.assertEqual(u1[0].seeded_from, ["fuzz params"])

    def test_mode_family_selection(self):
        report = sa.advise("acme", [{"unit_id": "x", "mode": "llm"}])
        surfaces = {p.surface for p in report.proposals}
        self.assertIn("tool auth", surfaces)
        self.assertIn("RAG", surfaces)

    def test_unknown_mode_falls_back_to_web(self):
        report = sa.advise("acme", [{"unit_id": "x", "mode": "bogus"}])
        self.assertEqual(len(report.proposals), 5)

    def test_verdict_priority_shift_bounded(self):
        report = sa.advise("acme", self.UNITS, verdicts=[
            {"unit_id": "u-2", "priority": 4},
        ])
        u2 = [p for p in report.proposals if p.unit_id == "u-2"]
        self.assertTrue(all(p.priority == 4 for p in u2))
        self.assertLessEqual(max(p.priority for p in u2), 4)

    def test_deterministic(self):
        a = sa.advise("acme", self.UNITS).to_dict()
        b = sa.advise("acme", self.UNITS).to_dict()
        a.pop("generated_at")
        b.pop("generated_at")
        self.assertEqual(a, b)

    def test_write_path(self):
        report = sa.advise("acme", self.UNITS)
        with tempfile.TemporaryDirectory() as td:
            out = sa.write_report(report, base_dir=td)
            self.assertEqual(out.name, "seed-proposals.json")
            self.assertIn("advisor", str(out))


class TestPriceManipulationAnalyzer(unittest.TestCase):
    SPOT = (
        "function getPrice() public view returns (uint) {\n"
        "    (uint r0, uint r1,) = pair.getReserves();\n"
        "    return r1 * 1e18 / r0;\n"
        "}\n")

    def test_spot_price_dependency_detected(self):
        analysis = pma.analyze("acme", "Vault.sol", self.SPOT)
        deps = {d.dependency_id for d in analysis.dependencies}
        self.assertIn("amm_spot_price", deps)
        # No flash-loan markers in this code — only the AMM spot dependency.
        self.assertNotIn("flash_loan_surface", deps)

    def test_spot_plan_high(self):
        analysis = pma.analyze("acme", "Vault.sol", self.SPOT)
        plan = next(p for p in analysis.plans
                    if p.dependency == "amm_spot_price")
        self.assertEqual(plan.severity, "high")
        self.assertEqual(plan.title, "Flash-loan reserve skew -> spot price move")
        self.assertIn("Flash-borrow", plan.sequence[0])

    def test_oracle_dependency(self):
        code = "uint price = priceFeed.latestAnswer();"
        analysis = pma.analyze("acme", "Feed.sol", code)
        deps = {d.dependency_id for d in analysis.dependencies}
        self.assertIn("external_oracle", deps)
        plan = next(p for p in analysis.plans
                    if p.dependency == "external_oracle")
        self.assertEqual(plan.severity, "high")

    def test_twap_window_detected(self):
        code = "uint avg = getTwap(pair, observationWindow);"
        analysis = pma.analyze("acme", "Oracle.sol", code)
        deps = {d.dependency_id for d in analysis.dependencies}
        self.assertIn("twap_window", deps)

    def test_flash_callback_plan(self):
        code = ("function onFlashLoan(...) external {\n"
                "    swapAndSettle();\n"
                "}")
        analysis = pma.analyze("acme", "Lender.sol", code)
        deps = {d.dependency_id for d in analysis.dependencies}
        self.assertIn("flash_loan_surface", deps)
        plans = [p for p in analysis.plans
                 if p.dependency == "flash_loan_surface"]
        self.assertGreaterEqual(len(plans), 1)

    def test_mint_burn_ratio(self):
        code = ("function mint(uint amount) external {\n"
                "    uint shares = amount * totalSupply / reserveRatio();\n"
                "}")
        analysis = pma.analyze("acme", "LP.sol", code)
        deps = {d.dependency_id for d in analysis.dependencies}
        self.assertIn("mint_burn_ratio", deps)

    def test_no_dependencies(self):
        code = "contract Empty { uint x; }"
        analysis = pma.analyze("acme", "Empty.sol", code)
        self.assertEqual(len(analysis.dependencies), 0)
        self.assertEqual(len(analysis.plans), 0)

    def test_deterministic(self):
        a = pma.analyze("acme", "Vault.sol", self.SPOT).to_dict()
        b = pma.analyze("acme", "Vault.sol", self.SPOT).to_dict()
        a.pop("generated_at")
        b.pop("generated_at")
        self.assertEqual(a, b)

    def test_write_path(self):
        analysis = pma.analyze("acme", "Vault.sol", self.SPOT)
        with tempfile.TemporaryDirectory() as td:
            out = pma.write_analysis(analysis, base_dir=td)
            self.assertEqual(out.name, "price-manipulation-plans.json")
            self.assertIn("contracts", str(out))


if __name__ == "__main__":
    unittest.main()
