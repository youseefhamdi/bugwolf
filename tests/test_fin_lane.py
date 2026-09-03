#!/usr/bin/env python3
"""Business-logic lane: FIN technique matrix (plan v2 section 5.6 S5).

Contract under test:
  * money-flow surfaces auto-instantiate the FIN matrix (attack-first rule);
  * the full technique matrix runs per surface regardless of early wins
    (R2 accounting) and techniques sharing a prober dispatch once;
  * every winner is a DIFFERENTIAL against the canary baseline (price trust,
    TOCTOU, replay, rounding, test-gateway forcing, numeric language);
  * non-FIN surfaces stay untouched (no traffic, no leads);
  * the registry manifest links attempts to canonical FIN-* entry IDs;
  * verify-lane replay re-executes the winning technique independently.

Runs against the deterministic stub target (tests/_stub_target.py), which
stands in for an operator-declared target in CI.  Production hunting binds
to operator targets only.
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.mission_runner import (
    discover_money_surfaces,
    fin_registry_entries,
    replay_fin_technique,
    _probe_fin_matrix,
)
from tools.runtime.lead_protocol import TECHNIQUE_MATRIX

ROOT = Path(__file__).resolve().parents[1]
STUB_TARGET = ROOT / "tests" / "_stub_target.py"


def _boot_stub_target():
    if not STUB_TARGET.is_file():
        return None, None
    spec = importlib.util.spec_from_file_location("stub_target", STUB_TARGET)
    module = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    sys.argv = ["_stub_target.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved_argv
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/tech.json", timeout=2) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.1)
    return base, (lambda: (server.shutdown(), server.server_close()))


class TestFinRegistry(unittest.TestCase):
    def test_manifest_ships_41_unique_entries(self):
        entries = fin_registry_entries()
        self.assertEqual(len(entries), 41)
        ids = [e["id"] for e in entries]
        self.assertEqual(len(ids), len(set(ids)))
        for prefix in ("FIN-TOCTOU", "FIN-PARAM", "FIN-REPLAY", "FIN-ROUND",
                       "FIN-NUM", "FIN-VOUCHER", "FIN-CRYPTO",
                       "FIN-TESTDATA", "FIN-ARBITRAGE"):
            self.assertTrue(any(i.startswith(prefix) for i in ids),
                            f"missing family {prefix}")

    def test_swarm_and_matrix_align_key_for_key(self):
        # R2 exhaustion accounting requires the swarm's technique set to
        # equal TECHNIQUE_MATRIX["business_logic"] exactly.
        self.assertEqual(
            set(_probe_fin_matrix.__globals__["FIN_TECHNIQUES"]),
            set(TECHNIQUE_MATRIX["business_logic"]))

    def test_manifest_fallback_and_malformed_fail_open(self):
        # Missing workspace manifest -> the shipped code-root registry.
        with tempfile.TemporaryDirectory() as tmp:
            entries = fin_registry_entries(tmp)
            self.assertEqual(len(entries), 41)
        # Malformed manifest -> fail-open to empty, never a crash.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "configs").mkdir()
            (Path(tmp) / "configs" / "fin_logic.json").write_text("{oops")
            self.assertEqual(fin_registry_entries(tmp), [])


class TestFinLane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base, cls._shutdown_stub = _boot_stub_target()

    @classmethod
    def tearDownClass(cls):
        if cls._shutdown_stub is not None:
            cls._shutdown_stub()
            cls._shutdown_stub = None

    def setUp(self):
        if self.base is None:
            self.skipTest("stub target not present (tests/_stub_target.py)")

    OPERATOR_PATHS = [
        "/api/users/1", "/api/gateway", "/api/ingest", "/graphql",
        "/api/checkout", "/api/voucher/redeem",
    ]

    def test_money_surfaces_discovered_from_declared_paths(self):
        surfaces = discover_money_surfaces(self.base, self.OPERATOR_PATHS)
        names = [s for s, _m in surfaces]
        self.assertIn("/api/checkout", names)
        self.assertIn("/api/voucher/redeem", names)
        for non_fin in ("/api/users/1", "/api/gateway", "/api/ingest",
                        "/graphql"):
            self.assertNotIn(non_fin, names)

    def test_fin_matrix_confirms_all_differentials_on_checkout(self):
        signals = _probe_fin_matrix(self.base, ["/api/checkout"])
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertEqual(sig["signal"], "differential")
        self.assertEqual(sig["path"], "/api/checkout")
        winners = set(sig["fin_winners"])
        # The stub's deterministic money-flow flaws, all differentially
        # confirmed against the canary baseline:
        self.assertIn("price-trust", winners)          # FIN-PARAM-01
        self.assertIn("quantity-mutation", winners)    # FIN-PARAM-03 / NUM
        self.assertIn("toctou-race", winners)          # FIN-TOCTOU-03
        self.assertIn("replay", winners)               # FIN-REPLAY-01
        self.assertIn("test-gateway-forcing", winners)  # FIN-TESTDATA-01
        self.assertIn("format-mutation-matrix", winners)  # FIN-NUM-01..10
        # Clean techniques report honestly as tried (R2 accounting data).
        by_name = {a["technique"]: a for a in sig["attempts"]}
        self.assertEqual(by_name["rounding-abuse"]["outcome"], "tried")
        # Every registry_ids list only contains canonical FIN-* ids.
        for att in sig["attempts"]:
            for rid in att.get("registry_ids", []):
                self.assertTrue(rid.startswith("FIN-"))

    def test_clean_and_nonfin_surfaces_produce_no_signals(self):
        # /api/voucher/redeem IS a direct redemption surface: the voucher
        # reuse confirms there (no single-use state).  The direct-surface
        # path join must hit the endpoint itself, not a doubled suffix.
        signals = _probe_fin_matrix(self.base, ["/api/voucher/redeem"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["winning_technique"],
                         "voucher-stacking")
        # Non-FIN surfaces never generate traffic.
        signals = _probe_fin_matrix(self.base, ["/api/users/1", "/graphql"])
        self.assertEqual(signals, [])

    def test_replay_reexecutes_winning_technique(self):
        self.assertIs(
            replay_fin_technique(self.base, "/api/checkout", "price-trust"),
            True)
        self.assertIs(
            replay_fin_technique(self.base, "/api/checkout", "toctou-race"),
            True)
        # An honest negative: rounding on the stub's withdraw does not
        # produce a requester-favor drift for these amounts.
        self.assertIs(
            replay_fin_technique(self.base, "/api/checkout", "rounding-abuse"),
            False)
        # Unknown technique: undecidable, never a verdict.
        self.assertIsNone(
            replay_fin_technique(self.base, "/api/checkout", "nope"))

    def test_fin_registry_ids_cite_canonical_entries(self):
        reg_ids = {e["id"] for e in fin_registry_entries()}
        expected = {"FIN-PARAM-01", "FIN-TOCTOU-03", "FIN-REPLAY-01",
                    "FIN-NUM-01", "FIN-TESTDATA-01"}
        self.assertTrue(expected <= reg_ids)


if __name__ == "__main__":
    unittest.main()
