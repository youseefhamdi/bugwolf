#!/usr/bin/env python3
"""Contract / cloud / LLM domain lanes (plan v2 section 5.6, Phase 5).

Contract under test:
  * TECHNIQUE_MATRIX alignment -- every canonical technique for each new
    bug class is recorded by its swarm (R2 exhaustion accounting is exact);
  * the contract lane loads operator-declared ABIs (file or abi=<url>) and
    turns payable/impact-verb differentials into leads with replayable
    winning techniques;
  * the cloud lane runs the deterministic IAM privesc closure over
    operator-declared policy dumps (file or policy=<url>) and leads only on
    admin reachability / direct hops;
  * the LLM lane probes operator-declared completion surfaces with the
    injection matrix (echo differentials) and analyzes declared code
    archives offline;
  * clean differentials are negative evidence, never leads;
  * verify-lane F0.5 replay re-executes the winning technique for each
    class and the full mission reaches PWNED;
  * FIN voucher/replay run through race_engine windows (plan S5 binding).

Runs against the deterministic stub target (tests/_stub_target.py).
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.runtime.contracts import MissionSpec, LEAD_PWNED
from tools.runtime.lead_protocol import LeadStore, TECHNIQUE_MATRIX
from tools.runtime.mission_runner import (
    MissionRunner, _probe_contract_matrix, _probe_cloud_matrix,
    _probe_llm_matrix, replay_contract_technique, replay_cloud_technique,
    replay_llm_technique, CONTRACT_PLAN_KINDS, CLOUD_PRIVESC_FAMILIES,
    is_llm_surface,
)

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


def _write_tmp(tmpdir: str, name: str, obj) -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "w") as fh:
        json.dump(obj, fh)
    return path


ABI = {
    "target": "test-vault",
    "functions": [
        {"name": "withdraw", "args": [{"name": "amount", "type": "uint256"}],
         "payable": True},
        {"name": "transferOwnership",
         "args": [{"name": "newOwner", "type": "address"}], "payable": False},
    ],
    "invariants": [],
    "roles": ["attacker", "owner"],
}

POLICY_ADMIN = {
    "Statement": [{"Effect": "Allow",
                   "Action": ["iam:PassRole", "iam:CreatePolicyVersion"]}],
}

POLICY_CLEAN = {
    "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket"]}],
}


class _DomainMissionHarness:
    """Boots the stub + runs one mission with the domain lanes declared."""

    def __init__(self, domains, paths):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.base, self._shutdown = _boot_stub_target()
        self.mission = MissionSpec(
            mission_id="bw-domain-lane-test", target=self.base,
            domains=list(domains),
            budget={"max_agents": 8, "max_parallel_tasks": 4,
                    "max_runtime_seconds": 600},
        )
        self.runner = MissionRunner(self.mission, base_url=self.base,
                                    paths=list(paths))

    def __enter__(self):
        return self.runner

    def __exit__(self, *exc):
        # Restore before cleanup: tests after us must not inherit a
        # deleted temp dir (that poisoned the trigger-ledger suite).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        if self._shutdown:
            self._shutdown()
        self._td.cleanup()


class TestMatrixAlignment(unittest.TestCase):
    """R2 accounting: every canonical technique is recorded by the swarm."""

    def test_contract_matrix_covers_plan_kinds_and_verbs(self):
        canonical = set(TECHNIQUE_MATRIX["contract_logic"])
        swarm = set(CONTRACT_PLAN_KINDS) | {"impact-verb-analysis",
                                            "payable-flow"}
        self.assertEqual(canonical, swarm)

    def test_cloud_matrix_covers_privesc_families(self):
        canonical = set(TECHNIQUE_MATRIX["cloud_iam"])
        swarm = {"policy-dump-analysis", "privesc-graph", "action-mapping",
                 "wildcard-scope", "exposure-review"}
        self.assertEqual(canonical, swarm)
        # The per-family privesc techniques are finer-grained entries on
        # top of the canonical set (R2 superset rule).
        self.assertTrue(set(CLOUD_PRIVESC_FAMILIES)
                        <= {"privesc-policy-write", "privesc-passrole",
                            "privesc-identity"})

    def test_llm_surface_predicate(self):
        self.assertTrue(is_llm_surface("/api/ai/chat"))
        self.assertTrue(is_llm_surface("/v1/completions"))
        self.assertFalse(is_llm_surface("/api/users/1"))


class TestContractLane(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.base, self._shutdown = _boot_stub_target()
        self.abi_path = _write_tmp(self._td.name, "vault.json", ABI)

    def tearDown(self):
        # Restore before cleanup (cross-suite env hygiene).
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        if self._shutdown:
            self._shutdown()
        self._td.cleanup()

    def test_payable_attacker_reachable_opens_lead(self):
        signals = _probe_contract_matrix(self.base, [self.abi_path])
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertEqual(sig["signal"], "contract_surface")
        self.assertEqual(sig["winning_technique"], "argument-fuzzing")
        techniques = {a["technique"] for a in sig["attempts"]}
        # R2 accounting: the canonical matrix is fully covered (per-verb
        # probes add finer-grained entries on top).
        self.assertTrue(set(TECHNIQUE_MATRIX["contract_logic"])
                        <= techniques)

    def test_abi_url_entry(self):
        signals = _probe_contract_matrix(
            self.base, [f"abi={self.base}/abi/app.json"])
        self.assertEqual(len(signals), 1)
        self.assertIn("transfer", signals[0]["detail"])
        self.assertEqual(signals[0]["winning_technique"], "argument-fuzzing")

    def test_no_abi_no_signal(self):
        self.assertEqual(_probe_contract_matrix(self.base, ["/api/checkout"]),
                         [])

    def test_replay_argument_fuzzing(self):
        self.assertTrue(
            replay_contract_technique(self.abi_path, "argument-fuzzing"))
        self.assertTrue(replay_contract_technique(self.abi_path,
                                                  "payable-flow"))
        self.assertFalse(replay_contract_technique(self.abi_path,
                                                   "nonexistent-technique"))

    def test_missing_asset_refutes_on_replay(self):
        self.assertFalse(replay_contract_technique("/nonexistent.json",
                                                   "argument-fuzzing"))


class TestCloudLane(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.base, self._shutdown = _boot_stub_target()
        self.admin_path = _write_tmp(self._td.name, "admin.json",
                                     POLICY_ADMIN)
        self.clean_path = _write_tmp(self._td.name, "clean.json",
                                     POLICY_CLEAN)

    def tearDown(self):
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        if self._shutdown:
            self._shutdown()
        self._td.cleanup()

    def test_admin_reachable_policy_opens_lead(self):
        signals = _probe_cloud_matrix(self.base, [self.admin_path])
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertEqual(sig["signal"], "iam_privesc")
        self.assertEqual(sig["winning_technique"], "policy-dump-analysis")
        techniques = {a["technique"] for a in sig["attempts"]}
        # R2 accounting: the canonical matrix is fully covered (per-method
        # action-mapping entries add finer-grained evidence on top).
        self.assertTrue(set(TECHNIQUE_MATRIX["cloud_iam"]) <= techniques)
        self.assertIn("CreatePolicyVersion", sig["evidence"])

    def test_clean_policy_is_negative_evidence(self):
        signals = _probe_cloud_matrix(self.base, [self.clean_path])
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["winning_technique"], "")

    def test_policy_url_entry(self):
        signals = _probe_cloud_matrix(
            self.base, [f"policy={self.base}/iam/policy.json"])
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["winning_technique"],
                         "policy-dump-analysis")

    def test_replay_policy_analysis(self):
        self.assertTrue(replay_cloud_technique(self.admin_path,
                                               "policy-dump-analysis"))
        self.assertTrue(replay_cloud_technique(self.admin_path,
                                               "privesc-graph"))
        self.assertFalse(replay_cloud_technique(self.clean_path,
                                                "privesc-graph"))


class TestLlmLane(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._saved_root = os.environ.get("BUGWOLF_PROJECT_ROOT")
        os.environ["BUGWOLF_PROJECT_ROOT"] = self._td.name
        self.base, self._shutdown = _boot_stub_target()
        agent_py = ("def run(user_input):\n"
                    "    run_command(cmd=user_input)\n"
                    "    send_email(to=user_input)\n")
        self.agent_path = os.path.join(self._td.name, "agent.py")
        with open(self.agent_path, "w") as fh:
            fh.write(agent_py)

    def tearDown(self):
        if self._saved_root is None:
            os.environ.pop("BUGWOLF_PROJECT_ROOT", None)
        else:
            os.environ["BUGWOLF_PROJECT_ROOT"] = self._saved_root
        if self._shutdown:
            self._shutdown()
        self._td.cleanup()

    def test_injection_echo_opens_signal(self):
        signals = _probe_llm_matrix(self.base, ["/api/ai/chat"])
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertEqual(sig["signal"], "llm_injection")
        self.assertTrue(sig["winning_technique"].startswith("injection-"))
        techniques = {a["technique"] for a in sig["attempts"]}
        self.assertTrue(set(TECHNIQUE_MATRIX["llm_tooling"]) <= techniques)

    def test_code_archive_produces_sensitive_call_site_signal(self):
        signals = _probe_llm_matrix(self.base, [self.agent_path])
        self.assertEqual(len(signals), 1)
        sig = signals[0]
        self.assertEqual(sig["signal"], "llm_agentic_authz")
        self.assertEqual(sig["winning_technique"], "call-site-analysis")
        self.assertIn("run_command", sig["evidence"])

    def test_plain_surface_ignored(self):
        self.assertEqual(_probe_llm_matrix(self.base, ["/api/users/1"]), [])

    def test_replay_injection(self):
        signals = _probe_llm_matrix(self.base, ["/api/ai/chat"])
        winner = signals[0]["winning_technique"]
        self.assertTrue(replay_llm_technique(self.base, "/api/ai/chat",
                                             winner))
        self.assertFalse(replay_llm_technique(self.base, "/api/ai/chat",
                                              "injection-nonexistent"))

    def test_replay_call_site(self):
        self.assertTrue(replay_llm_technique(self.base, self.agent_path,
                                             "call-site-analysis"))
        # auth-plan-diff stays falsifiable: empty plans (code-scan sources
        # are unprovable) refute on replay.
        self.assertFalse(replay_llm_technique(self.base, self.agent_path,
                                              "auth-plan-diff"))


class TestDomainLaneE2E(unittest.TestCase):
    """Full mission: domain lanes open leads, verify lane replays them."""

    def test_contract_cloud_llm_mission_reaches_pwned(self):
        with tempfile.TemporaryDirectory() as tmp:
            abi_path = _write_tmp(tmp, "vault.json", ABI)
            pol_path = _write_tmp(tmp, "admin.json", POLICY_ADMIN)
            agent_py = os.path.join(tmp, "agent.py")
            with open(agent_py, "w") as fh:
                fh.write("def run(x):\n    run_command(cmd=x)\n")
            with _DomainMissionHarness(
                    domains=["web_api", "smart_contract", "cloud_cicd",
                             "llm_ai", "verify", "report"],
                    paths=[abi_path, pol_path, agent_py, "/api/ai/chat",
                           "/api/checkout", "/api/voucher/redeem",
                           "/api/users/1", "/api/users/2", "/api/users/42"],
            ) as runner:
                report = runner.run()
        by_class = {}
        for lead in runner.leads.list_leads():
            by_class.setdefault(lead.bug_class, []).append(lead.status)

        self.assertIn("contract_logic", by_class)
        self.assertIn("cloud_iam", by_class)
        self.assertIn("llm_tooling", by_class)
        self.assertTrue(all(LEAD_PWNED in statuses
                            for statuses in by_class.values()),
                        f"expected a PWNED per class: {by_class}")
        # The FIN race binding still pays out on the commerce surfaces.
        fin_pwned = [l for l in runner.leads.list_leads()
                     if l.bug_class == "business_logic"
                     and l.status == LEAD_PWNED]
        self.assertTrue(fin_pwned, "FIN race binding still pays out")

    def test_race_bound_voucher_and_replay_findings(self):
        with _DomainMissionHarness(
                domains=["web_api", "verify", "report"],
                paths=["/api/checkout", "/api/voucher/redeem",
                       "/api/users/1", "/api/users/2", "/api/users/42"],
        ) as runner:
            report = runner.run()
        fin_leads = [l for l in runner.leads.list_leads()
                     if l.bug_class == "business_logic"]
        self.assertTrue(fin_leads, "FIN lane produced no leads")
        pwned_fin = [l for l in fin_leads if l.status == LEAD_PWNED]
        self.assertTrue(pwned_fin, "no business_logic lead reached PWNED")
        details = " | ".join(e.get("detail", "")
                             for l in pwned_fin
                             for e in l.technique_log)
        self.assertIn("FIN-VOUCHER-01", details)
        self.assertIn("FIN-REPLAY-01", details)


if __name__ == "__main__":
    unittest.main()
