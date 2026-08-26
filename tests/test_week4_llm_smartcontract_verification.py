"""Week 4 tests: LLM contract triage, agentic tool auth, RAG memory
poisoning, verification lab planner."""

import json
import tempfile
import unittest

from tools.domains.smart_contracts import llm_contract_triage as triage
from tools.domains.llm import agentic_tool_auth as ata
from tools.domains.llm import rag_memory_poisoning as rag
from tools.validation import verification_lab as lab

REENTRANCY = (
    "function withdraw(uint amount) public {\n"
    "    require(balances[msg.sender] >= amount);\n"
    "    (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
    "    balances[msg.sender] -= amount;\n"
    "}"
)

CANDIDATES = [
    {"candidate_id": "f-1", "contract": "Vault.sol",
     "bug_class": "reentrancy", "code_slice": REENTRANCY,
     "severity_guess": "high"},
    {"candidate_id": "f-2", "contract": "Token.sol", "bug_class": "arithmetic",
     "code_slice": "function transfer(address to, uint amount) public {\n"
                   "    balances[msg.sender] -= amount;\n"
                   "    balances[to] += amount;\n}"},
]


def _without_ts(obj):
    if isinstance(obj, dict):
        return {k: _without_ts(v) for k, v in obj.items() if k != "generated_at"}
    if isinstance(obj, list):
        return [_without_ts(v) for v in obj]
    return obj


class TestLlmContractTriage(unittest.TestCase):
    def test_reentrancy_scores_highest(self):
        report = triage.triage("acme", CANDIDATES)
        self.assertEqual(report.verdicts[0].candidate_id, "f-1")
        self.assertGreater(report.verdicts[0].deterministic_score,
                           report.verdicts[1].deterministic_score)
        self.assertIn("low-level external call", report.verdicts[0].markers)

    def test_verdict_merge_boosts_confirmed(self):
        report = triage.triage("acme", CANDIDATES, verdicts=[
            {"candidate_id": "f-1", "exploitable": True, "confidence": 0.9,
             "attack_path": "reenter withdraw"},
        ])
        v = next(v for v in report.verdicts if v.candidate_id == "f-1")
        self.assertEqual(v.llm_verdict, "confirmed")
        self.assertGreater(v.final_score, v.deterministic_score)
        self.assertEqual(v.attack_path, "reenter withdraw")

    def test_verdict_refute_lowers_score(self):
        report = triage.triage("acme", CANDIDATES, verdicts=[
            {"candidate_id": "f-1", "exploitable": False, "confidence": 0.9},
        ])
        v = next(v for v in report.verdicts if v.candidate_id == "f-1")
        self.assertEqual(v.llm_verdict, "refuted")
        self.assertLess(v.final_score, v.deterministic_score)

    def test_prompts_generated_per_candidate(self):
        report = triage.triage("acme", CANDIDATES)
        self.assertEqual(len(report.prompts), len(CANDIDATES) * 3)
        ids = {p.prompt_id for p in report.prompts}
        self.assertEqual(len(ids), len(report.prompts))  # unique

    def test_exploitability_labels(self):
        self.assertEqual(triage._exploitability_label(8.5), "critical")
        self.assertEqual(triage._exploitability_label(6.0), "high")
        self.assertEqual(triage._exploitability_label(3.5), "medium")
        self.assertEqual(triage._exploitability_label(1.0), "low")

    def test_deterministic(self):
        a = _without_ts(triage.triage("acme", CANDIDATES).to_dict())
        b = _without_ts(triage.triage("acme", CANDIDATES).to_dict())
        self.assertEqual(a, b)

    def test_write_path(self):
        report = triage.triage("acme", CANDIDATES)
        with tempfile.TemporaryDirectory() as td:
            out = triage.write_report(report, base_dir=td)
            self.assertEqual(out.name, "triage-verdicts.json")
            self.assertIn("contracts", str(out))


class TestAgenticToolAuth(unittest.TestCase):
    def test_sensitive_tool_user_input_high(self):
        analysis = ata.analyze("acme", inventory=[
            {"tool": "run_command", "args": {"cmd": "user_input"},
             "identity": "service"},
        ])
        plans = {p.category: p for p in analysis.plans}
        self.assertIn("tool_misuse", plans)
        self.assertEqual(plans["tool_misuse"].severity, "high")
        self.assertEqual(plans["tool_misuse"].owasp_asi, "ASI02")
        self.assertEqual(plans["tool_misuse"].attacker_args, ["cmd"])

    def test_privileged_identity_asi03_high(self):
        analysis = ata.analyze("acme", inventory=[
            {"tool": "write_file", "args": {"path": "user_input"},
             "identity": "admin"},
        ])
        asi03 = [p for p in analysis.plans if p.owasp_asi == "ASI03"]
        self.assertEqual(len(asi03), 1)
        self.assertEqual(asi03[0].severity, "high")

    def test_nonprivileged_identity_asi03_medium(self):
        analysis = ata.analyze("acme", inventory=[
            {"tool": "fetch_url", "args": {"url": "web_content"},
             "identity": "user"},
        ])
        asi03 = [p for p in analysis.plans if p.owasp_asi == "ASI03"]
        self.assertEqual(len(asi03), 1)
        self.assertEqual(asi03[0].severity, "medium")

    def test_trusted_args_no_plan(self):
        analysis = ata.analyze("acme", inventory=[
            {"tool": "run_command", "args": {"cmd": "constant"}},
        ])
        self.assertEqual(len(analysis.plans), 0)

    def test_code_scan_finds_call_sites(self):
        analysis = ata.analyze("acme", code=(
            "def handle(msg):\n"
            "    run_command(cmd=msg)\n"
            "    fetch_url(url=msg)\n"))
        self.assertGreaterEqual(len(analysis.call_sites), 2)

    def test_deterministic(self):
        inv = [{"tool": "run_command", "args": {"cmd": "user_input"},
                "identity": "service"}]
        a = _without_ts(ata.analyze("acme", inventory=inv).to_dict())
        b = _without_ts(ata.analyze("acme", inventory=inv).to_dict())
        self.assertEqual(a, b)


class TestRagMemoryPoisoning(unittest.TestCase):
    RAG = {
        "name": "support-rag", "store_type": "memory_store",
        "write_back": True, "sanitization": False,
        "provenance_tagging": False,
        "sources": [{"type": "docs", "trust": "high"},
                    {"type": "user_upload", "trust": "low"},
                    {"type": "web_crawl", "trust": "low"}],
    }

    def test_memory_write_back_ranks_first(self):
        analysis = rag.analyze("acme", self.RAG)
        self.assertEqual(analysis.vectors[0].name, "memory_write_back")
        self.assertGreaterEqual(analysis.vectors[0].score, 7)
        self.assertEqual(analysis.vectors[0].owasp_ref, "ASI06")

    def test_indirect_injection_high_with_low_trust(self):
        analysis = rag.analyze("acme", self.RAG)
        indirect = next(v for v in analysis.vectors
                        if v.name == "indirect_prompt_injection")
        self.assertEqual(indirect.severity, "high")

    def test_sanitization_reduces_score(self):
        safe = dict(self.RAG, sanitization=True)
        unsafe = rag.analyze("acme", self.RAG)
        safe_a = rag.analyze("acme", safe)
        unsafe_v = next(v for v in unsafe.vectors
                        if v.name == "indirect_prompt_injection")
        safe_v = next(v for v in safe_a.vectors
                      if v.name == "indirect_prompt_injection")
        self.assertLess(safe_v.score, unsafe_v.score)

    def test_provenance_tagging_reduces_confusion(self):
        tagged = dict(self.RAG, provenance_tagging=True)
        base = rag.analyze("acme", self.RAG)
        tagged_a = rag.analyze("acme", tagged)
        base_v = next(v for v in base.vectors if v.name == "source_confusion")
        tagged_v = next(v for v in tagged_a.vectors
                        if v.name == "source_confusion")
        self.assertLess(tagged_v.score, base_v.score)

    def test_trust_inference(self):
        analysis = rag.analyze("acme", {
            "store_type": "vector_db",
            "sources": [{"type": "user_upload"}, {"type": "docs"}],
        })
        trust = {s.type: s.trust for s in analysis.store.sources}
        self.assertEqual(trust["user_upload"], "low")
        self.assertEqual(trust["docs"], "high")

    def test_deterministic(self):
        a = _without_ts(rag.analyze("acme", self.RAG).to_dict())
        b = _without_ts(rag.analyze("acme", self.RAG).to_dict())
        self.assertEqual(a, b)


class TestVerificationLab(unittest.TestCase):
    def test_family_detection(self):
        self.assertEqual(lab._family_for("reentrancy"), "smart-contract")
        self.assertEqual(lab._family_for("jwt forgery"), "auth")
        self.assertEqual(lab._family_for("bfla"), "api")
        self.assertEqual(lab._family_for("prompt injection"), "llm")
        self.assertEqual(lab._family_for("unknown"), "web")

    def test_plan_structure(self):
        plan_set = lab.plan_labs("acme", CANDIDATES)
        self.assertEqual(len(plan_set.plans), 2)
        plan = plan_set.plans[0]
        self.assertEqual(plan.family, "smart-contract")
        self.assertEqual(plan.finding_id, "f-1")
        self.assertIn("discard", plan.to_dict())
        steps = [s.action for s in plan.steps]
        self.assertEqual(steps, ["setup", "reproduce", "verify", "capture",
                                 "discard"])

    def test_reproduce_verify_scripts_present(self):
        plan_set = lab.plan_labs("acme", CANDIDATES)
        for plan in plan_set.plans:
            self.assertIn("reproduce", plan.reproduce_script)
            self.assertIn("verify", plan.verify_script)

    def test_operator_inputs_from_candidate(self):
        plan_set = lab.plan_labs("acme", [{
            "finding_id": "f-x", "bug_class": "ssrf",
            "url": "https://api.example.test/fetch",
            "payload": "?url=http://169.254.169.254/",
        }])
        plan = plan_set.plans[0]
        self.assertEqual(plan.family, "web")
        self.assertTrue(any("https://api.example.test/fetch" in i
                            for i in plan.operator_inputs))

    def test_deterministic(self):
        a = _without_ts(lab.plan_labs("acme", CANDIDATES).to_dict())
        b = _without_ts(lab.plan_labs("acme", CANDIDATES).to_dict())
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
