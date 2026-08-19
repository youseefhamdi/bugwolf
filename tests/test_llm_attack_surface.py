#!/usr/bin/env python3
"""
Tests for the BugWolf LLM / Agentic AI attack-surface detector.

Run:  python3 -m unittest discover -s tests -v

Guards the core property: the detector is deterministic (no network for
`scan_text`/`scan_path`), maps every hit to a canonical `llm-*` bug class,
and never misses the headline surfaces (excessive agency, RAG retrieval,
MCP config, hidden-context secrets).
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.llm_attack_surface import (
    LLMAttackSurfaceScanner, SurfaceFinding, RULES,
)


def classes(findings):
    return sorted({f.bug_class for f in findings})


class TestScanText(unittest.TestCase):

    def setUp(self):
        self.scanner = LLMAttackSurfaceScanner()

    def test_detects_excessive_agency_shell_exec(self):
        code = 'def run_tool(cmd):\n    return subprocess.run(cmd, shell=True)'
        findings = self.scanner.scan_text(code)
        self.assertIn("excessive-agency", classes(findings))
        hit = next(f for f in findings if f.bug_class == "excessive-agency")
        self.assertEqual(hit.severity, "critical")
        self.assertEqual(hit.owasp_llm, "LLM03")

    def test_detects_prompt_injection_surface(self):
        code = 'prompt = f"Summarize the following: {user_input}"'
        findings = self.scanner.scan_text(code)
        self.assertIn("prompt-injection", classes(findings))
        hit = next(f for f in findings if f.bug_class == "prompt-injection")
        self.assertIn("ASI01", hit.owasp_asi)

    def test_detects_rag_retrieval_pipeline(self):
        code = ("from langchain_community.vectorstores import Pinecone\n"
                "docs = vectorstore.similarity_search(query)")
        findings = self.scanner.scan_text(code)
        self.assertIn("rag-poisoning", classes(findings))
        hit = next(f for f in findings if f.bug_class == "rag-poisoning")
        self.assertEqual(hit.owasp_llm, "LLM09")

    def test_detects_mcp_config(self):
        code = '{"mcpServers": {"filesystem": {"command": "npx"}}}'
        findings = self.scanner.scan_text(code)
        self.assertIn("mcp-injection", classes(findings))
        hit = next(f for f in findings if f.bug_class == "mcp-injection")
        self.assertEqual(hit.owasp_asi, "ASI04")

    def test_detects_hidden_context_secret_in_system_prompt(self):
        code = 'system_prompt = "You are an admin. Use api_key=sk_live_abc123."'
        findings = self.scanner.scan_text(code)
        self.assertIn("hidden-context-exposure", classes(findings))
        hit = next(f for f in findings
                   if f.bug_class == "hidden-context-exposure")
        self.assertEqual(hit.severity, "high")
        self.assertEqual(hit.owasp_llm, "LLM08")

    def test_detects_agent_memory(self):
        code = "memory.save(key, value)  # persistent agent memory store"
        findings = self.scanner.scan_text(code)
        self.assertIn("memory-poisoning", classes(findings))
        hit = next(f for f in findings if f.bug_class == "memory-poisoning")
        self.assertEqual(hit.owasp_asi, "ASI06")

    def test_detects_cross_tenant_vector_filter(self):
        code = ("results = index.similarity_search(query, "
                "filter={'tenant_id': tenant})  # search before filter")
        findings = self.scanner.scan_text(code)
        self.assertIn("cross-tenant-vector-leak", classes(findings))

    def test_line_numbers_are_1_indexed_and_accurate(self):
        code = "a = 1\nb = 2\nsubprocess.run('id')\n"
        findings = self.scanner.scan_text(code)
        hit = next(f for f in findings if f.bug_class == "excessive-agency")
        self.assertEqual(hit.line, 3)

    def test_clean_code_returns_no_findings(self):
        findings = self.scanner.scan_text("x = 1 + 2\nprint(x)\n")
        self.assertEqual(findings, [])


class TestSeverityFiltering(unittest.TestCase):

    def test_min_severity_high_drops_medium_and_below(self):
        scanner = LLMAttackSurfaceScanner(min_severity="high")
        findings = scanner.scan_text(
            "memory.save(k, v)\nsubprocess.run('id')\nprompt = user_input")
        sevs = {f.severity for f in findings}
        self.assertNotIn("low", sevs)
        self.assertNotIn("medium", sevs)
        self.assertNotIn("informational", sevs)

    def test_default_includes_all_severities(self):
        scanner = LLMAttackSurfaceScanner()
        # rogue-agent / cascading-failure rules are low-severity; include a
        # low-severity surface to assert it is present by default.
        findings = scanner.scan_text("human_in_the_loop approval_flow")
        self.assertTrue(any(f.bug_class == "human-agent-trust"
                            for f in findings))


class TestScanPath(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.scanner = LLMAttackSurfaceScanner()

    def tearDown(self):
        self.tmp.cleanup()

    def test_scans_directory_and_skips_node_modules(self):
        (self.dir / "app.py").write_text(
            "import os\nos.system('ls')\n")
        (self.dir / "node_modules").mkdir()
        (self.dir / "node_modules" / "dep.js").write_text(
            "subprocess.run('rm -rf /')")
        (self.dir / "README.md").write_text("# no surface here\n")
        findings = self.scanner.scan_path(str(self.dir))
        self.assertIn("excessive-agency", classes(findings))
        files = {f.file for f in findings}
        self.assertTrue(any(f.endswith("app.py") for f in files))
        self.assertFalse(any("node_modules" in f for f in files))

    def test_scan_single_file(self):
        f = self.dir / "one.py"
        f.write_text('llm = openai.chat.completions.create(model="gpt-4")\n')
        findings = self.scanner.scan_path(str(f))
        self.assertTrue(findings)
        self.assertTrue(all(fi.file.endswith("one.py") for fi in findings))

    def test_missing_path_returns_empty(self):
        findings = self.scanner.scan_path("/nonexistent/path/xyz")
        self.assertEqual(findings, [])


class TestSummaryAndSerialization(unittest.TestCase):

    def setUp(self):
        self.scanner = LLMAttackSurfaceScanner()

    def test_summary_counts_by_class_and_severity(self):
        findings = self.scanner.scan_text(
            "subprocess.run('id')\nsubprocess.run('whoami')\n"
            "vectorstore.similarity_search(q)")
        summary = self.scanner.summarize(findings)
        self.assertEqual(summary["total"], len(findings))
        self.assertGreaterEqual(summary["by_bug_class"]["excessive-agency"], 2)
        self.assertIn("rag-poisoning", summary["by_bug_class"])

    def test_finding_to_dict_roundtrip(self):
        findings = self.scanner.scan_text("subprocess.run('id')")
        d = findings[0].to_dict()
        self.assertEqual(d["bug_class"], "excessive-agency")
        self.assertEqual(d["owasp_llm"], "LLM03")
        # SurfaceFinding is reconstructible from its dict
        back = SurfaceFinding(**d)
        self.assertEqual(back.bug_class, findings[0].bug_class)
        self.assertEqual(back.line, findings[0].line)


class TestRulesIntegrity(unittest.TestCase):

    def test_all_rules_have_valid_fields(self):
        for bug_class, severity, llm, asi, detail, patterns in RULES:
            self.assertIsInstance(bug_class, str)
            self.assertTrue(bug_class, "empty bug class")
            self.assertIn(severity,
                          ["informational", "low", "medium", "high", "critical"])
            self.assertIsInstance(patterns, list)
            self.assertTrue(patterns, f"rule {bug_class} has no patterns")
            for p in patterns:
                try:
                    __import__("re").compile(p)
                except __import__("re").error as e:
                    self.fail(f"bad regex in {bug_class}: {p} -> {e}")


if __name__ == "__main__":
    unittest.main()
