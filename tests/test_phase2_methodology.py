#!/usr/bin/env python3
"""Phase 2.4 methodology library tests.

Exercises the methodology corpus: pattern index, search, citation engine,
vector index, chain loader, templates and content-policy guards.

Run from the project root:

    python3 -m pytest tests/test_phase2_methodology.py -x --no-header
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

from bugwolf.methodology.chain_loader import ChainLoader
from bugwolf.methodology.citation import CitationEngine
from bugwolf.methodology.search import (
    MethodologySearch,
    _FORBIDDEN_LITERALS,
    contains_forbidden_literal,
)
from bugwolf.methodology.vector_index import VectorIndex

REPO_ROOT = Path(__file__).resolve().parents[1]
METHODOLOGY_ROOT = REPO_ROOT / "bugwolf" / "methodology"
PATTERNS_ROOT = METHODOLOGY_ROOT / "patterns"
CHAINS_ROOT = METHODOLOGY_ROOT / "chains"
TEMPLATES_ROOT = METHODOLOGY_ROOT / "templates"

CATEGORY_DIRS = [
    "ssrf",
    "xss",
    "sqli",
    "idor",
    "auth",
    "deserialization",
    "business_logic",
    "ci_cd",
    "cloud",
    "llm_ai",
    "mobile",
    "recon",
    "api",
    "waf_bypass",
]


class TestMethodologyCorpus(unittest.TestCase):
    """File-system level invariants of the methodology library."""

    def test_all_categories_have_directory(self):
        for cat in CATEGORY_DIRS:
            self.assertTrue(
                (PATTERNS_ROOT / cat).is_dir(),
                f"missing category directory: {cat}",
            )

    def test_pattern_count_meets_floor(self):
        yamls = list(PATTERNS_ROOT.rglob("*.yaml"))
        self.assertGreaterEqual(
            len(yamls),
            70,
            f"expected >= 70 pattern files, found {len(yamls)}",
        )

    def test_every_pattern_parses_as_yaml(self):
        bad = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                bad.append((path, str(exc)))
                continue
            if raw is None:
                bad.append((path, "empty document"))
                continue
        self.assertFalse(bad, f"unparseable pattern YAML: {bad}")

    def test_every_pattern_has_required_fields(self):
        required = {
            "schema",
            "id",
            "bug_class",
            "category",
            "severity",
            "title",
            "description",
            "detection",
            "remediation",
            "references",
            "bounty_range",
            "h100_proven",
        }
        bad = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                bad.append((path.name, "not a dict"))
                continue
            missing = required - set(raw.keys())
            if missing:
                bad.append((path.name, sorted(missing)))
            if not isinstance(raw.get("detection"), dict):
                bad.append((path.name, "detection not a dict"))
        self.assertFalse(bad, f"patterns missing required fields: {bad}")

    def test_no_pattern_contains_forbidden_literal(self):
        offenders = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            text = path.read_text(encoding="utf-8").lower()
            for lit in _FORBIDDEN_LITERALS:
                if lit in text:
                    offenders.append((path.name, lit))
        self.assertFalse(
            offenders,
            f"patterns containing forbidden literals: {offenders}",
        )

    def test_every_pattern_signature_compiles(self):
        bad = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            sig = raw.get("detection", {}).get("signature", "")
            try:
                re.compile(sig)
            except re.error as exc:
                bad.append((path.name, str(exc)))
        self.assertFalse(bad, f"patterns with invalid regex: {bad}")

    def test_every_pattern_description_has_min_length(self):
        short = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            desc = (raw.get("description") or "").strip()
            if len(desc) < 50:
                short.append((path.name, len(desc)))
        self.assertFalse(short, f"patterns with short description: {short}")

    def test_every_pattern_remediation_has_min_length(self):
        short = []
        for path in sorted(PATTERNS_ROOT.rglob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            rem = (raw.get("remediation") or "").strip()
            if len(rem) < 50:
                short.append((path.name, len(rem)))
        self.assertFalse(short, f"patterns with short remediation: {short}")


class TestMethodologySearch(unittest.TestCase):
    """Behavioural tests for the search index."""

    @classmethod
    def setUpClass(cls):
        cls.search = MethodologySearch(METHODOLOGY_ROOT)
        cls.search.index()

    def test_index_populates_patterns_and_chains(self):
        self.assertGreaterEqual(len(self.search.patterns), 70)
        self.assertEqual(len(self.search.chains), 12)

    def test_search_free_text_returns_hits(self):
        results = self.search.search("ssrf imds aws metadata", top_k=5)
        self.assertGreaterEqual(len(results), 1)
        for r in results:
            self.assertTrue(r.pattern_id)

    def test_search_by_bug_class(self):
        xss = self.search.search_by_bug_class("xss")
        self.assertGreaterEqual(len(xss), 5)
        self.assertTrue(all(p.bug_class == "xss" for p in xss))

    def test_search_by_id(self):
        first = self.search.search_by_bug_class("ssrf")[0]
        rec = self.search.search_by_id(first.pattern_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.pattern_id, first.pattern_id)

    def test_sample_signature_actually_matches(self):
        imds = self.search.search_by_id("imds_metadata_v1")
        self.assertIsNotNone(imds)
        body = "GET /?url=http://169.254.169.254/latest/meta-data/"
        self.assertIsNotNone(
            re.search(imds.detection_signature, body),
            "IMDS pattern signature should match a body with 169.254.169.254",
        )

    def test_search_handles_unknown_query_gracefully(self):
        # gibberish tokens that no pattern should match
        results = self.search.search("zzzqqqxxxnomatch", top_k=5)
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 0)

    def test_forbidden_literal_helper(self):
        self.assertTrue(contains_forbidden_literal("see file:// payload"))
        self.assertTrue(contains_forbidden_literal("gopher:// tunnel"))
        self.assertFalse(contains_forbidden_literal("https://example.com"))


class TestVectorIndex(unittest.TestCase):
    """Standalone vector-index tests."""

    def test_add_and_query_returns_ranked_results(self):
        idx = VectorIndex()
        idx.add("doc1", "ssrf cloud metadata aws imds")
        idx.add("doc2", "xss stored comment injection")
        idx.add("doc3", "ssrf imds 169.254.169.254")
        results = idx.query("ssrf aws imds", top_k=5)
        ids = [doc_id for doc_id, _ in results]
        # Only docs with term overlap produce a positive cosine score.
        self.assertEqual(set(ids), {"doc1", "doc3"})
        # doc1 has more term overlap than doc3 → highest score.
        self.assertEqual(results[0][0], "doc1")
        for _doc_id, score in results:
            self.assertGreater(score, 0.0)

    def test_query_empty_index_returns_empty(self):
        idx = VectorIndex()
        self.assertEqual(idx.query("anything"), [])

    def test_query_with_no_tokens_returns_empty(self):
        idx = VectorIndex()
        idx.add("doc1", "alpha beta")
        self.assertEqual(idx.query(""), [])
        self.assertEqual(idx.query("   "), [])

    def test_replace_existing_doc(self):
        idx = VectorIndex()
        idx.add("a", "xss payload")
        idx.add("a", "ssrf imds")  # replace
        results = idx.query("ssrf imds", top_k=5)
        ids = [doc_id for doc_id, _ in results]
        self.assertEqual(ids.count("a"), 1)


class TestCitationEngine(unittest.TestCase):
    """Citation engine behaviour."""

    @classmethod
    def setUpClass(cls):
        cls.engine = CitationEngine(METHODOLOGY_ROOT)

    def test_cite_returns_citations_for_finding(self):
        finding = {
            "title": "SSRF to AWS IMDS",
            "summary": "Attacker reaches cloud metadata service",
            "bug_class": "ssrf",
        }
        result = self.engine.cite([finding])
        self.assertEqual(len(result), 1)
        self.assertGreaterEqual(len(result[0]), 1)
        cite = result[0][0]
        self.assertTrue(cite.pattern_id)
        self.assertTrue(cite.title)
        self.assertGreater(cite.confidence, 0.0)

    def test_format_produces_markdown(self):
        finding = {"title": "Stored XSS in comment", "bug_class": "xss"}
        cites = self.engine.cite([finding])
        md = self.engine.format(cites)
        self.assertIn("Finding 1", md)
        self.assertIn("[", md)

    def test_cite_flat_collapses_groups(self):
        finding = {"title": "SQLi in login", "bug_class": "sqli"}
        flat = self.engine.cite_flat([finding])
        self.assertGreaterEqual(len(flat), 1)

    def test_cite_empty_findings_returns_empty(self):
        self.assertEqual(self.engine.cite([]), [])
        self.assertEqual(self.engine.cite(None), [])  # type: ignore[arg-type]


class TestChainLoader(unittest.TestCase):
    """Chain catalog loader tests."""

    @classmethod
    def setUpClass(cls):
        cls.loader = ChainLoader(METHODOLOGY_ROOT)

    def test_load_all_returns_twelve_chains(self):
        chains = self.loader.load_all()
        self.assertEqual(len(chains), 12)

    def test_load_returns_specific_chain(self):
        spec = self.loader.load("01_oauth_to_ato")
        self.assertIsNotNone(spec)
        self.assertIn("OAuth", spec.title)
        self.assertGreater(len(spec.steps), 0)
        for order, desc in spec.steps:
            self.assertIsInstance(order, int)
            self.assertIsInstance(desc, str)

    def test_load_returns_none_for_unknown(self):
        self.assertIsNone(self.loader.load("not_a_real_chain"))

    def test_chain_ids_unique(self):
        ids = self.loader.ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 12)

    def test_stats_includes_total(self):
        stats = self.loader.stats()
        self.assertEqual(stats.get("total"), 12)

    def test_by_final_severity_filters(self):
        critical = self.loader.by_final_severity("critical")
        self.assertGreaterEqual(len(critical), 1)
        self.assertTrue(all(c.final_severity == "critical" for c in critical))


class TestChainsParseAndConform(unittest.TestCase):
    """YAML schema-level checks for every chain file."""

    def test_all_chain_files_parse(self):
        for path in sorted(CHAINS_ROOT.glob("*.yaml")):
            with self.subTest(path=path.name):
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(raw, dict)
                self.assertEqual(raw.get("schema"), "bugwolf-methodology-chain-v1")
                for required in (
                    "id",
                    "title",
                    "bounty",
                    "steps",
                    "final_severity",
                ):
                    self.assertIn(required, raw)
                steps = raw.get("steps") or []
                self.assertGreater(len(steps), 0)
                for s in steps:
                    self.assertIn("order", s)
                    self.assertIn("description", s)

    def test_chain_count(self):
        files = list(CHAINS_ROOT.glob("*.yaml"))
        self.assertEqual(len(files), 12)


class TestTemplates(unittest.TestCase):
    """Engagement template inventory."""

    def test_templates_directory_has_minimum_entries(self):
        files = [p for p in TEMPLATES_ROOT.glob("*.md")]
        self.assertGreaterEqual(
            len(files),
            10,
            f"expected >= 10 templates, found {len(files)}",
        )

    def test_every_template_is_non_trivial(self):
        for path in sorted(TEMPLATES_ROOT.glob("*.md")):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertGreater(len(text), 200)
                self.assertIn("##", text)  # at least one section heading

    def test_required_templates_present(self):
        required = {
            "pentest_kickoff.md",
            "redteam_kickoff.md",
            "bug_bounty_triage.md",
            "web_app_assessment.md",
            "api_assessment.md",
            "cloud_assessment.md",
            "mobile_assessment.md",
            "llm_assessment.md",
            "smart_contract_assessment.md",
            "osint_engagement.md",
        }
        existing = {p.name for p in TEMPLATES_ROOT.glob("*.md")}
        self.assertTrue(
            required.issubset(existing),
            f"missing templates: {required - existing}",
        )


if __name__ == "__main__":
    unittest.main()