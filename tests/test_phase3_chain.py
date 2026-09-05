#!/usr/bin/env python3
"""
## Source: BugWolf Phase 3.5 (in-house) — test suite
## License: bugwolf-MIT
## Port: 2026-09-05

Phase 3.5 tests for the ``bugwolf.chain`` package and the 12 H100 chain
YAMLs. At least 20 test cases cover:

  * import + core-function smoke per module (6 modules + h100/).
  * :class:`CrossProtocolChainBuilder.build_cross_protocol_chain` returns
    :class:`CrossProtocolChain`.
  * :class:`CrossTargetChainBuilder.build_cross_target_chain` returns
    :class:`CrossTargetChain`.
  * :class:`ChainValidator.validate` returns
    :class:`ChainValidationResult` with issues when invalid.
  * :class:`ChainPoCGenerator.generate_poc` writes a file.
  * :class:`ChainPoCGenerator` returns :class:`PoCUnavailable` for
    invalid chains.
  * all 12 H100 YAML files parse and conform to the schema.
  * each YAML has ≥2 steps, ≥1 reference.
  * NO chain YAML contains literal ``file://`` or ``gopher://``.
  * the shim ``kill_chain_bridge()`` returns the builder class.
  * NO module uses ``shell=True``, ``verify=False``, hardcoded UA.
  * every file has ``## Source:`` + ``## License:`` comments.
"""
from __future__ import annotations

import importlib
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ===========================================================================
# Imports
# ===========================================================================

class TestImports(unittest.TestCase):
    """Every module imports cleanly."""

    def test_import_builder(self):
        m = importlib.import_module("bugwolf.chain.builder")
        self.assertTrue(hasattr(m, "CrossProtocolChainBuilder"))

    def test_import_cross_protocol(self):
        m = importlib.import_module("bugwolf.chain.cross_protocol")
        self.assertTrue(hasattr(m, "build_http_to_grpc_chain"))

    def test_import_cross_target(self):
        m = importlib.import_module("bugwolf.chain.cross_target")
        self.assertTrue(hasattr(m, "CrossTargetChainBuilder"))

    def test_import_validator(self):
        m = importlib.import_module("bugwolf.chain.validator")
        self.assertTrue(hasattr(m, "ChainValidator"))

    def test_import_poc_chain(self):
        m = importlib.import_module("bugwolf.chain.poc_chain")
        self.assertTrue(hasattr(m, "ChainPoCGenerator"))

    def test_import_h100(self):
        m = importlib.import_module("bugwolf.chain.h100")
        self.assertTrue(hasattr(m, "load_all"))

    def test_package_init_exports(self):
        m = importlib.import_module("bugwolf.chain")
        for name in (
            "CrossProtocolChainBuilder",
            "CrossTargetChainBuilder",
            "ChainValidator",
            "ChainPoCGenerator",
        ):
            self.assertTrue(hasattr(m, name), f"missing export: {name}")


# ===========================================================================
# CrossProtocolChainBuilder
# ===========================================================================

class TestCrossProtocolChainBuilder(unittest.TestCase):

    def test_build_returns_chain(self):
        from bugwolf.chain.builder import (
            CrossProtocolChain,
            CrossProtocolChainBuilder,
        )
        b = CrossProtocolChainBuilder()
        result = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="grpc",
        )
        self.assertIsInstance(result, CrossProtocolChain)

    def test_build_identical_protocols_returns_unavailable(self):
        from bugwolf.chain.builder import (
            CrossProtocolChainBuilder,
            Unavailable,
        )
        b = CrossProtocolChainBuilder()
        result = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="http",
        )
        self.assertIsInstance(result, Unavailable)

    def test_build_unknown_pattern_returns_unavailable(self):
        from bugwolf.chain.builder import (
            CrossProtocolChainBuilder,
            Unavailable,
        )
        b = CrossProtocolChainBuilder()
        result = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="dns",
        )
        self.assertIsInstance(result, Unavailable)

    def test_build_enriched_with_findings(self):
        from bugwolf.chain.builder import (
            CrossProtocolChain,
            CrossProtocolChainBuilder,
        )
        b = CrossProtocolChainBuilder()
        result = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="cloud",
            findings=[{"bug_class": "ssrf", "endpoint": "/fetch"}],
        )
        self.assertIsInstance(result, CrossProtocolChain)
        self.assertGreaterEqual(result.confidence, 0.5)

    def test_list_known_patterns(self):
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        b = CrossProtocolChainBuilder()
        pats = b.list_known_patterns()
        self.assertGreaterEqual(len(pats), 5)
        for p in pats:
            self.assertIn("source", p)
            self.assertIn("target", p)


# ===========================================================================
# CrossTargetChainBuilder
# ===========================================================================

class TestCrossTargetChainBuilder(unittest.TestCase):

    def test_build_returns_chain(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.builder import CrossTargetChain
        b = CrossTargetChainBuilder()
        result = b.build_cross_target_chain(
            primary_target="app.example.com",
            lateral_targets=("api.example.com", "admin.example.com"),
        )
        self.assertIsInstance(result, CrossTargetChain)
        self.assertEqual(result.primary_target, "app.example.com")
        self.assertEqual(len(result.lateral_targets), 2)

    def test_build_empty_primary_returns_unavailable(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.builder import Unavailable
        b = CrossTargetChainBuilder()
        result = b.build_cross_target_chain(
            primary_target="",
            lateral_targets=("a.example.com",),
        )
        self.assertIsInstance(result, Unavailable)

    def test_build_dedupes_laterals(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.builder import CrossTargetChain
        b = CrossTargetChainBuilder()
        result = b.build_cross_target_chain(
            primary_target="app.example.com",
            lateral_targets=("a.example.com", "a.example.com", "b.example.com"),
        )
        self.assertIsInstance(result, CrossTargetChain)
        self.assertEqual(len(result.lateral_targets), 2)

    def test_with_laterals_appends(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.builder import CrossTargetChain
        b = CrossTargetChainBuilder()
        chain = b.build_cross_target_chain(
            primary_target="app.example.com",
            lateral_targets=("a.example.com",),
        )
        self.assertIsInstance(chain, CrossTargetChain)
        new = b.with_laterals(chain, ("b.example.com", "c.example.com"))
        self.assertIsInstance(new, CrossTargetChain)
        self.assertEqual(len(new.lateral_targets), 3)


# ===========================================================================
# ChainValidator
# ===========================================================================

class TestChainValidator(unittest.TestCase):

    def test_valid_chain_passes(self):
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        from bugwolf.chain.validator import (
            ChainValidationResult,
            ChainValidator,
        )
        b = CrossProtocolChainBuilder()
        chain = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="cloud",
        )
        v = ChainValidator()
        result = v.validate(chain)
        self.assertIsInstance(result, ChainValidationResult)
        self.assertTrue(result.is_valid, msg=f"unexpected issues: {result.issues}")

    def test_invalid_chain_returns_issues(self):
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        from bugwolf.chain.validator import ChainValidator
        # Force an invalid chain: identical protocols so builder returns Unavailable
        b = CrossProtocolChainBuilder()
        bad = b.build_cross_protocol_chain(
            source_protocol="http", target_protocol="http"
        )
        v = ChainValidator()
        result = v.validate(bad)
        self.assertFalse(result.is_valid)
        self.assertGreater(len(result.issues), 0)

    def test_cross_target_validation(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.validator import ChainValidator
        b = CrossTargetChainBuilder()
        chain = b.build_cross_target_chain(
            primary_target="app.example.com",
            lateral_targets=("a.example.com",),
        )
        v = ChainValidator()
        result = v.validate(chain)
        self.assertTrue(result.is_valid)


# ===========================================================================
# ChainPoCGenerator
# ===========================================================================

class TestChainPoCGenerator(unittest.TestCase):

    def test_generate_poc_writes_file(self):
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        from bugwolf.chain.poc_chain import ChainPoCGenerator
        b = CrossProtocolChainBuilder()
        chain = b.build_cross_protocol_chain(
            source_protocol="http",
            target_protocol="cloud",
        )
        with tempfile.TemporaryDirectory() as tmp:
            g = ChainPoCGenerator(
                output_dir=Path(tmp),
                forbid_destructive=True,
            )
            out = g.generate_poc(chain)
            self.assertIsInstance(out, Path)
            self.assertTrue(out.exists())
            body = out.read_text(encoding="utf-8")
            self.assertIn("http", body)
            self.assertIn("cloud", body)

    def test_generate_poc_unavailable_for_invalid(self):
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        from bugwolf.chain.poc_chain import ChainPoCGenerator, PoCUnavailable
        b = CrossProtocolChainBuilder()
        bad = b.build_cross_protocol_chain(
            source_protocol="http", target_protocol="http"
        )
        with tempfile.TemporaryDirectory() as tmp:
            g = ChainPoCGenerator(
                output_dir=Path(tmp),
                forbid_destructive=True,
            )
            out = g.generate_poc(bad)
            self.assertIsInstance(out, PoCUnavailable)

    def test_markdown_render_skips_forbidden_schemes(self):
        from bugwolf.chain.builder import (
            ChainStep,
            CrossProtocolChain,
        )
        from bugwolf.chain.poc_chain import ChainPoCGenerator
        chain = CrossProtocolChain(
            chain_id="x",
            source_protocol="http",
            target_protocol="db",
            steps=(
                ChainStep(
                    order=1, description="d", protocol="http",
                    evidence={"url": "file:///etc/passwd"},
                ),
            ),
            validity=True, confidence=0.5,
        )
        with tempfile.TemporaryDirectory() as tmp:
            g = ChainPoCGenerator(output_dir=Path(tmp))
            path = g.generate_poc(chain)
            self.assertIsInstance(path, Path)
            body = path.read_text(encoding="utf-8")
            # The literal "file://" must not appear in the rendered PoC.
            self.assertNotIn("file://", body)


# ===========================================================================
# H100 YAML bundle
# ===========================================================================

class TestH100Bundle(unittest.TestCase):
    """All 12 H100 YAMLs parse and conform to the schema."""

    REQUIRED_IDS = {
        "01_oauth_to_ato",
        "02_ssrf_to_rce",
        "03_graphql_to_mass_leak",
        "04_cache_poison_xss",
        "05_http_smuggle_hijack",
        "06_credspray_to_admin",
        "07_subdomain_takeover",
        "08_idor_pii_leak",
        "09_race_double_spend",
        "10_jwt_to_admin",
        "11_supply_chain_rce",
        "12_cicd_secrets_leak",
    }

    def test_all_twelve_present(self):
        from bugwolf.chain.h100 import list_h100_yamls, get_chain_count
        n = get_chain_count()
        self.assertEqual(n, 12, f"expected 12 YAMLs, got {n}")
        paths = list_h100_yamls()
        self.assertEqual(len(paths), 12)
        ids = {p.stem for p in paths}
        self.assertEqual(ids, self.REQUIRED_IDS)

    def test_all_yamls_parse_and_conform(self):
        from bugwolf.chain.h100 import H100_SCHEMA, load_all
        for c in load_all():
            self.assertEqual(c.schema, H100_SCHEMA, msg=f"{c.id} wrong schema")
            self.assertIn(c.id, self.REQUIRED_IDS)
            self.assertTrue(c.title, f"{c.id} empty title")
            self.assertTrue(c.bounty, f"{c.id} empty bounty")
            self.assertIn(
                c.final_severity,
                ("info", "low", "medium", "high", "critical"),
                msg=f"{c.id} invalid severity",
            )

    def test_each_yaml_has_steps_and_references(self):
        from bugwolf.chain.h100 import load_all
        for c in load_all():
            with self.subTest(chain=c.id):
                self.assertGreaterEqual(
                    len(c.steps), 2,
                    msg=f"{c.id} has fewer than 2 steps",
                )
                self.assertGreaterEqual(
                    len(c.references), 1,
                    msg=f"{c.id} has no references",
                )

    def test_no_yaml_contains_file_or_gopher_payload(self):
        from bugwolf.chain.h100 import list_h100_yamls
        for p in list_h100_yamls():
            text = p.read_text(encoding="utf-8")
            # CI gate: no literal "file://" or "gopher://" payloads.
            self.assertNotIn(
                "file://", text,
                msg=f"{p.name} contains literal file:// payload",
            )
            self.assertNotIn(
                "gopher://", text,
                msg=f"{p.name} contains literal gopher:// payload",
            )


# ===========================================================================
# Shim
# ===========================================================================

class TestKillChainBridge(unittest.TestCase):

    def test_kill_chain_bridge_returns_builder(self):
        from tools.kill_chain import kill_chain_bridge
        from bugwolf.chain.builder import CrossProtocolChainBuilder
        cls = kill_chain_bridge()
        self.assertIs(cls, CrossProtocolChainBuilder)


# ===========================================================================
# Compliance
# ===========================================================================

def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


class TestCompliance(unittest.TestCase):
    """Repo-wide compliance checks for the new chain package."""

    def test_no_shell_true_in_chain_modules(self):
        targets = [
            ROOT / "bugwolf" / "chain" / "builder.py",
            ROOT / "bugwolf" / "chain" / "cross_protocol.py",
            ROOT / "bugwolf" / "chain" / "cross_target.py",
            ROOT / "bugwolf" / "chain" / "validator.py",
            ROOT / "bugwolf" / "chain" / "poc_chain.py",
            ROOT / "bugwolf" / "chain" / "__init__.py",
            ROOT / "bugwolf" / "chain" / "h100" / "__init__.py",
        ]
        for p in targets:
            text = _read_text(p)
            self.assertNotIn(
                "shell=True", text,
                msg=f"{p.name} contains shell=True",
            )

    def test_no_verify_false_in_chain_modules(self):
        targets = [
            ROOT / "bugwolf" / "chain" / "builder.py",
            ROOT / "bugwolf" / "chain" / "cross_protocol.py",
            ROOT / "bugwolf" / "chain" / "cross_target.py",
            ROOT / "bugwolf" / "chain" / "validator.py",
            ROOT / "bugwolf" / "chain" / "poc_chain.py",
            ROOT / "bugwolf" / "chain" / "__init__.py",
            ROOT / "bugwolf" / "chain" / "h100" / "__init__.py",
        ]
        for p in targets:
            text = _read_text(p)
            self.assertNotIn(
                "verify=False", text,
                msg=f"{p.name} contains verify=False",
            )

    def test_no_hardcoded_ua_in_chain_modules(self):
        # A "hardcoded UA" is a non-parameterized User-Agent string literal.
        # We accept the keyword for documentation purposes but flag any
        # assignment like `User-Agent = "..."` with a literal value.
        targets = [
            ROOT / "bugwolf" / "chain" / "builder.py",
            ROOT / "bugwolf" / "chain" / "cross_protocol.py",
            ROOT / "bugwolf" / "chain" / "cross_target.py",
            ROOT / "bugwolf" / "chain" / "validator.py",
            ROOT / "bugwolf" / "chain" / "poc_chain.py",
            ROOT / "bugwolf" / "chain" / "__init__.py",
            ROOT / "bugwolf" / "chain" / "h100" / "__init__.py",
        ]
        ua_re = re.compile(
            r"""(?ix)
            (?:User-?[Aa]gent|UA)\s*[:=]\s*["'][A-Za-z0-9./_\- ]{4,}["']
            """,
        )
        for p in targets:
            text = _read_text(p)
            m = ua_re.search(text)
            self.assertIsNone(
                m, msg=f"{p.name} contains hardcoded UA: {m.group(0) if m else ''}",
            )

    def test_every_python_file_has_source_and_license(self):
        targets = [
            ROOT / "bugwolf" / "chain" / "builder.py",
            ROOT / "bugwolf" / "chain" / "cross_protocol.py",
            ROOT / "bugwolf" / "chain" / "cross_target.py",
            ROOT / "bugwolf" / "chain" / "validator.py",
            ROOT / "bugwolf" / "chain" / "poc_chain.py",
            ROOT / "bugwolf" / "chain" / "__init__.py",
            ROOT / "bugwolf" / "chain" / "h100" / "__init__.py",
        ]
        for p in targets:
            text = _read_text(p)
            self.assertIn("## Source:", text, msg=f"{p.name} missing ## Source:")
            self.assertIn("## License:", text, msg=f"{p.name} missing ## License:")

    def test_every_yaml_has_source_and_license(self):
        from bugwolf.chain.h100 import list_h100_yamls
        for p in list_h100_yamls():
            text = _read_text(p)
            self.assertIn(
                "## Source:", text,
                msg=f"{p.name} missing ## Source:",
            )
            self.assertIn(
                "## License:", text,
                msg=f"{p.name} missing ## License:",
            )

    def test_every_yaml_meets_minimum_length(self):
        from bugwolf.chain.h100 import list_h100_yamls
        for p in list_h100_yamls():
            text = _read_text(p)
            # 50 LOC threshold.
            self.assertGreaterEqual(
                text.count("\n"), 50,
                msg=f"{p.name} shorter than 50 lines",
            )


# ===========================================================================
# Cross-module integration
# ===========================================================================

class TestIntegration(unittest.TestCase):

    def test_factory_returns_validated_chain(self):
        from bugwolf.chain.cross_protocol import build_http_to_grpc_chain
        from bugwolf.chain.validator import ChainValidator
        chain = build_http_to_grpc_chain()
        v = ChainValidator()
        result = v.validate(chain)
        self.assertTrue(result.is_valid, msg=f"{result.issues}")

    def test_cross_target_factory_end_to_end(self):
        from bugwolf.chain.cross_target import CrossTargetChainBuilder
        from bugwolf.chain.validator import ChainValidator
        from bugwolf.chain.poc_chain import ChainPoCGenerator
        b = CrossTargetChainBuilder()
        chain = b.build_cross_target_chain(
            primary_target="app.example.com",
            lateral_targets=("api.example.com", "admin.example.com"),
        )
        v = ChainValidator()
        result = v.validate(chain)
        self.assertTrue(result.is_valid)
        with tempfile.TemporaryDirectory() as tmp:
            g = ChainPoCGenerator(output_dir=Path(tmp))
            poc = g.generate_poc(chain)
            self.assertIsInstance(poc, Path)
            self.assertTrue(poc.exists())


if __name__ == "__main__":
    unittest.main()
