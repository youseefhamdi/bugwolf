#!/usr/bin/env python3
"""Phase 2.2 + 2.3 capability absorption tests.

These tests assert that the bugwolf web3, cloud, cicd, and mobile
modules are importable and that the documented contracts hold.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path("/home/ubuntu/project/bugwolf")
sys.path.insert(0, str(REPO_ROOT))

from bugwolf.web3.evm_patterns import PATTERNS as EVM_PATTERNS  # noqa: E402
from bugwolf.web3.solana_patterns import PATTERNS as SOLANA_PATTERNS  # noqa: E402
from bugwolf.web3.evm_disassembler import EVMDisassembler  # noqa: E402
from bugwolf.web3.bytecode_taint import BytecodeTaintFlow  # noqa: E402
from bugwolf.web3.slither_runner import SlitherRunner, RunnerUnavailable  # noqa: E402
from bugwolf.web3.mythril_runner import MythrilRunner  # noqa: E402
from bugwolf.web3.manticore_runner import ManticoreRunner  # noqa: E402
from bugwolf.web3.foundry_poc import FoundryPoCGenerator  # noqa: E402
from bugwolf.cloud.scanner import CloudScanner  # noqa: E402
from bugwolf.cicd.scanner import CICDScanner  # noqa: E402
from bugwolf.cicd.supply_chain import SupplyChainScanner  # noqa: E402
from bugwolf.mobile.objection_runner import ObjectionRunner  # noqa: E402
from bugwolf.mobile.apk_extractor import APKExtractor, APKExtractorUnavailable  # noqa: E402
from bugwolf.mobile.frida_scripts import (  # noqa: E402
    BYPASS_SSL_JS,
    BYPASS_ROOT_JS,
    HOOK_CRYPTO_JS,
    ENUMERATE_CLASSES_JS,
    DUMP_STRINGS_JS,
    INTERCEPT_NETWORK_JS,
    BYPASS_BIOMETRIC_JS,
    BYPASS_JAILBREAK_JS,
    DUMP_KEYCHAIN_JS,
    HOOK_NATIVE_JS,
)


class TestPhase2CapabilityAbsorption(unittest.TestCase):

    def test_all_10_web3_modules_import(self) -> None:
        import importlib

        mod_names = [
            "bugwolf.web3.evm_patterns",
            "bugwolf.web3.solana_patterns",
            "bugwolf.web3.slither_runner",
            "bugwolf.web3.mythril_runner",
            "bugwolf.web3.manticore_runner",
            "bugwolf.web3.evm_disassembler",
            "bugwolf.web3.bytecode_taint",
            "bugwolf.web3.foundry_poc",
        ]
        for name in mod_names:
            importlib.import_module(name)
        # Markdown prose files: defi_audit.md and meme_coin.md
        self.assertTrue((REPO_ROOT / "bugwolf/web3/defi_audit.md").exists())
        self.assertTrue((REPO_ROOT / "bugwolf/web3/meme_coin.md").exists())

    def test_evm_disassembler_decodes_push_add(self) -> None:
        insns = EVMDisassembler().disassemble(b"\x60\x01\x60\x02\x01")
        self.assertEqual(len(insns), 3)
        self.assertEqual(insns[0].mnemonic, "PUSH1")
        self.assertEqual(insns[0].immediate, b"\x01")
        self.assertEqual(insns[1].mnemonic, "PUSH1")
        self.assertEqual(insns[1].immediate, b"\x02")
        self.assertEqual(insns[2].mnemonic, "ADD")

    def test_slither_runner_returns_unavailable_when_missing(self) -> None:
        runner = SlitherRunner()
        if runner.is_available():
            self.skipTest("slither is on PATH — skipping unavailability assertion")
        result = runner.run("/tmp/does-not-exist")
        self.assertIsInstance(result, RunnerUnavailable)
        self.assertEqual(result.exit_code, 127)

    def test_mythril_runner_returns_unavailable_when_missing(self) -> None:
        runner = MythrilRunner()
        if runner.is_available():
            self.skipTest("myth is on PATH — skipping unavailability assertion")
        result = runner.run("/tmp/does-not-exist")
        self.assertIsInstance(result, RunnerUnavailable)
        self.assertEqual(result.exit_code, 127)

    def test_evm_patterns_has_at_least_50(self) -> None:
        self.assertGreaterEqual(len(EVM_PATTERNS), 50)

    def test_solana_patterns_has_at_least_30(self) -> None:
        self.assertGreaterEqual(len(SOLANA_PATTERNS), 30)

    def test_cloud_scanner_run_aws_returns_empty_when_prowler_missing(self) -> None:
        scanner = CloudScanner()
        if scanner.is_available():
            self.skipTest("prowler is on PATH — skipping empty-result assertion")
        self.assertEqual(scanner.run_aws(), {})

    def test_cicd_scanner_detects_expression_injection(self) -> None:
        text = (
            "name: ci\n"
            "on: [pull_request]\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ github.event.issue.title }}\n"
        )
        findings = CICDScanner().scan_workflow_yaml(text)
        categories = {f.category for f in findings}
        self.assertIn("expression-injection", categories)

    def test_supply_chain_returns_unavailable_without_api_key(self) -> None:
        scanner = SupplyChainScanner()
        for env in ("BUGWOLF_NPM_API_KEY", "BUGWOLF_PYPI_API_KEY", "BUGWOLF_RUBYGEM_API_KEY"):
            os.environ.pop(env, None)
        scanner = SupplyChainScanner()
        result = scanner.check_npm("lodash", "4.17.21")
        self.assertEqual(result.get("status"), "unavailable")

    def test_apk_extractor_unavailable_when_apktool_missing(self) -> None:
        extractor = APKExtractor()
        if extractor.is_available():
            self.skipTest("apktool / unzip on PATH — skipping unavailable assertion")
        result = extractor.extract("/tmp/does-not-exist.apk", "/tmp/out")
        self.assertIsInstance(result, APKExtractorUnavailable)

    def test_frida_bypass_ssl_script_is_non_empty_with_java_perform(self) -> None:
        self.assertGreater(len(BYPASS_SSL_JS), 200)
        self.assertIn("Java.perform", BYPASS_SSL_JS)
        # All other scripts also expose Java.perform or ObjC.available
        for js in (BYPASS_ROOT_JS, HOOK_CRYPTO_JS, ENUMERATE_CLASSES_JS,
                   DUMP_STRINGS_JS, INTERCEPT_NETWORK_JS, BYPASS_BIOMETRIC_JS):
            self.assertGreater(len(js), 50)
        for js in (BYPASS_JAILBREAK_JS, DUMP_KEYCHAIN_JS, HOOK_NATIVE_JS):
            self.assertGreater(len(js), 50)

    def test_defi_audit_and_meme_coin_exist_and_over_1kb(self) -> None:
        defi = REPO_ROOT / "bugwolf/web3/defi_audit.md"
        meme = REPO_ROOT / "bugwolf/web3/meme_coin.md"
        self.assertTrue(defi.exists())
        self.assertTrue(meme.exists())
        self.assertGreater(defi.stat().st_size, 1024)
        self.assertGreater(meme.stat().st_size, 1024)

    def test_cis_aws_markdown_count_at_least_40(self) -> None:
        aws_dir = REPO_ROOT / "bugwolf/cloud/cis/aws"
        md_files = sorted(aws_dir.glob("*.md"))
        self.assertGreaterEqual(len(md_files), 40)
        for path in md_files:
            self.assertTrue(path.read_text().startswith("# CIS AWS"))

    def test_cis_azure_markdown_count_at_least_100(self) -> None:
        azure_dir = REPO_ROOT / "bugwolf/cloud/cis/azure"
        md_files = sorted(azure_dir.glob("*.md"))
        self.assertGreaterEqual(len(md_files), 100)

    def test_bytecode_taint_trace_returns_empty_when_no_source_sink(self) -> None:
        flow = BytecodeTaintFlow(b"\x35\x55\xf1")
        result = flow.trace()
        self.assertEqual(result, [])

    def test_foundry_poc_generator_renders_reentrancy(self) -> None:
        gen = FoundryPoCGenerator()
        tpl = gen.render_reentrancy("Vault")
        self.assertIn("Vault", tpl.test_source)
        self.assertGreater(len(tpl.helper_source), 100)

    def test_supply_chain_flags_typosquat(self) -> None:
        scanner = SupplyChainScanner(
            npm_api_key="stub",
            pypi_api_key="stub",
            rubygem_api_key="stub",
        )
        result = scanner.check_npm("1odash", "4.17.21")
        self.assertEqual(result["status"], "suspicious")

    def test_cicd_scanner_handles_empty_input(self) -> None:
        scanner = CICDScanner()
        self.assertEqual(scanner.scan_workflow_yaml(None), [])
        self.assertEqual(scanner.scan_workflow_yaml(""), [])

    def test_cloud_scanner_run_azure_returns_empty_when_missing(self) -> None:
        scanner = CloudScanner()
        if scanner.is_available():
            self.skipTest("prowler on PATH — skipping empty-result assertion")
        self.assertEqual(scanner.run_azure(), {})

    def test_cloud_scanner_run_gcp_returns_empty_when_missing(self) -> None:
        scanner = CloudScanner()
        if scanner.is_available():
            self.skipTest("prowler on PATH — skipping empty-result assertion")
        self.assertEqual(scanner.run_gcp(), {})

    def test_objection_runner_is_stub_safe(self) -> None:
        runner = ObjectionRunner()
        if runner.is_available():
            self.skipTest("objection on PATH — skipping unavailability assertion")
        from bugwolf.mobile.objection_runner import ObjectionUnavailable
        result = runner.explore("com.target.app")
        self.assertIsInstance(result, ObjectionUnavailable)


if __name__ == "__main__":
    unittest.main()