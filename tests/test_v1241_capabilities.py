#!/usr/bin/env python3
"""Tests for the new capability modules (v1.24.1+)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class SymexecAdapterTests(unittest.TestCase):
    def test_inventory(self):
        from tools.symexec_adapter import ENGINES, is_available
        self.assertIn("angr", ENGINES)
        self.assertIn("mythril", ENGINES)
        self.assertIn("halmos", ENGINES)
        self.assertIn("certora", ENGINES)
        # is_available returns bool
        self.assertIsInstance(is_available("klee"), bool)

    def test_spec_angr(self):
        from tools.symexec_adapter import generate_spec
        spec = generate_spec("angr", binary="/bin/ls", target_func="main")
        self.assertEqual(spec["engine"], "angr")
        self.assertIn("script", spec)
        self.assertIn("run", spec)
        self.assertIn("available", spec)

    def test_spec_mythril(self):
        from tools.symexec_adapter import generate_spec
        spec = generate_spec("mythril", target="0xabc", sol_file="V.sol")
        self.assertEqual(spec["target"], "0xabc")
        self.assertIn("myth analyze", spec["run"])

    def test_spec_halmos(self):
        from tools.symexec_adapter import generate_spec
        spec = generate_spec("halmos", contract="Vault")
        self.assertEqual(spec["contract"], "Vault")
        self.assertIn("halmos", spec["run"])

    def test_spec_unknown_engine(self):
        from tools.symexec_adapter import generate_spec
        with self.assertRaises(ValueError):
            generate_spec("not-a-real-engine")

    def test_parse_mythril_output(self):
        from tools.symexec_adapter import parse_mythril_output
        sample = json.dumps({
            "issues": [{
                "address": "0xabc",
                "function": "withdraw",
                "title": "integer overflow",
                "severity": "High",
            }]
        })
        findings = parse_mythril_output(sample)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["function"], "withdraw")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["schema"], "bugwolf-symexec/v1")

    def test_parse_mythril_empty(self):
        from tools.symexec_adapter import parse_mythril_output
        self.assertEqual(parse_mythril_output(""), [])
        self.assertEqual(parse_mythril_output("not json"), [])
        self.assertEqual(parse_mythril_output("[]"), [])


class BinaryREAdapterTests(unittest.TestCase):
    def test_inventory(self):
        from tools.binary_re_adapter import TOOLS, is_available
        self.assertIn("ghidra", TOOLS)
        self.assertIn("r2", TOOLS)
        self.assertIn("frida", TOOLS)
        self.assertIsInstance(is_available("r2"), bool)

    def test_spec_ghidra(self):
        from tools.binary_re_adapter import generate_spec
        spec = generate_spec("ghidra", binary="/bin/ls")
        self.assertIn("post_script", spec)
        self.assertIn("analyzeHeadless", spec["run"])

    def test_spec_r2(self):
        from tools.binary_re_adapter import generate_spec
        spec = generate_spec("r2", binary="/bin/ls")
        self.assertIn("aaa", spec["run"])

    def test_spec_frida(self):
        from tools.binary_re_adapter import generate_spec
        spec = generate_spec("frida", binary="test", target_func="open")
        self.assertIn("Module.findExportByName", spec["script"])

    def test_parse_objdump(self):
        from tools.binary_re_adapter import parse_objdump
        sample = """
0000000000401000 <main>:
0000000000401100 <process_request>:
0000000000401200 <.note>:
"""
        findings = parse_objdump(sample, "/bin/test")
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["function"], "main")
        self.assertEqual(findings[0]["tool"], "objdump")
        self.assertTrue(findings[0]["address"].endswith("401000"))

    def test_parse_nm(self):
        from tools.binary_re_adapter import parse_nm
        sample = "0000000000401000 T main\n0000000000401100 D my_data\n"
        findings = parse_nm(sample, "/bin/test")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["function"], "main")
        self.assertEqual(findings[0]["type"], "T")

    def test_parse_strings_sensitive(self):
        from tools.binary_re_adapter import parse_strings
        sample = "hello world\npassword=hunter2\nmy_api_key=AKIA\nnormal string"
        findings = parse_strings(sample, "/bin/test")
        # 2 sensitive strings (password, api_key/AKIA)
        self.assertGreaterEqual(len(findings), 2)
        sensitive = [f for f in findings if f["severity"] == "high"]
        self.assertGreaterEqual(len(sensitive), 1)


class OnchainExecutorTests(unittest.TestCase):
    def test_inventory(self):
        from tools.onchain_executor import CHAINS, is_anvil_available
        self.assertIn("mainnet", CHAINS)
        self.assertIn("sepolia", CHAINS)
        self.assertIn("polygon", CHAINS)
        self.assertIsInstance(is_anvil_available(), bool)

    def test_fork_config(self):
        from tools.onchain_executor import ForkConfig
        c = ForkConfig(chain="mainnet", rpc_url="http://x")
        self.assertEqual(c.chain, "mainnet")
        self.assertEqual(c.port, 8545)


class BurpBridgeTests(unittest.TestCase):
    def test_inert_when_unconfigured(self):
        from tools import burp_bridge
        import os
        # Force unconfigured
        old = os.environ.pop("BUGWOLF_BURP_URL", None)
        os.environ.pop("BURP_REST_URL", None)
        try:
            self.assertFalse(burp_bridge.is_configured())
            r = burp_bridge._request("/x")
            self.assertEqual(r["status"], "skipped")
        finally:
            if old:
                os.environ["BUGWOLF_BURP_URL"] = old


class AccountCreatorTests(unittest.TestCase):
    def test_refuses_without_confirm(self):
        from tools.account_creator import create_account
        a = create_account("acme.com", signup_url="https://acme.com/signup",
                          display_name="test user")
        self.assertEqual(a.status, "refused")
        self.assertIn("confirm", a.error.lower())

    def test_refuses_financial(self):
        from tools.account_creator import create_account
        a = create_account("chase.com", signup_url="https://chase.com/signup",
                          display_name="t", confirm=True)
        self.assertEqual(a.status, "refused")
        self.assertIn("refused", a.error.lower())

    def test_refuses_government(self):
        from tools.account_creator import create_account
        a = create_account("whitehouse.gov", signup_url="https://x.gov/signup",
                          display_name="t", confirm=True)
        self.assertEqual(a.status, "refused")

    def test_captcha_detection(self):
        from tools.account_creator import needs_captcha
        self.assertTrue(needs_captcha('<div class="h-captcha">...</div>'))
        self.assertTrue(needs_captcha('g-recaptcha src=...'))
        self.assertFalse(needs_captcha('<form>normal</form>'))


class DnsOastTests(unittest.TestCase):
    def test_default_zone(self):
        from tools.dns_oast import DEFAULT_ZONE, DEFAULT_PORT
        self.assertEqual(DEFAULT_ZONE, "bugwolf.local")
        self.assertEqual(DEFAULT_PORT, 5354)

    def test_register_deterministic(self):
        from tools.dns_oast import DnsOastListener
        with tempfile.TemporaryDirectory() as tmp:
            listener = DnsOastListener(log_path=Path(tmp) / "log.jsonl")
            a = listener.register("lead-001")
            b = listener.register("lead-001")
            # Same lead_id → same canary
            self.assertEqual(a, b)
            self.assertIn(".bugwolf.local", a)


class RegressionRunnerTests(unittest.TestCase):
    def test_unreachable_when_no_url(self):
        from tools.regression_runner import replay_finding
        r = replay_finding({"id": "f", "target": "x", "status": "confirmed"},
                           scope_check=False)
        self.assertEqual(r.current_status, "inconclusive")
        self.assertEqual(r.delta, "no-url")

    def test_schema(self):
        from tools.regression_runner import RegressionResult
        r = RegressionResult(finding_id="f1", target="t", previous_status="p",
                            current_status="present")
        d = r.to_dict()
        self.assertEqual(d["schema"], "bugwolf-regression/v1")
        self.assertEqual(d["finding_id"], "f1")
        self.assertEqual(d["current_status"], "present")


class H2RaceDispatcherTests(unittest.TestCase):
    def test_is_h2_available_returns_bool(self):
        from tools.validation.h2_race_dispatcher import is_h2_available
        self.assertIsInstance(is_h2_available(), bool)


class FuzzEngineAdditionalTests(unittest.TestCase):
    def test_all_engines_produce_minimum_3_files(self):
        """Every engine must emit at least 3 files (build/run/harness)."""
        from tools.fuzz_engine import FuzzTarget, generate, ENGINES
        for eng in ENGINES:
            lang = "solidity" if eng in ("foundry", "echidna", "medusa") else "c"
            t = FuzzTarget(name="t", engine=eng, language=lang)
            try:
                h = generate(t)
            except Exception as exc:
                self.fail(f"engine {eng} failed: {exc}")
            self.assertGreaterEqual(len(h.files), 3,
                                    f"engine {eng} produced only {len(h.files)} files")


if __name__ == "__main__":
    unittest.main()
