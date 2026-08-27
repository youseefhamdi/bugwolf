#!/usr/bin/env python3
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestWeb3LabFixture(unittest.TestCase):
    def test_fixture_files_exist(self):
        self.assertTrue((ROOT / "lab" / "web3" / "src" / "Vault.sol").is_file())
        self.assertTrue((ROOT / "lab" / "web3" / "test" / "Invariants.t.sol").is_file())
        self.assertTrue((ROOT / "lab" / "web3" / "foundry.toml").is_file())

    def test_manifest_declares_intentional_findings(self):
        manifest = json.loads((ROOT / "lab" / "web3" / "manifest.json").read_text())
        self.assertEqual(manifest["isolated"], True)
        self.assertEqual(manifest["disposable"], True)
        self.assertTrue(any("reentrancy" in f for f in
                            manifest["contracts"]["src/Vault.sol"]["intentional_findings"]))

    def test_fixture_sources_contain_vulnerability_markers(self):
        source = (ROOT / "lab" / "web3" / "src" / "Vault.sol").read_text()
        self.assertIn("msg.sender.call", source)
        self.assertIn("balances[msg.sender] -= amount", source)
        self.assertIn("setOracle", source)


if __name__ == "__main__":
    unittest.main()