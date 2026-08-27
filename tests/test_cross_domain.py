#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from tools.candidate_lifecycle import ResearchCandidate
from tools.cross_domain import CrossDomainCorrelator, CrossDomainChain


def _candidate(domain, *, endpoint="", behavior=None, target="lab"):
    return ResearchCandidate(
        domain=domain, target=target, bug_class="test",
        title=f"{domain} candidate", endpoint=endpoint,
        behavior=behavior or {},
    )


class TestCrossDomainCorrelator(unittest.TestCase):
    def test_links_ai_to_web_api_via_shared_endpoint(self):
        ai = _candidate("ai", endpoint="fetch", behavior={
            "tool": "fetch", "arguments": {"url": "https://lab/api/transfer"}})
        web = _candidate("web_api", endpoint="/api/transfer")
        chains = CrossDomainCorrelator("lab").correlate([ai, web])
        self.assertEqual(len(chains), 1)
        self.assertEqual(set(chains[0].domains), {"ai", "web_api"})
        self.assertIn(ai.candidate_id, chains[0].candidate_ids)
        self.assertIn(web.candidate_id, chains[0].candidate_ids)

    def test_builds_three_domain_chain(self):
        ai = _candidate("ai", endpoint="call_api", behavior={
            "tool": "call_api", "arguments": {"url": "https://lab/api/withdraw"}})
        web = _candidate("web_api", endpoint="/api/withdraw", behavior={
            "state_after": {"contract": "Vault"}})
        web3 = _candidate("web3", endpoint="withdraw", behavior={
            "sequence": ["withdraw"], "contract": "Vault"})
        chains = CrossDomainCorrelator("lab").correlate([ai, web, web3])
        self.assertEqual(len(chains), 1)
        self.assertEqual(set(chains[0].domains), {"ai", "web_api", "web3"})

    def test_respects_max_depth_and_no_cycles(self):
        ai = _candidate("ai", endpoint="api", behavior={"arguments": {"url": "https://lab/x"}})
        web = _candidate("web_api", endpoint="/x")
        web3 = _candidate("web3", endpoint="x")
        chains = CrossDomainCorrelator("lab", max_chain_depth=2).correlate([ai, web, web3])
        self.assertLessEqual(max(len(c.candidate_ids) for c in chains), 2)

    def test_writes_chain_report_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            ai = _candidate("ai", endpoint="fetch", behavior={"arguments": {"url": "https://lab/api/x"}})
            web = _candidate("web_api", endpoint="/api/x")
            correlator = CrossDomainCorrelator("lab", project_root=tmp)
            chains = correlator.correlate([ai, web])
            report_path = correlator.write_report(chains)
            self.assertTrue(report_path.is_file())
            import json
            data = json.loads(report_path.read_text())
            self.assertEqual(len(data["chains"]), 1)


if __name__ == "__main__":
    unittest.main()