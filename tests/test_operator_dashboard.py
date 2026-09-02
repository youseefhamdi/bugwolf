"""Operator dashboard: summarize candidate lifecycle and chains across targets."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.candidate_lifecycle import CandidateStatus, CandidateStore, ResearchCandidate
from tools.cross_domain import CrossDomainChain, CrossDomainCorrelator
from tools.operator_dashboard import dashboard_summary


def _candidate(domain: str, target: str, bug_class: str, severity: str,
               status: CandidateStatus, endpoint: str = "") -> ResearchCandidate:
    return ResearchCandidate(
        domain=domain,
        title=f"{bug_class} on {target}",
        target=target,
        bug_class=bug_class,
        severity=severity,
        endpoint=endpoint,
        status=status,
        behavior={"observed": f"{bug_class} behavior on {endpoint or target}"},
    )


class OperatorDashboardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store(self, target: str) -> CandidateStore:
        path = self.root / "state" / "sessions" / target / "candidates.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        return CandidateStore(path)

    def test_summary_counts_candidates_by_domain_status_severity(self) -> None:
        web = self._store("api.stub-target.local")
        web.add(_candidate("web_api", "api.stub-target.local", "bola", "high",
                           CandidateStatus.CONFIRMED, "/api/users/42"))
        web.add(_candidate("web_api", "api.stub-target.local", "mass-assignment", "medium",
                           CandidateStatus.TRIAGED, "/api/users"))
        chain = CrossDomainCorrelator("api.stub-target.local", project_root=str(self.root))
        chain.write_report([
            CrossDomainChain(chain_id="c1", target="api.stub-target.local",
                             candidate_ids=["a", "b"], domains=["web_api", "ai"],
                             shared_tokens=["/api/users"], severity="high"),
        ])
        summary = dashboard_summary(self.root)
        self.assertEqual(summary["targets"], ["api.stub-target.local"])
        self.assertEqual(summary["candidate_count"], 2)
        self.assertEqual(summary["by_domain"]["web_api"], 2)
        self.assertEqual(summary["by_status"]["confirmed"], 1)
        self.assertEqual(summary["by_status"]["triaged"], 1)
        self.assertEqual(summary["by_severity"]["high"], 1)
        self.assertEqual(summary["by_severity"]["medium"], 1)
        self.assertEqual(summary["active_count"], 1)
        self.assertEqual(summary["terminal_count"], 1)
        self.assertEqual(summary["chain_count"], 1)
        self.assertEqual(summary["corrupt_lines"], 0)

    def test_summary_is_empty_when_no_state(self) -> None:
        empty = Path(tempfile.mkdtemp()) / "nope"
        summary = dashboard_summary(empty)
        self.assertEqual(summary["targets"], [])
        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(summary["chain_count"], 0)

    def test_summary_tolerates_corrupt_candidate_lines(self) -> None:
        store_path = self.root / "state" / "sessions" / "x.local" / "candidates.jsonl"
        store_path.parent.mkdir(parents=True, exist_ok=True)
        store_path.write_text('{"schema": "bugwolf/research-candidate/v1", "domain": "web_api", "candidate_id": "ok", "status": "discovered"}\nnot-json\n', encoding="utf-8")
        summary = dashboard_summary(self.root)
        self.assertEqual(summary["candidate_count"], 1)
        self.assertEqual(summary["corrupt_lines"], 1)

    def test_summary_reports_novelty_mix_from_notes(self) -> None:
        store = self._store("ai.local")
        candidate = _candidate("ai", "ai.local", "prompt-injection", "high",
                               CandidateStatus.IMPACT_VALIDATION)
        candidate.notes.append("novelty: potentially_novel")
        store.add(candidate)
        summary = dashboard_summary(self.root)
        self.assertIn("potentially_novel", summary["by_notes"])
        self.assertEqual(summary["by_notes"]["potentially_novel"], 1)


if __name__ == "__main__":
    unittest.main()