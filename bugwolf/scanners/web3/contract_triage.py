"""Web3 / smart-contract triage scanner — shim re-export of tools.domains.smart_contracts.llm_contract_triage.

Thin adapter; the deterministic triage + LLM verification planning stays in
tools.domains.smart_contracts.
"""
from __future__ import annotations

from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding

from tools.domains.smart_contracts.llm_contract_triage import triage as _triage


SCHEMA = "bugwolf-scanner-v1"


_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class Web3ContractTriageScanner(Scanner):
    name = "web3_contract_triage"
    description = "Smart-contract vulnerability triage + LLM verification prompt planner"
    bug_class = "web3"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "candidates" in target or "contract" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        candidates = target.get("candidates") or []
        contract = target.get("contract", "")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "GET")
        if not candidates:
            return []
        report = _triage(target.get("name", "target"),
                         candidates,
                         contract=contract)
        out: List[LiveFinding] = []
        for verdict in report.verdicts:
            sev = _SEVERITY_MAP.get(verdict.exploitability, self.default_severity)
            out.append(LiveFinding(
                scanner=self.name,
                bug_class=self.bug_class,
                severity=sev,
                endpoint=endpoint,
                method=method,
                evidence=f"contract {verdict.contract} candidate {verdict.candidate_id} "
                         f"({verdict.bug_class}) score={verdict.final_score:.2f}",
                reproducer=verdict.attack_path[:160],
                remediation="Patch the contract; deploy behind an upgrade proxy with timelock; add monitoring.",
                payload_id="web3-" + verdict.bug_class + "-" + verdict.candidate_id,
                extra={"score": verdict.final_score, "markers": verdict.markers},
            ))
        return out


__all__ = ["Web3ContractTriageScanner", "export_web3_scanner"]


def export_web3_scanner():
    return Web3ContractTriageScanner()
