"""BugWolf Phase 1.5 web3 scanners."""
from __future__ import annotations

from bugwolf.scanners.web3.contract_triage import Web3ContractTriageScanner


def all_web3_scanners():
    return [Web3ContractTriageScanner()]


__all__ = ["Web3ContractTriageScanner", "all_web3_scanners"]
