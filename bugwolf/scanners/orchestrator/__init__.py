"""Orchestrator scanners — Phase 2.1.

Orchestrators operate on a list of scanners, dispatching each one
against a target via a transport, and aggregating findings into a
single :class:`CampaignResult`.
"""

from bugwolf.scanners.orchestrator.hunt import HuntOrchestrator, CampaignResult
from bugwolf.scanners.orchestrator.spray import CredentialSpray
from bugwolf.scanners.orchestrator.zero_day_fuzzer import (
    ZeroDayFuzzerMutationEngine,
)

__all__ = [
    "HuntOrchestrator",
    "CampaignResult",
    "CredentialSpray",
    "ZeroDayFuzzerMutationEngine",
]