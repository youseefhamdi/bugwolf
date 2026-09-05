#!/usr/bin/env python3
"""Canonical runtime capability truth for BugWolf mission lanes.

This registry describes what the MissionRunner can actually execute.  It is
intentionally smaller than the documentation/knowledge-base vocabulary:
planned, offline-only, or unimplemented capabilities must be reported as
blocked rather than being represented as successful no-op work.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List

SCHEMA = "bugwolf-runtime-capabilities/v1"

IMPLEMENTED = "implemented"
BLOCKED = "blocked"
OFFLINE_ONLY = "offline-only"
STATUSES = (IMPLEMENTED, BLOCKED, OFFLINE_ONLY)


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    domain: str
    status: str
    entrypoint: str
    evidence_kind: str
    limitation: str = ""
    required_inputs: tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["required_inputs"] = list(self.required_inputs)
        return value


# This is the active mission-lane contract, not a list of every planned tool.
_CAPABILITIES = (
    CapabilitySpec("mission.preflight", "preflight", IMPLEMENTED,
                    "tools.runtime.preflight", "preflight_receipt"),
    CapabilitySpec("mission.recon", "recon", IMPLEMENTED,
                    "MissionRunner._run_recon_lane", "probe"),
    CapabilitySpec("web.api", "web_api", IMPLEMENTED,
                    "MissionRunner._run_web_lane", "replay_evidence"),
    CapabilitySpec("web.generic", "web", IMPLEMENTED,
                    "MissionRunner._run_web_lane", "replay_evidence"),
    CapabilitySpec("web.auth", "auth", IMPLEMENTED,
                    "MissionRunner._run_auth_lane", "replay_evidence",
                    required_inputs=("accounts",)),
    CapabilitySpec("web.business_logic", "business_logic", IMPLEMENTED,
                    "MissionRunner._run_business_logic_lane", "replay_evidence"),
    CapabilitySpec("web.fuzz", "fuzz", IMPLEMENTED,
                    "MissionRunner._run_fuzz_lane", "replay_evidence"),
    CapabilitySpec("web.client_side", "client_side", IMPLEMENTED,
                    "MissionRunner._run_client_side_lane", "browser_evidence"),
    CapabilitySpec("web.verify", "verify", IMPLEMENTED,
                    "MissionRunner._run_verify_lane", "replay_evidence"),
    CapabilitySpec("web.report", "report", IMPLEMENTED,
                    "MissionRunner._run_report_lane", "report"),
    CapabilitySpec("web3.smart_contract", "smart_contract", IMPLEMENTED,
                    "MissionRunner._run_domain_lane", "contract_evidence"),
    CapabilitySpec("cloud.iam", "cloud_cicd", IMPLEMENTED,
                    "MissionRunner._run_domain_lane", "policy_evidence"),
    CapabilitySpec("ai.llm", "llm_ai", IMPLEMENTED,
                    "MissionRunner._run_domain_lane", "agent_evidence"),
    CapabilitySpec("mobile.analysis", "mobile", BLOCKED,
                    "", "none", "No executable mobile mission lane is wired"),
    CapabilitySpec("chain.analysis", "chain", BLOCKED,
                    "", "none", "Chain synthesis is not a MissionRunner side-effect lane"),
    CapabilitySpec("triage.analysis", "triage", BLOCKED,
                    "", "none", "Triage requires candidate lifecycle inputs not present in this lane"),
)

BY_DOMAIN = {item.domain: item for item in _CAPABILITIES}


def get(domain: str) -> CapabilitySpec | None:
    return BY_DOMAIN.get(str(domain or "").strip().lower())


def validate_domains(domains: Iterable[str]) -> List[str]:
    """Return explicit capability errors for unknown or non-executable domains."""
    issues: List[str] = []
    for domain in domains:
        spec = get(domain)
        if spec is None:
            issues.append(f"unknown runtime capability domain: {domain}")
        elif spec.status != IMPLEMENTED:
            issues.append(f"runtime capability {domain} is {spec.status}: {spec.limitation}")
    return issues


def manifest() -> Dict[str, Any]:
    return {"schema": SCHEMA, "capabilities": [item.to_dict() for item in _CAPABILITIES]}
