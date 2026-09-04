#!/usr/bin/env python3
"""BugWolf Specialized Agent Registry v1.0.0.

The registry turns BugWolf from a single-session tool orchestrator into a
multi-agent platform: every research surface gets a **specialized subagent**
whose prompt is the matching hacking-agent playbook under
``references/hacking-agents/``, loaded lazily at dispatch time and
content-digested so a tampered playbook can never ride silently into a
mission.

Design (mirrors the framework's existing contracts):

  * Declarative: agents are data (``AgentSpec``), not classes.  The registry
    validates and serves them; the *harness* executes them (Claude Code
    subagents, the team engine in ``tools/runtime/team.py``, or an operator's
    own runner).
  * Tiered: every agent declares a model-tier affinity
    (``deterministic`` / ``local_slm`` / ``frontier``) consumed by
    ``tools/core/model_router.route_unit_agent`` so a dispatch carries both
    WHO runs and WHAT model tier.
  * Scoped: every agent carries ``scope_required=True`` and
    ``sandbox_required=True``.  The scope gate
    (``tools/runtime/scope.py``) and spawn sandbox
    (``tools/runtime/sandbox.py``) hold for every agent of the team --
    the hostile-target assumption does not weaken with parallelism.
  * Fail-closed provenance: prompt digests are computed at registration and
    re-verified at load; a mismatched playbook raises ``AgentRegistryError``.
  * Never gates on model availability: the registry serves specs; tier
    degradation is the router's job, per the P1 lever contract.

Usage:
    from tools.core.agent_registry import AgentRegistry, AGENT_ROLES
    reg = AgentRegistry()
    agent = reg.select(bug_class="auth_bypass", domain="auth")
    prompt = reg.load_prompt(agent.role)          # digest-verified
    dispatch = reg.dispatch_for(bug_class="ssrf") # agent + tier + fallback

CLI:
    python3 -m tools.core.agent_registry --list --json
    python3 -m tools.core.agent_registry --agent waf-bypass --prompt
    python3 -m tools.core.agent_registry --verify
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

SCHEMA = "bugwolf-agent-registry/v1"

# Model tiers -- same vocabulary as tools/core/model_router.py.
TIER_DETERMINISTIC = "deterministic"
TIER_LOCAL = "local_slm"
TIER_FRONTIER = "frontier"
TIERS = (TIER_DETERMINISTIC, TIER_LOCAL, TIER_FRONTIER)

# Team lanes an agent can be scheduled into (tools/runtime/team.py).
LANES = ("recon", "hunt", "verify", "report")

# ---------------------------------------------------------------------------
# Agent specialization catalog
# ---------------------------------------------------------------------------
# One entry per hacking-agent playbook (references/hacking-agents/*.md) plus
# the four workflow agents every mission needs regardless of bug class
# (recon lead, verifier, chain synthesizer, report writer).
#
# Fields:
#   role              stable identifier handed to the harness as the
#                     subagent type ("bugwolf:<role>")
#   playbook          reference doc the prompt loads from
#   lanes             team lanes this agent may be scheduled into
#   domains           TASK_DOMAINS this agent covers (contracts.py)
#   bug_classes       bug classes it owns (model_router vocabulary)
#   tier_affinity     preferred model tier; the ROUTER decides, this is the
#                     agent's own preference when complexity is ambiguous
#   tools             the BugWolf modules the agent is expected to drive
#   entry             "agent" | "workflow" -- workflow agents ship in every
#                     team; entry agents are selected per lead/bug class.

@dataclass(frozen=True)
class AgentSpec:
    role: str
    title: str
    playbook: str
    lanes: Tuple[str, ...]
    domains: Tuple[str, ...]
    bug_classes: Tuple[str, ...]
    tier_affinity: str
    tools: Tuple[str, ...]
    description: str
    entry: str = "agent"
    scope_required: bool = True
    sandbox_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def harness_role(self) -> str:
        """Subagent type string the harness dispatches (OMC convention)."""
        return f"bugwolf:{self.role}"


_ENTRY_AGENTS: Tuple[Dict[str, Any], ...] = (
    dict(role="recon", title="Recon & Attack-Surface Agent",
         playbook="recon-agent.md", lanes=("recon",),
         domains=("recon", "web"), bug_classes=(),
         tier_affinity=TIER_LOCAL,
         tools=("asset_discovery", "tech_fingerprint", "surface_model",
                "schema_extractor", "js_ct_intel"),
         description="Recursive multi-source asset discovery, tech "
                     "fingerprinting, attack-surface and schema modeling.",
         entry="workflow"),
    dict(role="web-api", title="Web/API Exploitation Agent",
         playbook="web-api-agent.md", lanes=("hunt",),
         domains=("web_api", "web"), bug_classes=(
             "idor", "bola", "access_control", "ssrf", "cors",
             "information_disclosure", "misconfiguration"),
         tier_affinity=TIER_LOCAL,
         tools=("hunt", "differential_runner", "header_trust",
                "cache_traversal", "surface_model"),
         description="Endpoint-level exploitation: IDOR/BOLA, access "
                     "control, SSRF, CORS, header trust, cache behavior."),
    dict(role="access-control", title="Access-Control Agent",
         playbook="access-control-agent.md", lanes=("hunt",),
         domains=("auth", "web_api"), bug_classes=(
             "idor", "bola", "bfla", "auth_bypass", "privilege_escalation",
             "mass_assignment"),
         tier_affinity=TIER_LOCAL,
         tools=("idor_research", "runtime.mission_runner", "accounts"),
         description="Horizontal/vertical privilege boundaries: IDOR, "
                     "BFLA, mass assignment, role matrices (A/B/C)."),
    dict(role="business-logic", title="Business-Logic Agent",
         playbook="business-logic-agent.md", lanes=("hunt",),
         domains=("business_logic",), bug_classes=(
             "business_logic", "race_condition", "toctou",
             "parameter_tampering", "replay", "rounding", "arbitrage"),
         tier_affinity=TIER_FRONTIER,
         tools=("runtime.mission_runner", "leads", "observation"),
         description="Money/quantity/state TOCTOU matrices, voucher and "
                     "replay abuse, FIN-* technique ladder."),
    dict(role="waf-bypass", title="WAF-Bypass Agent",
         playbook="waf-bypass-agent.md", lanes=("hunt",),
         domains=("web", "web_api"), bug_classes=(
             "waf_bypass", "xss", "sqli", "sql_injection", "rce",
             "command_injection"),
         tier_affinity=TIER_LOCAL,
         tools=("domains.web.parser_differential", "art_selector",
                "mutator", "hunt"),
         description="Filter edge-case mining: parser differentials, "
                     "encoding and payload-splitting families, ART payload "
                     "selection."),
    dict(role="http-smuggling", title="HTTP Smuggling Agent",
         playbook="http-smuggling-agent.md", lanes=("hunt",),
         domains=("web",), bug_classes=(
             "request_smuggling", "cl_te", "te_cl", "http2_smuggling"),
         tier_affinity=TIER_LOCAL,
         tools=("domains.web.http_smuggling_detector", "hunt"),
         description="Desync probe generation and oracle confirmation "
                     "across CL.TE / TE.CL / H2 frontends."),
    dict(role="race-condition", title="Race-Condition Agent",
         playbook="race-condition-agent.md", lanes=("hunt",),
         domains=("business_logic", "web_api"), bug_classes=(
             "race_condition", "toctou", "double_submit"),
         tier_affinity=TIER_LOCAL,
         tools=("validation.race_engine", "hunt"),
         description="Single-packet and parallel-limb racing of "
                     "state-changing endpoints (scope-gated raw sockets)."),
    dict(role="cache-poisoning", title="Cache-Poisoning Agent",
         playbook="cache-poisoning-agent.md", lanes=("hunt",),
         domains=("web",), bug_classes=(
             "cache_poisoning", "web_cache_deception", "path_traversal"),
         tier_affinity=TIER_LOCAL,
         tools=("cache_traversal", "header_trust", "hunt"),
         description="Cache-key injection, unkeyed-header poisoning, "
                     "deception and traversal tracks."),
    dict(role="graphql", title="GraphQL Agent",
         playbook="graphql-agent.md", lanes=("hunt",),
         domains=("web_api",), bug_classes=(
             "graphql_introspection", "graphql_dos", "graphql_idor",
             "graphql_batch_abuse", "graphql_field_suggestion"),
         tier_affinity=TIER_LOCAL,
         tools=("graphql_gid", "domains.api.graphql_batch_analyzer",
                "graphql_workflow"),
         description="Introspection harvesting, node(id:) global-ID "
                     "abuse, batching DoS, field-suggestion mining."),
    dict(role="smart-contract", title="Smart-Contract Agent",
         playbook="smart-contract-agent.md", lanes=("hunt",),
         domains=("smart_contract",), bug_classes=(
             "reentrancy", "oracle_manipulation", "access_control_sc",
             "price_manipulation", "flash_loan", "signature_replay"),
         tier_affinity=TIER_FRONTIER,
         tools=("contract_discovery", "formal_verify",
                "domains.smart_contracts.price_manipulation_analyzer",
                "domains.smart_contracts.llm_contract_triage"),
         description="EVM state-space exploration, DeFi oracle and "
                     "price-manipulation lifecycles, exploitability triage."),
    dict(role="llm-ai", title="LLM/AI Security Agent",
         playbook="llm-ai-agent.md", lanes=("hunt",),
         domains=("llm_ai",), bug_classes=(
             "prompt_injection", "agentic_abuse", "rag_poisoning",
             "tool_abuse", "model_dos", "training_data_leak"),
         tier_affinity=TIER_FRONTIER,
         tools=("llm_attack_surface", "llm_sandbox",
                "domains.llm.agentic_tool_auth",
                "domains.llm.rag_memory_poisoning"),
         description="Prompt-injection surfaces, agentic tool-auth "
                     "matrices, RAG poisoning, sandbox escape traces."),
    dict(role="cloud-cicd", title="Cloud/CI-CD Agent",
         # No dedicated hacking-agent playbook exists for cloud; the
         # attack-vector catalog is the specialized corpus for this lane.
         playbook="../attack-vectors/cloud-vectors.md", lanes=("hunt",),
         domains=("cloud_cicd",), bug_classes=(
             "iam_privesc", "s3_misconfig", "ssrf_metadata",
             "pipeline_injection", "oidc_trust", "secrets_leak"),
         tier_affinity=TIER_LOCAL,
         tools=("domains.cloud.iam_privesc_graph", "identity_cloud",
                "supply_chain_analyzer"),
         description="IAM privilege-escalation graphs, metadata SSRF, "
                     "OIDC trust and pipeline exposure."),
    dict(role="mobile-client", title="Mobile Client Agent",
         playbook="mobile-client-agent.md", lanes=("hunt",),
         domains=("mobile",), bug_classes=(
             "deep_link_abuse", "insecure_storage", "shadow_api",
             "certificate_pinning_bypass", "ipc_exposure"),
         tier_affinity=TIER_LOCAL,
         tools=("domains.mobile.deep_link_analyzer",
                "domains.mobile.mobile_policy_checker"),
         description="Deep-link surface, manifest/plist policy, shadow "
                     "API and client-side storage analysis."),
    dict(role="credential-leak", title="Credential-Leak Agent",
         playbook="credential-leak-agent.md", lanes=("recon", "hunt"),
         domains=("recon", "web"), bug_classes=(
             "credential_leak", "token_leak", "js_secrets",
             "git_exposure", "ct_log_secrets"),
         tier_affinity=TIER_LOCAL,
         tools=("js_token_forge", "js_ct_intel", "asset_intel"),
         description="JS bundle secret mining, CT-log and history "
                     "correlation, redacted fingerprint storage."),
    dict(role="crypto-math", title="Crypto/Math Agent",
         playbook="crypto-math-agent.md", lanes=("hunt", "verify"),
         domains=("auth", "web_api"), bug_classes=(
             "jwt_attack", "length_extension", "padding_oracle",
             "weak_randomness", "signature_bypass"),
         tier_affinity=TIER_FRONTIER,
         tools=("domains.auth.jwt_forgery", "runtime.mission_runner",
                "refutation"),
         description="JWT forgery families, hash length-extension, "
                     "oracle padding, signature boundary math."),
    dict(role="browser-automation", title="Browser Automation Agent",
         playbook="browser-automation-agent.md", lanes=("hunt", "verify"),
         domains=("client_side", "web"), bug_classes=(
             "xss", "dom_clobbering", "postmessage", "client_side_sqli"),
         tier_affinity=TIER_LOCAL,
         tools=("runtime.browser_driver", "hunt"),
         description="Client-side validation through the browser driver "
                     "protocol; never fabricates without a bound driver."),
    dict(role="supply-chain", title="Supply-Chain Agent",
         playbook="supply-chain-agent.md", lanes=("hunt",),
         domains=("cloud_cicd", "web"), bug_classes=(
             "dependency_confusion", "typosquatting", "build_injection",
             "artifact_tampering"),
         tier_affinity=TIER_LOCAL,
         tools=("supply_chain_analyzer", "dependency_map", "static_bridge"),
         description="Manifest and lockfile analysis, registry "
                     "confusion, build-pipeline exposure."),
    dict(role="counter-intelligence", title="Counter-Intelligence Agent",
         playbook="counter-intelligence-agent.md", lanes=("verify",),
         domains=("verify", "recon"), bug_classes=(),
         tier_affinity=TIER_LOCAL,
         tools=("opsec", "digest_canary", "chain_of_custody"),
         description="Canary-leak checks, OPSEC posture, attribution "
                     "hygiene for the team's own footprint."),
    dict(role="temp-email", title="Disposable-Identity Agent",
         playbook="temp-email-agent.md", lanes=("hunt",),
         domains=("auth", "business_logic"), bug_classes=(
             "signup_abuse", "verification_bypass", "email_spoofing"),
         tier_affinity=TIER_LOCAL,
         tools=("leads", "accounts"),
         description="Disposable-mail verification flows and signup "
                     "abuse trails (operator-supplied identities only)."),
    dict(role="regression", title="Regression Agent",
         playbook="regression-agent.md", lanes=("verify",),
         domains=("verify",), bug_classes=(),
         tier_affinity=TIER_DETERMINISTIC,
         tools=("reproducibility", "retest_scheduler", "benchmark"),
         description="Deterministic replay of confirmed findings and "
                     "retest scheduling on scope/CVE deltas."),
    dict(role="rogue", title="Rogue-Agent Hypothesis Agent",
         playbook="rogue-agent.md", lanes=("verify",),
         domains=("chain", "llm_ai"), bug_classes=(
             "agentic_abuse", "insider_chain", "lateral_movement"),
         tier_affinity=TIER_FRONTIER,
         tools=("intelligence.chain_graph_ai", "deep_chain",
                "kill_chain"),
         description="Adversarial self-review: where would OUR pipeline "
                     "be abused? Feeds chain synthesis."),
    dict(role="threat-research", title="Threat-Research Agent",
         playbook="threat-research-agent.md", lanes=("recon", "hunt"),
         domains=("recon", "cloud_cicd", "web", "web_api"), bug_classes=(
             "cve_hunting", "version_exploit", "nuclei_lead",
             "advisory_triage"),
         tier_affinity=TIER_FRONTIER,
         tools=("intel.research_engine", "nvd_ingester", "patch_gap",
                "threat_intel", "technique_ledger"),
         description="Live CVE/advisory research per exact tech version; "
                     "compiles research packs and version-evidenced "
                     "hypotheses (the X/Medium/NVD/GitHub loop)."),
    dict(role="community-signal", title="Community-Signal Agent",
         playbook="community-signal-agent.md", lanes=("recon",),
         domains=("recon", "report"), bug_classes=(
             "bounty_pattern", "trend_intel", "technique_intel"),
         tier_affinity=TIER_LOCAL,
         tools=("intel.research_engine", "intel.technique_ledger",
                "threat_intel"),
         description="Mines Reddit/HN/X/Medium for fresh techniques and "
                     "bounty patterns; submits to the technique ledger "
                     "for operator approval before agents see them."),
    dict(role="exploit-intel", title="Exploit-Intel Agent",
         playbook="exploit-intel-agent.md", lanes=("hunt", "verify"),
         domains=("web", "web_api", "smart_contract"), bug_classes=(
             "poc_matching", "exploit_adaptation", "kev_triage"),
         tier_affinity=TIER_FRONTIER,
         tools=("intel.research_engine", "exploit_gen", "refutation",
                "observation"),
         description="Matches public PoCs to the target surface and "
                     "adapts them to canary-safe minimum-impact proofs; "
                     "KEV-listed paths get priority triage."),
    dict(role="mcp-supply-chain", title="MCP/Agentic Supply-Chain Agent",
         playbook="../attack-vectors/agentic-ai-vectors-2026.md",
         lanes=("hunt", "verify"),
         domains=("llm_ai", "cloud_cicd"), bug_classes=(
             "mcp_tool_poisoning", "mcp_rug_pull", "mcp_path_traversal",
             "agentic_supply_chain", "tool_metadata_injection",
             "ide_autoexec_rce"),
         tier_affinity=TIER_FRONTIER,
         tools=("llm_attack_surface", "llm_sandbox", "supply_chain_analyzer",
                "intel.technique_ledger"),
         description="MCP/agentic supply-chain surfaces: tool poisoning, "
                     "rug pulls, server path traversal (82% stat), missing "
                     "OAuth, IDE auto-exec chains per OWASP Agentic 2026."),
    dict(role="agentic-hijack", title="Agentic Goal-Hijack Agent",
         playbook="../attack-vectors/agentic-ai-vectors-2026.md",
         lanes=("hunt",),
         domains=("llm_ai", "web"), bug_classes=(
             "agent_goal_hijack", "indirect_prompt_injection",
             "tool_misuse", "memory_poisoning", "cross_agent_abuse",
             "system_prompt_leak"),
         tier_affinity=TIER_FRONTIER,
         tools=("llm_attack_surface", "domains.llm.agentic_tool_auth",
                "domains.llm.rag_memory_poisoning", "observation"),
         description="ASI01/02/06/07: goal hijack, web-based indirect "
                     "prompt injection (Unit42 22-technique taxonomy), "
                     "tool misuse via injected content, memory/context "
                     "poisoning, inter-agent trust abuse. Canary "
                     "instructions only."),
    dict(role="cache-attack", title="Cache-Attack Agent",
         playbook="../attack-vectors/web-cache-vectors-2026.md",
         lanes=("hunt",),
         domains=("web", "web_api"), bug_classes=(
             "cache_deception", "cache_poisoning", "cache_key_confusion",
             "h2_desync_poisoning", "cpdos"),
         tier_affinity=TIER_LOCAL,
         tools=("cache_traversal", "header_trust", "hunt",
                "runtime.browser_driver"),
         description="2026 WCD/WCP playbook: delimiter ladder (;, %3B, "
                     ".;, ..;), unkeyed-input sweeps, gadget chaining, "
                     "H2-era desync poisoning, CPDoS variants; second-"
                     "account impact verification."),
    dict(role="ato-chain", title="ATO-Chain Specialist",
         playbook="../attack-vectors/ato-chains-2026.md",
         lanes=("hunt", "verify"),
         domains=("auth", "web_api"), bug_classes=(
             "account_takeover", "oauth_fusion", "pkce_downgrade",
             "reset_poisoning", "email_verification_ato",
             "session_rotation_failure"),
         tier_affinity=TIER_FRONTIER,
         tools=("domains.auth.oauth_flow_analyzer", "domains.auth.jwt_forgery",
                "domains.auth.ato_chain_planner", "runtime.mission_runner"),
         description="2026 ATO escalation: OAuth account fusion/linking "
                     "abuse, PKCE downgrades on open client registration, "
                     "0-click reset chains, email-verification ATO "
                     "windows, token-entropy feasibility proofs."),
    dict(role="economic-security", title="Economic-Security Agent",
         playbook="economic-security-agent.md", lanes=("hunt",),
         domains=("business_logic", "cloud_cicd"), bug_classes=(
             "arbitrage", "market_manipulation", "fraud_chain",
             "abuse_economics"),
         tier_affinity=TIER_FRONTIER,
         tools=("post_finding_trigger", "impact_focus", "leads"),
         description="Abuse-economics modeling: fraud chains, incentive "
                     "boundaries, cost-of-attack analysis."),
    # -- corpus-v3 specialists (76-PDF distillation, Sept 2026) -------------
    dict(role="mfa-bypass", title="MFA-Bypass Agent",
         playbook="mfa-bypass-agent.md", lanes=("hunt", "verify"),
         domains=("auth",), bug_classes=(
             "mfa_bypass", "otp_bypass", "two_factor_bypass"),
         tier_affinity=TIER_LOCAL,
         tools=("runtime.mission_runner", "accounts", "differential_runner",
                "leads"),
         description="Second-factor flow disassembly: user-binding swap "
                     "matrix, OTP lifetime/replay, session double-spend, "
                     "2026 MFA ladder (attest-gated). AUTH-01..15."),
    dict(role="host-header", title="Host-Header Agent",
         playbook="host-header-agent.md", lanes=("hunt",),
         domains=("web",), bug_classes=(
             "host_header", "header_injection", "routing_confusion"),
         tier_affinity=TIER_LOCAL,
         tools=("header_trust", "cache_traversal", "hunt",
                "differential_runner"),
         description="Host/override/trust-header attacks: reset-link "
                     "poisoning, cache-key injection, internal trust-" 
                     "header smuggling, vhost confusion to SSRF. "
                     "INF-09..11, AUTH-17."),
    dict(role="rce-chain", title="RCE-Chain Agent",
         playbook="rce-chain-agent.md", lanes=("hunt",),
         domains=("web",), bug_classes=(
             "file_upload", "ssti", "deserialization", "lfi_to_rce",
             "image_parser_rce", "regex_validation_gap"),
         tier_affinity=TIER_FRONTIER,
         tools=("hunt", "differential_runner", "observation", "refutation"),
         description="File-processing RCE chains: upload validation "
                     "ladders, EXIF/ImageMagick parsers, PDF/export "
                     "engines, SSTI/deser canaries, dependency-confusion "
                     "pre-checks. Canary-echo proof ceiling. RCE-01..10."),
    dict(role="xml-xxe", title="XML/XXE Agent",
         playbook="xml-xxe-agent.md", lanes=("hunt",),
         domains=("web", "auth"), bug_classes=(
             "xxe", "saml", "xml_injection", "xslt_injection",
             "soap_attack"),
         tier_affinity=TIER_LOCAL,
         tools=("hunt", "differential_runner", "observation"),
         description="Every XML parser on the surface: classical/blind/" 
                     "OOB XXE via any file format, local-DTD triggers, "
                     "SAML XSW1-8 ladder, XSLT probes. XML-01..08, "
                     "AUTH-29."),
    dict(role="shadow-surface", title="Shadow-Surface Agent",
         playbook="shadow-surface-agent.md", lanes=("recon", "hunt"),
         domains=("recon",), bug_classes=(
             "surface_expansion", "staging_exposure", "takeover_candidate",
             "acquired_assets", "port_exposure"),
         tier_affinity=TIER_LOCAL,
         tools=("asset_discovery", "js_ct_intel", "asset_intel",
                "intel.research_engine"),
         description="The surfaces nobody tests: non-standard ports, "
                     "staging mirrors, unclaimed CDN CNAMEs, acquisitions, "
                     "historical endpoints. Enumerates with provenance; "
                     "never attacks. RCN-01..10."),
    dict(role="platform-misconfig", title="Platform-Misconfig Agent",
         playbook="platform-misconfig-agent.md", lanes=("hunt",),
         domains=("web",), bug_classes=(
             "platform_misconfig", "aem_exposure", "jira_exposure",
             "default_credentials", "source_disclosure"),
         tier_affinity=TIER_LOCAL,
         tools=("hunt", "differential_runner", "tech_fingerprint",
                "surface_model"),
         description="Known software, unknown defaults: AEM dispatcher "
                     "ladder, Jira/Confluence CVE census, admin-panel "
                     "bypass matrix, source/backup disclosure. PLT-01..06."),
    dict(role="webhook-logic", title="Webhook-Logic Agent",
         playbook="webhook-logic-agent.md", lanes=("hunt",),
         domains=("business_logic", "web_api"), bug_classes=(
             "webhook_abuse", "payment_logic", "entitlement_bypass",
             "replay_attack", "rounding_abuse"),
         tier_affinity=TIER_FRONTIER,
         tools=("runtime.mission_runner", "validation.race_engine",
                "leads", "observation"),
         description="Server-to-server trust: webhook signature "
                     "boundary mapping, alternative-event-type parsing "
                     "gaps, replay/race idempotency, financial parameter "
                     "matrices. LOG-01..11."),
)

# Workflow agents every mission needs (ship in every team).
_WORKFLOW_AGENTS: Tuple[Dict[str, Any], ...] = (
    dict(role="verify", title="Verification & Refutation Agent",
         playbook="shared-rules.md", lanes=("verify",),
         domains=("verify",), bug_classes=(),
         tier_affinity=TIER_FRONTIER,
         tools=("refutation", "observation", "reproducibility"),
         description="Independent refutation with strict F0.5; "
                     "CONFIRMED requires replayable proof.",
         entry="workflow"),
    dict(role="chain", title="Chain Synthesis Agent",
         playbook="chain-analysis.md", lanes=("hunt",),
         domains=("chain",), bug_classes=(),
         tier_affinity=TIER_FRONTIER,
         tools=("chain_orchestrator", "deep_chain", "intelligence.chain_graph_ai",
                "trust_map"),
         description="Cross-surface escalation assembly from confirmed "
                     "findings and open leads.",
         entry="workflow"),
    dict(role="report", title="Reporting Agent",
         playbook="judging.md", lanes=("report",),
         domains=("report",), bug_classes=(),
         tier_affinity=TIER_LOCAL,
         tools=("reporting", "sarif_export", "evidence",
                "chain_of_custody"),
         description="Report assembly with provenance, redaction, and "
                     "the zero-open-leads gate.",
         entry="workflow"),
)

# Bug classes owned by no entry agent fall back to these generalists.
_GENERALIST_BY_DOMAIN: Dict[str, str] = {
    "web_api": "web-api", "web": "web-api", "auth": "access-control",
    "business_logic": "business-logic", "smart_contract": "smart-contract",
    "cloud_cicd": "cloud-cicd", "llm_ai": "llm-ai", "mobile": "mobile-client",
    "recon": "recon", "client_side": "browser-automation",
}


class AgentRegistryError(ValueError):
    """Raised on registry misuse or playbook tampering."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


class AgentRegistry:
    """Validate, index, select, and serve the specialized agent catalog."""

    def __init__(self, *, references_dir: Optional[Path] = None) -> None:
        self._refs = Path(references_dir) if references_dir else (
            _repo_root() / "references" / "hacking-agents")
        self._agents: Dict[str, AgentSpec] = {}
        self._by_bug_class: Dict[str, List[str]] = {}
        self._by_domain: Dict[str, List[str]] = {}
        self._prompt_cache: Dict[str, str] = {}
        self._register_all()

    # -- registration -------------------------------------------------------

    def _register_all(self) -> None:
        for raw in _ENTRY_AGENTS + _WORKFLOW_AGENTS:
            spec = self._build_spec(raw)
            self._register(spec)

    def _build_spec(self, raw: Dict[str, Any]) -> AgentSpec:
        unknown_tier = raw.get("tier_affinity") not in TIERS
        if unknown_tier:
            raise AgentRegistryError(
                f"agent {raw.get('role')!r}: unknown tier "
                f"{raw.get('tier_affinity')!r}")
        spec = AgentSpec(
            role=str(raw["role"]),
            title=str(raw.get("title") or raw["role"]),
            playbook=str(raw.get("playbook") or ""),
            lanes=tuple(raw.get("lanes") or ()),
            domains=tuple(raw.get("domains") or ()),
            bug_classes=tuple(raw.get("bug_classes") or ()),
            tier_affinity=str(raw["tier_affinity"]),
            tools=tuple(raw.get("tools") or ()),
            description=str(raw.get("description") or ""),
            entry=str(raw.get("entry") or "agent"),
        )
        for lane in spec.lanes:
            if lane not in LANES:
                raise AgentRegistryError(
                    f"agent {spec.role!r}: unknown lane {lane!r}")
        return spec

    def _register(self, spec: AgentSpec) -> None:
        if spec.role in self._agents:
            raise AgentRegistryError(f"duplicate agent role {spec.role!r}")
        self._agents[spec.role] = spec
        for bug in spec.bug_classes:
            self._by_bug_class.setdefault(bug, []).append(spec.role)
        for domain in spec.domains:
            self._by_domain.setdefault(domain, []).append(spec.role)

    # -- lookups ------------------------------------------------------------

    def get(self, role: str) -> AgentSpec:
        spec = self._agents.get(str(role or "").strip())
        if spec is None:
            raise AgentRegistryError(
                f"unknown agent role {role!r}; known: {sorted(self._agents)}")
        return spec

    def all_roles(self) -> List[str]:
        return sorted(self._agents)

    def agents_for_lane(self, lane: str) -> List[AgentSpec]:
        if lane not in LANES:
            raise AgentRegistryError(f"unknown lane {lane!r}")
        return [s for s in self._agents.values() if lane in s.lanes]

    def workflow_roles(self) -> List[str]:
        return sorted(r for r, s in self._agents.items()
                      if s.entry == "workflow")

    # -- selection ----------------------------------------------------------

    def select(self, *, bug_class: str = "", domain: str = "",
               lane: str = "hunt") -> AgentSpec:
        """Deterministically pick the agent for a lead/bug class/domain.

        Order: exact bug-class ownership, then domain generalist, then any
        agent serving the domain, then the lane's workflow agent.  Ties
        resolve alphabetically by role -- selection is a pure function.
        """
        lane = lane if lane in LANES else "hunt"
        bug = str(bug_class or "").strip().lower()
        if bug:
            roles = sorted(self._by_bug_class.get(bug) or [])
            if roles:
                return self.get(roles[0])
        dom = str(domain or "").strip().lower()
        if dom:
            generalist = _GENERALIST_BY_DOMAIN.get(dom)
            if generalist and generalist in self._agents:
                return self.get(generalist)
            roles = sorted(self._by_domain.get(dom) or [])
            if roles:
                return self.get(roles[0])
        workflow_in_lane = [r for r in self.workflow_roles()
                            if lane in self.get(r).lanes]
        if workflow_in_lane:
            return self.get(sorted(workflow_in_lane)[0])
        lane_agents = sorted(s.role for s in self.agents_for_lane(lane))
        if lane_agents:
            return self.get(lane_agents[0])
        raise AgentRegistryError(f"no agent serves lane {lane!r}")

    def dispatch_for(self, *, bug_class: str = "", domain: str = "",
                     lane: str = "hunt") -> Dict[str, Any]:
        """Selection + tier routing in one dict (scheduler/model_router
        friendly): who runs, at what tier, with which fallback."""
        spec = self.select(bug_class=bug_class, domain=domain, lane=lane)
        try:
            from tools.core.model_router import route_agent_dispatch
        except ImportError:  # pragma: no cover - bundled fallback
            route_agent_dispatch = None  # type: ignore
        if route_agent_dispatch is not None:
            routing = route_agent_dispatch(
                bug_class=bug_class, domain=domain,
                affinity=spec.tier_affinity)
        else:  # pragma: no cover - defensive
            routing = {"tier": spec.tier_affinity,
                       "model_preference": "", "fallback_preference": ""}
        return {
            "schema": SCHEMA,
            "agent_role": spec.role,
            "harness_role": spec.harness_role,
            "tier": routing.get("tier", spec.tier_affinity),
            "model_preference": routing.get("model_preference", ""),
            "fallback_preference": routing.get("fallback_preference", ""),
            "lane": lane,
            "scope_required": spec.scope_required,
            "sandbox_required": spec.sandbox_required,
        }

    # -- prompts ------------------------------------------------------------

    def playbook_path(self, role: str) -> Path:
        spec = self.get(role)
        candidates = [self._refs / spec.playbook,
                      self._refs.parent / spec.playbook]
        for path in candidates:
            if spec.playbook and path.is_file():
                return path
        raise AgentRegistryError(
            f"agent {role!r}: playbook {spec.playbook!r} not found under "
            f"{self._refs} or {self._refs.parent}")

    def load_prompt(self, role: str, *, verify: bool = True) -> str:
        """Load the agent's playbook text; re-verify the digest each load."""
        if role in self._prompt_cache:
            return self._prompt_cache[role]
        text = self.playbook_path(role).read_text(encoding="utf-8")
        if verify:
            self.verify_prompt(role, text)
        self._prompt_cache[role] = text
        return text

    def prompt_digest(self, role: str) -> str:
        spec = self.get(role)
        return hashlib.sha256(
            self.playbook_path(role).read_bytes()).hexdigest()[:16]

    def verify_prompt(self, role: str, text: str) -> None:
        expected = hashlib.sha256(
            self.playbook_path(role).read_bytes()).hexdigest()[:16]
        actual = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        if actual != expected:
            raise AgentRegistryError(
                f"playbook digest mismatch for {role!r}: file changed "
                f"during mission (tamper guard)")

    # -- team composition ---------------------------------------------------

    def compose_team(self, *, domains: List[str],
                     bug_classes: Optional[List[str]] = None,
                     max_agents: int = 12) -> Dict[str, Any]:
        """Deterministic roster for a mission.

        Workflow agents always in; entry agents selected per observed bug
        class first (specialists), then per domain generalist; budget-
        capped; identical input => identical roster.
        """
        bugs = [str(b or "").strip().lower()
                for b in (bug_classes or []) if str(b or "").strip()]
        picked: Dict[str, str] = {}
        order: List[str] = []
        for role in self.workflow_roles():
            picked[role] = "workflow"
            order.append(role)
        for bug in bugs:
            try:
                spec = self.select(bug_class=bug, lane="hunt")
            except AgentRegistryError:
                continue
            if spec.role not in picked:
                picked[spec.role] = f"bug_class:{bug}"
                order.append(spec.role)
        for dom in domains or []:
            dom = str(dom or "").strip().lower()
            if not dom or dom in self._agents:
                continue
            try:
                spec = self.select(domain=dom, lane="hunt")
            except AgentRegistryError:
                continue
            if spec.role not in picked:
                picked[spec.role] = f"domain:{dom}"
                order.append(spec.role)
        roster = order[:max(1, int(max_agents))]
        return {
            "schema": SCHEMA,
            "roster": roster,
            "reasons": {r: picked[r] for r in roster},
            "agents": [self.get(r).to_dict() for r in roster],
            "harness_roles": [self.get(r).harness_role for r in roster],
            "digest": hashlib.sha256(
                json.dumps(roster, sort_keys=True).encode()).hexdigest()[:16],
        }

    def inventory(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "count": len(self._agents),
            "workflow_roles": self.workflow_roles(),
            "roles": [self._agents[r].to_dict() for r in self.all_roles()],
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="BugWolf specialized agent registry")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--agent", default="")
    ap.add_argument("--prompt", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--team", action="store_true")
    ap.add_argument("--domains", default="")
    ap.add_argument("--bugs", default="")
    ap.add_argument("--max-agents", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    reg = AgentRegistry()
    if args.verify:
        bad = []
        for role in reg.all_roles():
            try:
                reg.load_prompt(role)
            except AgentRegistryError as exc:
                bad.append(f"{role}: {exc}")
        if bad:
            print("\n".join(bad), file=sys.stderr)
            return 1
        print(f"OK {len(reg.all_roles())} agent playbooks verified")
        return 0
    if args.team:
        domains = [d for d in args.domains.split(",") if d]
        bugs = [b for b in args.bugs.split(",") if b]
        team = reg.compose_team(domains=domains, bug_classes=bugs,
                                max_agents=args.max_agents)
        print(json.dumps(team, indent=2) if args.json else
              "team: " + ", ".join(team["roster"]))
        return 0
    if args.agent:
        spec = reg.get(args.agent)
        if args.prompt:
            print(reg.load_prompt(args.agent))
        else:
            print(json.dumps(spec.to_dict(), indent=2))
        return 0
    if args.list:
        if args.json:
            print(json.dumps(reg.inventory(), indent=2))
        else:
            for role in reg.all_roles():
                spec = reg.get(role)
                marker = "*" if spec.entry == "workflow" else " "
                print(f"{marker} {spec.role:22s} {spec.tier_affinity:13s} "
                      f"{spec.title}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
