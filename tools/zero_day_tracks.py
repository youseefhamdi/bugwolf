#!/usr/bin/env python3
"""Deterministic discovery adapters for the five research surfaces.

These adapters produce hypotheses and bounded mutations. They do not perform
network calls, transactions, model calls, or device actions; callers must use
ActiveExecutionController for authorized validation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from tools.research_model import ResearchCandidate, Surface
except ImportError:
    from research_model import ResearchCandidate, Surface


@dataclass
class TrackResult:
    candidate: ResearchCandidate
    reason: str


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Chain synthesis — zero-days live at the boundaries between bug classes.
#
# A single-class hypothesis is usually a known class. A *chain* — one
# candidate's input class feeding another's sink/impact class — is where
# novelty survives dedup. Each rule maps (source classes → sink classes) to a
# chain bug class with a severity and a validation template. Synthesis is
# bounded, deterministic, and offline: it pairs the highest-severity source
# with the highest-severity sink per rule and records the component lineage.
# ---------------------------------------------------------------------------

#: (source_classes, sink_classes, chain_class, severity, validation_template)
CHAIN_RULES: Sequence[Tuple[Sequence[str], Sequence[str], str, str, str]] = (
    # Web / API
    (("cache_key_path_control", "cache_key_derived_from_request"),
     ("cache_write_sink",),
     "arbitrary_file_write_chain", "critical",
     "Request-controlled cache key reaching a write sink is an unauthenticated "
     "arbitrary file write (CVE-2026-18051 class): validate traversal escapes "
     "the cache root with a marker file, then stop — never overwrite existing "
     "artifacts."),
    (("cache_key_derived_from_request",), ("cache_key_path_control",),
     "cache_poisoning_to_path_control_chain", "high",
     "Cache keys derived from request input that also reach a path control "
     "create poisoning-to-path-control: a poisoned key can steer later "
     "requests to an attacker-chosen cache slot."),
    (("daemon_input_to_shell",), ("command_sink_on_message",),
     "unauthenticated_command_execution_chain", "critical",
     "Daemon/notification input reaching a command sink is unauthenticated "
     "command execution (CVE-2026-73570 class): validate quoting/metacharacter "
     "boundaries with a benign marker command in a lab."),
    (("graphql_global_id_enumeration", "graphql_node_id_surface"),
     ("jwt_claim_identity_reference", "client_supplied_account_header",
      "id_bearing_cookie"),
     "cross_tenant_global_id_disclosure_chain", "high",
     "A global node id lookup combined with a claim/header/cookie identity "
     "boundary can disclose objects across tenants: validate with two test "
     "accounts and owned fixture gids only."),
    (("graphql_global_id_enumeration", "graphql_node_id_surface"),
     ("authorization_boundary",),
     "object_level_authorization_bypass_chain", "high",
     "Global id resolvers bypass field-level authorization: validate each "
     "returned field against a second account's owned fixture."),
    (("client_supplied_account_header",), ("id_bearing_cookie",),
     "identity_source_confusion_chain", "high",
     "Two client-controlled identity sources (header vs cookie) can disagree; "
     "the server must derive authorization from the session, not either input."),
    (("client_supplied_account_header", "id_bearing_cookie"),
     ("authorization_boundary",),
     "input_trusted_authz_bypass_chain", "high",
     "A caller-controlled identity input defining the authorization boundary "
     "bypasses it when the server trusts the input over the session."),
    (("predictable_file_reference",), ("authorization_boundary",),
     "file_reference_authz_bypass_chain", "medium",
     "Predictable file references combined with a missing object-level check "
     "turn guessability into cross-account file disclosure."),
    (("parser_or_state_differential", "response_differential",
      "header_side_effect"), ("authorization_boundary",),
     "differential_authz_bypass_chain", "high",
     "A controlled mutation producing divergent routing/response behavior is "
     "the trigger for an authorization-boundary bypass: replay with two test "
     "accounts."),
    (("state_invariant_violation",), ("authorization_boundary",),
     "stateful_authz_bypass_chain", "high",
     "A state invariant failure on an authorized transition can desync "
     "authorization state: minimize the violating sequence and replay it as a "
     "second account."),
    # Cloud / CI-CD
    (("workflow_trust_boundary",), ("untrusted_checkout",),
     "pipeline_trust_to_checkout_chain", "critical",
     "A privileged workflow that checks out untrusted pull-request refs lets "
     "attacker content run in the privileged context (GitHub Actions class)."),
    (("untrusted_checkout",), ("remote_script_execution",),
     "checkout_to_code_execution_chain", "critical",
     "Untrusted checked-out content feeding a remote script pipe becomes code "
     "execution in the build runner."),
    (("workflow_trust_boundary",), ("remote_script_execution",),
     "pipeline_input_to_execution_chain", "critical",
     "A trust boundary accepting untrusted input that reaches a remote script "
     "pipe is pipeline code execution."),
    (("broad_workflow_identity",), ("public_network_boundary",),
     "exposed_identity_chain", "high",
     "Broad workflow identity combined with a public network boundary exposes "
     "a powerful principal to unauthenticated reachability."),
    # LLM / agentic
    (("hidden_context_exposure",), ("tool_authorization_boundary",),
     "prompt_injection_tool_abuse_chain", "critical",
     "Hidden context containing secrets that reaches tool execution is prompt "
     "injection into a privileged tool: validate tool-argument authorization "
     "independently of model output."),
    (("tool_authorization_boundary",), ("rag_tenant_isolation",),
     "agentic_cross_tenant_chain", "high",
     "Tools without independent authorization combined with retrieval that "
     "does not bind to the tenant can read and act on cross-tenant data."),
    (("rag_tenant_isolation",), ("agent_memory_integrity",),
     "memory_tenant_leak_chain", "high",
     "Tenant-unbounded retrieval feeding persistent memory writes lets one "
     "tenant's data leak into another tenant's later sessions."),
    (("mcp_trust_boundary",), ("tool_authorization_boundary",),
     "mcp_tool_authorization_chain", "high",
     "MCP tool metadata that is mutable or scope-less combined with tools that "
     "lack independent authorization is an MCP privilege boundary bypass."),
    # Mobile
    (("exported_component",), ("webview_bridge",),
     "exported_webview_chain", "critical",
     "An exported component that hosts a WebView JavaScript bridge lets another "
     "app drive the bridge from an attacker-chosen origin."),
    (("mutable_pendingintent",), ("exported_component",),
     "tap_to_component_chain", "high",
     "A mutable PendingIntent whose tap target is an exported component lets an "
     "attacker redirect the tap into a privileged surface."),
    (("mutable_pendingintent",), ("insecure_endpoint_reference",),
     "notification_hijack_to_network_chain", "high",
     "Notification-tap hijack combined with an insecure endpoint reference "
     "steers the victim's tap into a cleartext or attacker-reachable flow."),
    # Smart contracts
    (("invariant_violation",), ("execution_trace_differential",),
     "contract_state_exploit_chain", "critical",
     "An invariant-violating sequence whose execution diverges from the "
     "expected trace is a contract state exploit: minimize the sequence to a "
     "reproducer before live validation."),
)


def synthesize_chains(candidates: Iterable[ResearchCandidate], *,
                      max_chains: int = 32) -> List[ResearchCandidate]:
    """Pair candidates into bounded chained hypotheses.

    For each rule, the highest-severity source candidate is combined with the
    highest-severity sink candidate (deterministic tie-break by candidate id).
    Chain candidates record their component lineage (``chain_components``),
    the rule, and the chain severity. Duplicate (source, sink) pairs per rule
    are skipped, so re-synthesis never multiplies chains. Offline — pairing
    is template selection, not execution.
    """
    by_class: Dict[str, List[ResearchCandidate]] = {}
    for candidate in candidates:
        by_class.setdefault(candidate.bug_class, []).append(candidate)

    def best_of(classes: Sequence[str]) -> Optional[ResearchCandidate]:
        pool = []
        for cls in classes:
            pool.extend(by_class.get(cls, []))
        if not pool:
            return None
        return sorted(pool, key=lambda c: (
            _SEVERITY_RANK.get(str(c.severity).lower(), 5), c.candidate_id))[0]

    chains: List[ResearchCandidate] = []
    used_pairs: set = set()
    for source_classes, sink_classes, chain_class, severity, template in CHAIN_RULES:
        if len(chains) >= max_chains:
            break
        source = best_of(source_classes)
        sink = best_of(sink_classes)
        if source is None or sink is None or source.candidate_id == sink.candidate_id:
            continue
        pair_key = (chain_class, source.candidate_id, sink.candidate_id)
        if pair_key in used_pairs:
            continue
        used_pairs.add(pair_key)
        chains.append(_candidate(
            target=source.target,
            surface=source.surface,
            bug_class=chain_class,
            title=f"Chain: {chain_class}",
            hypothesis=(f"{source.hypothesis} → {sink.hypothesis} — {template}"),
            location=f"{source.location} → {sink.location}",
            severity=severity,
            metadata={
                "chain": True,
                "chain_components": [source.candidate_id, sink.candidate_id],
                "chain_class": chain_class,
                "source_class": source.bug_class,
                "sink_class": sink.bug_class,
                "source": source.metadata.get("source", ""),
            },
        ))
    return chains


def _candidate(target: str, surface: Surface, bug_class: str, title: str,
               hypothesis: str, *, location: str = "",
               severity: str = "info",
               metadata: Optional[Dict[str, Any]] = None) -> ResearchCandidate:
    return ResearchCandidate(
        target=target,
        surface=surface,
        bug_class=bug_class,
        title=title,
        hypothesis=hypothesis,
        location=location,
        severity=severity,
        metadata=metadata or {},
    )


class WebApiTrack:
    """Differential, static, and state-machine hypothesis generation for web/API data."""

    # Static zero-day-class hypotheses distilled from reviewed research:
    # GraphQL global node-id enumeration (HackerOne #1618347), cache/page-key
    # path traversal to arbitrary file write (CVE-2026-18051 class), daemon /
    # notification input reaching a shell sink (CVE-2026-73570 class), and the
    # common-vector object-reference surfaces (account headers, id cookies,
    # JWT claims, predictable file references). These are offline hypothesis
    # seeds only — validation requires the execution controller, scope, and
    # two test accounts.
    WEB_STATIC_PATTERNS: Sequence[Tuple[str, str, str]] = (
        (r"gid://[A-Za-z0-9_]+/[^/\s]+/\d[0-9-]*",
         "graphql_global_id_enumeration",
         "A global node id (gid://...) is passed to a GraphQL lookup; node(id:) "
         "resolves objects by id without field-level filters, so enumerable ids "
         "can leak objects across visibility boundaries (HackerOne #1618347: "
         "private program scope and report titles leaked via composite ids)."),
        (r"node\s*\(\s*id\s*:",
         "graphql_node_id_surface",
         "GraphQL node(id:) resolves any object from its global id; validate "
         "ownership/visibility checks with two cooperating test accounts."),
        (r"(?:cache|page)[ _-]?key[^\n]{0,80}(?:path|file|dir|directory|filename)",
         "cache_key_path_control",
         "A cache/page key derived from the request path flows into a "
         "filesystem path; a traversal in the key can escape the cache "
         "directory and write or overwrite files (CVE-2026-18051 class, "
         "unauthenticated arbitrary file write)."),
        (r"(?:file_put_contents|write_file|fwrite|write_cache|cache[ _-]?store)[^\n]{0,80}(?:key|path|filename|name)",
         "cache_write_sink",
         "A write sink builds its target path from a request-derived key; "
         "validate that separators and '..' cannot escape the intended root."),
        (r"(?:md5|sha1|sha256|hash)[^\n]{0,40}(?:url|path|request|key)",
         "cache_key_derived_from_request",
         "Cache keys hash request input; unhashed portions, collisions, or "
         "reversible keys can cross user/tenant cache boundaries."),
        (r"(?:notification|notify|alert|webhook|daemon|snmp)[^\n]{0,80}(?:shell|exec|system|popen|subprocess|command)",
         "daemon_input_to_shell",
         "Daemon/notification input appears to reach a shell or command sink; "
         "unsanitized input can execute commands (CVE-2026-73570 class, "
         "unauthenticated RCE via SNMP notification handling)."),
        (r"(?:exec|system|shell_exec|popen|subprocess|os\.system)[^\n]{0,60}(?:message|input|data|payload|notification)",
         "command_sink_on_message",
         "A command sink consumes message/event input; validate quoting and "
         "whether the input is attacker-controllable."),
        (r"X-Account-Id|X-User-Id|X-Tenant-Id|X-Customer-Id|X-Org-Id",
         "client_supplied_account_header",
         "A client-supplied account/tenant header defines an authorization "
         "boundary only if the server re-derives it from the session; validate "
         "with two cooperating test accounts."),
        (r"userid\s*=|tenant\s*=",
         "id_bearing_cookie",
         "An id-bearing cookie (userid/tenant) may be trusted as the acting "
         "identity; cookies are attacker-controllable input."),
        (r"\"sub\"\s*:\s*\d+|\"tenant\"\s*:\s*\d+",
         "jwt_claim_identity_reference",
         "JWT claims (sub/tenant) read from the token must be server-validated; "
         "check only the claim-validation boundary with each account's own token."),
        (r"/uploads?/|/downloads?/|/files?/",
         "predictable_file_reference",
         "Predictable file/upload reference surface; validate ownership and "
         "guessability with owned disposable files only."),
    )

    @classmethod
    def static_hypotheses(cls, target: str, text: str,
                          source: str = "") -> List[ResearchCandidate]:
        """Seed zero-day-class hypotheses from static text (source, config, docs).

        Each matched pattern becomes one ``ResearchCandidate`` located at its
        source line. Output is hypothesis-only; no request is made.
        """
        results = []
        seen = set()
        for pattern, bug_class, explanation in cls.WEB_STATIC_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue
            line_number = text[:match.start()].count("\n") + 1
            key = (bug_class, line_number)
            if key in seen:
                continue
            seen.add(key)
            results.append(_candidate(
                target, Surface.WEB_API, bug_class,
                f"Web/API zero-day hypothesis: {bug_class}",
                explanation + " Validate reachability, actor control, and impact "
                              "with two test accounts in a sandbox.",
                location=f"{source}:{line_number}",
                metadata={"pattern": pattern, "source": source,
                          "static_seed": True},
            ))
        if re.search(r"(?i)(authorization|access control|user_id)", text):
            results.append(_candidate(
                target, Surface.WEB_API, "authorization_boundary",
                "Authorization boundary requires differential validation",
                "A caller-controlled identity or object reference may be trusted "
                "across a security boundary; validate with two test accounts.",
                location=source,
                metadata={"source": source, "static_seed": True},
            ))
        return results

    @staticmethod
    def differential(target: str, location: str,
                     control: Dict[str, Any], candidate: Dict[str, Any]) -> List[ResearchCandidate]:
        results = []
        if control.get("status") != candidate.get("status"):
            results.append(_candidate(
                target, Surface.WEB_API, "parser_or_state_differential",
                "HTTP status differs under one controlled mutation",
                "A single input mutation changes routing or authorization behavior "
                "between otherwise equivalent requests.",
                location=location,
                metadata={"control": control, "candidate": candidate,
                          "difference": "status"},
            ))
        if control.get("body_hash") != candidate.get("body_hash"):
            results.append(_candidate(
                target, Surface.WEB_API, "response_differential",
                "Response body differs under one controlled mutation",
                "The mutated request reaches a materially different response path; "
                "the difference requires replay and authorization/impact validation.",
                location=location,
                metadata={"control": control, "candidate": candidate,
                          "difference": "body"},
            ))
        control_headers = set(control.get("headers", {}))
        candidate_headers = set(candidate.get("headers", {}))
        added = sorted(candidate_headers - control_headers)
        if added:
            results.append(_candidate(
                target, Surface.WEB_API, "header_side_effect",
                "Mutation introduces new response headers",
                "A controlled mutation changes response metadata, potentially exposing "
                "a security-relevant execution path or state transition.",
                location=location,
                metadata={"added_headers": added, "control": control,
                          "candidate": candidate},
            ))
        return results

    @staticmethod
    def mutation_values(value: Any, *, limit: int = 12) -> List[Any]:
        """Generate bounded, one-variable mutations for a parameter or state value."""
        values = [None, "", "0", "-1", "1", "true", "false", "null",
                  " ", "../", "UTF-8", str(value)]
        if isinstance(value, bool):
            values.extend([not value])
        elif isinstance(value, int):
            values.extend([value - 1, value + 1, 2**31 - 1, 2**31])
        elif isinstance(value, str):
            values.extend([value.upper(), value + " ", value + "\u0000"])
        unique = []
        seen = set()
        for item in values:
            key = repr(item)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique[:max(1, limit)]

    @staticmethod
    def check_invariant(target: str, location: str, before: Dict[str, Any],
                        after: Dict[str, Any], invariant: Callable[[Dict[str, Any]], bool],
                        name: str) -> Optional[ResearchCandidate]:
        """Create a candidate only when a caller-supplied invariant fails."""
        if invariant(after):
            return None
        return _candidate(
            target, Surface.WEB_API, "state_invariant_violation",
            f"State invariant failed: {name}",
            f"The controlled transition changed state from {before!r} to {after!r} "
            f"without preserving invariant {name!r}.",
            location=location,
            metadata={"invariant": name, "before": before, "after": after},
        )


class SmartContractTrack:
    """Bounded local sequence exploration for contract state/invariant checks."""

    @staticmethod
    def explore_sequences(target: str, initial_state: Dict[str, Any],
                           transitions: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
                           invariant: Callable[[Dict[str, Any]], bool],
                           invariant_name: str, *, max_depth: int = 3,
                           max_sequences: int = 128) -> List[ResearchCandidate]:
        if max_depth < 1 or max_sequences < 1:
            return []
        results = []
        visited = set()

        def walk(state: Dict[str, Any], sequence: List[str], depth: int) -> None:
            if len(results) >= max_sequences:
                return
            if not invariant(state):
                results.append(_candidate(
                    target, Surface.SMART_CONTRACT, "invariant_violation",
                    f"Contract invariant failed after {' → '.join(sequence)}",
                    f"Sequence {' → '.join(sequence)} reaches a state violating "
                    f"invariant {invariant_name!r}.",
                    location="sequence:" + ",".join(sequence),
                    metadata={"sequence": sequence, "state": state,
                              "invariant": invariant_name},
                ))
                return
            if depth >= max_depth:
                return
            for name, transition in transitions.items():
                next_state = transition(dict(state))
                marker = (tuple(sequence + [name]), repr(sorted(next_state.items())))
                if marker in visited:
                    continue
                visited.add(marker)
                walk(next_state, sequence + [name], depth + 1)

        walk(dict(initial_state), [], 0)
        return results

    @staticmethod
    def differential_trace(target: str, trace_a: Sequence[Dict[str, Any]],
                           trace_b: Sequence[Dict[str, Any]]) -> List[ResearchCandidate]:
        results = []
        for index, (left, right) in enumerate(zip(trace_a, trace_b)):
            if left != right:
                results.append(_candidate(
                    target, Surface.SMART_CONTRACT, "execution_trace_differential",
                    "Equivalent contract calls produce different traces",
                    "A controlled identity, caller, or sequence mutation changes the "
                    "execution trace and may cross an unexpected authority boundary.",
                    location=f"trace-step:{index}",
                    metadata={"trace_a": left, "trace_b": right, "index": index},
                ))
        return results


class CloudCicdTrack:
    """Static trust-boundary and workflow hypothesis generation."""

    PATTERNS: Sequence[Tuple[str, str, str]] = (
        (r"pull_request_target", "workflow_trust_boundary",
         "Workflow executes privileged context for untrusted pull-request input."),
        (r"checkout[^\n]*ref:\s*\$\{\{", "untrusted_checkout",
         "Workflow checkout ref is derived from attacker-controlled expression data."),
        (r"curl[^\n|]*\|\s*(?:ba)?sh", "remote_script_execution",
         "Build or deployment workflow pipes remote content directly into a shell."),
        (r"permissions:\s*\n(?:\s+[^\n]+\n)*\s+contents:\s*write", "broad_workflow_identity",
         "Workflow grants write identity capability that may exceed the job's need."),
        (r"0\.0\.0\.0/0", "public_network_boundary",
         "Infrastructure rule exposes a resource to the public network."),
        (r"skip[_ -]?tenant|tenant[_ -]?filter\s*:\s*false", "tenant_isolation_gap",
         "Configuration disables or bypasses an explicit tenant isolation control."),
    )

    @classmethod
    def analyze(cls, target: str, text: str, source: str = "") -> List[ResearchCandidate]:
        results = []
        for pattern, bug_class, explanation in cls.PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                results.append(_candidate(
                    target, Surface.CLOUD_CICD, bug_class,
                    f"Cloud/CI trust-boundary hypothesis: {bug_class}",
                    explanation + " Validate reachability, actor control, and impact in a sandbox.",
                    location=f"{source}:{text[:match.start()].count(chr(10)) + 1}",
                    metadata={"pattern": pattern, "source": source},
                ))
        return results


class LlmAgenticTrack:
    """Static trust-boundary checks for model, tool, RAG, and MCP artifacts."""

    PATTERNS: Sequence[Tuple[str, str, str]] = (
        (r"tools?\s*[:=]\s*\[[^\]]+\]", "tool_authorization_boundary",
         "Tool declarations require an independent authorization check before execution."),
        (r"(?:system prompt|system_message)[^\n]{0,80}(?:secret|token|password|api[_-]?key)",
         "hidden_context_exposure", "System context appears to contain sensitive material."),
        (r"(?:tenant|organization|user)[_-]?(?:id|filter)[^\n]{0,80}(?:missing|none|false)",
         "rag_tenant_isolation", "Retrieval filtering may not bind results to the requesting tenant."),
        (r"mcp|model context protocol", "mcp_trust_boundary",
         "MCP/tool metadata is present and requires origin, schema, and capability validation."),
        (r"memory\.(?:write|append)|save_memory|long[_ -]?term memory", "agent_memory_integrity",
         "Persistent agent memory writes require provenance and authorization controls."),
    )

    @classmethod
    def analyze(cls, target: str, text: str, source: str = "") -> List[ResearchCandidate]:
        results = []
        for pattern, bug_class, explanation in cls.PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                results.append(_candidate(
                    target, Surface.LLM_AGENTIC, bug_class,
                    f"LLM/agentic hypothesis: {bug_class}",
                    explanation + " Confirm with isolated fixtures and bounded tool calls.",
                    location=f"{source}:{text[:match.start()].count(chr(10)) + 1}",
                    metadata={"pattern": pattern, "source": source},
                ))
        return results


class MobileBinaryTrack:
    """Local artifact checks and bounded parser-mutation hypotheses."""

    PATTERNS: Sequence[Tuple[bytes, str, str]] = (
        (b"android:exported=\"true\"", "exported_component",
         "Manifest exposes an exported component; validate permission and intent boundaries."),
        (b"usesCleartextTraffic=\"true\"", "cleartext_transport",
         "Application permits cleartext transport; validate whether sensitive flows use it."),
        (b"addJavascriptInterface", "webview_bridge",
         "WebView JavaScript bridge is present; validate origin and object exposure."),
        (b"http://", "insecure_endpoint_reference",
         "Binary contains an HTTP endpoint reference; validate whether it carries sensitive data."),
        (b"pendingintent", "mutable_pendingintent",
         "PendingIntent usage requires FLAG_IMMUTABLE and explicit package/component "
         "targeting; a mutable or implicit PendingIntent lets another app hijack "
         "the notification tap target (notification-hijack class)."),
    )

    @classmethod
    def analyze(cls, target: str, artifact: bytes, source: str = "") -> List[ResearchCandidate]:
        results = []
        lowered = artifact.lower()
        for marker, bug_class, explanation in cls.PATTERNS:
            index = lowered.find(marker.lower())
            if index >= 0:
                results.append(_candidate(
                    target, Surface.MOBILE_BINARY, bug_class,
                    f"Mobile/binary hypothesis: {bug_class}",
                    explanation + " Reproduce against a local device/emulator fixture before live testing.",
                    location=f"{source}:offset:{index}",
                    metadata={"marker": marker.decode(errors="replace"),
                              "offset": index},
                ))
        return results

    @staticmethod
    def parser_mutations(blob: bytes, *, limit: int = 16) -> List[bytes]:
        """Generate bounded parser mutations without executing the artifact."""
        mutations = [b"", blob[:1], blob + b"\x00", blob + b"\xff",
                     blob.replace(b"/", b"//", 1)]
        return mutations[:max(1, limit)]
