#!/usr/bin/env python3
"""BugWolf potentially-novel vulnerability research orchestrator.

The orchestrator performs local/static candidate generation and records the
artifacts needed for later authorized validation. It does not claim zero-days
or perform live network actions by itself.

Usage:
  python3 tools/zero_day.py --target T --surface web_api --path recon/T/urls.txt --json
  python3 tools/zero_day.py --target T --surface web_api --path recon/T/urls.txt --sequential --rounds 3 --per-round 2 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class ProbeObservation:
    """Minimal probe response shape the Phase-3 modes consume.

    Both the live executor's ``ProbeResult`` and simple dict-shaped results
    duck-type into this (``status`` / ``body`` are all the modes read), so
    the orchestrator can hand real probe results straight to these modes.
    """
    status: int = 0
    body: str = ""

try:
    from tools.art_selector import DEFAULT_FIXED_SIZE, adaptive_select
    from tools.evidence import EvidenceStore
    from tools.mutator import Mutation
    from tools.novelty import NoveltyEngine, candidate_payload
    from tools.research_model import (
        CandidateStatus, EvidenceRef, NoveltyLabel, ResearchCandidate, Surface,
    )
    from tools.zero_day_tracks import (
        CloudCicdTrack, LlmAgenticTrack, MobileBinaryTrack,
        SmartContractTrack, WebApiTrack, synthesize_chains,
    )
    from tools.research_loop import run_mandatory_research
    from tools.adaptive_learning import learn_from_journey
    from tools.stage_controller import WorkflowController, WorkflowError
except ImportError:  # direct script execution
    from art_selector import DEFAULT_FIXED_SIZE, adaptive_select
    from evidence import EvidenceStore
    from mutator import Mutation
    from novelty import NoveltyEngine, candidate_payload
    from research_model import (
        CandidateStatus, EvidenceRef, NoveltyLabel, ResearchCandidate, Surface,
    )
    from zero_day_tracks import (
        CloudCicdTrack, LlmAgenticTrack, MobileBinaryTrack,
        SmartContractTrack, WebApiTrack, synthesize_chains,
    )
    from research_loop import run_mandatory_research
    from adaptive_learning import learn_from_journey
    from stage_controller import WorkflowController, WorkflowError


NOVELTY_RANK = {
    NoveltyLabel.POTENTIALLY_NOVEL: 0,
    NoveltyLabel.NOVELTY_REVIEWED: 1,
    NoveltyLabel.UNKNOWN: 2,
    NoveltyLabel.LIKELY_VARIANT: 3,
    NoveltyLabel.EXACT_DUPLICATE: 4,
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Sequential research: deterministic refinement templates per bug class.
#
# Each entry is the *next* hypothesis a researcher should chase after the
# parent candidate is found — the second-order surface. Research results from
# the previous round attach as evidence to the derived candidates; the
# derivations themselves are bounded and offline.
# ---------------------------------------------------------------------------

#: bug_class -> ((title, hypothesis, metadata), ...)
DERIVATION_TABLE: Dict[str, Sequence[Tuple[str, str, Dict[str, Any]]]] = {
    # Web / API
    "graphql_global_id_enumeration": (
        ("Composite gid components replayed separately",
         "Replay each numeric component of a composite gid (group-id-object-id) "
         "through node(id:) independently; each axis can carry its own ownership "
         "check (HackerOne #1618347 pattern).",
         {"derivation": "composite_gid_axis_replay"}),
        ("Batch nodes(ids:) lookup on the owned gid",
         "Resolve the owned fixture gid through nodes(ids:) and compare "
         "field-level authorization against node(id:); batch resolvers sometimes "
         "skip per-object checks.",
         {"derivation": "batch_nodes_authorization"}),
        ("Field-level non-node query with the same gid",
         "Where node(id:) errors for an unauthorized session, query the same gid "
         "through a field-level resolver argument to establish a comparison "
         "baseline.",
         {"derivation": "field_level_comparison"}),
    ),
    "graphql_node_id_surface": (
        ("Gid reused as an id argument on mutations",
         "Pass the owned gid into mutation/relation id arguments; resolvers that "
         "accept raw ids may bypass node(id:) object-level checks.",
         {"derivation": "gid_in_mutation_argument"}),
        ("Sibling gid class confusion",
         "Feed a gid of one type into a resolver typed for another; type confusion "
         "can skip the expected authorization branch.",
         {"derivation": "gid_type_confusion"}),
    ),
    "cache_key_path_control": (
        ("Fully-encoded traversal in the cache key",
         "Send %2e%2e%2f (fully-encoded dots+slash); a sanitizer stripping literal "
         "'..' is bypassed when decoding happens at key-build time (CVE-2026-18051 "
         "order-of-operations class).",
         {"derivation": "encoded_dot_slash_traversal"}),
        ("Double-encoded traversal in the cache key",
         "Double-encode separators (%252e%252e%252f) and probe for a second decode "
         "pass before the path is used.",
         {"derivation": "double_encoded_traversal"}),
        ("Traversal through sibling cache roots",
         "Probe adjacent cache roots (mobile/AMP/admin variants of the key root) "
         "for the same unsanitized key construction.",
         {"derivation": "sibling_cache_root"}),
    ),
    "cache_write_sink": (
        ("Separator and encoding variants at the write sink",
         "Vary separators (/, \\, %2f, %5c, null byte) in the request-derived key "
         "component that reaches the write sink.",
         {"derivation": "sink_separator_variants"}),
        ("Symlink/.. targeting through the write sink",
         "Target an existing directory inside the cache root to test whether the "
         "sink follows '..' into a second directory.",
         {"derivation": "sink_directory_targeting"}),
    ),
    "cache_key_derived_from_request": (
        ("Collision probe across user-controlled key parts",
         "Identify which request parts feed the key hash and probe collisions or "
         "reversible keys that cross tenant cache boundaries.",
         {"derivation": "cache_key_collision"}),
        ("Unhashed suffix control",
         "Probe request-derived key suffixes appended after the hash; unhashed "
         "suffixes allow direct cache-file control.",
         {"derivation": "unhashed_suffix"}),
    ),
    "daemon_input_to_shell": (
        ("Quoting and metacharacter variants into the sink",
         "Probe quoting/separator characters (\", $(), ``, ;, |) in the "
         "daemon/notification field that reaches the shell (CVE-2026-73570 class).",
         {"derivation": "shell_metacharacter_variants"}),
        ("Indirect sink: log/queue content replayed to a command",
         "Check whether daemon input is first written to a log or queue and later "
         "consumed by a command sink; indirect flow bypasses input filters.",
         {"derivation": "indirect_command_sink"}),
    ),
    "command_sink_on_message": (
        ("Message field quoted-variable breakout",
         "Vary the message field into a quoted shell variable to test breakout "
         "across quote contexts.",
         {"derivation": "quoted_variable_breakout"}),
        ("Message length and encoding boundaries",
         "Probe truncation and encoding boundaries in the message field that "
         "could smuggle a second command past a length filter.",
         {"derivation": "message_length_smuggling"}),
    ),
    "client_supplied_account_header": (
        ("Header forwarded into nested or proxied requests",
         "Test whether the account header survives into nested/proxied requests "
         "where the server re-derives identity from a different source.",
         {"derivation": "header_forwarding"}),
        ("Header vs JWT claim mismatch",
         "Send an account header that disagrees with the JWT claim; validate "
         "which source the server trusts.",
         {"derivation": "header_claim_mismatch"}),
    ),
    "id_bearing_cookie": (
        ("Cookie vs header identity mismatch",
         "Set the id cookie and an account header to different values; observe "
         "which source binds the session's authorization.",
         {"derivation": "cookie_header_mismatch"}),
        ("Multi-value cookie injection",
         "Probe duplicate/multi-value cookie variants that parsers resolve "
         "differently from the authorization lookup.",
         {"derivation": "cookie_parser_differential"}),
    ),
    "jwt_claim_identity_reference": (
        ("Claim rotation within the same session token",
         "Rotate tenant/sub claims in the requesting account's own token and check "
         "whether the server re-derives the boundary or trusts the claim.",
         {"derivation": "claim_rotation"}),
        ("Claim-only boundary with missing object ownership",
         "Verify the claim establishes the boundary but object-level ownership is "
         "still enforced per resource (two-account flow).",
         {"derivation": "claim_ownership_gap"}),
    ),
    "predictable_file_reference": (
        ("Filename encoding and traversal variants",
         "Vary encoding (.., %2e%2e, null byte) in the predictable file reference; "
         "check path normalization before ownership lookup.",
         {"derivation": "filename_encoding"}),
        ("Owned-file boundary on adjacent references",
         "With two test accounts, replay account A's owned file reference against "
         "account B to confirm the boundary is object-level, not guessability-only.",
         {"derivation": "owned_file_boundary"}),
    ),
    "authorization_boundary": (
        ("Nested-object authorization",
         "Probe authorization on nested objects reachable through an authorized "
         "parent; ownership checks on the top object do not imply child checks.",
         {"derivation": "nested_object_authz"}),
        ("Mass-assignment role boundary",
         "Probe role/status fields accepted on creation where the default role "
         "boundary is not enforced server-side.",
         {"derivation": "mass_assignment_role"}),
    ),
    "parser_or_state_differential": (
        ("Same mutation across HTTP methods",
         "Replay the single-variable mutation across GET/POST/PUT/PATCH; routing "
         "and authz branches often differ per method.",
         {"derivation": "method_differential"}),
        ("Adjacent parameter with the same mutation",
         "Apply the same mutation to sibling parameters to find the second path "
         "with the divergent behavior.",
         {"derivation": "adjacent_parameter"}),
    ),
    "response_differential": (
        ("Response path divergence under repeated mutation",
         "Replay the differing request to confirm the divergence is stable and "
         "map which response fields differ beyond the body hash.",
         {"derivation": "divergence_replay"}),
        ("Differential across authenticated roles",
         "Replay the same controlled request as each test account to separate "
         "role-based from object-based response divergence.",
         {"derivation": "role_differential"}),
    ),
    "header_side_effect": (
        ("State transition behind the new header",
         "Probe whether the added response header indicates a state transition "
         "(set-cookie, cache, redirect) with security consequences.",
         {"derivation": "header_state_transition"}),
        ("Header mirrored into a sink",
         "Check whether the new header value is derived from request input and "
         "flows into a later sink (logging, redirect, cache key).",
         {"derivation": "header_input_reflection"}),
    ),
    "state_invariant_violation": (
        ("Longer sequence past the violation",
         "Extend the violating sequence past the invariant failure to find the "
         "first recoverable or amplifying state transition.",
         {"derivation": "sequence_extension"}),
        ("Reordered sequence variant",
         "Replay the violating transition set in a different order; order-based "
         "checks are the usual missing control.",
         {"derivation": "sequence_reorder"}),
    ),
    # Cloud / CI-CD
    "workflow_trust_boundary": (
        ("PR-label/comment-triggered privileged path",
         "Probe the privileged workflow's other triggers (labels, comments, "
         "reviews) for paths that accept untrusted content.",
         {"derivation": "pr_trigger_variants"}),
        ("Reusable workflow parameter injection",
         "Check whether the trusted workflow consumes reusable-workflow inputs "
         "that a caller-controlled workflow can set.",
         {"derivation": "reusable_workflow_params"}),
    ),
    "untrusted_checkout": (
        ("Ref expression injection",
         "Probe branch/tag names that break the checkout ref expression into a "
         "second command or path.",
         {"derivation": "ref_expression_injection"}),
        ("Artifact/cache poisoning after checkout",
         "Trace whether checked-out untrusted content later seeds caches or "
         "artifacts consumed by other jobs.",
         {"derivation": "artifact_poisoning"}),
    ),
    "remote_script_execution": (
        ("Quoted-variable breakout in the pipe",
         "Probe quoting of the piped remote content; unquoted variables let "
         "attacker content alter the command line.",
         {"derivation": "pipe_variable_breakout"}),
        ("Redirector and shortener targets",
         "Check whether the remote target is an attacker-controllable redirector "
         "that changes the executed content.",
         {"derivation": "remote_target_redirect"}),
    ),
    "broad_workflow_identity": (
        ("Scope-reduction byproduct check",
         "Identify capabilities the broad identity enables beyond the job's need "
         "and probe one capability boundary.",
         {"derivation": "capability_byproduct"}),
        ("Self-hosted runner escalation",
         "Probe whether the broad identity can schedule work on a self-hosted "
         "runner or reuse a stored secret.",
         {"derivation": "runner_escalation"}),
    ),
    "public_network_boundary": (
        ("Default-deny gap probe",
         "Enumerate the resource's access list for default-allow gaps outside the "
         "documented 0.0.0.0/0 rule.",
         {"derivation": "default_deny_gap"}),
        ("Secondary interface exposure",
         "Check adjacent interfaces (metrics, admin, debug) that share the "
         "public boundary rule.",
         {"derivation": "secondary_interface"}),
    ),
    "tenant_isolation_gap": (
        ("Filter bypass in nested jobs",
         "Probe whether the disabled tenant filter propagates into nested jobs or "
         "templates that re-enable isolation controls.",
         {"derivation": "nested_job_filter_bypass"}),
        ("Cross-tenant artifact access",
         "With the filter disabled, verify whether artifacts from one tenant are "
         "readable by another tenant's job.",
         {"derivation": "cross_tenant_artifact"}),
    ),
    # LLM / agentic
    "tool_authorization_boundary": (
        ("Indirect tool invocation via model output",
         "Probe whether attacker-influenced content can cause the model to invoke "
         "the tool with attacker-chosen arguments.",
         {"derivation": "indirect_tool_invocation"}),
        ("Over-permissioned tool arguments",
         "Probe tool arguments that accept paths/ids beyond the caller's "
         "authorization boundary.",
         {"derivation": "tool_argument_overreach"}),
    ),
    "hidden_context_exposure": (
        ("Context exfiltration through model output",
         "Probe whether hidden context material can be reflected into model output "
         "(summarization, tool calls, error messages).",
         {"derivation": "context_exfiltration"}),
        ("RAG chunk boundary crossing",
         "Probe retrieval chunking that splits hidden context across tenant "
         "boundaries.",
         {"derivation": "rag_chunk_boundary"}),
    ),
    "rag_tenant_isolation": (
        ("Filter bypass terms",
         "Probe retrieval filter bypass terms (negation, wildcard, case variants) "
         "that return cross-tenant chunks.",
         {"derivation": "rag_filter_bypass"}),
        ("Cross-tenant chunk retrieval replay",
         "Replay account A's retrieval query against account B and compare chunk "
         "sets for tenant leakage.",
         {"derivation": "rag_cross_tenant_replay"}),
    ),
    "mcp_trust_boundary": (
        ("MCP OAuth scope boundary",
         "Probe whether the MCP server's OAuth scopes bound tool actions to the "
         "requesting session's tenant.",
         {"derivation": "mcp_oauth_scope"}),
        ("Tool discovery poisoning",
         "Probe whether tool/schema metadata is mutable by a lower-privilege "
         "caller and changes subsequent authorization decisions.",
         {"derivation": "mcp_tool_discovery"}),
    ),
    "agent_memory_integrity": (
        ("Memory poisoning via user input",
         "Probe whether attacker-influenced user content can be written into "
         "persistent memory and later retrieved across sessions.",
         {"derivation": "memory_poisoning"}),
        ("Cross-tenant memory retention",
         "Verify that memory writes are bound to the writing tenant and cannot be "
         "retrieved by another tenant.",
         {"derivation": "memory_tenant_boundary"}),
    ),
    # Mobile
    "exported_component": (
        ("Intent extra injection into the exported component",
         "Probe intent extras/URIs into the exported component to find sinks that "
         "accept attacker-controlled data.",
         {"derivation": "intent_extra_injection"}),
        ("Permission bypass via implicit intent",
         "Probe implicit intent resolution to a second exported component that "
         "skips the declared permission.",
         {"derivation": "implicit_intent_permission_bypass"}),
    ),
    "cleartext_transport": (
        ("Downgrade probe",
         "Probe whether the sensitive flow can be downgraded to the cleartext "
         "endpoint by a network position.",
         {"derivation": "transport_downgrade"}),
        ("Interception of auth material",
         "Check whether authentication material transits the cleartext endpoint "
         "in headers or body.",
         {"derivation": "auth_over_cleartext"}),
    ),
    "webview_bridge": (
        ("Bridge origin and object exposure",
         "Probe which origins can reach the bridge and which objects/methods are "
         "exposed without a filter.",
         {"derivation": "bridge_origin_exposure"}),
        ("File access via bridge methods",
         "Probe bridge methods that expose file/URI access to a compromised or "
         "remote origin.",
         {"derivation": "bridge_file_access"}),
    ),
    "insecure_endpoint_reference": (
        ("Reference chaining from the insecure endpoint",
         "Trace what the insecure endpoint reference can reach (login, token, "
         "admin) and whether it carries sensitive data.",
         {"derivation": "insecure_reference_chain"}),
        ("Redirect-to-HTTPS enforcement",
         "Probe whether a network position can force the flow to the insecure "
         "endpoint despite HTTPS defaults.",
         {"derivation": "insecure_redirect"}),
    ),
    "mutable_pendingintent": (
        ("Notification tap hijack via implicit PendingIntent",
         "Probe PendingIntent flags and component targeting; a mutable/implicit "
         "PendingIntent lets another app hijack the notification tap target.",
         {"derivation": "pendingintent_hijack"}),
        ("Extra-based escalation through the tap",
         "Probe extras carried by the PendingIntent for attacker-controlled values "
         "that escalate on tap.",
         {"derivation": "pendingintent_extra_escalation"}),
    ),
    # Smart contracts
    "invariant_violation": (
        ("Shorter minimal reproducer",
         "Minimize the violating sequence to the shortest prefix that still "
         "violates the invariant (deterministic BFS over transitions).",
         {"derivation": "minimal_reproducer"}),
        ("Reentrancy ordering variant",
         "Replay the violating transition under reentrant call ordering to test "
         "checks-effects-interactions discipline.",
         {"derivation": "reentrancy_ordering"}),
    ),
    "execution_trace_differential": (
        ("Caller identity mutation",
         "Mutate the caller identity for the divergent trace step; authority "
         "boundaries are the usual differential axis.",
         {"derivation": "caller_identity_mutation"}),
        ("Sequence prefix extension",
         "Extend the divergent trace with follow-on transitions to measure the "
         "impact boundary of the differential.",
         {"derivation": "trace_prefix_extension"}),
    ),
}

#: Generic fallback when a bug class has no specific refinement table.
_GENERIC_DERIVATIONS: Sequence[Tuple[str, str, Dict[str, Any]]] = (
    ("Adjacent boundary variant",
     "Probe the same hypothesis on the adjacent boundary: sibling location, "
     "role, or state axis with one controlled variable.",
     {"derivation": "adjacent_boundary_variant"}),
    ("Chained-surface variant",
     "Chain this hypothesis into the neighboring surface (auth -> state, "
     "input -> sink) and re-derive the impact boundary.",
     {"derivation": "chained_surface"}),
)


def derive_refinements(parent: ResearchCandidate, *, round_number: int,
                       research_sources: Sequence[str] = ()) -> List[ResearchCandidate]:
    """Second-order hypotheses a researcher should probe after a candidate.

    Deterministic per bug class. Each derived candidate records its lineage
    (``derived_from`` + ``round``), a ``derivation_lineage`` that skips
    templates already explored on this chain (no self-refinement no-ops), and
    any research sources from the previous round. The derived hypothesis
    carries the parent's candidate id so every lineage has a unique identity
    (``stable_id`` excludes the title) and re-derivations of the same template
    from different parents deduplicate correctly. Offline — derivation is
    template selection, not execution.
    """
    templates = DERIVATION_TABLE.get(parent.bug_class) or _GENERIC_DERIVATIONS
    explored = list(parent.metadata.get("derivation_lineage") or [])
    parent_lineage = explored + [parent.metadata.get("derivation")] \
        if parent.metadata.get("derivation") else explored
    derived: List[ResearchCandidate] = []
    for title, hypothesis, meta in templates:
        derivation = meta.get("derivation", "")
        if derivation and derivation in parent_lineage:
            continue  # already probed on this chain; move to a new angle
        lineage = parent_lineage + ([derivation] if derivation else [])
        metadata: Dict[str, Any] = {
            "derived_from": parent.candidate_id,
            "round": round_number,
            "source": parent.metadata.get("source", ""),
            "static_seed": False,
            "derivation_lineage": lineage,
        }
        metadata.update(meta)
        if research_sources:
            metadata["research_sources"] = sorted(set(research_sources))
        derived.append(ResearchCandidate(
            target=parent.target,
            surface=parent.surface,
            bug_class=parent.bug_class,
            title=f"[r{round_number}] {title}",
            hypothesis=f"{hypothesis} (derived from candidate {parent.candidate_id})",
            location=parent.location,
            severity=parent.severity,
            confidence=round(parent.confidence * 0.8, 4),
            metadata=metadata,
        ))
    return derived


def _research_sources(results: Sequence[Dict[str, Any]]) -> List[str]:
    """Flatten injected research results into reference strings."""
    sources: List[str] = []
    for item in results:
        if not item.get("ok"):
            continue
        result = item.get("result")
        if isinstance(result, dict):
            url = result.get("url") or result.get("link") or ""
            title = result.get("title") or ""
            if url:
                sources.append(f"{title} {url}".strip())
            elif title:
                sources.append(title)
        elif isinstance(result, str) and result.strip():
            sources.append(result.strip())
    return sources


class ZeroDayResearchEngine:
    """Coordinate candidate generation and evidence/novelty persistence."""

    def __init__(self, target: str):
        self.target = target
        self.evidence = EvidenceStore(target)
        self.novelty = NoveltyEngine(target)

    def prioritize(self, candidates: Iterable[ResearchCandidate], *,
                   k: Optional[int] = None,
                   spread: bool = False) -> List[ResearchCandidate]:
        """Rank candidates for validation: potentially-novel and severe first.

        With ``spread=True`` the payload-bearing candidates (those carrying a
        concrete trigger value) are ordered with ART4SQLi farthest-first
        selection over their token space, so the validation budget samples
        distinct input regions instead of re-testing near-duplicate triggers
        (the rare-cluster intuition from ART4SQLi: effective bugs cluster in
        token space, so spread maximizes the chance of landing in one).
        Non-payload candidates follow in the same ranking. Deterministic.
        """
        ranked = sorted(
            candidates,
            key=lambda c: (
                NOVELTY_RANK.get(c.novelty, 5),
                SEVERITY_RANK.get(str(c.severity).lower(), 5),
                -c.confidence,
                c.created_at,
            ),
        )
        if not spread:
            return ranked[:k] if k is not None else ranked

        payload_candidates = [c for c in ranked if candidate_payload(c)]
        others = [c for c in ranked if not candidate_payload(c)]
        budget = k if k is not None else len(payload_candidates)
        if len(payload_candidates) < 2 or budget <= 0:
            result = ranked
        else:
            by_id = {}
            mutations = []
            for candidate in payload_candidates:
                mutation = Mutation(
                    mutation_id=candidate.candidate_id,
                    operation_id=candidate.target,
                    method="GET",
                    path=candidate.location or "/",
                    kind="injection",
                    variable="",
                    mutated=candidate_payload(candidate),
                    bug_class=candidate.bug_class,
                    risk="read",
                )
                by_id[mutation.mutation_id] = candidate
                mutations.append(mutation)
            selected = adaptive_select(mutations, budget,
                                       fixed_size=DEFAULT_FIXED_SIZE)
            result = [by_id[m.mutation_id] for m in selected] + others
        return result[:k] if k is not None else result

    def chain_candidates(self, candidates: Iterable[ResearchCandidate], *,
                         max_chains: int = 32) -> List[ResearchCandidate]:
        """Synthesize chained hypotheses from the candidate pool.

        Chains pair an input-class candidate with a sink/impact-class candidate
        per the causality table (:func:`zero_day_tracks.synthesize_chains`),
        register them through the normal novelty dedup, and return the kept
        (non-duplicate) chains. Chain hypotheses carry their component
        lineage, so duplicates across re-runs are caught.
        """
        registered = self.register(synthesize_chains(candidates, max_chains=max_chains))
        return [c for c in registered
                if c.novelty != NoveltyLabel.EXACT_DUPLICATE]

    def sequential_research(
        self,
        candidates: Iterable[ResearchCandidate],
        researchers: Optional[Dict[str, Any]] = None,
        *,
        max_rounds: int = 3,
        per_round: int = 4,
        max_candidates: int = 64,
        max_chains: int = 32,
        spread: bool = True,
    ) -> Dict[str, Any]:
        """Run zero-day research **sequentially**: round over round.

        Round 0 registers the input candidates. Each later round:

        1. takes the top ``per_round`` candidates from the previous round's
           kept output (novelty/severity ranked, spread across payload token
           space);
        2. runs the injected research adapters on each (offline when none are
           injected) and collects their sources;
        3. derives bounded second-order hypotheses per bug class
           (:func:`derive_refinements`), registers them (novelty dedup against
           the whole history), and keeps only non-duplicate candidates;
        4. stops when a round yields nothing new, ``max_rounds`` is reached,
           or ``max_candidates`` bounds the total.

        After the rounds converge, chained hypotheses are synthesized from the
        whole kept pool (``chain_candidates``) so input-class findings are
        paired with their sink/impact classes — chains carry the severity.

        Every round is deterministic and offline; research adapters are
        responsible for their own network authorization. The returned dict
        carries the round log, the chain count, and the final kept candidates.
        """
        registered = self.register(candidates)
        kept = [c for c in registered if c.novelty != NoveltyLabel.EXACT_DUPLICATE]
        rounds_log: List[Dict[str, Any]] = [{"round": 0, "kept": len(kept)}]
        lineage = kept
        for round_number in range(1, max_rounds + 1):
            focus = [c for c in self.prioritize(lineage, k=per_round, spread=spread)
                     if c.novelty != NoveltyLabel.EXACT_DUPLICATE]
            if not focus:
                break
            derived: List[ResearchCandidate] = []
            for parent in focus:
                research_results: List[Dict[str, Any]] = []
                if researchers:
                    research_results = self.research_candidate(parent, researchers)
                derived.extend(derive_refinements(
                    parent, round_number=round_number,
                    research_sources=_research_sources(research_results)))
            if not derived:
                break
            registered_derived = self.register(derived)
            kept_derived = [c for c in registered_derived
                            if c.novelty != NoveltyLabel.EXACT_DUPLICATE]
            rounds_log.append({
                "round": round_number,
                "sources": len(focus),
                "derived": len(derived),
                "kept": len(kept_derived),
            })
            if not kept_derived:
                break
            # The budget caps the total pool, not the start of a round.
            room = max_candidates - len(kept)
            if room <= 0:
                break
            if len(kept_derived) > room:
                kept_derived = kept_derived[:room]
            kept.extend(kept_derived)
            lineage = kept_derived
        chains = self.chain_candidates(kept, max_chains=max_chains)
        kept.extend(chains)
        return {"rounds": rounds_log, "candidates": kept,
                "rounds_count": len(rounds_log), "chains": len(chains)}

    def register(self, candidates: Iterable[ResearchCandidate]) -> List[ResearchCandidate]:
        registered = []
        for candidate in candidates:
            evidence = self.evidence.add(
                "hypothesis",
                {
                    "candidate_id": candidate.candidate_id,
                    "surface": candidate.surface.value,
                    "bug_class": candidate.bug_class,
                    "hypothesis": candidate.hypothesis,
                    "location": candidate.location,
                    "metadata": candidate.metadata,
                },
                metadata={"candidate_id": candidate.candidate_id},
            )
            candidate.add_evidence(EvidenceRef(
                evidence_id=evidence.evidence_id,
                kind=evidence.kind,
                sha256=evidence.sha256,
                path=evidence.path,
                note=evidence.metadata.get("candidate_id", ""),
            ))
            assessment = self.novelty.assess(candidate)
            registered.append(self.novelty.apply(candidate, assessment))
        return registered

    def record_stage(self, candidate: ResearchCandidate,
                     status: CandidateStatus | str,
                     payload: Dict[str, Any], *,
                     kind: str = "stage") -> ResearchCandidate:
        """Persist stage evidence and apply one validated lifecycle transition."""
        evidence = self.evidence.add(kind, payload,
                                     metadata={"candidate_id": candidate.candidate_id,
                                               "status": str(status)})
        candidate.add_evidence(EvidenceRef(
            evidence_id=evidence.evidence_id,
            kind=evidence.kind,
            sha256=evidence.sha256,
            path=evidence.path,
        ))
        candidate.transition(status, reason=f"recorded {kind} evidence")
        return candidate

    def research_candidate(self, candidate: ResearchCandidate,
                           researchers: Dict[str, Any], *,
                           max_workers: int = 4) -> List[Dict[str, Any]]:
        """Run injected research adapters sequentially in stable order.

        ``max_workers`` remains accepted for API compatibility but is
        intentionally ignored: research context must be consumed in order.
        """
        return self.novelty.research_sequential(candidate, researchers)

    def analyze_text(self, surface: Surface | str, text: str,
                     source: str = "") -> List[ResearchCandidate]:
        surface = Surface(surface)
        if surface == Surface.WEB_API:
            return WebApiTrack.static_hypotheses(self.target, text, source)
        if surface == Surface.CLOUD_CICD:
            return CloudCicdTrack.analyze(self.target, text, source)
        if surface == Surface.LLM_AGENTIC:
            return LlmAgenticTrack.analyze(self.target, text, source)
        raise ValueError(f"text analysis is not supported for surface {surface.value}")

    def analyze_binary(self, data: bytes, source: str = "") -> List[ResearchCandidate]:
        return MobileBinaryTrack.analyze(self.target, data, source)

    def analyze_contract_sequences(
        self,
        initial_state: Dict[str, Any],
        transitions: Dict[str, Any],
        invariant: Any,
        invariant_name: str,
        *,
        max_depth: int = 3,
    ) -> List[ResearchCandidate]:
        return SmartContractTrack.explore_sequences(
            self.target, initial_state, transitions, invariant,
            invariant_name, max_depth=max_depth,
        )

    # ------------------------------------------------------------------
    # Phase 3: novel-class hunting (beyond the fixed bug-class templates)
    # ------------------------------------------------------------------

    def diff_analysis_mode(
        self,
        snapshots: Sequence[Dict[str, Any]],
        *,
        probe: Optional[Callable[[str], ProbeObservation]] = None,
        project_root: Optional[str] = None,
    ) -> List[ResearchCandidate]:
        """Compare the same endpoint across two points (versions/snapshots)
        and turn *divergent behavior* into hypotheses.

        Each snapshot carries the endpoint + its recorded response; when two
        snapshots of the same endpoint disagree on status/body shape, the
        divergence is a candidate (a behavior delta is where novel bugs live
        — a new code path, a changed authz decision, a dropped header). If
        ``probe`` is supplied, each snapshot's endpoint is re-probed live
        (Phase 3 integration) instead of trusting the recorded body.
        """
        by_endpoint: Dict[str, List[Dict[str, Any]]] = {}
        for snap in snapshots:
            endpoint = str(snap.get("endpoint") or "").strip()
            if not endpoint:
                continue
            by_endpoint.setdefault(endpoint, []).append(snap)
        def _body(item: Dict[str, Any]) -> str:
            return str(item.get("body") or item.get("response_body") or "").strip()

        candidates: List[ResearchCandidate] = []
        for endpoint, group in by_endpoint.items():
            if len(group) < 2:
                continue
            first, second = group[0], group[1]
            if probe is not None:
                # Phase 3: re-probe the endpoint live; compare the recorded
                # (v1) snapshot against current behavior (v2 = "now").
                try:
                    live = probe(endpoint)
                    second = {
                        "status": int(getattr(live, "status", 0)),
                        "body": getattr(live, "body", None)
                        or getattr(live, "response_body", ""),
                    }
                except Exception:
                    continue
            s1 = int(first.get("status") or 0)
            s2 = int(second.get("status") or 0)
            b1 = _body(first)
            b2 = _body(second)
            divergent = (s1 != s2) or (b1 and b2 and b1 != b2)
            if not divergent:
                continue
            candidates.append(ResearchCandidate(
                target=self.target,
                surface=Surface.WEB_API,
                bug_class="behavior_differential",
                title=f"Behavior delta on {endpoint}",
                hypothesis=(
                    f"{endpoint} returned {s1} (v1) vs {s2} (v2): "
                    "a changed execution path — hunt the delta."),
                location=endpoint,
                severity="medium",
                confidence=0.55,
                metadata={"mode": "diff_analysis",
                          "endpoint": endpoint,
                          "status_v1": s1, "status_v2": s2,
                          "delta": True},
            ))
        return candidates

    def anomaly_detection_mode(
        self,
        observations: Sequence[Dict[str, Any]],
        *,
        baseline_status: int = 200,
        baseline_elapsed_ms: float = 500.0,
    ) -> List[ResearchCandidate]:
        """Flag unusual responses (unexpected headers, timing, error patterns).

        Deterministic anomaly classifier over probe observations: status
        deltas from the endpoint baseline, extreme timing, unexpected
        security/error headers, and error-pattern bodies all become
        hypotheses. An optional per-observation ``signal`` (e.g. the fuzz
        classifier's deterministic reason) is itself a reason, so fuzz
        crash/timeout/anomaly observations surface even without a
        status/timing delta. Pure function of the observations — no live
        probing here (the executor collects them; this hunts the anomalies).
        """
        candidates: List[ResearchCandidate] = []
        for obs in observations:
            endpoint = str(obs.get("endpoint") or "").strip()
            status = int(obs.get("status") or 0)
            elapsed = float(obs.get("elapsed_ms") or 0.0)
            headers = obs.get("headers") or {}
            body = str(obs.get("body") or "")
            reasons: List[str] = []
            if status and status != baseline_status:
                reasons.append(f"status {status} vs baseline {baseline_status}")
            if elapsed and elapsed > baseline_elapsed_ms * 4:
                reasons.append(f"timing {elapsed:.0f}ms vs baseline "
                               f"{baseline_elapsed_ms:.0f}ms")
            # An explicit deterministic signal (e.g. the fuzz classifier's
            # reason) is itself an anomaly — fuzz observations with no
            # status/timing delta still surface as candidates.
            signal_note = str(obs.get("signal") or "").strip()
            if signal_note:
                reasons.append(signal_note)
            for hdr in ("x-powered-by", "server", "x-aspnet-version",
                        "x-debug-token", "x-backend"):
                if hdr in {k.lower() for k in headers}:
                    reasons.append(f"unexpected header {hdr}")
            for marker in ("stack trace", "traceback", "syntax error",
                           "exception", "debug:"):
                if marker in body.lower():
                    reasons.append(f"error-pattern '{marker}' in body")
                    break
            if not reasons:
                continue
            candidates.append(ResearchCandidate(
                target=self.target,
                surface=Surface.WEB_API,
                bug_class="anomaly",
                title=f"Anomaly on {endpoint or 'unknown'}",
                hypothesis=f"{'; '.join(reasons)} — investigate the deviation.",
                location=endpoint,
                severity="medium",
                confidence=0.5,
                metadata={"mode": "anomaly_detection",
                          "endpoint": endpoint,
                          "status": status,
                          "elapsed_ms": elapsed,
                          "reasons": reasons},
            ))
        return candidates

    def state_machine_probing(
        self,
        workflow: Sequence[Dict[str, Any]],
        *,
        probe: Optional[Callable[[Dict[str, Any]], ProbeObservation]] = None,
    ) -> List[ResearchCandidate]:
        """Hunt business-logic flaws: workflow skip / repeat / reorder.

        Given the declared workflow steps (ordered), generate the bounded set
        of *illegal* sequences — each step probed out of order, skipped, and
        repeated — and treat any step that succeeds (2xx) when it should not
        be reachable as a candidate. ``probe`` executes a step request
        (injectable; the orchestrator supplies the live executor).
        """
        steps = [dict(s) for s in workflow if s.get("step")]
        candidates: List[ResearchCandidate] = []
        seen: set = set()
        for i, step in enumerate(steps):
            for kind, seq in (
                ("skip", [s for j, s in enumerate(steps) if j != i]),
                ("reorder", [steps[j] for j in range(len(steps) - 1, -1, -1)]
                             if i == 0 else None),
                ("repeat", [s for s in steps] + [step]),
            ):
                if seq is None:
                    continue
                key = f"{kind}:{step.get('step')}:{len(seq)}"
                if key in seen:
                    continue
                seen.add(key)
                reached = False
                if probe is not None:
                    try:
                        reached = int(probe(step).status) in (200, 201, 204)
                    except Exception:
                        reached = False
                if not reached:
                    continue
                candidates.append(ResearchCandidate(
                    target=self.target,
                    surface=Surface.WEB_API,
                    bug_class="business_logic",
                    title=f"Workflow {kind} succeeds: {step.get('step')}",
                    hypothesis=(
                        f"Step '{step.get('step')}' succeeded despite illegal "
                        f"workflow order ({kind}) — the state machine does not "
                        "enforce sequencing."),
                    location=str(step.get("endpoint") or ""),
                    severity="high",
                    confidence=0.6,
                    metadata={"mode": "state_machine",
                              "kind": kind, "step": step.get("step"),
                              "sequence": [s.get("step") for s in seq]},
                ))
        return candidates

    # -- Fuzz-bridge feed (novel-class hunting consumes fuzz signals too) --

    @staticmethod
    def _obs_get(obs: Any, key: str, default: Any = "") -> Any:
        """Read a field from a dict-shaped or dataclass-shaped observation."""
        if isinstance(obs, dict):
            return obs.get(key, default)
        return getattr(obs, key, default)

    def hunt_fuzz_signals(
        self,
        observations: Sequence[Any],
        *,
        baseline_status: int = 200,
        baseline_elapsed_ms: float = 500.0,
    ) -> List[ResearchCandidate]:
        """Feed fuzz crash/timeout/anomaly evidence into the novel-class modes.

        Fuzz signals are both *anomalies* (5xx, timing outliers, transport
        failures) and *behavior deltas* (the endpoint diverged from its
        oracle under mutation), so they are routed through the two Phase-3
        modes:

          1. ``anomaly_detection_mode`` — every crash / timeout / anomaly
             becomes an anomaly candidate; the deterministic fuzz signal
             (e.g. ``server error 500 on probe input``) is carried as a
             reason, so even a pure timeout with no timing delta surfaces.
          2. ``diff_analysis_mode`` — every crash is paired with the
             endpoint's oracle (baseline) behavior and emitted as a
             ``behavior_differential`` candidate: same endpoint, normal vs
             mutated input.

        Every candidate is stamped with the fuzz provenance (``mutation_id``,
        ``kind``, fuzz ``state``, ``replay_key``) so the novel-class hunter
        can reproduce the crash from the recorded evidence.  Accepts
        ``FuzzObservation`` dataclass instances or dict-shaped records; pure
        function of the observations (no persistence, no live probing).
        """
        signals = [o for o in observations
                   if self._obs_get(o, "state", "")
                   in ("crash", "timeout", "anomaly")]
        if not signals:
            return []

        # -- 1. Anomaly mode: every fuzz signal is an anomaly ----------------
        anomaly_obs: List[Dict[str, Any]] = []
        for obs in signals:
            state = str(self._obs_get(obs, "state") or "")
            evidence = self._obs_get(obs, "evidence", {}) or {}
            response = evidence.get("response") or {}
            anomaly_obs.append({
                "endpoint": str(self._obs_get(obs, "url")
                                 or self._obs_get(obs, "endpoint") or ""),
                "status": self._obs_get(obs, "status", 0),
                "elapsed_ms": self._obs_get(obs, "elapsed_ms", 0.0),
                "headers": response.get("headers") or {},
                "body": response.get("body")
                or self._obs_get(obs, "body", ""),
                # Guaranteed non-empty so the mode always yields a candidate
                # (the signal reason is first-class) — the 1:1 stamp below is
                # therefore exact.
                "signal": str(self._obs_get(obs, "signal")
                               or f"fuzz {state}"),
                "state": state,
                "mutation_id": str(self._obs_get(obs, "mutation_id") or ""),
                "kind": str(self._obs_get(obs, "kind") or ""),
                "replay_key": str(evidence.get("replay_key") or ""),
            })
        candidates = self.anomaly_detection_mode(
            anomaly_obs, baseline_status=baseline_status,
            baseline_elapsed_ms=baseline_elapsed_ms)
        for cand, obs in zip(candidates, anomaly_obs):
            _stamp_fuzz_provenance(cand, obs, mode="fuzz_anomaly",
                                   state=obs["state"])

        # -- 2. Diff mode: crashes are baseline-vs-mutation behavior deltas --
        crash_snaps: List[Dict[str, Any]] = []
        crash_provenance: Dict[str, Dict[str, Any]] = {}
        for obs in signals:
            if self._obs_get(obs, "state") != "crash":
                continue
            url = str(self._obs_get(obs, "url") or "").strip()
            if not url:
                continue
            evidence = self._obs_get(obs, "evidence", {}) or {}
            response = evidence.get("response") or {}
            crash_provenance[url] = {
                "mutation_id": str(self._obs_get(obs, "mutation_id") or ""),
                "kind": str(self._obs_get(obs, "kind") or ""),
                "state": "crash",
                "signal": str(self._obs_get(obs, "signal") or ""),
                "replay_key": str(evidence.get("replay_key") or ""),
            }
            crash_snaps.append({"endpoint": url, "status": baseline_status,
                                "body": ""})
            crash_snaps.append({"endpoint": url,
                                "status": int(self._obs_get(obs, "status")
                                               or 0),
                                "body": str(response.get("body") or "")})
        if crash_snaps:
            for cand in self.diff_analysis_mode(crash_snaps):
                provenance = crash_provenance.get(
                    cand.metadata.get("endpoint", ""))
                if provenance is None:
                    continue
                _stamp_fuzz_provenance(cand, provenance, mode="fuzz_diff",
                                       state="crash")
                candidates.append(cand)
        return candidates


    def hunt_exploit_feedback(
        self,
        impacts: Sequence[Dict[str, Any]],
        *,
        baseline_status: int = 200,
    ) -> List[ResearchCandidate]:
        """Feed exploited findings' demonstrated impact into the novel-class hunter.

        A reproduced exploit is the hardest evidence the loop produces: the
        replay returned real data (``demonstrated_impact``).  That data both
        *reveals* an anomaly (the endpoint demonstrably returns data it
        should not) and *unlocks* the derived chain-hypothesis classes
        (``chain_hypotheses`` on the impact record).  Every candidate is
        stamped with the exploit provenance (``finding_id``, ``replay_key``,
        ``replayed_status``) so the hunter can reproduce it from the recorded
        evidence, and — the novelty refinement — the unlock candidates are
        built **impact-bounded**: the demonstrated impact proves the impact
        half, so ``NoveltyEngine.apply`` promotes them into
        ``NOVELTY_PENDING`` (human-review-ready) instead of leaving them as
        bare hypotheses.  Candidates that duplicate an already-known surface
        come back ``EXACT_DUPLICATE`` from the engine — the impact *confirms*
        the known pool rather than re-reporting it.

        Pure function of the impact records (no persistence, no live
        probing); accepts the ``live_exploit`` impact dicts the exploitation
        phase produces.  Dedup is in-feed: pass@k variants of the same
        finding replay the same endpoint, so one candidate per
        (bug_class, endpoint) — first impact wins.
        """
        candidates: List[ResearchCandidate] = []
        seen_reveal: set = set()
        seen_unlock: set = set()
        for impact in impacts or []:
            if not impact.get("reproduced"):
                continue
            endpoint = str(impact.get("endpoint") or "").strip()
            body = str(impact.get("demonstrated_impact") or "").strip()
            if not body or not endpoint:
                continue
            finding_id = str(impact.get("finding_id")
                             or impact.get("thread_id") or "")
            source_class = str(impact.get("bug_class") or "")
            replay_key = str(impact.get("replay_key") or "")
            status = int(impact.get("replayed_status") or 0)
            provenance = {
                "finding_id": finding_id,
                "bug_class": source_class,
                "replay_key": replay_key,
                "replayed_status": status,
                "demonstrated_impact": body[:500],
            }

            # 1. Impact-reveal anomaly: the exploit returned data the
            #    operator cannot normally hold.
            anomaly_obs = [{
                "endpoint": endpoint,
                "status": status or baseline_status,
                "body": body,
                "signal": (f"exploit replay reproduced ({status or 200}) "
                            "with demonstrated impact"),
            }]
            if endpoint not in seen_reveal:
                seen_reveal.add(endpoint)
                for cand in self.anomaly_detection_mode(
                        anomaly_obs, baseline_status=baseline_status):
                    _stamp_exploit_provenance(cand, provenance,
                                              mode="exploit_impact")
                    candidates.append(cand)

            # 2. Unlock candidates: each chain hypothesis the impact derived
            #    is a novel class the demonstrated data makes reachable.
            for hypo in impact.get("chain_hypotheses") or []:
                cls = str(hypo.get("bug_class") or "").strip()
                if not cls:
                    continue
                if (cls, endpoint) in seen_unlock:
                    continue
                seen_unlock.add((cls, endpoint))
                cand = ResearchCandidate(
                    target=self.target,
                    surface=Surface.WEB_API,
                    bug_class=cls,
                    title=f"Exploit-unlocked: {cls} reachable via {endpoint}",
                    hypothesis=str(hypo.get("reason")
                                   or f"demonstrated impact on {endpoint} "
                                   f"unlocks {cls}"),
                    location=endpoint,
                    severity=_bump_severity(
                        str(impact.get("severity") or "low")),
                    confidence=0.8,
                    # The demonstrated impact proves the impact half: the
                    # novelty engine promotes IMPACT_BOUNDED -> NOVELTY_PENDING
                    # on assessment, so the impact refines where the
                    # hypothesis sits in the pipeline.
                    status=CandidateStatus.IMPACT_BOUNDED,
                    trigger_trace=(f"Exploited {source_class or 'finding'} "
                                   f"{finding_id or '?'} on {endpoint}"),
                    impact_trace=body[:500],
                    metadata={"hypothesis_id": str(hypo.get("lead_id") or ""),
                              "source": "exploit-feedback"},
                )
                _stamp_exploit_provenance(cand, provenance, mode="exploit_unlock")
                candidates.append(cand)
        return candidates


#: Exploit evidence is the hardest signal the loop produces: a reproduced
#: replay with returned data outranks bare fuzz crashes.
_EXPLOIT_CONFIDENCE = 0.8

_SEVERITY_UP = {"info": "low", "low": "medium", "medium": "high",
                "high": "critical", "critical": "critical"}


def _bump_severity(severity: str) -> str:
    """One tier up the severity ladder (capped at critical)."""
    return _SEVERITY_UP.get(str(severity).strip().lower(), "medium")


def _stamp_exploit_provenance(candidate: ResearchCandidate,
                              provenance: Dict[str, Any], *, mode: str) -> None:
    """Attach exploit provenance to a candidate and scale its confidence."""
    candidate.metadata["mode"] = mode
    candidate.metadata["exploit"] = {
        "finding_id": provenance.get("finding_id", ""),
        "bug_class": provenance.get("bug_class", ""),
        "replay_key": provenance.get("replay_key", ""),
        "replayed_status": provenance.get("replayed_status", 0),
    }
    candidate.metadata["source"] = "exploit-feedback"
    candidate.confidence = max(candidate.confidence, _EXPLOIT_CONFIDENCE)


#: Fuzz evidence is stronger than a bare header fingerprint: crashes are the
#: hardest signal, timeouts next, generic anomalies weakest.
_FUZZ_CONFIDENCE = {"crash": 0.7, "timeout": 0.6, "anomaly": 0.55}


def _stamp_fuzz_provenance(candidate: ResearchCandidate,
                           provenance: Dict[str, Any], *, mode: str,
                           state: str) -> None:
    """Attach fuzz provenance to a candidate and scale its confidence."""
    candidate.metadata["mode"] = mode
    candidate.metadata["fuzz"] = {
        "mutation_id": provenance.get("mutation_id", ""),
        "kind": provenance.get("kind", ""),
        "state": state,
        "signal": provenance.get("signal", ""),
        "replay_key": provenance.get("replay_key", ""),
    }
    candidate.confidence = _FUZZ_CONFIDENCE.get(state, candidate.confidence)


def _load_input(path: str) -> str:
    return Path(path).read_text(errors="replace")


def build_ranked_output(engine: ZeroDayResearchEngine, candidates: Iterable[ResearchCandidate], *,
                        surface: str, spread: bool = False,
                        top_k: Optional[int] = None) -> Dict[str, Any]:
    """Rank candidates for validation and build the structured CLI output.

    The candidate list is pre-ranked by ``engine.prioritize`` before any
    consumer (the CLI JSON or the human summary) sees it: potentially-novel,
    severe, high-confidence candidates come first, and with ``spread=True``
    payload-bearing candidates are further spaced across their ART4SQLi token
    space so a bounded validation budget samples distinct trigger regions.
    Each emitted candidate carries a 1-based ``rank`` and the top-level
    ``ordering`` block records the mode and any ``top_k`` bound.
    """
    pool = list(candidates)
    ranked = engine.prioritize(pool, k=top_k, spread=spread)
    mode = "novelty_severity_spread" if spread else "novelty_severity"
    ordered = []
    for index, candidate in enumerate(ranked):
        record = candidate.to_dict()
        record["rank"] = index + 1
        ordered.append(record)
    return {
        "schema": "bugwolf-zero-day-output-v2",
        "target": engine.target,
        "surface": surface,
        "claim": "potentially_novel_candidates_only",
        "ordering": {
            "ranked_for_validation": True,
            "mode": mode,
            "spread": spread,
            "top_k": top_k,
            "total_generated": len(pool),
        },
        "candidates": ordered,
        "evidence_integrity": engine.evidence.verify(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf Novel Research Track")
    parser.add_argument("--target", required=True, help="Authorized target or local project name")
    parser.add_argument("--surface", required=True,
                        choices=[surface.value for surface in Surface])
    parser.add_argument("--path", required=True, help="Local artifact/text input")
    parser.add_argument("--source", default="", help="Source label for evidence location")
    parser.add_argument("--spread", action="store_true",
                        help="Order payload-bearing candidates farthest-first across their "
                             "token space so the validation budget samples distinct trigger regions")
    parser.add_argument("--top-k", type=int, default=None,
                        help="Validation budget: only the top K ranked candidates are emitted")
    parser.add_argument("--sequential", action="store_true",
                        help="Run research sequentially: each round researches the top ranked "
                             "candidates and derives bounded refinements for the next round")
    parser.add_argument("--rounds", type=int, default=3,
                        help="Max research rounds in --sequential mode (default: 3)")
    parser.add_argument("--per-round", type=int, default=4,
                        help="Candidates researched per round (default: 4)")
    parser.add_argument("--budget", type=int, default=64,
                        help="Max total candidates kept across all rounds (default: 64)")
    parser.add_argument("--chains", action="store_true",
                        help="Synthesize chained hypotheses across the candidate pool "
                             "(input class -> sink/impact class); automatic in "
                             "--sequential mode")
    parser.add_argument("--max-chains", type=int, default=32,
                        help="Max chained hypotheses to synthesize (default: 32)")
    parser.add_argument("--json", action="store_true", help="Emit structured candidates")
    args = parser.parse_args()

    # Candidate generation is a coverage-planning operation, not a shortcut
    # around the staged audit. The harness must complete setup, preflight,
    # authorization, passive intelligence, maps, and research first.
    try:
        WorkflowController(
            args.target, project_root=str(Path.cwd()),
            mode=args.surface,
        ).require_stage("coverage-plan")
    except (WorkflowError, ValueError) as exc:
        message = {
            "schema": "bugwolf-zero-day-output-v2",
            "target": args.target,
            "claim": "workflow_blocked",
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(message, indent=2))
        else:
            print(f"[!] Workflow denied: {exc}", file=sys.stderr)
        raise SystemExit(2)

    mode_by_surface = {
        Surface.WEB_API.value: "web",
        Surface.CLOUD_CICD.value: "cloud,cicd",
        Surface.LLM_AGENTIC.value: "llm-ai",
        Surface.MOBILE_BINARY.value: "mobile",
        Surface.SMART_CONTRACT.value: "solidity",
    }
    research_runs: Dict[str, Any] = {}
    try:
        research_runs["before_analysis"] = run_mandatory_research(
            args.target, mode_by_surface.get(args.surface, "web"),
            phase="before_hunt", require_latest=True)
    except Exception as exc:
        research_runs["before_analysis"] = {
            "phase": "before_hunt", "latest_ready": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    engine = ZeroDayResearchEngine(args.target)
    if args.surface == Surface.MOBILE_BINARY.value:
        candidates = engine.analyze_binary(Path(args.path).read_bytes(), args.source or args.path)
    else:
        candidates = engine.analyze_text(args.surface, _load_input(args.path), args.source or args.path)
    rounds: Optional[List[Dict[str, Any]]] = None
    chain_count = 0
    if args.sequential:
        sequential = engine.sequential_research(
            candidates, max_rounds=args.rounds, per_round=args.per_round,
            max_candidates=args.budget, max_chains=args.max_chains)
        candidates = sequential["candidates"]
        rounds = sequential["rounds"]
        chain_count = sequential["chains"]
    else:
        candidates = engine.register(candidates)
        if args.chains:
            candidates.extend(engine.chain_candidates(
                candidates, max_chains=args.max_chains))
    try:
        classes = sorted({candidate.bug_class for candidate in candidates if candidate.bug_class})
        research_runs["after_analysis"] = run_mandatory_research(
            args.target, mode_by_surface.get(args.surface, "web"),
            phase="after_findings", bug_classes=",".join(classes),
            require_latest=True)
    except Exception as exc:
        research_runs["after_analysis"] = {
            "phase": "after_findings", "latest_ready": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    output = build_ranked_output(engine, candidates, surface=args.surface,
                                 spread=args.spread, top_k=args.top_k)
    output["research"] = research_runs
    try:
        output["learning"] = learn_from_journey(
            args.target,
            {"candidates": [candidate.to_dict() for candidate in candidates],
             "research": research_runs},
            journey_type="zero-day")
    except Exception as exc:
        output["learning"] = {
            "schema": "bugwolf-adaptive-learning/v1",
            "journey_type": "zero-day",
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    if rounds is not None:
        output["rounds"] = rounds
        output["ordering"]["sequential"] = True
        output["ordering"]["rounds_count"] = len(rounds)
    if chain_count or (args.chains and not args.sequential):
        chain_count = sum(1 for c in candidates if c.metadata.get("chain"))
        output["ordering"]["chains"] = chain_count
    ranked = output["candidates"]
    if args.json:
        print(json.dumps(output, indent=2, default=str))
    else:
        print(f"[*] Candidates (ranked for validation): {len(ranked)}"
              f"{f'/{len(candidates)}' if args.top_k is not None else ''} "
              f"[mode {output['ordering']['mode']}]")
        if rounds is not None:
            derived_total = sum(r.get("derived", 0) for r in rounds)
            print(f"    sequential research: {len(rounds)} round(s), "
                  f"{derived_total} refinements derived")
        if output["ordering"].get("chains"):
            print(f"    chained hypotheses: {output['ordering']['chains']}")
        for record in ranked:
            print(f"  #{record['rank']} [{record['novelty']}] {record['candidate_id']} "
                  f"{record['title']} ({record['location']})")


if __name__ == "__main__":
    main()
