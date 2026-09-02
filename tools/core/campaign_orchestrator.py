#!/usr/bin/env python3
"""BugWolf Campaign Orchestrator — APT Commander (Stage 2 rebuild).

The plugin's brain.  It manages the complete lifecycle:

  1. RECEIVE TARGET -> 2. DISCOVER ALL ASSETS -> 3. PRIORITIZE ->
  4. EXHAUST EACH ASSET A->Z -> 5. CROSS-ASSET CHAINING ->
  6. REPORT -> 7. CONTINUE TO NEXT TARGET

The orchestrator NEVER executes research itself.  It dispatches research units
to the HARNESS (Claude Code / Freebuff / Codex), which executes them with full
intelligence.  The orchestrator tracks progress, persists state, and ensures:

  - One asset at a time, exhaustively (never skip before completion)
  - A REAL recon gate: an asset cannot be threat-modeled until its surface
    (endpoints / tech / ports) is registered
  - Discovery terminates on a round cap / source-exhaustion flag, never on an
    arbitrary asset-count threshold
  - Thread results are registered back (observations, state transitions,
    blockers) so threads actually resolve instead of stalling in HYPOTHESIS
  - Session persistence (survive harness restarts and crashes)
  - Resume from exact point (never lose progress)

Workflow integration (restored 12-stage pipeline + 7-checkpoint research loop):

  - ``WorkflowController`` (tools/stage_controller.py) is the outer state
    machine: the orchestrator records completed stages as their artifacts
    appear (recon-complete.json, asset-intel/, tech-fingerprint.json, maps,
    sequence.json, coverage plan) and surfaces ``next_command`` when a stage
    blocks.
  - The 7-checkpoint research loop (tools/research_loop.py) gates validation
    and chaining: ``latest_ready == false`` returns a research-refresh unit
    instead of proceeding (never a silent skip).

Execution remains UNCENSORED: no scope/authorization gates anywhere.

Usage:
  python3 tools/campaign_orchestrator.py --target company.com --init
  python3 tools/campaign_orchestrator.py --target company.com --next-unit
  python3 tools/campaign_orchestrator.py --target company.com --register-recon recon.json
  python3 tools/campaign_orchestrator.py --target company.com --register-result result.json
  python3 tools/campaign_orchestrator.py --target company.com --run-research --phase full --mode web
  python3 tools/campaign_orchestrator.py --target company.com --status
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CODE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from tools.runtime_paths import workspace_root

from tools.campaign import (
    AssetRecord, AssetStatus, AssetType, CampaignManager, CampaignState,
    Priority, ResumePoint, ThreatHypothesis, ThreadState,
)
from tools.runtime_paths import target_slug
from tools.asset_discovery import AssetDiscoveryEngine, build_research_unit
from tools.research_thread import ThreadBuilder, attach_deterministic_artifacts
from tools.stage_controller import WorkflowController, WorkflowError
from tools.research_loop import (
    run_mandatory_research, verify_sequence, ResearchFreshnessError,
)

logger = logging.getLogger("bugwolf.campaign_orchestrator")

# ---------------------------------------------------------------------------
# Campaign phases
# ---------------------------------------------------------------------------

class CampaignPhase:
    """Named campaign phases with descriptions for the harness."""
    INITIALIZING = "initializing"
    DISCOVERING = "discovering"
    PRIORITIZING = "prioritizing"
    RECON = "recon"
    RESEARCHING = "researching"
    RESEARCH = "research"
    WORKFLOW = "workflow"
    CHAINING = "chaining"
    REPORTING = "reporting"
    EXHAUSTED = "exhausted"


# Discovery terminates after this many rounds unless the harness declares
# source exhaustion earlier via --discovery-complete.  Never an asset count.
MAX_DISCOVERY_ROUNDS = 3

# The five mandatory methodology maps (P1–P5).
MAP_FILES = ("asset.md", "trust.md", "authz.md", "state.md", "capability.md")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _priority_rank(value: Priority | str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        value.value if hasattr(value, "value") else str(value), 3)


@dataclass
class OrchestratorContext:
    """Context passed to the harness for campaign decision-making."""
    target: str
    phase: str
    summary: str
    assets_discovered: int
    assets_exhausted: int
    active_threads: int
    findings: int
    zero_day_candidates: int
    next_action: str
    pending_decisions: List[Dict[str, Any]] = field(default_factory=list)
    workflow: Dict[str, Any] = field(default_factory=dict)
    research: Dict[str, Any] = field(default_factory=dict)
    preflight: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Campaign Orchestrator
# ---------------------------------------------------------------------------

class CampaignOrchestrator:
    """Master controller for a single target's research campaign."""

    def __init__(self, target: str, *,
                 budget_hours: int = 72,
                 max_concurrent_threads: int = 8,
                 mode: str = "web",
                 modes: Optional[List[str]] = None,
                 llm_advisor: bool = False,
                 pass_at_k: int = 1):
        self.project = workspace_root()
        self.target = target_slug(target)
        self.mode = mode or "web"
        self.modes = [m.strip() for m in (modes or self.mode.split(",")) if m.strip()] \
            or ["web"]
        self.llm_advisor = llm_advisor
        self.pass_at_k = max(1, int(pass_at_k or 1))
        self.campaign = CampaignManager(target)
        # Freshness marker BEFORE any component (AssetDiscoveryEngine et al.)
        # creates campaign.json: True means a campaign file already existed,
        # i.e. this orchestrator is resuming, not starting a new mission.
        self._campaign_preexisting = self.campaign.campaign_path.exists()
        self.discovery = AssetDiscoveryEngine(target)
        self.threads = ThreadBuilder(target, pass_at_k=self.pass_at_k)
        self.workflow = WorkflowController(target, mode=self.mode)
        self.budget_hours = budget_hours
        self.max_concurrent_threads = max_concurrent_threads
        # Event-driven chain reaction: when a finding lands, the chain
        # orchestrator refreshes the target's chain graph immediately so
        # chain partners surface without a manual re-run.
        try:
            from tools.chain_orchestrator import make_finding_discovered_listener
            from tools.core.signal_bus import SignalBus
            self._signal_bus = SignalBus(self.target)
            self._signal_bus.subscribe(
                "FINDING_DISCOVERED",
                make_finding_discovered_listener(
                    self.target, project_root=str(self.project)))
        except Exception:
            self._signal_bus = None  # advisory — never gates the campaign
        # Mandatory pre-flight (plan v2 section 4.5): capability discovery
        # runs once per orchestrator (lazy) and is fail-open — a failure is
        # recorded, never a gate.
        self._preflight: Optional[Dict[str, Any]] = None

    # -- Pre-flight (plan v2 section 4.5) ----------------------------------

    def ensure_preflight(self, *, probe_binaries: bool = True,
                         force: bool = False) -> Optional[Dict[str, Any]]:
        """Run the mandatory pre-flight once per orchestrator (fail-open).

        PF1/PF2 capability discovery + PF3 memory: the manifest digest is
        attached to the campaign context and every research unit so no lane
        has to rediscover the machine's capabilities.  Records capability --
        it does not restrict it: a failed check marks dependent work
        BLOCKED/DEGRADED in the manifest and lets the scheduler/lane decide.
        """
        if self._preflight is not None and not force:
            return self._preflight
        try:
            from tools.runtime.preflight import run_preflight
            self._preflight = run_preflight(
                self.target, project_root=str(self.project),
                probe_binaries=probe_binaries)
            self.campaign.log_event("preflight_complete", {
                "sha256": self._preflight.get("sha256", ""),
                "summary": self._preflight.get("summary", {}),
                "digest": self._preflight.get("digest", ""),
            })
        except Exception as exc:  # noqa: BLE001 — advisory, never gates
            logger.info("preflight unavailable (fail-open): %s", exc)
            self._preflight = None
        return self._preflight

    def preflight_digest(self) -> str:
        manifest = self.ensure_preflight()
        return str(manifest.get("digest") or "") if manifest else ""

    # -- Workflow passthroughs ---------------------------------------------

    def workflow_status(self) -> Dict[str, Any]:
        return self.workflow.status()

    def complete_workflow_stage(self, stage: str, *,
                                artifacts: Optional[List[str]] = None,
                                scope_file: Optional[str] = None,
                                notes: str = "") -> Dict[str, Any]:
        return self.workflow.complete(stage, artifacts=artifacts,
                                      scope_file=scope_file, notes=notes)

    def _try_workflow_complete(self, stage: str, *,
                               artifacts: Optional[List[str]] = None,
                               scope_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Best-effort stage recording — the strict pipeline still governs."""
        self._auto_advance_workflow()
        try:
            return self.workflow.complete(stage, artifacts=artifacts,
                                          scope_file=scope_file)
        except WorkflowError as exc:
            logger.info("workflow stage %s not yet completable: %s", stage, exc)
            return None

    def _auto_advance_workflow(self) -> None:
        """Self-heal the workflow as its artifacts appear.

        Stages whose deterministic artifacts already exist are recorded in
        order (strict pipeline still applies).  authorization stays
        operator-declared — it requires an explicit scope file and is never
        auto-completed.  research/validation/triage/report are never
        auto-advanced.
        """
        def has(stage: str) -> bool:
            target = self.target
            root = self.project
            return {
                "setup": (root / ".bugwolf" / "harness.json").is_file()
                         and (root / "BUGWOLF.md").is_file(),
                "environment-preflight": (root / "state" / "environment.json").is_file(),
                "passive-recon": (root / "recon" / target / "recon-complete.json").is_file(),
                "asset-intelligence": any(
                    (root / "recon" / target / "asset-intel").glob("*")),
                "technology-fingerprint": (root / "recon" / target
                                           / "tech-fingerprint.json").is_file(),
                "maps": all(
                    (root / "state" / "sessions" / target / "maps" / name).is_file()
                    for name in MAP_FILES),
                "coverage-plan": (root / "recon" / target / "discovery"
                                  / "plan.jsonl").is_file(),
            }[stage]

        order = ("setup", "environment-preflight", "passive-recon",
                 "asset-intelligence", "technology-fingerprint", "maps",
                 "coverage-plan")
        for stage in order:
            try:
                current = self.workflow.status().get("current_stage")
            except WorkflowError:
                return
            if current is None:
                return  # workflow already complete
            if current != stage:
                continue  # already behind this stage — skip ahead
            if not has(stage):
                return  # strict order — cannot advance past a missing artifact
            try:
                self.workflow.complete(stage)
            except WorkflowError as exc:
                logger.info("auto-advance blocked on %s: %s", stage, exc)
                return

    def _refresh_workflow_hashes(self, stage: str) -> None:
        """Re-record hashes for a stage the campaign legitimately updated."""
        try:
            self.workflow.refresh_artifact_hashes(stage)
        except WorkflowError as exc:
            logger.info("hash refresh for %s skipped: %s", stage, exc)

    # -- Lifecycle ---------------------------------------------------------

    def initialize(self) -> CampaignState:
        """Initialize (or resume) the campaign and its workflow manifest."""
        try:
            self.workflow.initialize(force=False)
        except WorkflowError:
            # A pre-restore manifest (stripped era) is invalid under the
            # restored contract — rebuild it deterministically.
            self.workflow.initialize(force=True)
        self._auto_advance_workflow()
        # Freshness must come from the __init__ disk marker, not from
        # state.status: this method itself saves status INITIALIZING, so a
        # status check alone would re-announce MISSION_CREATED on every
        # resume, and campaign.json exists by initialize() time regardless.
        fresh_start = not getattr(self, "_campaign_preexisting", False)
        state = self.campaign.initialize(
            budget_hours=self.budget_hours,
            max_concurrent_threads=self.max_concurrent_threads,
        )
        if state.status == "initializing":
            state.status = CampaignPhase.INITIALIZING
            state.phase = "Campaign initialized. Ready for asset discovery."
            self.campaign.save(state)
            if fresh_start:
                # Section 4.2: a fresh mission start is announced once.
                try:
                    bus = getattr(self, "_signal_bus", None)
                    if bus is not None:
                        bus.publish("MISSION_CREATED", "campaign_orchestrator",
                                    {"target": self.target,
                                     "modes": list(self.modes)})
                except Exception:  # noqa: BLE001 — advisory
                    pass
                # Once per mission: re-initialize on this instance (or a new
                # instance for the same target) is a resume, not a new start.
                self._campaign_preexisting = True
        # Mandatory pre-flight before any mission work (section 4.5 order
        # rule).  Fail-open: recorded in the context, never a gate.
        self.ensure_preflight()
        return state

    def get_context(self) -> OrchestratorContext:
        """Build the campaign context for the harness."""
        state = self.campaign.load()
        assets = self.campaign.list_assets()
        threads = self.campaign.list_threads()
        resume = self.campaign.get_resume()

        phase = self._derive_phase(state)
        summary = self._build_summary(state, assets, threads)
        next_action = resume.next_action if resume else "Initialize campaign"

        return OrchestratorContext(
            target=self.target,
            phase=phase,
            summary=summary,
            assets_discovered=state.assets_discovered,
            assets_exhausted=state.assets_exhausted,
            active_threads=len([t for t in threads if not t.is_terminal]),
            findings=state.total_findings,
            zero_day_candidates=state.zero_day_candidates,
            next_action=next_action,
            pending_decisions=resume.pending_decisions if resume else [],
            workflow=self.workflow_status(),
            research=self._research_report(),
            preflight=(self.ensure_preflight(probe_binaries=False) or {}),
        )

    def _derive_phase(self, state: CampaignState) -> str:
        if state.assets_discovered == 0:
            return CampaignPhase.DISCOVERING
        if state.assets_exhausted >= state.assets_discovered:
            return (CampaignPhase.CHAINING if state.discovery_complete
                    else CampaignPhase.DISCOVERING)
        return CampaignPhase.RESEARCHING

    @staticmethod
    def _build_summary(state: CampaignState,
                       assets: List[AssetRecord],
                       threads: List) -> str:
        lines = [
            f"Campaign: {state.target}",
            f"Phase: {state.status}",
            f"Assets: {len(assets)} discovered, {state.assets_exhausted} exhausted",
            f"Discovery: round {state.discovery_rounds}/{MAX_DISCOVERY_ROUNDS} "
            f"{'complete' if state.discovery_complete else 'active'}",
            "",
            "Assets by priority:",
        ]
        by_priority: Dict[str, List[str]] = {}
        for a in assets:
            key = a.priority.value if hasattr(a.priority, 'value') else str(a.priority)
            by_priority.setdefault(key, []).append(a.hostname)

        for pri in ["critical", "high", "medium", "low"]:
            hosts = by_priority.get(pri, [])
            if hosts:
                status_counts = {}
                for h in hosts:
                    a = next((x for x in assets if x.hostname == h), None)
                    s = a.status.value if a else "unknown"
                    status_counts[s] = status_counts.get(s, 0) + 1
                status_str = ", ".join(f"{v} {k}" for k, v in status_counts.items())
                lines.append(f"  {pri.upper()}: {len(hosts)} ({status_str})")

        active = [t for t in threads if not t.is_terminal]
        complete = [t for t in threads if t.state == ThreadState.COMPLETE]
        refuted = [t for t in threads if t.state == ThreadState.REFUTED]

        lines.extend([
            "",
            f"Threads: {len(active)} active, {len(complete)} complete, {len(refuted)} refuted",
            f"Findings: {state.total_findings} total",
        ])

        return "\n".join(lines)

    # -- Research integration ----------------------------------------------

    def _research_report(self) -> Dict[str, Any]:
        try:
            return verify_sequence(self.target,
                                   base_dir=str(self.project / "research"))
        except Exception as exc:  # defensive — report never raises
            return {"ready": False, "errors": [f"research check failed: {exc}"]}

    def _research_context(self) -> Dict[str, Any]:
        """Derive hierarchical sub-checkpoint triggers from campaign artifacts.

        Deterministic: reads the tech fingerprint (``graphql`` / ``waf`` /
        ``cloud`` signals) and the maps so the research loop dives deeper
        exactly where the surface demands it.
        """
        context: Dict[str, Any] = {}
        fingerprint = self.project / "recon" / self.target / "tech-fingerprint.json"
        try:
            data = json.loads(fingerprint.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        stack_text = json.dumps(data).lower()
        context["graphql"] = any(term in stack_text for term in
                                  ("graphql", "apollo", "hasura", "gql"))
        context["waf"] = any(term in stack_text for term in
                              ("waf", "cloudflare", "akamai", "aws shield",
                               "imperva", "fastly", "modsecurity", "f5"))
        context["cloud"] = any(term in stack_text for term in
                                ("aws", "azure", "gcp", "kubernetes", "ec2",
                                 "s3", "lambda", "cloudfront", "metadata"))
        # Dynamic event-driven checkpoints: chain partners / lab plans /
        # blocked threads append deep research beyond the mandatory 7.
        chains = self.project / "state" / "chains" / self.target \
            / "orchestration.json"
        try:
            chain_data = json.loads(chains.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            chain_data = {}
        chain_count = len(chain_data.get("chains") or chain_data.get("edges")
                          or [])
        context["chain_candidates"] = chain_count > 0
        lab_plans = self.project / "research" / self.target \
            / "verification" / "lab-plans.json"
        context["lab_verification"] = lab_plans.is_file()
        blocked = [t for t in self.campaign.list_threads()
                   if t.state == ThreadState.BLOCKED]
        context["blocker_exhausted"] = len(blocked) > 0
        return context

    def run_research(self, *, phase: str = "full", modes: Optional[List[str]] = None,
                     stack: str = "", bug_classes: str = "", defense: str = "") -> Dict[str, Any]:
        """Run the mandatory 7-checkpoint research sequence for the target.

        After a successful run the workflow's ``research`` stage is recorded
        (``complete`` when fresh, ``complete_pending`` when searches are
        pending — the strict pipeline refuses stale validation either way).
        Hierarchical depth: sub-checkpoint triggers are derived from the tech
        fingerprint so a GraphQL/WAF/cloud surface gets its deep-dive research.
        """
        result = run_mandatory_research(
            self.target, modes or self.modes, phase=phase,
            base_dir=str(self.project / "research"),
            stack=stack, bug_classes=bug_classes, defense=defense,
            context=self._research_context(), require_latest=True,
        )
        try:
            current = self.workflow.status().get("current_stage")
            if current == "research":
                self.workflow.complete("research")
        except WorkflowError as exc:
            result["workflow_blocked"] = str(exc)
        # The research run rewrote sequence.json — keep its recorded hash in
        # sync so the integrity gate stays satisfiable on later advances.
        self._refresh_workflow_hashes("research")
        return result

    def _build_research_refresh_unit(self, errors: List[str]) -> Dict[str, Any]:
        """Blocking unit: research must be refreshed before validation/chaining."""
        command = (
            f"python3 tools/research_loop.py --sequential --phase full --execute "
            f"--target {self.target} --mode {','.join(self.modes)} --require-latest"
        )
        unit = build_research_unit(
            objective=("Refresh the mandatory research sequence (all 7 checkpoints) "
                       "until latest_ready is true"),
            context={
                "target": self.target,
                "errors": errors,
                "command": command,
                "required_sequence": [
                    "pre-hunt", "post-recon", "post-maps", "bypass",
                    "post-findings", "escalation", "pre-report",
                ],
            },
            success_criteria=[
                f"research/{self.target}/sequence.json has latest_ready == true",
                "No pending searches (all checkpoints fetched from live sources)",
            ],
        )
        unit["campaign_phase"] = CampaignPhase.RESEARCH
        return unit

    def _build_workflow_blocked_unit(self, error: str) -> Dict[str, Any]:
        """Blocking unit: the outer 12-stage pipeline must advance first."""
        current = self.workflow.status().get("current_stage")
        unit = build_research_unit(
            objective="Advance the 12-stage workflow before the campaign continues",
            context={
                "workflow_error": error,
                "current_stage": current,
                "next_command": self.workflow.next_command(current),
            },
            success_criteria=[
                "The blocking stage is completed with its artifacts",
                "Campaign can continue past the workflow gate",
            ],
        )
        unit["campaign_phase"] = CampaignPhase.WORKFLOW
        return unit

    # -- Phase: Asset Discovery --------------------------------------------

    def _enrich_unit(self, unit: Dict[str, Any], *, bug_class: str = "") -> Dict[str, Any]:
        """Attach U2 deterministic artifacts + U5 model-routing hints.

        Both are advisory context; the dispatch format and the strict
        workflow are untouched.
        """
        attach_deterministic_artifacts(
            unit, self.target, project_root=str(self.project),
            bug_class=bug_class)
        # PF3 memory: every unit carries the pre-flight digest so no lane
        # ever has to rediscover (or "remember") machine capabilities.
        context = unit.setdefault("context", {})
        if isinstance(context, dict):
            digest = self.preflight_digest()
            if digest:
                context["preflight_digest"] = digest
        try:
            from tools.core.model_router import attach_hint
            attach_hint(unit)
            routing = (unit.get("context") or {}).get("model_routing") or {}
            if routing:
                self.campaign.log_event("unit_routed", {
                    "unit_id": str(unit.get("unit_id") or unit.get("id")
                                   or unit.get("objective", "unit"))[:80],
                    "model_tier": routing.get("tier"),
                    "model_preference": routing.get("model_preference"),
                    "complexity": routing.get("complexity"),
                })
        except Exception:
            pass  # routing is advisory, never a dispatch gate
        return unit

    def get_discovery_unit(self) -> Dict[str, Any]:
        """Next discovery round — round-capped, source-aware, never count-based."""
        state = self.campaign.load()
        state.status = CampaignPhase.DISCOVERING
        state.phase = f"Asset discovery round {state.discovery_rounds + 1}"
        state.discovery_rounds += 1
        self.campaign.save(state)

        unit = self.discovery.get_research_unit()
        report = self.discovery.status_report()
        unit["context"]["discovery_round"] = state.discovery_rounds
        unit["context"]["max_rounds"] = MAX_DISCOVERY_ROUNDS
        unit["context"]["sources_used"] = report["sources_used"]
        unit["success_criteria"] = [
            "Discover assets not already listed in known_assets",
            "Use at least one discovery source not in sources_used",
            "Register results with --register-discoveries",
            "If no source yields a new asset, run --discovery-complete",
        ]
        unit["campaign_phase"] = CampaignPhase.DISCOVERING
        return self._enrich_unit(unit)

    def register_discovered_assets(self,
                                    discoveries: List[Dict[str, Any]]) -> int:
        """Register assets discovered by the harness."""
        count = self.discovery.register_batch(discoveries)
        state = self.campaign.load()
        state.assets_discovered = len(self.campaign.list_assets())
        self.campaign.save(state)
        return count

    def mark_discovery_complete(self) -> CampaignState:
        """Declare discovery source-exhausted (termination rule, not a count)."""
        state = self.campaign.load()
        already = state.discovery_complete
        state.discovery_complete = True
        state.phase = "Asset discovery complete — moving to prioritized research"
        self.campaign.save(state)
        if not already:
            self.finalize_recon()  # idempotent — artifacts written exactly once
        return state

    # -- Phase: Asset Prioritization ---------------------------------------

    def get_prioritized_assets(self) -> List[AssetRecord]:
        """Get assets ordered by priority, then type, then hostname."""
        assets = self.campaign.list_assets()
        type_order = {
            "oauth_idp": 0, "admin_panel": 0, "ci_cd": 0,
            "web_api": 1, "graphql": 1,
            "web_app": 2, "mobile_api": 2, "internal_tool": 2,
            "websocket": 3, "database": 3, "storage_bucket": 3,
        }
        return sorted(assets, key=lambda a: (
            _priority_rank(a.priority),
            type_order.get(
                a.type.value if hasattr(a.type, 'value') else str(a.type), 9),
            a.hostname,
        ))

    # -- Phase: Recon gate -------------------------------------------------

    def get_next_asset(self) -> Optional[AssetRecord]:
        """Highest-priority non-exhausted, non-paused asset."""
        for asset in self.get_prioritized_assets():
            if asset.status not in {AssetStatus.EXHAUSTED, AssetStatus.PAUSED}:
                return asset
        return None

    @staticmethod
    def _asset_recon_ready(asset: AssetRecord) -> bool:
        """A QUEUED/RECON asset may not advance until its surface is mapped."""
        return bool(asset.recon_complete or asset.endpoints
                    or asset.endpoints_discovered > 0 or asset.detected_tech
                    or asset.ports)

    def _build_recon_unit(self, asset: AssetRecord) -> Dict[str, Any]:
        """Dispatch a deep recon unit for one asset — the recon gate."""
        unit = build_research_unit(
            objective=f"Deep surface recon on {asset.hostname}: enumerate every "
                      f"endpoint, technology, and open port",
            asset_hostname=asset.hostname,
            bug_class="",
            endpoint="",
            context={
                "asset_id": asset.asset_id,
                "asset_type": asset.type.value,
                "asset_priority": asset.priority.value,
                "already_known": {
                    "endpoints": asset.endpoints,
                    "tech": asset.detected_tech,
                    "ports": asset.ports,
                },
                "instructions": (
                    "Map the asset's full attack surface: URLs, API paths, "
                    "GraphQL/WebSocket endpoints, auth boundaries, tech stack "
                    "with versions, open ports. Then register the result with "
                    "python3 tools/campaign_orchestrator.py --target T "
                    "--register-recon <file> — the asset cannot advance to "
                    "threat modeling until recon is registered."
                ),
                "register_recon_schema": {
                    "asset_id": asset.asset_id,
                    "endpoints": ["https://api.example.com/v1/users"],
                    "tech": ["next.js 15.1", "postgres 16"],
                    "ports": [443, 8443],
                },
            },
            success_criteria=[
                f"Register recon for {asset.hostname} (endpoints + tech + ports)",
                "Endpoints are concrete (URLs/paths), not just the hostname",
            ],
        )
        unit["campaign_phase"] = CampaignPhase.RECON
        return self._enrich_unit(unit, bug_class="recon")

    def register_recon(self, asset_id: str, *, endpoints: Optional[List[str]] = None,
                       tech: Optional[List[str]] = None,
                       ports: Optional[List[int]] = None) -> AssetRecord:
        """Register per-asset recon output; unblocks the recon gate."""
        asset = self.campaign.get_asset(asset_id)
        if not asset:
            raise ValueError(f"unknown asset: {asset_id}")
        asset.endpoints = list(dict.fromkeys(
            str(e).strip() for e in (endpoints or []) if str(e).strip()))[:500]
        asset.detected_tech = list(dict.fromkeys(
            str(t).strip() for t in (tech or []) if str(t).strip()))[:200]
        asset.ports = sorted({
            int(p) for p in (ports or [])
            if isinstance(p, int) or (str(p).isdigit() and 0 < int(p) < 65536)
        })
        asset.endpoints_discovered = len(asset.endpoints)
        asset.recon_complete = True
        self.campaign.update_asset(asset)

        # Artifact for the workflow's asset-intelligence stage.
        intel_dir = self.project / "recon" / self.target / "asset-intel"
        intel_dir.mkdir(parents=True, exist_ok=True)
        (intel_dir / f"{asset.asset_id}.json").write_text(
            json.dumps(asset.to_dict(), indent=2, default=str) + "\n",
            encoding="utf-8")
        self._write_tech_fingerprint()
        self._try_workflow_complete("asset-intelligence")
        self._try_workflow_complete("technology-fingerprint")
        # Campaign legitimately appends per-asset recon output — keep the
        # recorded hashes in sync so the integrity gate stays satisfiable.
        self._refresh_workflow_hashes("asset-intelligence")
        self._refresh_workflow_hashes("technology-fingerprint")
        return asset

    def mark_recon_complete(self, asset_id: str) -> AssetRecord:
        """Explicitly declare an asset's surface mapped (no endpoints needed)."""
        asset = self.campaign.get_asset(asset_id)
        if not asset:
            raise ValueError(f"unknown asset: {asset_id}")
        asset.recon_complete = True
        self.campaign.update_asset(asset)
        return asset

    def _write_tech_fingerprint(self) -> None:
        assets = self.campaign.list_assets()
        tech: Dict[str, List[str]] = {}
        for a in assets:
            for t in a.detected_tech:
                tech.setdefault(t, []).append(a.hostname)
        path = self.project / "recon" / self.target / "tech-fingerprint.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "target": self.target,
            "detected_tech": tech,
            "updated_at": _now(),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def finalize_recon(self) -> None:
        """Write the target-level recon artifacts once discovery is done."""
        assets = self.campaign.list_assets()
        if not assets:
            return
        recon_dir = self.project / "recon" / self.target
        recon_dir.mkdir(parents=True, exist_ok=True)
        (recon_dir / "recon-complete.json").write_text(json.dumps({
            "complete": True,
            "assets": len(assets),
            "finished_at": _now(),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._write_tech_fingerprint()
        self._try_workflow_complete("passive-recon")
        self._try_workflow_complete("asset-intelligence")
        self._try_workflow_complete("technology-fingerprint")

    # -- Phase: Maps -------------------------------------------------------

    def ensure_maps(self) -> None:
        """Write the five mandatory methodology maps from campaign state.

        The maps are the workflow's ``maps`` stage artifacts; asset.md carries
        the real recon inventory, the remaining four are structural frames the
        harness fills during threat modeling.  Contract targets additionally
        get invariants.md (workflow gate enforces it).
        """
        maps_dir = self.project / "state" / "sessions" / self.target / "maps"
        maps_dir.mkdir(parents=True, exist_ok=True)
        assets = self.campaign.list_assets()

        asset_rows = "\n".join(
            f"| {a.hostname} | {a.type.value} | "
            f"{', '.join(a.detected_tech[:5]) or '-'} | "
            f"{a.endpoints_discovered} |"
            for a in assets)
        (maps_dir / "asset.md").write_text(
            f"# P1 Asset Map — {self.target}\n\n"
            f"| asset | type | technology | endpoints |\n"
            f"|---|---|---|---|\n{asset_rows}\n", encoding="utf-8")

        trust_rows = "\n".join(
            f"| {a.hostname} | client | unverified | public→private |"
            for a in assets
            if a.type in {AssetType.OAUTH_IDP, AssetType.ADMIN_PANEL,
                          AssetType.WEB_API})
        (maps_dir / "trust.md").write_text(
            f"# P2 Trust Map — {self.target}\n\n"
            f"| trustor | trustee | trust_type | boundary_crossed |\n"
            f"|---|---|---|---|\n{trust_rows}\n", encoding="utf-8")

        (maps_dir / "authz.md").write_text(
            f"# P3 Identity Map — {self.target}\n\n"
            f"| action | anonymous | user | admin | service |\n"
            f"|---|---|---|---|---|\n"
            f"| (fill from recon endpoints) | ? | ? | ? | ? |\n", encoding="utf-8")

        (maps_dir / "state.md").write_text(
            f"# P4 State Map — {self.target}\n\n"
            f"| object | states[] | allowed_transitions[] | illegal_transitions[] |\n"
            f"|---|---|---|---|\n"
            f"| (fill during threat modeling) | | | |\n", encoding="utf-8")

        (maps_dir / "capability.md").write_text(
            f"# P5 Capability & Authority Map — {self.target}\n\n"
            f"| feature | capability | impact_verb | boundary_crossed |\n"
            f"|---|---|---|---|\n"
            f"| (fill during threat modeling) | | | |\n", encoding="utf-8")

        if self.workflow.is_contract_target:
            (maps_dir / "invariants.md").write_text(
                f"# Contract Invariants — {self.target}\n\n"
                f"| invariant_id | description | affected_contracts | variables |\n"
                f"|---|---|---|---|\n", encoding="utf-8")

        self._try_workflow_complete("maps")
        # Maps are living state — refreshed per threat-modeling pass.
        self._refresh_workflow_hashes("maps")

    # -- Phase: Asset Research ---------------------------------------------

    def _advance(self, asset: AssetRecord) -> AssetRecord:
        """Advance an asset exactly one lifecycle step (gated by the caller)."""
        if asset.status == AssetStatus.QUEUED:
            asset.status = AssetStatus.RECON
            self.campaign.update_asset(asset)
        elif asset.status == AssetStatus.RECON:
            asset.status = AssetStatus.THREAT_MODELING
            self.campaign.update_asset(asset)
        elif asset.status == AssetStatus.THREAT_MODELING:
            self.threads.start_asset_research(asset)  # spawns threads, sets DEEP_RESEARCH
            asset = self.campaign.get_asset(asset.asset_id) or asset
        return asset

    def _exhaust_asset(self, asset: AssetRecord) -> None:
        """Mark an asset exhausted exactly once (single increment)."""
        asset.status = AssetStatus.EXHAUSTED
        asset.completed_at = _now()
        self.campaign.update_asset(asset)
        state = self.campaign.load()
        state.assets_exhausted += 1
        self.campaign.save(state)
        self._write_coverage_plan()
        logger.info("asset exhausted: %s", asset.hostname)

    def _write_coverage_plan(self) -> None:
        """Persist the coverage-plan artifact from spawned threads."""
        threads = self.campaign.list_threads()
        if not threads:
            return
        discovery = self.project / "recon" / self.target / "discovery"
        discovery.mkdir(parents=True, exist_ok=True)
        with (discovery / "plan.jsonl").open("a", encoding="utf-8") as stream:
            for t in threads:
                stream.write(json.dumps({
                    "thread_id": t.thread_id,
                    "asset_id": t.asset_id,
                    "bug_class": t.bug_class,
                    "endpoint": t.endpoint,
                    "objective": t.objective,
                    "state": t.state.value,
                }, sort_keys=True) + "\n")
        self._try_workflow_complete("coverage-plan")
        # The plan grows as assets are exhausted — keep hashes in sync.
        self._refresh_workflow_hashes("coverage-plan")

    def get_next_research_unit(self) -> Optional[Dict[str, Any]]:
        """Get the next research unit for the harness to execute.

        Priority order (each step is gated):
          1. Resume active threads (deterministic priority order)
          2. Operator decision for blocked threads
          3. Current asset lifecycle with recon gate + map gate
          4. Discovery rounds (round-capped, source-aware)
          5. Chaining (gated on fresh research + workflow validation stage)

        With ``llm_advisor`` enabled, every unit is enriched with the seed
        advisor's probe proposals (deterministic core decides; the advisor
        only adds depth to ``suggested_approaches``).
        """
        unit = self._get_next_research_unit()
        if unit and self.llm_advisor:
            self._apply_llm_advisor(unit)
        return unit

    def _apply_llm_advisor(self, unit: Dict[str, Any]) -> None:
        """Enrich a unit's suggested_approaches with seed-advisor proposals.

        Advisory and never gating: failures leave the unit untouched.
        """
        try:
            from tools.intelligence.seed_advisor import advise
            unit_id = str(unit.get("unit_id") or unit.get("id") or "unit")
            mode = str(unit.get("mode") or self.mode or "web").lower()
            seeds = list(unit.get("suggested_approaches") or [])
            report = advise(self.target, [{
                "unit_id": unit_id, "mode": mode,
                "suggested_approaches": seeds,
            }])
            proposals = [p["approach"] for p in report.to_dict()["proposals"]]
            unit["suggested_approaches"] = seeds + proposals
            unit["llm_advisor"] = True
        except Exception as exc:
            logger.warning("llm advisor enrichment skipped: %s", exc)

    def _get_next_research_unit(self) -> Optional[Dict[str, Any]]:
        """(pre-advisor) raw next-research-unit dispatch."""
        self._auto_advance_workflow()

        # 1. Active threads across the campaign, deterministic priority order.
        # pass@k variants of one threat are adjacent (pass_variant before
        # thread_id) so the deep-dive group dispatches together.
        active = sorted(
            (t for t in self.campaign.list_threads()
             if not t.is_terminal and t.state != ThreadState.BLOCKED),
            key=lambda t: (_priority_rank(t.priority),
                           getattr(t, "pass_variant", 0), t.thread_id))
        if active:
            unit = self.threads.get_next_research_unit(active[0])
            unit["campaign_phase"] = CampaignPhase.RESEARCHING
            return unit

        # 2. Blocked threads need an operator decision.
        blocked = [t for t in self.campaign.list_threads()
                   if t.state == ThreadState.BLOCKED]
        if blocked:
            return self._build_blocked_unit(blocked)

        # 3. Current asset — advance through the gated lifecycle.  Loop until
        # every remaining asset has yielded a unit or been exhausted, so an
        # exhausted asset never skips discovery of the next unprocessed one.
        while True:
            asset = self.get_next_asset()
            if not asset:
                break
            if asset.status not in {AssetStatus.QUEUED, AssetStatus.RECON,
                                    AssetStatus.THREAT_MODELING,
                                    AssetStatus.DEEP_RESEARCH}:
                # Unknown/foreign status — cannot progress; terminate it so the
                # loop always makes progress and never spins.
                logger.warning("asset %s in unhandled state %s; exhausting",
                                asset.hostname, asset.status.value)
                self._exhaust_asset(asset)
                continue
            if asset.status == AssetStatus.QUEUED:
                if not self._asset_recon_ready(asset):
                    return self._build_recon_unit(asset)
                asset = self._advance(asset)
            if asset.status == AssetStatus.RECON:
                if not self._asset_recon_ready(asset):
                    return self._build_recon_unit(asset)
                asset = self._advance(asset)
            if asset.status == AssetStatus.THREAT_MODELING:
                self.ensure_maps()
                asset = self._advance(asset)  # spawns threads -> DEEP_RESEARCH
            if asset.status == AssetStatus.DEEP_RESEARCH:
                active = sorted(
                    (t for t in self.campaign.list_threads(asset_id=asset.asset_id)
                     if not t.is_terminal and t.state != ThreadState.BLOCKED),
                    key=lambda t: (_priority_rank(t.priority),
                                   getattr(t, "pass_variant", 0), t.thread_id))
                if active:
                    unit = self.threads.get_next_research_unit(active[0])
                    unit["campaign_phase"] = CampaignPhase.RESEARCHING
                    return unit
                # Threads resolved — one more spawn pass for newly discovered
                # surface, then genuinely exhaust (single increment).
                new_threads = self.threads.build_threads_for_asset(asset)
                if new_threads:
                    unit = self.threads.get_next_research_unit(new_threads[0])
                    unit["campaign_phase"] = CampaignPhase.RESEARCHING
                    return unit
                self._exhaust_asset(asset)
            # Fall back to the next asset; only leave the loop when all assets
            # are exhausted/paused (get_next_asset returns None).

        # 4. Discovery — round-capped and source-aware, never count-based.
        state = self.campaign.load()
        if not state.discovery_complete and state.discovery_rounds < MAX_DISCOVERY_ROUNDS:
            return self.get_discovery_unit()
        if not state.discovery_complete:
            self.mark_discovery_complete()
            state = self.campaign.load()

        # 5. Chaining — gated on fresh research + the workflow validation gate.
        research = self._research_report()
        if not research["ready"]:
            return self._build_research_refresh_unit(research.get("errors", []))
        try:
            self.workflow.require_stage("validation")
        except WorkflowError as exc:
            return self._build_workflow_blocked_unit(str(exc))

        state.status = CampaignPhase.CHAINING
        state.phase = "Cross-asset chain analysis"
        self.campaign.save(state)
        return self._build_chain_unit()

    # -- Result registration (fixes the stalled-thread flaw) ---------------

    def register_thread_result(self, thread_id: str, *, action: str = "",
                               observation: str = "", conclusion: str = "",
                               new_state: Optional[str] = None,
                               confirmed_behavior: str = "",
                               last_successful_action: str = "",
                               endpoint: str = "",
                               suggested_approaches: Optional[List[str]] = None,
                               blocker: str = "") -> Any:
        """Register a harness result back onto a thread.

        With ``new_state`` the thread transitions (e.g. hypothesis -> probing ->
        signal_found -> ... -> complete/refuted); without it the observation is
        recorded and progress fields updated.  This is the feedback loop that
        lets threads actually resolve.
        """
        thread = self.campaign.get_thread(thread_id)
        if not thread:
            raise ValueError(f"unknown thread: {thread_id}")
        builder = self.threads

        if new_state:
            if new_state == ThreadState.BLOCKED.value:
                builder.set_blocker(thread, blocker or observation or "needs operator input")
            else:
                builder.transition_thread(thread, new_state,
                                          observation=observation or action,
                                          conclusion=conclusion)
        elif action or observation or conclusion:
            builder.record_observation(thread, action=action or "progress",
                                       observation=observation,
                                       conclusion=conclusion)

        thread = self.campaign.get_thread(thread_id)
        if confirmed_behavior or last_successful_action or endpoint \
                or suggested_approaches:
            builder.update_progress(thread,
                                    confirmed_behavior=confirmed_behavior,
                                    last_successful_action=last_successful_action,
                                    endpoint=endpoint,
                                    suggested_approaches=suggested_approaches)
        thread = self.campaign.get_thread(thread_id)
        # Event-driven chain reaction: a completed thread is a finding — but
        # it first runs through the F0.5 strict gate (U3) so only
        # report-eligible findings are promoted to the findings ledger and
        # broadcast; low-confidence findings are quarantined instead.
        if thread and getattr(thread, "state", None) == ThreadState.COMPLETE:
            self._apply_strict_gate(thread)
            self._publish_finding(thread)
        return thread

    # -- Fuzz-bridge integration (Phase 3) --------------------------------

    def _fuzz_mutations(self, base_url: str) -> List[Any]:
        """Deterministic fuzz mutation set from the campaign's own surface.

        Builds Mutation objects (tools.mutator) per registered asset endpoint
        with the fuzz catalog's boundary/injection values — the same shape
        the discovery scheduler consumes, so the fuzz pass is coverage-aware
        and deterministic (stable ordering, bounded set).  Absolute endpoint
        URLs are used as-is; relative paths join against ``base_url``.
        """
        from tools.mutator import Mutation, RiskClass

        mutations: List[Any] = []
        seen: set = set()
        base = (base_url or "").rstrip("/")
        for asset in self.campaign.list_assets():
            endpoints = list(getattr(asset, "endpoints", []) or [])
            if not endpoints:
                continue
            for ep in endpoints:
                url = ep if ep.startswith(("http://", "https://")) \
                    else f"{base}{ep}"
                # Deterministic fuzz catalog per endpoint (bounded).
                for kind, value in (("boundary", "0"),
                                    ("boundary", "-1"),
                                    ("boundary", "999999999999999999"),
                                    ("injection", "' OR '1'='1"),
                                    ("injection", "1 AND SLEEP(1)--"),
                                    ("mass_assignment", {"role": "admin"})):
                    key = (url, kind, str(value))
                    if key in seen:
                        continue
                    seen.add(key)
                    op_id = hashlib.sha256(
                        f"{asset.asset_id}:{url}:{kind}".encode()
                    ).hexdigest()[:12]
                    if kind == "mass_assignment":
                        path = url
                        mutated = value
                        method = "POST"
                        variable = ""
                    else:
                        # Embed the fuzz value in the query so the crash is
                        # reproducible: the spawned thread re-probes the SAME
                        # URL and must re-trigger the crash (recorded in its
                        # evidence) — a body-only fuzz value would vanish
                        # when the loop re-probes with the generic probe set.
                        from urllib.parse import quote
                        sep = "&" if "?" in url else "?"
                        path = f"{url}{sep}q={quote(str(value), safe='')}"
                        mutated = None
                        method = "GET"
                        variable = "q"
                    mutations.append(Mutation(
                        mutation_id=hashlib.sha256(
                            f"{asset.asset_id}:{url}:{kind}:{value}".encode()
                        ).hexdigest()[:16],
                        operation_id=op_id,
                        method=method,
                        path=path,
                        kind=kind,
                        variable=variable,
                        mutated=mutated,
                        bug_class=(kind if kind != "boundary"
                                   else "input_validation"),
                        risk=RiskClass.READ,
                    ))
        return mutations

    def _fuzz_and_spawn_threads(self, *, base_url: str = "",
                                budget: int = 0,
                                transport=None,
                                project_root: Optional[str] = None) -> Dict[str, Any]:
        """Run one fuzz pass; spawn a research thread per crash/anomaly.

        Executes the fuzz bridge over the campaign surface and converts every
        crash / timeout / anomaly / **blocked** observation into a **new
        research thread** targeting that endpoint.  Each spawned thread
        carries the recorded fuzz evidence (``live_evidence``) so the F0.5
        reproducible gate sees real proof, and its objective names the fuzz
        signal — the loop then probes the spawned thread like any other unit.
        Blocked (403/WAF) observations additionally run through
        ``failure_learning``: the blocker is recorded and bypass candidates
        are quarantined (``research/<target>/learning/
        failure-bypass-candidates.json``), and the spawned thread's research
        plan is to **bypass** the defense using those candidates.

        Novel-class feed: the same fuzz signals are also routed into the
        zero-day hunter (``ZeroDayResearchEngine.hunt_fuzz_signals``) so the
        anomaly and diff-analysis modes consume them — every signal becomes
        an anomaly candidate and every crash a baseline-vs-mutation behavior
        differential, stamped with the fuzz provenance (mutation_id,
        replay_key) and persisted under
        ``research/<target>/zero-day/fuzz-signals.jsonl``. Advisory: a feed
        failure never gates the fuzz pass.

        Dedup: a thread is only spawned when no active thread already targets
        the same endpoint with the same fuzz state (repeat fuzz passes on a
        stubborn surface never pile up threads).
        """
        from tools.core.fuzz_bridge import run_fuzzing_campaign

        mutations = self._fuzz_mutations(base_url)
        if not mutations:
            return {"probes": 0, "signals": 0, "blocked": 0,
                    "spawned": 0, "novel": 0}
        fuzz = run_fuzzing_campaign(
            self.target, base_url=base_url, mutations=mutations[: max(1, budget)],
            transport=transport, project_root=project_root, publish=False)

        spawned = 0
        active = {(t.endpoint, t.bug_class)
                  for t in self.campaign.list_threads() if not t.is_terminal}
        assets = self.campaign.list_assets()
        asset_by_id = {a.asset_id: a for a in assets}
        default_asset = next(iter(assets), None)

        for obs in fuzz.observations:
            if obs.state not in ("crash", "timeout", "anomaly", "blocked"):
                continue
            endpoint = obs.url
            bug_class = f"fuzz_{obs.state}"
            if (endpoint, bug_class) in active:
                continue
            # Attach the threat to the asset that owns this endpoint.
            asset = None
            for a in assets:
                if endpoint in (getattr(a, "endpoints", []) or []):
                    asset = a
                    break
            asset = asset or default_asset
            if asset is None:
                continue
            # Re-activate the asset so the newly spawned thread dispatches:
            # the queue drained because the asset was exhausted, and a
            # spawned thread must bring it back into deep research.
            if asset.status == AssetStatus.EXHAUSTED:
                asset.status = AssetStatus.DEEP_RESEARCH
                asset.completed_at = ""
                self.campaign.update_asset(asset)
            if obs.state == "blocked":
                # Adaptive learning: record the blocker and quarantine bypass
                # candidates so the spawned thread hunts a bypass (not a
                # crash).  Advisory — a learning failure never gates the spawn.
                blocker = obs.signal or f"blocked ({obs.status}) on {endpoint}"
                try:
                    from tools.intelligence.failure_learning import (
                        learn, write_report as fl_write)
                    report = learn(self.target, [{
                        "blocker": blocker,
                        "defense": str((getattr(obs, "evidence", None) or {})
                                       .get("waf") or "unknown"),
                        "bug_class": "web",
                    }], project_root=project_root)
                    if report.candidates:
                        fl_write(report, project_root=project_root)
                except Exception:
                    pass  # advisory
                # The rationale becomes the thread objective, so the bypass
                # intent must live here (research_plan alone is not carried).
                rationale = (f"fuzz blocked on {endpoint}: {obs.signal} — "
                             "bypass the defense with the quarantined "
                             "failure-learning candidates")
                research_plan = (
                    "Bypass the blocking defense using the quarantined "
                    "failure-learning candidates, then demonstrate impact.")
            else:
                rationale = f"fuzz {obs.state} on {endpoint}: {obs.signal}"
                research_plan = ("Reproduce the fuzz signal with a live "
                                 "probe and demonstrate impact.")
            threat = ThreatHypothesis(
                threat_id=hashlib.sha256(
                    f"{asset.asset_id}:{endpoint}:{obs.state}".encode()
                ).hexdigest()[:12],
                type=bug_class,
                confidence="high",
                rationale=rationale,
                target_endpoints=[endpoint],
                research_plan=research_plan,
            )
            thread = self.campaign.spawn_thread(asset, threat)
            # Carry the recorded fuzz evidence so the reproducible gate has
            # real proof and the probe objective names the signal.
            if getattr(obs, "evidence", None):
                thread.live_evidence = obs.evidence
            thread.confirmed_behavior = obs.signal
            thread.endpoint = endpoint
            thread.bug_class = bug_class
            self.campaign.save_thread(thread)
            active.add((endpoint, bug_class))
            spawned += 1

        # Feed the fuzz signals into the novel-class hunter (zero-day anomaly
        # + diff modes): crash/timeout/anomaly evidence becomes candidates
        # registered for novelty assessment and persisted for the operator.
        novel = 0
        try:
            from tools.research_model import NoveltyLabel
            from tools.zero_day import ZeroDayResearchEngine
            zengine = ZeroDayResearchEngine(self.target)
            registered = zengine.register(
                zengine.hunt_fuzz_signals(fuzz.observations))
            novel = len([c for c in registered
                         if c.novelty != NoveltyLabel.EXACT_DUPLICATE])
            if registered:
                out_dir = self.project / "research" / self.target / "zero-day"
                out_dir.mkdir(parents=True, exist_ok=True)
                with (out_dir / "fuzz-signals.jsonl").open(
                        "a", encoding="utf-8") as stream:
                    for candidate in registered:
                        stream.write(json.dumps(
                            candidate.to_dict(), sort_keys=True,
                            default=str) + "\n")
        except Exception as exc:
            logger.warning("fuzz -> novel-class feed skipped: %s", exc)
        return {"probes": fuzz.mutations_run,
                "signals": (fuzz.crashes + fuzz.timeouts + fuzz.anomalies
                             + fuzz.blocked),
                "blocked": fuzz.blocked,
                "spawned": spawned, "novel": novel}

    def live_feedback_loop(self, *, base_url: str = "",
                           max_units: int = 20,
                           require_reproducible: bool = True,
                           transport=None,
                           fuzz_budget: int = 0,
                           run_exploits: bool = True,
                           project_root: Optional[str] = None) -> Dict[str, Any]:
        """Run the live execution harness loop: probe -> observe -> adapt.

        For each dispatched research unit:
          1. Execute its probe set against the live target
             (``tools/core/live_executor.execute_probe``) — real HTTP,
             real responses, recorded evidence.
          2. Classify the result (clean / signal / blocked / error) and
             register the observation back onto the thread with the real
             probe evidence.
          3. Adapt:
             * blocked (403/WAF)  -> ``failure_learning`` records the
               blocker + quarantined bypass candidates; thread transitions
               to BLOCKED for an operator decision.
             * signal             -> thread moves SIGNAL_FOUND -> COMPLETE
               with confirmed behavior; the F0.5 gate runs (with the
               recorded evidence; ``require_reproducible`` forces the
               reproducible-evidence gate).
             * clean              -> thread REFUTED (definitively not
               vulnerable for this probe set).
             * error (timeout/refused) -> observation only, no state change.

        Fuzz-bridge integration: when ``fuzz_budget > 0`` and the research
        queue empties, one coverage-aware fuzz campaign runs against the
        live surface (``tools/core/fuzz_bridge``); every crash / timeout /
        anomaly observation **spawns a new research thread** targeting that
        endpoint with the recorded fuzz evidence attached, so the loop keeps
        probing the surface the deterministic fuzzer flagged.  The same
        signals are fed into the zero-day novel-class hunter
        (``ZeroDayResearchEngine.hunt_fuzz_signals``) — anomaly and
        diff-analysis candidates stamped with the fuzz provenance
        (``summary["fuzz"]["novel"]``), persisted under
        ``research/<target>/zero-day/fuzz-signals.jsonl``.  Fuzz spawns are
        deduped per (endpoint, state) and bounded by the fuzz budget.

        Returns a deterministic run summary (units/probes/outcomes/fuzz).
        Never raises: transport failures are observations, not gates.  This
        is the planner->hunter loop — units are executed, not handed to a
        model.
        """
        from tools.core.live_executor import execute_probe, classify_probe
        from tools.refutation import RefutationEngine

        summary = {"units": 0, "probes": 0, "confirmed": 0,
                   "refuted": 0, "blocked": 0, "errors": 0,
                   "outcomes": {}, "fuzz": {"ran": False, "probes": 0,
                   "signals": 0, "blocked": 0, "spawned": 0,
                   "novel": 0},
                   "exploits": 0, "exploits_reproduced": 0,
                   "exploit_novel": 0}
        base_url = (base_url or "").rstrip("/")

        fuzz_ran = False
        saw_research = False
        for _ in range(max(1, int(max_units))):
            unit = self.get_next_research_unit()
            if unit is None:
                break
            phase = unit.get("campaign_phase")
            if phase != "researching":
                # Queue drained (threads resolved; orchestrator moved on to
                # discovery/chaining/report): one fuzz pass finds new
                # surface, spawns threads for crash evidence, and the loop
                # keeps going so those threads are probed too.  Only fires
                # after at least one research unit dispatched and never more
                # than once per loop call.
                if (fuzz_budget > 0 and not fuzz_ran and saw_research):
                    fuzz_ran = True
                    fuzz_summary = self._fuzz_and_spawn_threads(
                        base_url=base_url, budget=fuzz_budget,
                        transport=transport,
                        project_root=project_root or str(self.project))
                    summary["fuzz"]["ran"] = True
                    summary["fuzz"]["probes"] += fuzz_summary.get("probes", 0)
                    summary["fuzz"]["signals"] += fuzz_summary.get("signals", 0)
                    summary["fuzz"]["spawned"] += fuzz_summary.get("spawned", 0)
                    summary["fuzz"]["novel"] += fuzz_summary.get("novel", 0)
                    summary["fuzz"]["blocked"] += fuzz_summary.get("blocked", 0)
                    if fuzz_summary.get("spawned"):
                        continue
                break
            saw_research = True
            tid = (unit.get("context") or {}).get("thread_id")
            if not tid:
                # Non-probeable unit (e.g. an operator-decision blocked-thread
                # unit that slipped through as researching): the loop cannot
                # execute it — stop instead of crashing.
                break
            thread = self.campaign.get_thread(tid)
            if thread is None or thread.is_terminal:
                continue


            # 1. Real probe execution.
            target_url = base_url or unit.get("endpoint", "")
            try:
                probe = execute_probe(
                    unit, target_url, transport=transport,
                    project_root=project_root or str(self.project))
            except Exception as exc:  # advisory: never a gate
                logger.warning("live probe failed for %s: %s", tid, exc)
                summary["errors"] += 1
                continue
            summary["units"] += 1
            summary["probes"] += 1
            verdict = classify_probe(probe, unit.get("bug_class", ""))
            summary["outcomes"][verdict] = summary["outcomes"].get(verdict, 0) + 1

            evidence = probe.evidence if probe.evidence else None
            confirmed_behavior = ""
            if verdict == "signal":
                confirmed_behavior = (
                    f"{unit.get('bug_class', '')} signal: "
                    f"{probe.status} on {probe.spec.get('url', '')} "
                    f"({'; '.join(probe.signals[:3]) or 'anomaly'})")

            # 2. Register the real observation back onto the thread.
            if verdict == "blocked":
                summary["blocked"] += 1
                blocker = (f"blocked by {probe.waf_name or 'defense'} "
                           f"({probe.status}) on {probe.spec.get('url', '')}")
                # Adaptive learning: record the blocker and quarantine
                # bypass candidates for the operator / future attempts.
                try:
                    from tools.intelligence.failure_learning import learn
                    learn(self.target, [{
                        "blocker": blocker,
                        "defense": probe.waf_name or "unknown",
                        "bug_class": unit.get("bug_class", "web"),
                    }], project_root=project_root or str(self.project))
                except Exception:
                    pass  # advisory
                self.register_thread_result(
                    tid, observation=blocker, conclusion="blocked",
                    new_state=ThreadState.BLOCKED.value, blocker=blocker)
            elif verdict == "signal":
                # Attach the recorded evidence to the thread BEFORE it
                # completes, so the F0.5 gate sees it and (for live threads)
                # requires reproducibility for CONFIRMED.
                if evidence:
                    thread.live_evidence = evidence
                    self.campaign.save_thread(thread)
                self.register_thread_result(
                    tid,
                    observation=(f"{probe.status} {probe.spec.get('url', '')} "
                                 f"signals={'; '.join(probe.signals[:3]) or 'anomaly'}"),
                    conclusion="confirmed", new_state="complete",
                    confirmed_behavior=confirmed_behavior)
                summary["confirmed"] += 1
                # Live exploitation phase: a gate-CONFIRMED finding (recorded
                # evidence, report-eligible) is replayed to demonstrate
                # impact — same input, recorded second response.
                if run_exploits:
                    fresh = self.campaign.get_thread(tid)
                    if fresh is not None:
                        impact = self._run_exploitation(
                            fresh, base_url=base_url, transport=transport,
                            project_root=project_root or str(self.project))
                        if impact is not None:
                            summary["exploits"] += 1
                            if impact.get("reproduced"):
                                summary["exploits_reproduced"] += 1
                            # Novel-class refinement: the demonstrated
                            # impact fed back into the zero-day hunter.
                            summary["exploit_novel"] += int(
                                impact.get("zero_day_novel") or 0)
            elif verdict == "error":
                summary["errors"] += 1
                self.register_thread_result(
                    tid, observation="probe transport error (timeout/refused)",
                    conclusion="inconclusive")
            else:  # clean
                summary["refuted"] += 1
                self.register_thread_result(
                    tid, observation="no signal across live probe set",
                    conclusion="not vulnerable", new_state="refuted")
        return summary

    @staticmethod
    def _thread_to_finding(thread: Any) -> Dict[str, Any]:
        """Build the finding dict the F0.5 refutation engine scores."""
        observations = list(getattr(thread, "observations", []) or [])
        last = observations[-1] if observations else {}
        severity = str(getattr(thread, "priority", "medium"))
        if hasattr(severity, "value"):
            severity = severity.value
        # Live-execution evidence (Phase 3): a recorded request/response
        # block attached by the live executor is the strongest proof and
        # enables the reproducible-evidence gate.
        recorded_evidence = getattr(thread, "live_evidence", None)
        evidence: Any = list(getattr(thread, "evidence_ids", []) or [])
        if recorded_evidence:
            evidence = recorded_evidence
        return {
            "finding_id": getattr(thread, "finding_id", "") or thread.thread_id,
            "title": getattr(thread, "objective", ""),
            "bug_class": getattr(thread, "bug_class", ""),
            "severity": severity,
            "endpoint": getattr(thread, "endpoint", ""),
            # Deterministic evidence signals for confidence_score.
            "trigger_trace": str(last.get("observation") or ""),
            "impact_trace": getattr(thread, "confirmed_behavior", ""),
            "evidence": evidence,
            "confirmed_behavior": getattr(thread, "confirmed_behavior", ""),
        }

    def _apply_strict_gate(self, thread: Any) -> None:
        """Run a completed thread's finding through the F0.5 strict gate.

        Idempotent: a thread is evaluated exactly once (the first time it is
        observed COMPLETE).  The verdict is recorded on the thread; a
        report-eligible finding is appended to the findings ledger
        (``state/sessions/<target>/findings.jsonl``, consumed by
        chain_orchestrator) and counted in ``report_eligible_findings``.
        Low-confidence findings are DEMOTED + quarantined by the refutation
        engine and never enter the findings ledger — the F0.5 reporting gate
        applied automatically.  Advisory: a failure leaves the thread
        unmarked and never blocks result registration.
        """
        if getattr(thread, "refutation", None):
            return  # already evaluated
        try:
            from tools.refutation import RefutationEngine
        except ImportError:
            return
        try:
            finding = self._thread_to_finding(thread)
            # Live-executed threads carry recorded evidence; the gate then
            # requires reproducible proof for CONFIRMED.  Legacy threads
            # (evidence ids only) keep the confidence-only gate.
            require_reproducible = bool(getattr(thread, "live_evidence", None))
            engine = RefutationEngine(self.target, project_root=str(self.project),
                                      require_reproducible=require_reproducible)
            record = engine.refute(finding, model="uncensored")
        except Exception as exc:
            logger.warning("F0.5 strict gate skipped for %s: %s",
                           thread.thread_id, exc)
            return
        thread.refutation = {
            "finding_id": record.finding_id,
            "final_verdict": record.final_verdict.value,
            "confidence": record.confidence,
            "eligible_for_report": record.eligible_for_report,
            "quarantined": record.quarantined,
            "survived_passes": record.survived_passes,
            "killed_passes": record.killed_passes,
            "evaluated_at": record.created_at,
        }
        self.campaign.save_thread(thread)
        if record.eligible_for_report:
            self._append_finding_record(thread)
            state = self.campaign.load()
            state.report_eligible_findings += 1
            self.campaign.save(state)

    def _append_finding_record(self, thread: Any) -> None:
        """Append a report-eligible finding to the findings ledger.

        Schema is chain_orchestrator-compatible (``state == "FINDING"``,
        ``finding_id``/``id``, ``bug_class``, ``endpoint``, ``severity``) plus
        the F0.5 refutation evidence.  Append-only JSONL under
        ``state/sessions/<target>/``.
        """
        from tools.state import add_finding
        severity = str(getattr(thread, "priority", "medium"))
        if hasattr(severity, "value"):
            severity = severity.value
        record = {
            "finding_id": getattr(thread, "finding_id", "") or thread.thread_id,
            "id": getattr(thread, "finding_id", "") or thread.thread_id,
            "thread_id": thread.thread_id,
            "state": "FINDING",
            "bug_class": getattr(thread, "bug_class", ""),
            "endpoint": getattr(thread, "endpoint", ""),
            "severity": severity,
            "title": getattr(thread, "objective", ""),
            "confirmed_behavior": getattr(thread, "confirmed_behavior", ""),
            "demonstrated_impact": (
                getattr(thread, "live_exploit", None) or {}
            ).get("demonstrated_impact", ""),
            "refutation": thread.refutation,
            "recorded_at": _now(),
            "method": getattr(thread, "method", "GET"),
            "evidence": getattr(thread, "live_evidence", None) or {},
        }
        add_finding(self.target, record, project_root=str(self.project))

    def _run_exploitation(self, thread: Any, *, base_url: str = "",
                          transport=None,
                          project_root: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Replay a gate-CONFIRMED finding's recorded request to show impact.

        Only runs for findings the F0.5 gate marked report-eligible (CONFIRMED
        with recorded, reproducible evidence).  Re-sends the recorded request
        via ``tools/core/live_executor.execute_exploit`` and records the
        *second* response — the deterministic impact demonstration: the same
        input reproduces the same outcome (``reproduced=True``) and the
        response body is captured as evidence of what the attacker obtains.

        The demonstration is persisted on the thread (``live_exploit``),
        appended to ``state/sessions/<target>/exploits.jsonl``, and returned.
        Advisory: a replay failure returns None and never gates the campaign.
        """
        from tools.core.live_executor import execute_exploit

        refutation = getattr(thread, "refutation", None) or {}
        if not refutation.get("eligible_for_report"):
            return None  # only CONFIRMED findings get exploited
        finding = self._thread_to_finding(thread)
        target_url = base_url or str(getattr(thread, "endpoint", "") or "")
        try:
            result = execute_exploit(
                finding, target_url, transport=transport,
                project_root=project_root or str(self.project))
        except Exception as exc:
            logger.warning("exploitation replay failed for %s: %s",
                           thread.thread_id, exc)
            return None
        evidence = getattr(result, "evidence", None) or {}
        response = evidence.get("response") or {}
        body = str(response.get("body") or response.get("body_preview") or "").strip()
        if not body and getattr(result, "response_body", None):
            body = str(result.response_body).strip()
        impact = {
            "schema": "bugwolf/exploit-demonstration/v1",
            "finding_id": refutation.get("finding_id") or thread.thread_id,
            "thread_id": thread.thread_id,
            "bug_class": getattr(thread, "bug_class", ""),
            "endpoint": getattr(thread, "endpoint", ""),
            "replayed_status": getattr(result, "status", 0),
            "reproduced": bool(evidence.get("reproduced")),
            "replay_key": evidence.get("replay_key", ""),
            "recorded_at": _now(),
        }
        # Impact demonstration: the data actually obtained by the replay
        # (truncated for the ledger; full body lives in the probe evidence).
        impact["demonstrated_impact"] = body[:500] or str(
            getattr(result, "response_body", "") or "")[:500]
        # Exploit feedback: the demonstrated impact unlocks new chain
        # hypotheses ("what else does the data unlock").  Advisory — a
        # feedback failure never gates the exploitation phase.
        thread.live_exploit = impact
        self._feed_exploit_to_chains(thread, impact,
                                     project_root=project_root)
        self.campaign.save_thread(thread)
        self._append_exploit_record(impact)
        return impact

    def exploit_approved_bypass(self, thread: Any, candidate: Any, *,
                                base_url: str = "",
                                transport=None,
                                project_root: Optional[str] = None
                                ) -> Optional[Dict[str, Any]]:
        """Exploit a fuzz_blocked thread with an operator-approved bypass.

        Once an operator approves a quarantined failure-learning candidate
        (``failure_learning.approve_candidate``), this replays the approved
        payload live against the blocked thread's endpoint: the blocked
        request is rebuilt from the thread's recorded evidence with the
        bypass applied (``Name: value`` payloads become headers,
        ``?…`` payloads append to the query, otherwise the payload rides in
        the body for mutating methods or ``?q=`` for GET) and re-sent via
        ``execute_exploit``.  The outcome is recorded in the exploit ledger
        as a ``kind="bypass-approval"`` demonstration — the impact of
        getting through the defense.

        Advisory: a replay failure returns None and never gates the
        campaign.  The thread itself stays BLOCKED (the operator decision
        is untouched); only the ledger records the approved exploitation.
        """
        import re as _re
        from tools.core.live_executor import execute_exploit

        endpoint = str(getattr(thread, "endpoint", "") or "")
        target_url = base_url or endpoint
        if not target_url:
            return None
        evidence = getattr(thread, "live_evidence", None) or {}
        request = dict(evidence.get("request") or {})
        method = str(request.get("method") or "GET")
        url = str(request.get("url") or target_url)
        headers = dict(request.get("headers") or {})
        body = request.get("body")
        payload = str(getattr(candidate, "payload", "") or "")
        technique = str(getattr(candidate, "technique", "") or "")
        if not payload:
            return None
        header_match = _re.match(r"^\s*([A-Za-z0-9-]+)\s*:\s*(.+?)\s*$",
                                 payload)
        if header_match:
            headers[header_match.group(1)] = header_match.group(2)
        elif payload.startswith("?"):
            url = url + payload
        elif method in ("POST", "PUT", "PATCH"):
            body = (str(body) + payload) if body is not None else payload
        else:
            from urllib.parse import quote
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}q={quote(payload, safe='')}"
        finding = {
            "finding_id": getattr(thread, "thread_id", ""),
            "bug_class": "fuzz_blocked",
            "evidence": {"request": {
                "method": method, "url": url, "headers": headers,
                "body": body, "technique": technique or "approved-bypass",
                "bug_class": "fuzz_blocked",
            }},
        }
        try:
            result = execute_exploit(
                finding, target_url, transport=transport,
                project_root=project_root or str(self.project))
        except Exception as exc:
            logger.warning("approved-bypass replay failed for %s: %s",
                           thread.thread_id, exc)
            return None
        evidence_out = getattr(result, "evidence", None) or {}
        response = evidence_out.get("response") or {}
        body_out = str(response.get("body") or response.get("body_preview") or "").strip()
        if not body_out and getattr(result, "response_body", None):
            body_out = str(result.response_body).strip()
        impact = {
            "schema": "bugwolf/exploit-demonstration/v1",
            "kind": "bypass-approval",
            "candidate_id": str(getattr(candidate, "candidate_id", "")),
            "technique": technique,
            "approved_by": str(getattr(candidate, "approved_by", "") or ""),
            "finding_id": getattr(thread, "thread_id", ""),
            "thread_id": getattr(thread, "thread_id", ""),
            "bug_class": "fuzz_blocked",
            "endpoint": endpoint,
            "replayed_status": getattr(result, "status", 0),
            # The bypass "reproduced" when the replay got through the
            # defense (a real response that is not a block).
            "reproduced": bool(getattr(result, "status", 0))
            and not bool(getattr(result, "blocked", False)),
            "replay_key": evidence_out.get("replay_key", ""),
            "recorded_at": _now(),
        }
        impact["demonstrated_impact"] = body_out[:500] or str(
            getattr(result, "response_body", "") or "")[:500]
        self._append_exploit_record(impact)
        return impact

    def _append_exploit_record(self, impact: Dict[str, Any]) -> None:
        """Append the impact demonstration to the exploit ledger (advisory)."""
        try:
            path = self.project / "state" / "sessions" / self.target \
                / "exploits.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(impact, sort_keys=True) + "\n")
                stream.flush()
        except OSError:
            pass  # advisory: an unwritable ledger never gates the campaign

    def _feed_exploit_to_chains(self, thread: Any, impact: Dict[str, Any], *,
                                project_root: Optional[str] = None) -> None:
        """Feed a reproduced exploit's impact back as new chain hypotheses.

        When the replay actually demonstrated impact (``reproduced`` with a
        recorded body), the data obtained may unlock further bug classes.
        Deterministic heuristics (``tools/leads.chain_hypotheses_from_exploit``)
        derive the downstream hypotheses, each is persisted as an OPEN-LEAD
        chain-pool record (``state/sessions/<target>/leads.jsonl``, the same
        store ``chain_orchestrator.refresh_target`` reads), the chain graph is
        rebuilt so the new leads surface in proposals, and the hypotheses ride
        back on the impact record + a ``CHAIN_PROPOSAL`` event.

        Advisory: any failure here (derivation, write, refresh, publish) is
        logged and never gates the exploitation phase.
        """
        try:
            from tools.leads import chain_hypotheses_from_exploit
            body = impact.get("demonstrated_impact") or ""
            if not impact.get("reproduced") or not body:
                return
            finding = self._thread_to_finding(thread)
            finding["target"] = self.target
            records = chain_hypotheses_from_exploit(body, finding)
            if not records:
                return
            path = self.project / "state" / "sessions" / self.target \
                / "leads.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            existing_ids = set()
            if path.is_file():
                for line in path.read_text(encoding="utf-8").splitlines():
                    try:
                        existing_ids.add(json.loads(line).get("lead_id", ""))
                    except json.JSONDecodeError:
                        continue
            with path.open("a", encoding="utf-8") as stream:
                for record in records:
                    if record.get("lead_id") in existing_ids:
                        continue
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                    existing_ids.add(record.get("lead_id", ""))
                stream.flush()
            # Rebuild the chain graph so the new leads join chain proposals.
            from tools.chain_orchestrator import refresh_target
            refresh_target(project_root or str(self.project), self.target)
            impact["chain_hypotheses"] = records
            self._publish_chain_hypotheses(records)
            # Novel-class refinement: the demonstrated impact is also fed
            # into the zero-day hunter so the novelty assessment of the
            # unlocked surfaces is refined by real exploit evidence.
            impact["zero_day_novel"] = self._feed_exploit_to_zero_day(impact)
        except Exception as exc:
            logger.warning("exploit->chain feedback failed for %s: %s",
                           thread.thread_id, exc)

    def _feed_exploit_to_zero_day(self, impact: Dict[str, Any]) -> int:
        """Feed a reproduced exploit's impact into the novel-class hunter.

        Routes the impact (demonstrated data + derived chain hypotheses)
        through ``ZeroDayResearchEngine.hunt_exploit_feedback``: the impact
        is registered for novelty assessment (unlock candidates are built
        impact-bounded, so the engine promotes them into NOVELTY_PENDING
        with impact evidence) and persisted under
        ``research/<target>/zero-day/exploit-feedback.jsonl``. Returns the
        count of non-duplicate novel-class candidates. Advisory: a feed
        failure logs and returns 0 — never gates the exploitation phase.
        """
        try:
            from tools.research_model import NoveltyLabel
            from tools.zero_day import ZeroDayResearchEngine
            zengine = ZeroDayResearchEngine(self.target)
            registered = zengine.register(
                zengine.hunt_exploit_feedback([impact]))
            novel = len([c for c in registered
                         if c.novelty != NoveltyLabel.EXACT_DUPLICATE])
            if registered:
                out_dir = self.project / "research" / self.target \
                    / "zero-day"
                out_dir.mkdir(parents=True, exist_ok=True)
                with (out_dir / "exploit-feedback.jsonl").open(
                        "a", encoding="utf-8") as stream:
                    for candidate in registered:
                        stream.write(json.dumps(
                            candidate.to_dict(), sort_keys=True,
                            default=str) + "\n")
            return novel
        except Exception as exc:
            logger.warning("exploit -> zero-day feed skipped: %s", exc)
            return 0

    def _publish_chain_hypotheses(self, records: List[Dict[str, Any]]) -> None:
        """Publish CHAIN_PROPOSAL so chain discovery reacts to the feedback.

        Advisory: a publish failure never gates the campaign.
        """
        if self._signal_bus is None:
            return
        try:
            self._signal_bus.publish(
                "CHAIN_PROPOSAL", source="campaign_orchestrator",
                payload={"target": self.target, "kind": "exploit-feedback",
                         "hypotheses": records})
        except OSError as exc:
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    def _publish_finding(self, thread: Any) -> None:
        """Publish FINDING_DISCOVERED so chain discovery reacts immediately.

        Advisory: the chain-graph refresh listener runs opportunistically and
        never gates the campaign.
        """
        if self._signal_bus is None:
            return
        try:
            payload = {
                "target": self.target,
                "thread_id": thread.thread_id,
                "bug_class": getattr(thread, "bug_class", ""),
                "endpoint": getattr(thread, "endpoint", ""),
                "confirmed_behavior": getattr(thread, "confirmed_behavior", ""),
            }
            refutation = getattr(thread, "refutation", None) or {}
            if refutation:
                payload["refutation_verdict"] = refutation.get("final_verdict")
                payload["confidence"] = refutation.get("confidence")
                payload["eligible_for_report"] = refutation.get("eligible_for_report")
            self._signal_bus.publish(
                "FINDING_DISCOVERED", source="campaign_orchestrator",
                payload=payload)
        except OSError as exc:
            # Advisory: an unwritable event log must never gate the campaign.
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
        # ValueError (unregistered event type) and other programming errors
        # propagate loudly instead of being silently swallowed.

    # -- Blocked / chain / report units ------------------------------------

    def _build_blocked_unit(self, blocked: List) -> Dict[str, Any]:
        """Build a research unit for handling blocked threads."""
        blockers = "\n".join(
            f"  - Thread {t.thread_id[:8]} ({t.bug_class}): {t.current_blocker}"
            for t in blocked[:5])
        unit = build_research_unit(
            objective="Resolve blocked research threads",
            context={
                "blocked_threads": [
                    {"id": t.thread_id, "bug_class": t.bug_class,
                     "blocker": t.current_blocker}
                    for t in blocked
                ],
                "options": [
                    "Provide an alternative approach and re-fire the probe",
                    "Accept limited impact and transition to DOCUMENTED_LIMITED",
                    "Mark as REFUTED if the blocker is insurmountable",
                    "Request more budget/time/resources",
                ],
            },
            success_criteria=[
                "Resolve or make progress on at least one blocked thread",
                "Register the outcome via --register-result",
            ],
        )
        # An operator-decision unit, not a live-probeable research unit: the
        # live loop must not try to execute it (no thread_id in context).
        unit["campaign_phase"] = CampaignPhase.RESEARCH
        return unit

    def _build_chain_unit(self) -> Dict[str, Any]:
        """Build a research unit for cross-asset chain analysis."""
        findings = []
        for t in self.campaign.list_threads(state=ThreadState.COMPLETE):
            findings.append({
                "thread_id": t.thread_id,
                "asset_id": t.asset_id,
                "bug_class": t.bug_class,
                "impact": t.confirmed_behavior,
            })

        unit = build_research_unit(
            objective="Cross-asset chain analysis — connect findings for maximum impact",
            context={
                "completed_findings": findings,
                "instructions": (
                    "Chain findings across assets to achieve higher-impact "
                    "compromise. For each chain: identify connectable findings, "
                    "verify each link is executable, chain end-to-end, and "
                    "record the complete attack chain with evidence."
                ),
            },
            success_criteria=[
                "Identify at least 3 viable cross-asset attack chains",
                "Execute and verify at least 1 chain end-to-end",
                "Document chain evidence for disclosure",
            ],
        )
        unit["campaign_phase"] = CampaignPhase.CHAINING
        return unit

    # -- Status & reporting -------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Get full campaign status (campaign + workflow + research)."""
        ctx = self.get_context()
        resume = self.campaign.get_resume()
        assets = self.campaign.list_assets()
        threads = self.campaign.list_threads()

        return {
            "campaign": {
                "target": ctx.target,
                "phase": ctx.phase,
                "summary": ctx.summary,
                "assets_discovered": ctx.assets_discovered,
                "assets_exhausted": ctx.assets_exhausted,
                "discovery_rounds": self.campaign.load().discovery_rounds,
                "discovery_complete": self.campaign.load().discovery_complete,
                "active_threads": ctx.active_threads,
                "findings": ctx.findings,
                "report_eligible_findings": self.campaign.load().report_eligible_findings,
                "zero_day_candidates": ctx.zero_day_candidates,
            },
            "workflow": ctx.workflow,
            "research": ctx.research,
            "next_action": ctx.next_action,
            "resume": resume.to_dict() if resume else None,
            "pending_decisions": ctx.pending_decisions,
            "assets": [a.to_dict() for a in assets],
            "active_threads_detail": [
                {
                    "thread_id": t.thread_id,
                    "state": t.state.value,
                    "bug_class": t.bug_class,
                    "objective": t.objective,
                    "endpoint": t.endpoint,
                    "iterations": t.iterations,
                }
                for t in threads if not t.is_terminal
            ],
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Campaign Orchestrator — APT Commander")
    parser.add_argument("--target", required=True,
                        help="Target hostname or project identifier")
    parser.add_argument("--init", action="store_true",
                        help="Initialize new campaign + workflow manifest")
    parser.add_argument("--next-unit", action="store_true",
                        help="Get the next research unit for the harness to execute")
    parser.add_argument("--status", action="store_true",
                        help="Show full campaign status (campaign + workflow + research)")
    parser.add_argument("--register-discoveries", metavar="FILE",
                        help="Register discovered assets from a JSON file")
    parser.add_argument("--register-recon", metavar="FILE",
                        help="Register recon output for one asset (JSON)")
    parser.add_argument("--register-result", metavar="FILE",
                        help="Register a thread result (JSON with thread_id + new_state/observation)")
    parser.add_argument("--discovery-complete", action="store_true",
                        help="Declare discovery source-exhausted (termination flag)")
    parser.add_argument("--run-research", action="store_true",
                        help="Run the mandatory 7-checkpoint research sequence")
    parser.add_argument("--phase", choices=["before_hunt", "recon", "bypass",
                        "after_findings", "full"], default="full")
    parser.add_argument("--mode", default="web",
                        help="Comma-separated research modes (web, llm-ai, solidity, ...)")
    parser.add_argument("--stack", default="",
                        help="Detected stack for CVE research (comma-separated)")
    parser.add_argument("--bug-classes", default="",
                        help="Found bug classes for post-findings research")
    parser.add_argument("--defense", default="",
                        help="Blocker defense for bypass research")
    parser.add_argument("--workflow-status", action="store_true",
                        help="Show the 12-stage workflow state")
    parser.add_argument("--workflow-complete", metavar="STAGE",
                        help="Advance the 12-stage workflow (strict pipeline)")
    parser.add_argument("--artifact", action="append", default=[],
                        help="Workflow stage artifact (repeatable)")
    parser.add_argument("--scope-file", help="Authorization scope file (workflow stage)")
    parser.add_argument("--notes", default="", help="Short operator note")
    parser.add_argument("--budget-hours", type=int, default=72,
                        help="Campaign time budget (default: 72h)")
    parser.add_argument("--llm-advisor", action="store_true",
                        help="Enrich research units with seed-advisor probe "
                             "proposals (deterministic core still decides)")
    parser.add_argument("--pass-at-k", type=int, default=1,
                        help="Test-time compute scaling: spawn k diverse "
                             "variant threads per threat (default: 1)")
    parser.add_argument("--deep-dive", action="store_true",
                        help="Preset for --pass-at-k 3: spawn three diverse "
                             "variant threads per threat")
    parser.add_argument("--live-run", action="store_true",
                        help="Run the live execution harness loop: probe -> "
                             "observe -> adapt (real HTTP, recorded evidence)")
    parser.add_argument("--live-base-url", default="",
                        help="Target base URL for --live-run (default: unit endpoint)")
    parser.add_argument("--live-max-units", type=int, default=20,
                        help="Max research units for --live-run")
    parser.add_argument("--fuzz-budget", type=int, default=0,
                        help="With --live-run: run one fuzz pass when the "
                             "research queue drains and spawn a thread per "
                             "crash/timeout/anomaly (0 = off)")
    parser.add_argument("--no-exploits", action="store_true",
                        help="With --live-run: skip the live exploitation "
                             "phase (replay of gate-CONFIRMED findings)")
    parser.add_argument("--json", action="store_true",
                        help="Emit strict JSON output")
    args = parser.parse_args()

    try:
        pass_at_k = args.pass_at_k
        if args.deep_dive:
            pass_at_k = max(pass_at_k, 3)
        orch = CampaignOrchestrator(
            args.target, budget_hours=args.budget_hours, mode=args.mode,
            llm_advisor=args.llm_advisor, pass_at_k=pass_at_k)

        if args.init:
            orch.initialize()
            ctx = orch.get_context()
            result = {"campaign": ctx.target, "phase": ctx.phase,
                      "next_action": ctx.next_action,
                      "workflow": ctx.workflow}
        elif args.workflow_status:
            result = orch.workflow_status()
        elif args.workflow_complete:
            orch.initialize()
            result = orch.complete_workflow_stage(
                args.workflow_complete, artifacts=args.artifact,
                scope_file=args.scope_file, notes=args.notes)
        elif args.discovery_complete:
            orch.initialize()
            state = orch.mark_discovery_complete()
            result = {"campaign": state.target, "phase": state.status,
                      "discovery_complete": True}
        elif args.register_discoveries:
            orch.initialize()
            data = json.loads(Path(args.register_discoveries).read_text(
                encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("--register-discoveries expects a JSON list")
            count = orch.register_discovered_assets(data)
            ctx = orch.get_context()
            result = {"campaign": ctx.target, "registered": count,
                      "phase": ctx.phase, "summary": ctx.summary}
        elif args.register_recon:
            orch.initialize()
            data = json.loads(Path(args.register_recon).read_text(
                encoding="utf-8"))
            asset = orch.register_recon(
                data.get("asset_id", ""),
                endpoints=data.get("endpoints"),
                tech=data.get("tech"),
                ports=data.get("ports"))
            result = {"asset_id": asset.asset_id, "hostname": asset.hostname,
                      "endpoints": len(asset.endpoints),
                      "tech": asset.detected_tech, "ports": asset.ports,
                      "recon_complete": asset.recon_complete}
        elif args.register_result:
            orch.initialize()
            data = json.loads(Path(args.register_result).read_text(
                encoding="utf-8"))
            thread = orch.register_thread_result(
                data.get("thread_id", ""),
                action=data.get("action", ""),
                observation=data.get("observation", ""),
                conclusion=data.get("conclusion", ""),
                new_state=data.get("new_state"),
                confirmed_behavior=data.get("confirmed_behavior", ""),
                last_successful_action=data.get("last_successful_action", ""),
                endpoint=data.get("endpoint", ""),
                suggested_approaches=data.get("suggested_approaches"),
                blocker=data.get("blocker", ""))
            result = {"thread_id": thread.thread_id,
                      "state": thread.state.value,
                      "iterations": thread.iterations,
                      "confirmed_behavior": thread.confirmed_behavior}
        elif args.live_run:
            orch.initialize()
            result = orch.live_feedback_loop(
                base_url=args.live_base_url, max_units=args.live_max_units,
                fuzz_budget=args.fuzz_budget,
                run_exploits=not args.no_exploits,
                project_root=str(orch.project))
            result = {"campaign": orch.target, "live_run": result}
        elif args.run_research:
            orch.initialize()
            result = orch.run_research(
                phase=args.phase, stack=args.stack,
                bug_classes=args.bug_classes, defense=args.defense)
        elif args.next_unit:
            orch.initialize()
            unit = orch.get_next_research_unit()
            if unit is None:
                ctx = orch.get_context()
                result = {"campaign": ctx.target, "phase": ctx.phase,
                          "next_action": "Campaign exhausted — all assets researched, "
                                         "chained, and reported"}
            else:
                unit["campaign_phase"] = unit.get("campaign_phase",
                                                  CampaignPhase.RESEARCHING)
                result = unit
        elif args.status:
            orch.initialize()
            result = orch.status()
        else:
            parser.print_help()
            return 1

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print("=" * 72)
            print(f"CAMPAIGN: {args.target} | {result.get('phase') or result.get('campaign_phase', 'ok')}")
            print("=" * 72)
            if isinstance(result, dict) and "summary" in result:
                print(result["summary"])
            if isinstance(result, dict) and "objective" in result:
                print(f"\nOBJECTIVE: {result['objective']}\n")
                for c in result.get("success_criteria", []):
                    print(f"  • {c}")
            else:
                print(json.dumps(result, indent=2, default=str))
            print("=" * 72)
        return 0

    except (ValueError, FileNotFoundError, OSError, WorkflowError,
            ResearchFreshnessError) as exc:
        if args.json:
            print(json.dumps({"schema": "bugwolf-campaign-v2",
                              "target": args.target, "error": str(exc)},
                             indent=2))
        else:
            print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
