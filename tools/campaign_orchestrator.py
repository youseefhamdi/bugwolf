#!/usr/bin/env python3
"""BugWolf Campaign Orchestrator — master controller for self-driven APT research.

This is the PLUGIN'S BRAIN. It manages the complete lifecycle:

  1. RECEIVE TARGET → 2. DISCOVER ALL ASSETS → 3. PRIORITIZE →
  4. EXHAUST EACH ASSET A→Z → 5. CROSS-ASSET CHAINING →
  6. REPORT → 7. CONTINUE TO NEXT TARGET

The orchestrator NEVER executes research itself. It dispatches research units
to the HARNESS (Claude Code / Freebuff / Codex), which executes them with full
intelligence. The orchestrator tracks progress, persists state, and ensures:

  - One asset at a time, exhaustively (never skip before completion)
  - Budget-aware allocation (time, threads, LLM tokens)
  - Session persistence (survive harness restarts and crashes)
  - Resume from exact point (never lose progress)

Usage:
  python3 tools/campaign_orchestrator.py --target company.com --init
  python3 tools/campaign_orchestrator.py --target company.com --next-unit
  python3 tools/campaign_orchestrator.py --target company.com --status
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.campaign import (
    AssetRecord, AssetStatus, AssetType, CampaignManager, CampaignState,
    Priority, ResumePoint, ThreadState, safe_target_name,
)
from tools.asset_discovery import AssetDiscoveryEngine
from tools.research_thread import ThreadBuilder


# ---------------------------------------------------------------------------
# Campaign phases
# ---------------------------------------------------------------------------

class CampaignPhase:
    """Named campaign phases with descriptions for the harness."""
    INITIALIZING = "initializing"
    DISCOVERING = "discovering"
    PRIORITIZING = "prioritizing"
    RESEARCHING = "researching"
    CHAINING = "chaining"
    REPORTING = "reporting"
    EXHAUSTED = "exhausted"


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


# ---------------------------------------------------------------------------
# Campaign Orchestrator
# ---------------------------------------------------------------------------

class CampaignOrchestrator:
    """Master controller for a single target's research campaign."""

    def __init__(self, target: str, *,
                 budget_hours: int = 72,
                 max_concurrent_threads: int = 8):
        self.target = safe_target_name(target).replace(":", "_")[:200]
        self.campaign = CampaignManager(target)
        self.discovery = AssetDiscoveryEngine(target)
        self.threads = ThreadBuilder(target)
        self.budget_hours = budget_hours
        self.max_concurrent_threads = max_concurrent_threads

    # -- Lifecycle ---------------------------------------------------------

    def initialize(self) -> CampaignState:
        """Initialize a new campaign for the target."""
        # If campaign already exists, just return it
        if self.campaign.campaign_path.exists():
            return self.campaign.load()

        state = self.campaign.initialize(
            budget_hours=self.budget_hours,
            max_concurrent_threads=self.max_concurrent_threads,
        )
        state.status = CampaignPhase.INITIALIZING
        state.phase = "Campaign initialized. Ready for asset discovery."
        self.campaign.save(state)
        return state

    def get_context(self) -> OrchestratorContext:
        """Build the campaign context for the harness.

        This is what the harness receives to understand what needs to be done
        and make intelligent decisions about how to proceed.
        """
        state = self.campaign.load()
        assets = self.campaign.list_assets()
        threads = self.campaign.list_threads()
        resume = self.campaign.get_resume()

        # Determine current phase
        phase = state.status
        if state.assets_discovered == 0:
            phase = CampaignPhase.DISCOVERING
        elif state.assets_exhausted == 0:
            phase = CampaignPhase.RESEARCHING
        elif state.assets_exhausted >= state.assets_discovered:
            phase = CampaignPhase.CHAINING
        else:
            phase = CampaignPhase.RESEARCHING

        # Build summary
        summary = self._build_summary(state, assets, threads)

        # Build next action
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
        )

    @staticmethod
    def _build_summary(state: CampaignState,
                       assets: List[AssetRecord],
                       threads: List) -> str:
        lines = [
            f"Campaign: {state.target}",
            f"Phase: {state.status}",
            f"Assets: {len(assets)} discovered, {state.assets_exhausted} exhausted",
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

    # -- Phase: Asset Discovery --------------------------------------------

    def get_discovery_unit(self) -> Dict[str, Any]:
        """Get the research unit for the asset discovery phase.

        The harness receives this and executes asset discovery with full
        intelligence — querying DNS, CT logs, search engines, etc.
        """
        state = self.campaign.load()
        state.status = CampaignPhase.DISCOVERING
        state.phase = "Discovering all assets for the target"
        self.campaign.save(state)

        return self.discovery.get_research_unit()

    def register_discovered_assets(self,
                                    discoveries: List[Dict[str, Any]]) -> int:
        """Register assets discovered by the harness."""
        count = self.discovery.register_batch(discoveries)
        state = self.campaign.load()
        state.assets_discovered = len(self.campaign.list_assets())
        self.campaign.save(state)
        return count

    # -- Phase: Asset Prioritization ---------------------------------------

    def get_prioritized_assets(self) -> List[AssetRecord]:
        """Get assets ordered by priority for research."""
        assets = self.campaign.list_assets()
        # Sort by priority, then by type (auth/admin first within same priority)
        priority_order = {
            "critical": 0, "high": 1, "medium": 2, "low": 3,
        }
        type_order = {
            "oauth_idp": 0, "admin_panel": 0, "ci_cd": 0,
            "web_api": 1, "graphql": 1,
            "web_app": 2, "mobile_api": 2, "internal_tool": 2,
            "websocket": 3, "database": 3, "storage_bucket": 3,
        }
        return sorted(assets, key=lambda a: (
            priority_order.get(
                a.priority.value if hasattr(a.priority, 'value')
                else str(a.priority), 3),
            type_order.get(
                a.type.value if hasattr(a.type, 'value')
                else str(a.type), 9),
            a.hostname,
        ))

    # -- Phase: Asset Research ---------------------------------------------

    def get_next_asset(self) -> Optional[AssetRecord]:
        """Get the next asset that needs research.

        Returns the highest-priority non-exhausted, non-paused asset.
        """
        for asset in self.get_prioritized_assets():
            if asset.status not in {AssetStatus.EXHAUSTED, AssetStatus.PAUSED}:
                return asset
        return None

    def start_asset(self, asset: AssetRecord) -> AssetRecord:
        """Begin research on an asset."""
        state = self.campaign.load()
        state.status = CampaignPhase.RESEARCHING
        state.phase = f"Researching {asset.hostname} ({asset.type.value})"
        self.campaign.save(state)

        # Advance through recon if needed
        if asset.status == AssetStatus.QUEUED:
            asset = self.threads.advance_asset(asset)
        if asset.status == AssetStatus.RECON:
            asset = self.threads.advance_asset(asset)
        if asset.status == AssetStatus.THREAT_MODELING:
            asset = self.threads.advance_asset(asset)

        return asset

    def get_next_research_unit(self) -> Optional[Dict[str, Any]]:
        """Get the next research unit for the harness to execute.

        Priority order:
          1. Active threads on the current asset (continue existing work)
          2. New threats on the current asset (spawn new threads)
          3. Move to next asset (advance lifecycle)
          4. Asset discovery (find more assets)
          5. Cross-asset chaining
          6. Reporting
        """
        state = self.campaign.load()

        # 1. Check for active threads
        active_threads = [t for t in self.campaign.list_threads()
                          if not t.is_terminal
                          and t.state != ThreadState.BLOCKED]
        if active_threads:
            # Return research unit for the highest-priority active thread
            thread = active_threads[0]
            unit = self.threads.get_next_research_unit(thread)
            unit["campaign_phase"] = CampaignPhase.RESEARCHING
            return unit

        # 2. Check for blocked threads
        blocked = [t for t in self.campaign.list_threads()
                   if t.state == ThreadState.BLOCKED]
        if blocked:
            # Return a unit that asks the operator about blocked threads
            return self._build_blocked_unit(blocked)

        # 3. Check for current asset with more work
        current_asset = self.get_next_asset()
        if current_asset:
            if current_asset.status == AssetStatus.QUEUED:
                current_asset = self.start_asset(current_asset)
            elif current_asset.status == AssetStatus.DEEP_RESEARCH:
                # Asset is in research but threads exhausted — check for new threats
                threads = self.threads.build_threads_for_asset(current_asset)
                if threads:
                    unit = self.threads.get_next_research_unit(threads[0])
                    unit["campaign_phase"] = CampaignPhase.RESEARCHING
                    return unit
                # No new threads — mark exhausted
                current_asset.status = AssetStatus.EXHAUSTED
                current_asset.completed_at = datetime.now(timezone.utc).isoformat()
                self.campaign.update_asset(current_asset)
                state.assets_exhausted += 1
                self.campaign.save(state)
            else:
                # Advance through lifecycle
                current_asset = self.threads.advance_asset(current_asset)

            # After advancing, try again to get active threads
            active = [t for t in self.campaign.list_threads(
                asset_id=current_asset.asset_id) if not t.is_terminal]
            if active:
                unit = self.threads.get_next_research_unit(active[0])
                unit["campaign_phase"] = CampaignPhase.RESEARCHING
                return unit

            # If still nothing, move to next asset
            current_asset.status = AssetStatus.EXHAUSTED
            current_asset.completed_at = datetime.now(timezone.utc).isoformat()
            self.campaign.update_asset(current_asset)
            state.assets_exhausted += 1
            self.campaign.save(state)

        # 4. All assets exhausted — try discovery for more
        state = self.campaign.load()
        if state.assets_discovered < 10:
            return self.get_discovery_unit()

        # 5. Cross-asset chaining
        state.status = CampaignPhase.CHAINING
        state.phase = "Cross-asset chain analysis"
        self.campaign.save(state)
        return self._build_chain_unit()

    def _build_blocked_unit(self,
                            blocked: List) -> Dict[str, Any]:
        """Build a research unit for handling blocked threads."""
        from tools.asset_discovery import build_research_unit

        blockers = "\n".join(
            f"  - Thread {t.thread_id[:8]} ({t.bug_class}): {t.current_blocker}"
            for t in blocked[:5]
        )

        return build_research_unit(
            objective="Resolve blocked research threads",
            context={
                "blocked_threads": [
                    {"id": t.thread_id, "bug_class": t.bug_class,
                     "blocker": t.current_blocker}
                    for t in blocked
                ],
                "options": [
                    "Provide alternative approach to bypass the blocker",
                    "Accept limited impact and document as DOCUMENTED_LIMITED",
                    "Mark as REFUTED if the blocker is insurmountable",
                    "Request more budget/time/resources",
                ],
            },
            success_criteria=[
                "Resolve or make progress on at least one blocked thread",
            ],
        )

    def _build_chain_unit(self) -> Dict[str, Any]:
        """Build a research unit for cross-asset chain analysis."""
        from tools.asset_discovery import build_research_unit

        findings = []
        for t in self.campaign.list_threads(state=ThreadState.COMPLETE):
            findings.append({
                "thread_id": t.thread_id,
                "asset_id": t.asset_id,
                "bug_class": t.bug_class,
                "impact": t.confirmed_behavior,
            })

        return build_research_unit(
            objective="Cross-asset chain analysis — connect findings for maximum impact",
            context={
                "completed_findings": findings,
                "instructions": """
Chain findings across assets to achieve higher-impact compromise.

Examples:
  - SQLi on api → extract admin emails → password reset on auth → account takeover
  - IDOR on web → access internal documents → find credentials → access admin panel
  - SSRF on api → reach internal services → exploit internal tools → RCE
  - XSS on www → session theft → impersonate user → access payment system
  - JWT forgery on auth → admin access → modify system configuration → full compromise

For each chain:
  1. Identify which findings can be connected
  2. Verify each link is executable
  3. Chain them together and confirm end-to-end impact
  4. Record the complete attack chain with evidence
""",
            },
            success_criteria=[
                "Identify at least 3 viable cross-asset attack chains",
                "Execute and verify at least 1 chain end-to-end",
                "Document chain evidence for disclosure",
            ],
        )

    # -- Status & reporting -------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Get full campaign status."""
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
                "active_threads": ctx.active_threads,
                "findings": ctx.findings,
                "zero_day_candidates": ctx.zero_day_candidates,
            },
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
        description="BugWolf Campaign Orchestrator — self-driven APT research")
    parser.add_argument("--target", required=True,
                        help="Target hostname or project identifier")
    parser.add_argument("--init", action="store_true",
                        help="Initialize new campaign")
    parser.add_argument("--next-unit", action="store_true",
                        help="Get the next research unit for the harness to execute")
    parser.add_argument("--register-discoveries",
                        help="Register discovered assets from JSON file")
    parser.add_argument("--status", action="store_true",
                        help="Show full campaign status")
    parser.add_argument("--budget-hours", type=int, default=72,
                        help="Campaign time budget (default: 72h)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output")
    args = parser.parse_args()

    try:
        orch = CampaignOrchestrator(
            args.target, budget_hours=args.budget_hours)

        if args.init:
            state = orch.initialize()
            print(f"[+] Campaign initialized: {args.target}")
            print(f"    Phase: {state.status}")
            print(f"    Budget: {state.budget_hours}h")
            print(f"    Next: Begin asset discovery")
            return 0

        if args.next_unit:
            # Ensure campaign exists
            orch.initialize()

            unit = orch.get_next_research_unit()
            if unit is None:
                ctx = orch.get_context()
                print(f"[*] Campaign exhausted: {ctx.summary}")
                return 0

            if args.json:
                print(json.dumps(unit, indent=2, default=str))
            else:
                print("=" * 72)
                print(f"CAMPAIGN: {args.target} | PHASE: {unit.get('campaign_phase', 'research')}")
                print("=" * 72)
                print(f"\nOBJECTIVE: {unit['objective']}\n")
                if unit.get('context'):
                    for key, value in unit['context'].items():
                        if isinstance(value, str) and len(value) < 200:
                            print(f"  {key}: {value}")
                print(f"\nSUCCESS CRITERIA:")
                for c in unit.get('success_criteria', []):
                    print(f"  • {c}")
                if unit.get('suggested_approaches'):
                    print(f"\nSUGGESTED APPROACHES:")
                    for a in unit['suggested_approaches'][:8]:
                        print(f"  • {a}")
                print(f"\n{'=' * 72}")
            return 0

        if args.register_discoveries:
            orch.initialize()
            data = json.loads(Path(args.register_discoveries).read_text())
            count = orch.register_discovered_assets(data)
            print(f"[+] Registered {count} new assets from harness discoveries")
            # Show what was found
            ctx = orch.get_context()
            print(ctx.summary)
            return 0

        if args.status:
            orch.initialize()
            status = orch.status()
            if args.json:
                print(json.dumps(status, indent=2, default=str))
            else:
                c = status["campaign"]
                print("=" * 72)
                print(f"CAMPAIGN: {c['target']}")
                print(f"Phase: {c['phase']}")
                print(f"Assets: {c['assets_discovered']} discovered, "
                      f"{c['assets_exhausted']} exhausted")
                print(f"Threads: {c['active_threads']} active")
                print(f"Findings: {c['findings']} ({c['zero_day_candidates']} ZD candidates)")
                print()
                if c['summary']:
                    print(c['summary'])
                print(f"\nNext action: {status['next_action'][:120]}...")

                if status['active_threads_detail']:
                    print("\nActive research threads:")
                    for t in status['active_threads_detail'][:10]:
                        print(f"  [{t['state']:20s}] {t['bug_class']:25s} "
                              f"{t['endpoint'][:50]}")
                print("=" * 72)
            return 0

        parser.print_help()
        return 1

    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())