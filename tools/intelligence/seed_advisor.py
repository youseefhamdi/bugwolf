#!/usr/bin/env python3
"""BugWolf Seed/Mutation Advisor — probe proposals for research units.

Given a research unit (asset + mode + deterministic ``suggested_approaches``),
proposes the top-k probes/approaches to try, seeded from deterministic rules
per domain.  This is the LLM-advisor hook for the campaign orchestrator: the
deterministic core always decides and records, and — when ``--verdicts`` is
supplied — model proposals adjust *priority* within a bounded band without
changing what the core considers valid.

Proposal families per mode (deterministic, offline):

  * web — parameter/endpoint probes, auth variants, WAF bypass, business logic
  * api — BOLA/BFLA/BOPLA, GraphQL batching/aliasing, rate-limit bypass
  * auth — JWT forgery, OAuth flows, session management
  * cloud — IAM privesc, metadata SSRF, container/ECS escape
  * mobile — deep links, exported components, WebView bridges
  * smart-contract — reentrancy, oracle/price, access control
  * llm — prompt injection, tool auth, RAG poisoning
  * cicd — pipeline injection, artifact poisoning

Output lands at ``research/<target>/advisor/seed-proposals.json`` (a
``research`` artifact) and emits ``RESEARCH_REFRESHED`` when proposals are
produced.  Uncensored: no scope/confirmation gates; no model is called.

Usage:
  python3 tools/intelligence/seed_advisor.py --target acme --units units.json
  python3 tools/intelligence/seed_advisor.py --target acme --units units.json --verdicts model.jsonl --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current


_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import workspace_root

try:
    from tools.core.signal_bus import SignalBus
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus

SCHEMA = "bugwolf/seed-advisor/v1"

# Deterministic proposal families per research mode.  Each entry:
#   (approach, surface, priority_hint, rationale)
PROPOSAL_FAMILIES: Dict[str, List[tuple]] = {
    "web": [
        ("Enumerate parameters on every discovered endpoint and fuzz each "
         "with the current payload set (XSS/SQLi/SSTI/command injection).",
         "all parameters", 1, "parameters are the highest-yield web surface"),
        ("Probe auth state transitions: register→login→logout→password reset "
         "as two accounts; look for IDOR/state confusion.",
         "auth flows", 2, "broken-object/function auth dominates payouts"),
        ("Test every redirect/forward (return, next, callback, redirect_uri) "
         "for open-redirect and SSRF via URL params.",
         "redirects", 3, "redirect params double as SSRF/open-redirect"),
        ("Fingerprint the WAF/defense and generate parser-differential "
         "payloads before fuzzing.",
         "WAF bypass", 4, "WAFFLED-style discrepancies beat raw payloads"),
        ("Exercise business-logic state machines (multi-step wizards, "
         "quotas, cart math) for race/trigger conditions.",
         "business logic", 5, "business logic is AI's documented weak spot"),
    ],
    "api": [
        ("Test BOLA: swap object ids across two accounts on every "
         "GET/PUT/DELETE endpoint.",
         "object-level auth", 1, "BOLA remains ~40% of API attacks"),
        ("Build the BFLA matrix: invoke privileged functions as the "
         "lower-privileged caller.",
         "function-level auth", 2, "function-level auth is under-tested"),
        ("Run the BOPLA matrix: over-POST sensitive properties from the "
         "OpenAPI request schemas.",
         "property-level auth", 3, "mass assignment is schema-detectable"),
        ("Probe GraphQL: batching/aliasing for rate-limit bypass, "
         "field-duplication DoS, introspection.",
         "GraphQL", 4, "batching defeats naive rate limits"),
        ("Test rate-limit bypasses on auth endpoints (IP rotation, header "
         "spoofing, parameter pollution).",
         "rate limiting", 5, "credential-stuffing gates are often bypassable"),
    ],
    "auth": [
        ("Decode every JWT found; test alg=none, RS256→HS256 confusion, "
         "jwk injection, kid path traversal.",
         "JWT", 1, "algorithm-confusion forgery is still common"),
        ("Map OAuth flows; test redirect_uri validation, missing state, "
         "PKCE downgrade, token-in-URL leakage.",
         "OAuth", 2, "OAuth misconfigurations dominate ATO chains"),
        ("Probe session fixation/rotation on login and privilege change.",
         "sessions", 3, "fixed sessions enable account takeover"),
        ("Test MFA bypass: response manipulation, backup codes, "
         "enrollment re-binding, timing.",
         "MFA", 4, "MFA bypass feeds ATO chains"),
    ],
    "cloud": [
        ("Run the IAM privesc graph on any supplied policy dumps; probe "
         "reachable PassRole/attach methods in the lab.",
         "IAM", 1, "IAM privesc is the highest-impact cloud class"),
        ("Test metadata SSRF (169.254.169.254) on every URL-accepting "
         "endpoint, including file/image parsers.",
         "metadata SSRF", 2, "metadata SSRF grants cloud credentials"),
        ("Probe container/ECS surfaces: docker socket, privileged mode, "
         "hostPID/hostNetwork, agent socket (ECS-cape).",
         "container escape", 3, "escape chains into IAM pivots"),
        ("Check object storage/bucket policy misconfigurations "
         "(public reads/writes, ACL escalation).",
         "storage", 4, "misconfigured buckets are low-hanging"),
    ],
    "mobile": [
        ("Enumerate exported components and deep links; test cross-app "
         "triggering of sensitive navigation.",
         "deep links", 1, "link hijacking is MASTG-TEST-0028"),
        ("Check manifest/plist policy: backup, cleartext, debuggable, "
         "minSdk, exported-without-permission.",
         "static policy", 2, "static checks are deterministic and cheap"),
        ("Probe WebView bridges (addJavascriptInterface) reachable from "
         "deep-link or injected content.",
         "WebView", 3, "JS bridges convert injection into RCE"),
        ("Test certificate-pinning bypass and interception of the app's "
         "API traffic.",
         "pinning", 4, "interception reveals the backend API surface"),
    ],
    "smart-contract": [
        ("Reentrancy audit: every external call before state update, "
         "including cross-function and read-only reentrancy.",
         "reentrancy", 1, "reentrancy remains the top DeFi loss class"),
        ("Oracle/price manipulation: spot AMM spot prices, TWAP windows, "
         "oracle reads; plan flash-loan moves.",
         "oracle/price", 2, "oracle manipulation detection is <40%"),
        ("Access control: every privileged function (withdraw, mint, "
         "setOwner, upgrade) for missing checks.",
         "access control", 3, "missing onlyOwner is a top audit finding"),
        ("Upgradeability: proxy storage collisions, initializer re-entry, "
         "uninitialized implementation.",
         "upgradeability", 4, "proxy patterns create new bug classes"),
    ],
    "llm": [
        ("Map every tool-call site to attacker-influenced arguments "
         "(user input, web content, tool results).",
         "tool auth", 1, "tool misuse is ASI02"),
        ("Probe indirect prompt injection: attacker content in the corpus "
         "carrying instructions.",
         "prompt injection", 2, "indirect injection is the top agentic risk"),
        ("Test RAG poisoning: memory write-back abuse and source confusion "
         "in retrieval.",
         "RAG", 3, "memory poisoning persists across sessions (ASI06)"),
        ("Check MCP tool-authorization boundaries: which tools each agent "
         "identity can invoke.",
         "MCP boundaries", 4, "identity/privilege abuse is ASI03"),
    ],
    "cicd": [
        ("Audit GitHub Actions for expression injection and untrusted "
         "inputs flowing into run steps.",
         "pipeline injection", 1, "poisoned pipelines grant CI secrets"),
        ("Check artifact/supply-chain poisoning: registry pushes, "
         "dependency confusion, cache poisoning.",
         "supply chain", 2, "dependency confusion is a P1 class"),
        ("Test secret exfiltration paths from CI (env exposure, logs, "
         "caches, artifact uploads).",
         "secret handling", 3, "CI secrets reach production"),
    ],
}


def _id(prefix: str, *parts: str) -> str:
    raw = "|".join(str(p).strip().lower() for p in parts)
    return prefix + "-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


@dataclass
class SeedProposal:
    proposal_id: str
    unit_id: str
    mode: str
    priority: int
    approach: str
    surface: str
    rationale: str
    seeded_from: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AdvisorReport:
    target: str
    generated_at: str
    proposals: List[SeedProposal] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "proposal_count": len(self.proposals),
            "proposals": [p.to_dict() for p in self.proposals],
        }


def advise(target: str, units: List[Dict[str, Any]],
           verdicts: Optional[List[Dict[str, Any]]] = None) -> AdvisorReport:
    """Deterministically propose top-k approaches per research unit."""
    report = AdvisorReport(
        target=target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    model_hints: Dict[str, float] = {}
    if verdicts:
        for v in verdicts:
            if not isinstance(v, dict):
                continue
            uid = str(v.get("unit_id") or v.get("id") or "")
            priority = v.get("priority")
            if uid and isinstance(priority, (int, float)):
                model_hints[uid] = float(priority)

    for unit in units:
        if not isinstance(unit, dict):
            continue
        unit_id = str(unit.get("unit_id") or unit.get("id") or "unknown")
        mode = str(unit.get("mode") or unit.get("domain") or "web").lower()
        seeds = list(unit.get("suggested_approaches") or [])
        families = PROPOSAL_FAMILIES.get(mode, PROPOSAL_FAMILIES["web"])
        for idx, (approach, surface, hint, rationale) in enumerate(families, start=1):
            priority = hint
            if unit_id in model_hints:
                # Model hint adjusts priority within a bounded band.
                delta = model_hints[unit_id] - 1.0
                priority = max(1, min(len(families),
                                      int(hint + delta)))
            report.proposals.append(SeedProposal(
                proposal_id=_id("seed", unit_id, mode, surface),
                unit_id=unit_id,
                mode=mode,
                priority=priority,
                approach=approach,
                surface=surface,
                rationale=rationale,
                seeded_from=seeds,
            ))
        # Deterministic order: priority asc, then stable by creation order.
    report.proposals.sort(key=lambda p: (p.unit_id, p.priority, p.surface))
    return report


def write_report(report: AdvisorReport, *, project_root: Optional[str] = None,
                 base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/advisor/seed-proposals.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", report.target) or "default"
    out_dir = root / "research" / target_slug / "advisor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "seed-proposals.json"
    out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed/mutation advisor")
    parser.add_argument("--target", required=True, help="target slug")
    parser.add_argument("--units", required=True,
                        help="path to research units JSON (list or {units: [...]})")
    parser.add_argument("--verdicts", default=None,
                        help="path to model proposals JSONL (unit_id + priority)")
    parser.add_argument("--json", action="store_true", help="emit JSON to stdout")
    parser.add_argument("--project-root", default=None, help="workspace root override")
    parser.add_argument("--base-dir", default=None, help="output base dir override")
    args = parser.parse_args()

    try:
        raw = json.loads(Path(args.units).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": f"cannot read units: {exc}"}))
        return 2
    units = raw.get("units") if isinstance(raw, dict) else raw
    if not isinstance(units, list):
        units = [raw]

    verdicts = None
    if args.verdicts:
        verdicts = []
        for line in Path(args.verdicts).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                verdicts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    report = advise(args.target, units, verdicts)
    out = write_report(report, project_root=args.project_root,
                       base_dir=args.base_dir)

    if report.proposals:
        try:
            bus = SignalBus(args.target,
                            project_root=args.project_root or args.base_dir)
            bus.publish("RESEARCH_REFRESHED", source="seed_advisor",
                        payload={"proposal_count": len(report.proposals),
                                 "target": args.target})
        except Exception as exc:  # advisory, never a gate
            print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"[+] {args.target}: {len(report.proposals)} proposals for "
              f"{len(units)} unit(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
