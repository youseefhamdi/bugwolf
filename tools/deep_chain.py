#!/usr/bin/env python3
"""
BugWolf Deep Chain Synthesizer v1.0.0

Multi-hop chain discovery beyond the predefined pairwise patterns. `kill_chain.py`
matches A+B against 23 known patterns; this tool builds a directed
compatibility graph over canonical bug classes and uses transitive closure to
find A→B→C→… chains that a pairwise matcher misses, scoring the combined
criticality of the longest, highest-value path.

A low `idor` that reaches `account-takeover` through three hops is a critical,
not a low. This tool surfaces that depth.

Usage:
  python3 tools/deep_chain.py --findings-file findings.jsonl
  python3 tools/deep_chain.py --findings-file findings.jsonl --min-hops 3 --json
  python3 tools/deep_chain.py --classes "idor, open-redirect" --min-hops 2
"""

import json
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

# Directed compatibility graph: bug_class → classes it enables/feeds into.
# Terminal classes (rce, account-takeover, funds-drain, mass-data-breach) are
# the high/critical end states the router cares about.
EDGES: Dict[str, List[str]] = {
    "idor": ["mass-assignment", "privilege-escalation-web", "info-disclosure"],
    "mass-assignment": ["privilege-escalation-web", "account-takeover"],
    "privilege-escalation-web": ["account-takeover", "rce", "mass-data-breach"],
    "open-redirect": ["oauth-bypass", "account-takeover"],
    "oauth-bypass": ["account-takeover"],
    "ssrf": ["rce", "info-disclosure", "api-key-exposure"],
    "api-key-exposure": ["rce", "info-disclosure", "account-takeover"],
    "xss-reflected": ["account-takeover", "info-disclosure"],
    "xss-stored": ["account-takeover", "info-disclosure"],
    "cache-poisoning": ["xss-stored", "account-takeover"],
    "request-smuggling": ["open-redirect", "account-takeover", "info-disclosure"],
    "graphql-introspection": ["idor", "info-disclosure", "mass-data-breach"],
    "sqli": ["info-disclosure", "account-takeover", "rce"],
    "csrf": ["privilege-escalation-web", "account-takeover"],
    "host-header-injection": ["account-takeover", "cache-poisoning"],
    "cors-misconfiguration": ["info-disclosure"],
    "subdomain-takeover": ["account-takeover", "info-disclosure"],
    "jwt-bypass": ["privilege-escalation-web", "account-takeover"],
    "prototype-pollution": ["privilege-escalation-web", "rce"],
    "xxe": ["ssrf", "info-disclosure", "rce"],
    "race-condition-web": ["business-logic", "funds-drain"],
    "business-logic": ["funds-drain", "account-takeover", "privilege-escalation-web"],
    "broken-auth": ["account-takeover", "privilege-escalation-web"],
    "insecure-deserialization": ["rce"],
    "path-traversal": ["info-disclosure", "rce"],
    "info-disclosure": ["account-takeover", "privilege-escalation-web"],
}

TERMINAL = {"rce", "account-takeover", "funds-drain", "mass-data-breach"}

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAME = {v: k for k, v in SEV_RANK.items()}


@dataclass
class DeepChain:
    path: List[str]          # bug classes in order (first = found, rest = escalation)
    source_finding: Optional[Dict] = None
    severity: str = "low"    # combined severity after escalation
    hops: int = 0
    terminal: bool = False
    impact: str = ""
    reason: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        if self.source_finding:
            d["source_finding"] = self.source_finding
        return d


def escalate(severity: str, hops: int) -> str:
    """Each hop bumps one severity tier, capped at critical."""
    lvl = min(4, SEV_RANK.get(severity, 1) + hops)
    return SEV_NAME[lvl]


def _terminal_impact(terminal: str) -> str:
    return {
        "rce": "remote code execution",
        "account-takeover": "account takeover / impersonation",
        "funds-drain": "funds / value drain",
        "mass-data-breach": "mass data breach",
    }.get(terminal, terminal)


class DeepChainSynthesizer:
    """Builds multi-hop escalation chains via transitive closure."""

    def __init__(self, min_hops: int = 2, max_hops: int = 5):
        self.min_hops = min_hops
        self.max_hops = max_hops

    def _paths_from(self, start: str) -> List[List[str]]:
        """All acyclic escalation paths from `start` up to max_hops edges."""
        results: List[List[str]] = []

        def dfs(node: str, path: List[str], depth: int):
            if depth >= self.max_hops:
                return
            for nxt in EDGES.get(node, []):
                if nxt in path:
                    continue
                new_path = path + [nxt]
                results.append(new_path)
                dfs(nxt, new_path, depth + 1)

        dfs(start, [start], 0)
        return results

    def synthesize(self, findings: List[Dict]) -> List[DeepChain]:
        chains: List[DeepChain] = []
        seen: Set[Tuple[str, ...]] = set()

        for f in findings:
            bc = (f.get("bug_class") or "").strip().lower()
            if not bc or bc not in EDGES:
                continue
            for path in self._paths_from(bc):
                hops = len(path) - 1
                if hops < self.min_hops:
                    continue
                key = tuple(path)
                if key in seen:
                    continue
                seen.add(key)

                terminal = path[-1]
                severity = escalate(f.get("severity", "low"), hops)
                chains.append(DeepChain(
                    path=path,
                    source_finding=f,
                    severity=severity,
                    hops=hops,
                    terminal=terminal in TERMINAL,
                    impact=_terminal_impact(terminal) if terminal in TERMINAL else "",
                    reason=(f"{bc} → {' → '.join(path[1:])} in {hops} hops"),
                ))

        # rank: severity first, then hops, then terminal
        chains.sort(key=lambda c: (
            SEV_RANK[c.severity], c.hops, int(c.terminal)), reverse=True)
        return chains

    def synthesize_classes(self, classes: List[str],
                           severity: str = "low") -> List[DeepChain]:
        findings = [{"bug_class": c, "severity": severity} for c in classes]
        return self.synthesize(findings)

    def report(self, chains: List[DeepChain]) -> str:
        lines = ["=" * 72, "  DEEP CHAIN REPORT — MULTI-HOP ESCALATION", "=" * 72,
                 f"  Chains: {len(chains)}", "=" * 72]
        for i, c in enumerate(chains, 1):
            terminal = " ⛓️TERMINAL" if c.terminal else ""
            impact = f"  →  {c.impact}" if c.impact else ""
            lines.append(f"\n  [{i:02d}] [{c.severity.upper():8s}] {c.hops} hop(s){terminal}")
            lines.append(f"      {' → '.join(c.path)}{impact}")
            if c.source_finding:
                src = c.source_finding.get("endpoint") or c.source_finding.get("title", "")
                if src:
                    lines.append(f"      source: {src}")
        if not chains:
            lines.append("\n  No multi-hop chains at/above min hops.")
        lines.append("=" * 72)
        return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Deep Chain Synthesizer v1.0.0")
    parser.add_argument("--findings-file", help="JSONL findings file")
    parser.add_argument("--classes", help="Comma-separated bug classes")
    parser.add_argument("--min-hops", type=int, default=2)
    parser.add_argument("--max-hops", type=int, default=5)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    syn = DeepChainSynthesizer(min_hops=args.min_hops, max_hops=args.max_hops)

    if args.classes:
        classes = [c.strip().lower() for c in args.classes.split(",") if c.strip()]
        chains = syn.synthesize_classes(classes)
    elif args.findings_file:
        raw = Path(args.findings_file).read_text()
        findings = [json.loads(l) for l in raw.splitlines() if l.strip()]
        chains = syn.synthesize(findings)
    else:
        parser.error("one of --classes or --findings-file required")

    if args.as_json:
        print(json.dumps([c.to_dict() for c in chains], indent=2))
        return

    print(syn.report(chains))


if __name__ == "__main__":
    main()
