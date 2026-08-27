#!/usr/bin/env python3
"""Supply-chain behavior analyzer (npm/PyPI/cargo-style metadata)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.candidate_lifecycle import CandidateStore, ResearchCandidate

_URL_RE = re.compile(r"https?://[^\s\"'`]+", re.IGNORECASE)
_SUSPICIOUS_HOSTS = ("evil", "pastebin", "raw.githubusercontent", "bit.ly", "tinyurl")


def _suspicious_url(url: str) -> bool:
    low = url.lower()
    return any(host in low for host in _SUSPICIOUS_HOSTS)


class SupplyChainAnalyzer:
    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = str(target)
        root = Path(project_root or ".").expanduser().resolve()
        from tools.runtime_paths import target_slug
        self.store = CandidateStore(
            root / "state" / "sessions" / target_slug(target) / "candidates.jsonl"
        )

    def analyze_package_behavior(self, packages: Iterable[Dict[str, Any]]) -> List[ResearchCandidate]:
        candidates: List[ResearchCandidate] = []
        for package in packages:
            scripts = list(package.get("install_scripts") or [])
            suspicious = []
            for script in scripts:
                for url in _URL_RE.findall(str(script)):
                    if _suspicious_url(url):
                        suspicious.append(url)
            if not suspicious:
                continue
            candidates.append(ResearchCandidate(
                domain="web_api", target=self.target, bug_class="supply_chain_install_script",
                title=f"Install script network behavior: {package.get('package', '')}",
                endpoint=str(package.get("package") or ""), severity="high",
                behavior={
                    "package": package.get("package"), "version": package.get("version"),
                    "registry": package.get("registry"), "suspicious_urls": suspicious,
                    "install_scripts": scripts,
                },
                notes=["Observe install behavior in a disposable sandbox; never run on a trusted host."],
            ))
        return self._deduplicate(candidates)

    def analyze_lockfile(self, lockfile: Dict[str, Any]) -> List[ResearchCandidate]:
        packages = list(lockfile.get("packages") or [])
        by_name: Dict[str, List[str]] = {}
        for package in packages:
            name = str(package.get("name") or "")
            resolved = str(package.get("resolved") or "")
            if name and resolved:
                by_name.setdefault(name, []).append(resolved)
        candidates: List[ResearchCandidate] = []
        for name, resolved in by_name.items():
            distinct = set(resolved)
            if len(distinct) < 2:
                continue
            candidates.append(ResearchCandidate(
                domain="web_api", target=self.target, bug_class="supply_chain_provenance",
                title=f"Dependency resolved from multiple sources: {name}",
                endpoint=name, severity="high",
                behavior={"lockfile": lockfile.get("lockfile"), "package": name,
                          "resolved": sorted(distinct)},
                notes=["Verify the package digest against the official registry and pin provenance."],
            ))
        return self._deduplicate(candidates)

    def register(self, candidates: Iterable[ResearchCandidate]) -> bool:
        added = False
        for candidate in candidates:
            candidate.target = candidate.target or self.target
            if self.store.add(candidate):
                added = True
        return added

    @staticmethod
    def _deduplicate(candidates: Iterable[ResearchCandidate]) -> List[ResearchCandidate]:
        from tools.candidate_lifecycle import candidate_signature
        seen = set()
        output = []
        for candidate in candidates:
            signature = candidate_signature(candidate)
            if signature not in seen:
                seen.add(signature)
                output.append(candidate)
        return output