#!/usr/bin/env python3
"""BugWolf Asset Discovery Engine — recursive multi-source enumeration.

This module provides the TOOL LAYER that the harness uses for asset discovery.
The harness (Claude Code / Freebuff) provides the INTELLIGENCE — it decides
which sources to query, how to interpret results, and when to go deeper.

The plugin provides:
  1. Discovery tool interfaces (DNS, WHOIS, Certificate Transparency, etc.)
  2. Asset deduplication and classification
  3. Priority scoring
  4. Recursive discovery orchestration — discovered hostnames become seeds
  5. Integration with the campaign state system

The actual queries are executed BY THE HARNESS through these tools. The harness
reasons about results and decides what to chase next.

Key principle: "Never stop at page 1. Every discovered hostname is a seed."
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from tools.campaign import (
    AssetRecord, AssetStatus, AssetType, CampaignManager, Priority,
    safe_target_name,
)

# ---------------------------------------------------------------------------
# Asset type classification
# ---------------------------------------------------------------------------

# Patterns that indicate specific asset types from hostname alone
_HOSTNAME_PATTERNS = {
    AssetType.WEB_API: [
        r"\bapi\d*\b", r"\bapi[-.]v\d", r"\brest\b", r"\bbackend\b",
        r"\bservice\b", r"\bgateway\b",
    ],
    AssetType.OAUTH_IDP: [
        r"\bauth\d*\b", r"\b(?:sso|idp|identity|oauth|login)\b",
        r"\b(?:signin|accounts?)\b",
    ],
    AssetType.ADMIN_PANEL: [
        r"\badmin\b", r"\bdashboard\b", r"\bpanel\b", r"\bconsole\b",
        r"\bmanage\b", r"\bcontrol\b", r"\bcp\b",
    ],
    AssetType.GRAPHQL: [
        r"\bgraphql?\b", r"\bgql\b",
    ],
    AssetType.WEBSOCKET: [
        r"\bws\d*\b", r"\bwebsocket\b", r"\brealtime\b", r"\bsocket\b",
    ],
    AssetType.CI_CD: [
        r"\bci\b", r"\bjenkins\b", r"\bgitlab\b", r"\bgithub\b",
        r"\bbuild\b", r"\bdeploy\b", r"\bdrone\b", r"\bactions\b",
        r"\brunner\b",
    ],
    AssetType.DATABASE: [
        r"\bdb\d*\b", r"\bdatabase\b", r"\b(?:mysql|postgres|mongodb|redis)\b",
    ],
    AssetType.STORAGE_BUCKET: [
        r"\bs3\b", r"\bstorage\b", r"\bbucket\b", r"\bblob\b",
        r"\bassets?\b", r"\bstatic\b", r"\bcdn\d*\b", r"\bmedia\b",
    ],
    AssetType.EMAIL_SERVER: [
        r"\bmail\d*\b", r"\bsmtp\b", r"\bimap\b", r"\bemail\b",
    ],
    AssetType.INTERNAL_TOOL: [
        r"\binternal\b", r"\bintranet\b", r"\bcorp\b", r"\bhr\b",
        r"\bwiki\b", r"\bdocs?\b", r"\bconfluence\b",
    ],
    AssetType.MOBILE_API: [
        r"\bmobile\b", r"\bm\b(?=[.-])", r"\bapp\b",
    ],
    AssetType.DNS_SERVER: [
        r"\bdns\d*\b", r"\bnameserver\b", r"\bns\d+\b",
    ],
    AssetType.CDN: [
        r"\bcdn\d*\b", r"\bcache\b", r"\bedge\b",
    ],
}

# TLD patterns that indicate tech companies vs others
_TECH_TLDS = {".io", ".dev", ".app", ".ai", ".cloud", ".tech", ".net", ".org"}


def classify_asset(hostname: str, *, tech_hints: Optional[List[str]] = None,
                   open_ports: Optional[List[int]] = None) -> AssetType:
    """Classify an asset from its hostname and optional hints."""
    host_lower = hostname.lower().rstrip(".")

    scores: Dict[AssetType, int] = {}
    for atype, patterns in _HOSTNAME_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, host_lower):
                score += 1
        if score > 0:
            scores[atype] = score

    if not scores:
        # Default classification
        if "www" in host_lower or host_lower.count(".") <= 2:
            return AssetType.WEB_APP
        return AssetType.WEB_API

    return max(scores, key=scores.get)


def score_priority(asset_type: AssetType, hostname: str, *,
                   has_auth: bool = False,
                   is_critical_path: bool = False) -> Priority:
    """Score asset priority based on type and characteristics."""
    critical_types = {
        AssetType.OAUTH_IDP, AssetType.ADMIN_PANEL, AssetType.WEB_API,
        AssetType.CI_CD, AssetType.DATABASE,
    }
    high_types = {
        AssetType.WEB_APP, AssetType.GRAPHQL, AssetType.INTERNAL_TOOL,
        AssetType.STORAGE_BUCKET, AssetType.WEBSOCKET, AssetType.MOBILE_API,
    }

    if asset_type in critical_types or is_critical_path:
        return Priority.CRITICAL
    if asset_type in high_types or has_auth:
        return Priority.HIGH
    return Priority.MEDIUM


# ---------------------------------------------------------------------------
# Discovery seeds
# ---------------------------------------------------------------------------

@dataclass
class DiscoverySeed:
    """A seed for recursive discovery — a newly found host that spawns more queries."""
    hostname: str
    source: str                          # how it was discovered
    depth: int = 0                       # how many levels deep from root
    parent: str = ""                     # what hostname led to this one
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoverySession:
    """Tracks one asset discovery session for audit."""
    target: str
    seeds_processed: int = 0
    assets_found: int = 0
    sources_used: List[str] = field(default_factory=list)
    started_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.started_at:
            self.started_at = now
        if not self.updated_at:
            self.updated_at = now


# ---------------------------------------------------------------------------
# Research Unit: Asset Discovery
# ---------------------------------------------------------------------------

# This is the research unit dispatched to the harness for asset discovery.
# The harness receives this context and executes it with full intelligence.

ASSET_DISCOVERY_UNIT = {
    "objective": "DISCOVER ALL ASSETS",
    "description": """
You are an APT-level reconnaissance agent. Your target is {target}.

Discover every asset. Work recursively. Never stop until you've exhausted
every avenue of passive discovery. Every discovered hostname is a SEED for
further discovery.

For each discovered asset, record:
  - hostname
  - type (web_api, web_app, oauth_idp, admin_panel, graphql, websocket,
          ci_cd, database, storage_bucket, email_server, internal_tool,
          mobile_api, dns_server, cdn, unknown)
  - how it was discovered (source)
  - priority (critical, high, medium, low)

Discovery SOURCES to exhaust (never stop at page 1):

  1. CERTIFICATE TRANSPARENCY
     - crt.sh (full results, not just first page)
     - crt.name (with date fields)
     - Query wildcards: %.target.com, %target%, *target*

  2. DNS ENUMERATION
     - All common subdomain wordlist patterns
     - -admin, -dev, -staging, -test, -uat variants for every found host
     - Version variants: api2, api-v2, api_v2, v2.api, api.v2
     - Regional: us.api, eu.api, apac.api

  3. SEARCH ENGINES (passive)
     - Google dorks: site:target.com, related:target.com
     - Shodan: org:target, hostname:target.com
     - Censys: same organization queries

  4. CODE REPOSITORIES
     - GitHub search: org:company, filename:config, target.com references
     - GitLab, Bitbucket equivalents
     - Commit messages referencing internal hostnames

  5. WAYBACK MACHINE
     - Historical URLs for target.com
     - Look for old endpoints, retired APIs, forgotten admin panels

  6. CLOUD ASSET DISCOVERY
     - S3/GCS bucket name bruteforce patterns
     - CloudFront distributions
     - Azure blob storage patterns

  7. JOB POSTINGS / SOCIAL MEDIA
     - Technology stack hints from job descriptions
     - Internal tool references from employee posts
     - Architecture diagrams shared publicly

RULES:
  - Never stop at the first page of results. Go deep.
  - If you find 'admin.company.com', also check: admin-staging, admin-dev,
    admin-v2, admintest, admin-beta, admin-old
  - If you find 'api.company.com', check: api2, api-v2, api.internal,
    internal-api, api-gateway
  - Every hostname is a SEED. Query subdomains of every discovered host.
  - Record everything. No finding is too small.
  - For each asset, estimate the type and priority.
""",
    "success_criteria": [
        "At least 20 assets discovered (adjust based on target size)",
        "At least 5 different discovery sources used",
        "Each asset has type and priority classification",
        "Recursive depth of at least 2 (hosts discovered FROM discovered hosts)",
    ],
    "output": "asset_manifest",
}


# ---------------------------------------------------------------------------
# Asset Discovery Engine
# ---------------------------------------------------------------------------

class AssetDiscoveryEngine:
    """Orchestrate asset discovery for a campaign target."""

    def __init__(self, target: str):
        self.target = safe_target_name(target).replace(":", "_")[:200]
        self.campaign = CampaignManager(target)
        # Auto-initialize campaign if it doesn't exist
        if not self.campaign.campaign_path.exists():
            self.campaign.initialize()
        self.seen_hostnames: Set[str] = set()
        # Load existing assets into seen set
        for asset in self.campaign.list_assets():
            self.seen_hostnames.add(asset.hostname)
        self.discovery_history: List[Dict[str, Any]] = []

    def get_research_unit(self) -> Dict[str, Any]:
        """Return the research unit for the harness to execute.

        This is the core dispatch: the plugin tells the harness WHAT to do
        and provides context, the harness decides HOW to do it.
        """
        unit = dict(ASSET_DISCOVERY_UNIT)
        unit["description"] = unit["description"].format(target=self.target)
        unit["context"] = {
            "target": self.target,
            "known_assets": [
                a.hostname for a in self.campaign.list_assets()
            ],
            "discovery_depth": 0,
            "sources_to_try": [
                "certificate_transparency",
                "dns_enumeration",
                "search_engines",
                "code_repositories",
                "wayback_machine",
                "cloud_assets",
            ],
        }
        return unit

    def register_asset(self, hostname: str, asset_type: AssetType | str,
                       *, priority: Optional[Priority | str] = None,
                       ports: Optional[List[int]] = None,
                       detected_tech: Optional[List[str]] = None,
                       source: str = "manual") -> Optional[AssetRecord]:
        """Register a discovered asset in the campaign."""
        # Normalize hostname
        hostname = hostname.lower().strip().rstrip(".")
        if not hostname or hostname in self.seen_hostnames:
            return None

        # Basic validation
        if any(c in hostname for c in " <>\"';&|$()"):
            return None
        if len(hostname) > 253:
            return None

        self.seen_hostnames.add(hostname)

        if not isinstance(asset_type, AssetType):
            asset_type = classify_asset(hostname, tech_hints=detected_tech,
                                        open_ports=ports)

        if priority is None:
            priority = score_priority(asset_type, hostname)

        asset = self.campaign.add_asset(
            hostname=hostname,
            asset_type=asset_type,
            priority=priority,
            ports=ports or [],
            detected_tech=detected_tech or [],
            source=source,
        )
        self.discovery_history.append({
            "hostname": hostname,
            "type": asset_type.value if isinstance(asset_type, AssetType) else str(asset_type),
            "source": source,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        return asset

    def register_batch(self, discoveries: Iterable[Dict[str, Any]]) -> int:
        """Register a batch of discovered assets from harness output."""
        count = 0
        for item in discoveries:
            hostname = item.get("hostname", "").strip()
            if not hostname:
                continue
            atype = item.get("type", "unknown")
            priority = item.get("priority")
            ports = item.get("ports", [])
            tech = item.get("detected_tech", [])
            source = item.get("source", "harness_discovery")

            result = self.register_asset(
                hostname, atype, priority=priority,
                ports=ports, detected_tech=tech, source=source,
            )
            if result:
                count += 1
        return count

    def get_seeds(self, depth: int = 0) -> List[DiscoverySeed]:
        """Get all discovered hostnames as seeds for the next round of discovery."""
        assets = self.campaign.list_assets()
        seeds = []
        for asset in assets:
            # Deep-variant seeds: for each known host, generate variant patterns
            host = asset.hostname
            seeds.append(DiscoverySeed(
                hostname=host, source=asset.source, depth=depth,
                parent=self.target,
                metadata={"existing_type": asset.type.value}
            ))

            # Generate variant seeds for the NEXT depth
            variants = self._generate_variants(host)
            for variant in variants:
                if variant not in self.seen_hostnames:
                    seeds.append(DiscoverySeed(
                        hostname=variant, source=f"variant_of:{host}",
                        depth=depth + 1, parent=host,
                    ))
        return seeds

    @staticmethod
    def _generate_variants(hostname: str) -> List[str]:
        """Generate common variant hostnames for deeper discovery."""
        variants = []
        host = hostname.lower().rstrip(".")

        # Split into prefix and domain
        parts = host.split(".")
        if len(parts) < 2:
            return variants

        # The "subdomain" is everything before the main domain
        # For api.company.com: sub=api, domain=company.com
        # For api.staging.company.com: sub=api, domain=staging.company.com
        for split_point in range(1, min(3, len(parts))):
            domain = ".".join(parts[-split_point:])
            prefix = ".".join(parts[:-split_point]) if parts[:-split_point] else ""

            if prefix:
                # Version variants
                for sep in ["", "-", "_", "."]:
                    for ver in ["v2", "v3", "v4"]:
                        base = f"{prefix}{sep}{ver}"
                        if base != prefix:
                            variants.append(f"{base}.{domain}")

                # Environment variants
                for env in ["dev", "staging", "test", "uat", "beta", "old", "new"]:
                    if not prefix.endswith(f"-{env}") and not prefix.endswith(f".{env}"):
                        variants.append(f"{env}.{host}")
                        variants.append(f"{prefix}-{env}.{domain}")

                # Admin/internal variants
                for label in ["admin", "internal", "private", "mgmt"]:
                    if prefix != label:
                        variants.append(f"{label}.{domain}")

        return variants[:50]  # cap per host

    def status_report(self) -> Dict[str, Any]:
        """Return a discovery status report."""
        assets = self.campaign.list_assets()
        by_type: Dict[str, int] = {}
        by_priority: Dict[str, int] = {}

        for a in assets:
            atype = a.type.value if hasattr(a.type, 'value') else str(a.type)
            apri = a.priority.value if hasattr(a.priority, 'value') else str(a.priority)
            by_type[atype] = by_type.get(atype, 0) + 1
            by_priority[apri] = by_priority.get(apri, 0) + 1

        return {
            "total_discovered": len(assets),
            "by_type": by_type,
            "by_priority": by_priority,
            "sources_used": len(set(a.source for a in assets)),
            "top_priority": [a.hostname for a in assets
                             if a.priority == Priority.CRITICAL][:10],
        }


# ---------------------------------------------------------------------------
# Research Unit Builder: Reusable factory for creating harness dispatch units
# ---------------------------------------------------------------------------

def build_research_unit(objective: str, *,
                        asset_hostname: str = "",
                        bug_class: str = "",
                        endpoint: str = "",
                        context: Optional[Dict[str, Any]] = None,
                        tools: Optional[List[str]] = None,
                        success_criteria: Optional[List[str]] = None,
                        max_iterations: int = 50) -> Dict[str, Any]:
    """Build a research unit for the harness to execute.

    This is the standard dispatch format. Every research task the plugin
    gives to the harness follows this structure.
    """
    return {
        "schema": "bugwolf-research-unit-v1",
        "objective": objective,
        "context": context or {},
        "asset": asset_hostname,
        "bug_class": bug_class,
        "endpoint": endpoint,
        "available_tools": tools or [
            "http_request",
            "execute_python",
            "read_code",
            "search_code",
            "web_search",
            "record_finding",
            "update_thread_state",
            "spawn_subtask",
        ],
        "success_criteria": success_criteria or [
            "Confirm vulnerability with reproducible evidence",
            "OR definitively refute the hypothesis",
        ],
        "max_iterations": max_iterations,
        "timeout_minutes": 30,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Asset Discovery Engine")
    parser.add_argument("--target", required=True,
                        help="Target hostname or domain")
    parser.add_argument("--discover", action="store_true",
                        help="Generate discovery research unit for harness")
    parser.add_argument("--register", help="Register a discovered asset (hostname:type:priority)")
    parser.add_argument("--register-batch", help="Register assets from JSON file")
    parser.add_argument("--seeds", action="store_true",
                        help="Show discovery seeds for next round")
    parser.add_argument("--status", action="store_true",
                        help="Show discovery status")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output")
    args = parser.parse_args()

    try:
        engine = AssetDiscoveryEngine(args.target)

        if args.discover:
            unit = engine.get_research_unit()
            if args.json:
                print(json.dumps(unit, indent=2))
            else:
                print(unit["description"])
            return 0

        if args.register:
            parts = args.register.split(":")
            hostname = parts[0]
            atype = parts[1] if len(parts) > 1 else "unknown"
            priority = parts[2] if len(parts) > 2 else None
            asset = engine.register_asset(hostname, atype, priority=priority)
            if asset:
                print(f"[+] Registered: {asset.hostname} [{asset.type.value}] "
                      f"priority={asset.priority.value}")
            else:
                print(f"[!] Could not register: {hostname}")
            return 0

        if args.register_batch:
            data = json.loads(Path(args.register_batch).read_text())
            count = engine.register_batch(data)
            print(f"[+] Registered {count} new assets")
            return 0

        if args.seeds:
            seeds = engine.get_seeds()
            if args.json:
                print(json.dumps([asdict(s) for s in seeds], indent=2, default=str))
            else:
                for s in seeds[:30]:
                    indent = "  " * min(s.depth, 4)
                    print(f"{indent}{s.hostname}  [via {s.source}]")
            return 0

        if args.status:
            report = engine.status_report()
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"[*] Asset Discovery: {args.target}")
                print(f"    Total: {report['total_discovered']} assets")
                print(f"    By type: {report['by_type']}")
                print(f"    By priority: {report['by_priority']}")
                print(f"    Critical:")
                for host in report['top_priority']:
                    print(f"      {host}")
            return 0

        parser.print_help()
        return 1

    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())