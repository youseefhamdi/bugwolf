#!/usr/bin/env python3
"""BugWolf Deep-Research Engine v1.0.0.

Hunt agents carry frozen playbooks; playbooks age. This engine keeps them
current: before a hunt wave dispatches, it runs a structured research pass
over public intel sources and compiles a **research pack** — the digest of
what changed in the world since the playbook was written — which is
injected into every agent dispatch payload.

Two access classes, honestly separated:

  * **direct** — sources with a stable, keyless JSON API the engine fetches
    itself (NVD CVE search, GitHub PoC search, Reddit, Hacker News, CISA
    KEV). Live when the network allows; degraded to query plans otherwise.
  * **harness** — sources whose best search interface is the *harness's*
    web-research tooling (X/Twitter, Medium, Google dorks, general web).
    The engine never fakes these: it emits precise query plans that the
    Claude Code session executes with WebSearch/WebFetch and writes back
    via ``technique_ledger`` / research checkpoints.

Design constraints (framework conventions):
  * ``urlopen`` is injectable for deterministic tests (live_executor
    convention).
  * Fixed UA string; short timeouts; every fetch failure degrades that
    source, never the pack (fail-open per source, fail-closed attribution:
    a claim always carries its source URL).
  * Output feeds ``tools/intel/technique_ledger.py`` — researched
    techniques land in quarantine until an operator approves them; agents
    only ever see ledger-approved entries plus raw source *leads*.

Usage:
    from tools.intel.research_engine import ResearchEngine
    eng = ResearchEngine()
    pack = eng.build_pack(tech_stack=[("nginx", "1.24.0"), ("next.js", "14.2.3")],
                          bug_classes=["ssrf", "idor"])
    dispatch_payload["research_pack"] = pack

CLI:
    python3 -m tools.intel.research_engine --tech nginx:1.24.0 --bugs ssrf --json
    python3 -m tools.intel.research_engine --plan-only --tech nginx:1.24.0 --json
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

SCHEMA = "bugwolf-research-pack/v1"
USER_AGENT = "bugwolf-research-engine/1.0 (+https://bugwolf.xyz)"

UrlOpen = Callable[..., Any]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class IntelItem:
    """One researched signal with mandatory provenance."""

    source: str                 # nvd | github | reddit | hackernews | kev |
                                # x-twitter | medium | dork (plan-only)
    kind: str                   # cve | poc | discussion | advisory | query_plan
    title: str
    url: str = ""
    published: str = ""
    cve_ids: List[str] = field(default_factory=list)
    tech: str = ""
    severity: str = ""          # CVSS text or community heat
    summary: str = ""
    confidence: float = 0.5     # source-weighted, set at pack build
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResearchPack:
    """The per-wave intel digest injected into agent dispatch payloads."""

    target_fingerprint: str
    built_at: str
    sources_polled: List[str]
    sources_degraded: List[str]         # polled but failed — honesty field
    cve_matches: List[Dict[str, Any]]
    poc_leads: List[Dict[str, Any]]
    community_signals: List[Dict[str, Any]]
    query_plans: List[Dict[str, Any]]   # harness-executed searches (X/Medium/dorks)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Source credibility weights (0..1) — feeds item confidence at pack build.
_SOURCE_WEIGHT = {
    "kev": 0.95,          # actively exploited: highest signal
    "nvd": 0.9,
    "github": 0.75,       # public PoC: real but quality varies
    "hackernews": 0.6,
    "reddit": 0.55,
    "medium": 0.5,
    "x-twitter": 0.45,
    "dork": 0.4,
}

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class ResearchEngine:
    """Poll public intel sources and compile research packs."""

    def __init__(self, *, timeout: int = 12, urlopen: Optional[UrlOpen] = None,
                 github_token: Optional[str] = None) -> None:
        self.timeout = int(timeout)
        self._urlopen = urlopen or urllib.request.urlopen
        self._github_token = github_token

    # -- fetch helpers -------------------------------------------------------

    def _get_json(self, url: str, *, headers: Optional[Dict[str, str]] = None
                  ) -> Optional[Any]:
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT,
                          "Accept": "application/json",
                          **(headers or {})})
        try:
            with self._urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - source degradation is expected
            return None

    # -- direct sources ------------------------------------------------------

    def fetch_nvd(self, keyword: str, *, days_back: int = 90
                  ) -> List[IntelItem]:
        """NVD CVE keyword search (keyless public API, 2.0)."""
        params = urllib.parse.urlencode({
            "keywordSearch": keyword, "resultsPerPage": 20})
        data = self._get_json(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}")
        if not data:
            return []
        items: List[IntelItem] = []
        for vuln in (data.get("vulnerabilities") or [])[:20]:
            cna = (((vuln.get("cve") or {}).get("containers") or {})
                   .get("cna") or {})
            metrics = (cna.get("metrics") or [])
            score = ""
            if metrics:
                try:
                    score = str(metrics[0]["cvssV3_1"]["baseSeverity"])
                except (KeyError, IndexError, TypeError):
                    score = ""
            cve_id = (vuln.get("cve") or {}).get("id", "")
            items.append(IntelItem(
                source="nvd", kind="cve", title=cna.get("title")
                or next((d.get("value", "") for d in cna.get("descriptions", [])
                         if d.get("lang") == "en"), cve_id),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=str((vuln.get("cve") or {}).get("published", "")),
                cve_ids=[cve_id] if cve_id else [],
                tech=keyword, severity=score,
                confidence=_SOURCE_WEIGHT["nvd"],
                raw={"source_url": "services.nvd.nist.gov"}))
        return items

    def fetch_github_pocs(self, tech: str) -> List[IntelItem]:
        """Public PoC search on GitHub (code/repositories search API)."""
        params = urllib.parse.urlencode({
            "q": f"{tech} exploit OR poc OR CVE",
            "sort": "updated", "per_page": 10})
        headers = {"Accept": "application/vnd.github+json"}
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        data = self._get_json(
            f"https://api.github.com/search/repositories?{params}",
            headers=headers)
        if not data:
            return []
        items: List[IntelItem] = []
        for repo in (data.get("items") or [])[:10]:
            items.append(IntelItem(
                source="github", kind="poc",
                title=str(repo.get("full_name") or repo.get("name") or ""),
                url=str(repo.get("html_url") or ""),
                published=str(repo.get("pushed_at") or ""),
                tech=tech,
                summary=str(repo.get("description") or "")[:300],
                confidence=_SOURCE_WEIGHT["github"],
                raw={"stars": repo.get("stargazers_count"),
                     "source_url": "api.github.com"}))
        return items

    def fetch_reddit(self, *, days_back: int = 30, limit: int = 15
                     ) -> List[IntelItem]:
        """r/netsec + r/bugcrowd + r/websecurity top recent posts."""
        items: List[IntelItem] = []
        for sub in ("netsec", "bugcrowd", "websecurity"):
            data = self._get_json(
                f"https://www.reddit.com/r/{sub}/new.json?limit={limit}")
            if not data:
                continue
            for child in (data.get("data") or {}).get("children") or []:
                post = child.get("data") or {}
                created = datetime.fromtimestamp(
                    float(post.get("created_utc") or 0), tz=timezone.utc)
                age_days = (datetime.now(timezone.utc)
                            - created).days
                if age_days > days_back:
                    continue
                items.append(IntelItem(
                    source="reddit", kind="discussion",
                    title=str(post.get("title") or ""),
                    url=f"https://reddit.com{post.get('permalink', '')}",
                    published=created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    summary=str(post.get("selftext") or "")[:280],
                    raw={"subreddit": sub, "score": post.get("score"),
                         "source_url": f"reddit.com/r/{sub}"}))
        return items

    def fetch_hackernews(self, *, days_back: int = 14, min_points: int = 50
                         ) -> List[IntelItem]:
        """HN Algolia search for recent high-signal security stories."""
        since = int(datetime.now(timezone.utc).timestamp()) - days_back * 86400
        params = urllib.parse.urlencode({
            "query": "vulnerability OR exploit OR CVE OR RCE OR bypass",
            "tags": "story", "numericFilters": f"created_at_i>{since},points>{min_points}",
            "hitsPerPage": 20})
        data = self._get_json(
            f"https://hn.algolia.com/api/v1/search?{params}")
        if not data:
            return []
        items: List[IntelItem] = []
        for hit in (data.get("hits") or [])[:20]:
            items.append(IntelItem(
                source="hackernews", kind="discussion",
                title=str(hit.get("title") or ""),
                url=str(hit.get("url")
                        or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"),
                published=datetime.fromtimestamp(
                    int(hit.get("created_at_i") or 0),
                    tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                summary=str(hit.get("story_text") or "")[:280],
                raw={"points": hit.get("points"),
                     "source_url": "hn.algolia.com"}))
        return items

    def fetch_kev(self) -> List[IntelItem]:
        """CISA KEV catalog — actively exploited CVEs (top signal)."""
        data = self._get_json(_KEV_URL)
        if not data:
            return []
        items: List[IntelItem] = []
        for entry in (data.get("vulnerabilities") or []):
            items.append(IntelItem(
                source="kev", kind="advisory",
                title=str(entry.get("vendorProject", "")) + " "
                      + str(entry.get("product", "")),
                cve_ids=[str(entry.get("cveID", ""))],
                published=str(entry.get("dateAdded", "")),
                severity="KEV",
                summary=str(entry.get("shortDescription", ""))[:280],
                raw={"ransomware_use": entry.get("knownRansomwareCampaignUse"),
                     "source_url": "cisa.gov/kev"}))
        return items

    # -- harness-research query plans (X/Medium/dorks — never faked) ---------

    def build_query_plans(self, *, techs: List[str],
                          bug_classes: List[str],
                          days_window: int = 30) -> List[Dict[str, Any]]:
        """Precise searches the harness executes with WebSearch/WebFetch.

        X/Twitter and Medium have no keyless search API; pretending to fetch
        them would be fabrication.  Instead the pack carries exact queries
        the operator's harness runs, with paste-back targets.
        """
        window = f"after:{_days_ago_iso(days_window)}"
        plans: List[Dict[str, Any]] = []
        for t in techs[:6]:
            plans.append({
                "source": "x-twitter", "kind": "query_plan",
                "query": f"{t} (CVE OR RCE OR bypass OR 0day) {window}",
                "execute_with": "WebSearch + x.com/search",
                "paste_back": "tools/intel/technique_ledger.py --submit",
                "rationale": "researcher first-look channel; new bypasses "
                             "circulate here before advisory publication",
            })
            plans.append({
                "source": "medium", "kind": "query_plan",
                "query": f"https://medium.com/search?q={urllib.parse.quote(t + ' vulnerability writeup')} {window}",
                "execute_with": "WebFetch (medium.com search page)",
                "paste_back": "tools/intel/technique_ledger.py --submit",
                "rationale": "deep technical writeups (bug-bounty reports, "
                             "chaining methodology)",
            })
        for b in bug_classes[:4]:
            plans.append({
                "source": "dork", "kind": "query_plan",
                "query": f'"{b}" site:github.com "Proof of Concept" after:{_days_ago_iso(days_window)}',
                "execute_with": "WebSearch",
                "paste_back": "technique_ledger --submit or research checkpoint",
                "rationale": "fresh PoCs indexed between NVD pulls",
            })
        # 2026 writeup-corpus dorks (XSS-Rat 2026 guide, live pulls):
        # writeup platforms are where chain methodology surfaces first
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("site:infosecwriteups.com OR site:medium.com "
                      f"account takeover OR oauth OR chain after:{_days_ago_iso(days_window)}"),
            "execute_with": "WebSearch",
            "paste_back": "technique_ledger --submit",
            "rationale": "ATO/OAuth chain writeups surface on writeup "
                         "platforms before advisory corpora",
        })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("site:portswigger.net/research OR "
                      f"site:unit42.paloaltonetworks.com 2026 technique OR desync OR injection"),
            "execute_with": "WebSearch",
            "paste_back": "research checkpoint",
            "rationale": "primary research (PortSwigger, Unit 42) — the "
                         "2026 corpus's smuggling/IDPI sources",
        })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("site:github.com "
                      f"bug-bounty OR writeups OR checklists 2026 pushed:>{_days_ago_iso(days_window)}"),
            "execute_with": "WebSearch",
            "paste_back": "technique_ledger --submit",
            "rationale": "community checklist/methodology repos refresh "
                         "continuously (e.g. XSS-Rat 2026 guide pattern)",
        })
        # -- corpus-v3 dork lanes (76-PDF recon corpus, Sept 2026) ----------
        # GitHub dorks (corpus 019): org-scoped secret/CI census lanes
        if techs or bug_classes:
            org_hint = techs[0] if techs else "target"
            plans.append({
                "source": "dork", "kind": "query_plan",
                "query": (f"org:{org_hint} (filename:.env OR filename:config.json "
                          "OR filename:settings.py OR extension:sql OR path:.github/workflows)"),
                "execute_with": "WebSearch (github.com/search)",
                "paste_back": "credential-leak / shadow-surface agent census",
                "rationale": "environment/config/CI discovery ladder "
                             "(corpus 019 dork collection)",
            })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("(ssl:\"TARGET ORG\" OR http.favicon.hash:HASH) "
                      "(port:8443 OR port:9090 OR port:3000 OR port:8000)"),
            "execute_with": "WebSearch (shodan.io search)",
            "paste_back": "shadow-surface agent census",
            "rationale": "non-standard-port census: internal panels live "
                         "where nobody looks (corpus 043 surface doctrine)",
        })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("site:crt.sh TARGET DOMAIN (staging OR dev OR qa OR uat "
                      "OR sandbox OR preprod)"),
            "execute_with": "WebFetch (crt.sh)",
            "paste_back": "shadow-surface staging census",
            "rationale": "CT-log environment census: 20 CT tricks corpus "
                         "(037) — staging mirrors run prod code without "
                         "prod guardrails",
        })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": (f"{techs[0] if techs else 'target'} "
                      "(inurl:webhook OR inurl:callback OR inurl:notify) "
                      "payment OR subscription"),
            "execute_with": "WebSearch + Google/Bing",
            "paste_back": "webhook-logic agent census",
            "rationale": "webhook exposure dorks: server-to-server "
                         "endpoints are invisible to UI crawls (corpus 049)",
        })
        plans.append({
            "source": "dork", "kind": "query_plan",
            "query": ("site:infosecwriteups.com OR site:medium.com "
                      "(IDOR OR \"account takeover\" OR smuggling OR XXE OR "
                      f"{' OR '.join(bug_classes[:2]) or 'SSRF'}) "
                      f"after:{_days_ago_iso(days_window)}"),
            "execute_with": "WebSearch",
            "paste_back": "technique_ledger --submit",
            "rationale": "per-class writeup lanes derived from the corpus "
                         "playbook series (020/025/040/042/044)",
        })
        return plans

    # -- pack compilation ------------------------------------------------------

    def build_pack(self, *, tech_stack: Optional[List[Any]] = None,
                   bug_classes: Optional[List[str]] = None,
                   kev_catalog: Optional[List[Dict[str, Any]]] = None,
                   live: bool = True) -> ResearchPack:
        """Compile the pack. ``live=False`` or fetch failures degrade that
        source to a query plan instead of failing the pack."""
        techs: List[tuple] = []
        for entry in (tech_stack or []):
            if isinstance(entry, (tuple, list)) and entry:
                techs.append((str(entry[0]), str(entry[1]) if len(entry) > 1 else ""))
            elif isinstance(entry, str):
                name, _, ver = entry.partition(":")
                techs.append((name.strip(), ver.strip()))
        bug_classes = [str(b) for b in (bug_classes or [])]

        pol: List[str] = []
        degraded: List[str] = []
        cve_items: List[IntelItem] = []
        poc_items: List[IntelItem] = []
        community: List[IntelItem] = []

        # -- KEV first: actively exploited beats everything
        kev_items: List[IntelItem] = []
        if kev_catalog is not None:
            for e in kev_catalog:
                kev_items.append(IntelItem(
                    source="kev", kind="advistory".replace("advistory", "advisory"),
                    title=f"{e.get('vendorProject','')} {e.get('product','')}",
                    cve_ids=[str(e.get("cveID", ""))],
                    published=str(e.get("dateAdded", "")), severity="KEV",
                    summary=str(e.get("shortDescription", ""))[:280]))
        else:
            kev_items = self.fetch_kev()
        if kev_items:
            pol.append("kev")
        else:
            degraded.append("kev")
        kev_set = {c for i in kev_items for c in i.cve_ids}

        # -- per-tech CVE + PoC research
        for name, version in techs:
            nvd = self.fetch_nvd(name) if live else []
            if nvd:
                pol.append(f"nvd:{name}")
            else:
                degraded.append(f"nvd:{name}")
            for item in nvd:
                item.tech = f"{name} {version}".strip()
                # CVE relevance: keyword hit + version string sanity
                if version and version not in (item.title + item.summary):
                    item.confidence *= 0.7  # keyword match, version unconfirmed
                cve_items.append(item)

            pocs = self.fetch_github_pocs(name) if live else []
            if pocs:
                pol.append(f"github:{name}")
            else:
                degraded.append(f"github:{name}")
            poc_items.extend(pocs)

        # -- community streams (bug-class focused, target-agnostic)
        if live:
            reddit = self.fetch_reddit(days_back=30)
            (pol if reddit else degraded).append(
                "reddit" if reddit else "reddit")
            if not reddit:
                degraded[-1] = "reddit"
            community.extend(reddit)
            hn = self.fetch_hackernews(days_back=14)
            (pol if hn else degraded).append("hackernews" if hn else "hackernews")
            if not hn:
                degraded[-1] = "hackernews"
            community.extend(hn)

        # -- CVE↔KEV correlation: KEV-listed matches jump in confidence
        matched_cves: List[Dict[str, Any]] = []
        for item in cve_items:
            hit_kev = any(c in kev_set for c in item.cve_ids)
            # item.confidence arrives source-weighted from the fetchers and
            # may already carry penalties (e.g. unconfirmed version match)
            base = item.confidence if item.confidence else \
                _SOURCE_WEIGHT.get(item.source, 0.5)
            matched_cves.append({
                **item.to_dict(),
                "kev": hit_kev,
                "confidence": min(1.0, 0.95 if hit_kev else base),
            })
        matched_cves.sort(key=lambda d: (-d["confidence"], d["title"]))

        matched_pocs = [i.to_dict() for i in poc_items[:20]]
        for p in matched_pocs:
            p["confidence"] = _SOURCE_WEIGHT.get(p["source"], 0.5)

        signals = sorted(community,
                         key=lambda i: -_SOURCE_WEIGHT.get(i.source, 0.5))[:15]
        community_out = [{**i.to_dict(),
                          "confidence": _SOURCE_WEIGHT.get(i.source, 0.5)}
                         for i in signals]

        plans = self.build_query_plans(
            techs=[t for t, _ in techs], bug_classes=bug_classes)

        notes = []
        if degraded:
            notes.append("degraded sources (fetched later or via harness "
                         "plans): " + ", ".join(sorted(set(degraded))))
        if kev_set:
            notes.append(f"KEV catalog loaded ({len(kev_set)} actively "
                         f"exploited CVEs correlated)")

        return ResearchPack(
            target_fingerprint=hashlib.sha256(
                json.dumps([techs, bug_classes], default=str)
                .encode()).hexdigest()[:16],
            built_at=_utc_now(),
            sources_polled=sorted(set(pol)),
            sources_degraded=sorted(set(degraded)),
            cve_matches=matched_cves[:40],
            poc_leads=matched_pocs,
            community_signals=community_out,
            query_plans=plans,
            notes=notes,
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_ago_iso(days: int) -> str:
    return (datetime.now(timezone.utc)
            - __import__("datetime").timedelta(days=days)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="BugWolf deep-research engine (research packs)")
    ap.add_argument("--tech", action="append", default=[],
                    help="tech:version (repeatable)")
    ap.add_argument("--bugs", default="")
    ap.add_argument("--plan-only", action="store_true",
                    help="emit harness query plans without live fetches")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    eng = ResearchEngine()
    pack = eng.build_pack(
        tech_stack=args.tech, bug_classes=[b for b in args.bugs.split(",") if b],
        live=not args.plan_only)
    if args.json:
        print(json.dumps(pack.to_dict(), indent=2))
    else:
        print(f"pack {pack.target_fingerprint} built {pack.built_at}")
        print(f"  polled:   {', '.join(pack.sources_polled) or '-'}")
        print(f"  degraded: {', '.join(pack.sources_degraded) or '-'}")
        print(f"  CVEs: {len(pack.cve_matches)}  PoCs: {len(pack.poc_leads)}  "
              f"signals: {len(pack.community_signals)}  "
              f"plans: {len(pack.query_plans)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
