#!/usr/bin/env python3
"""
BugWolf Mandatory Deep-Research Loop v1.0.0

Emits the ordered research tasks for a given progress checkpoint + mode, so the
orchestrator re-researches the latest techniques/upgrades at EVERY progress
milestone (not once at Turn 0). Grounded in canonical sources (OWASP, MITRE CWE,
CISA KEV, Rekt, GHSA/NVD).

Deterministic and offline: it produces the *spec* of what to search/fetch/map —
the agent then executes the searches and writes the results back into the hunt.

Usage:
  python3 tools/research_loop.py --checkpoint pre-hunt --mode web,llm-ai
  python3 tools/research_loop.py --checkpoint post-recon --stack "next.js 15.1, langchain 0.3" --json
  python3 tools/research_loop.py --checkpoint post-findings --mode web --json
  python3 tools/research_loop.py --checkpoint bypass --defense "Cloudflare WAF" --bug-classes sqli --mode web
  python3 tools/research_loop.py --checkpoint escalation --bug-classes idor --target acme --mode web
  python3 tools/research_loop.py --list-checkpoints
"""

import html
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@dataclass
class ResearchTask:
    checkpoint: str
    order: int
    task_type: str  # search | fetch | map
    query: str = ""
    source: str = ""  # canonical URL (for fetch) or map target (for map)
    detail: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Canonical sources
# ---------------------------------------------------------------------------

CANONICAL = {
    "owasp_web": ("OWASP Top 10 Web", "https://owasp.org/www-project-top-ten/"),
    "cwe25": ("CWE Top 25", "https://cwe.mitre.org/top25/"),
    "kev": ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    "llm26": ("OWASP GenAI LLM Top 10 2026",
              "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10"),
    "agentic26": ("OWASP Agentic Top 10 2026",
                  "https://genai.owasp.org/"),
    "mas": ("OWASP MASVS/MASWE/MASTG", "https://mas.owasp.org/"),
    "cnas": ("OWASP Cloud-Native Top 10",
             "https://owasp.org/www-project-cloud-native-security-top-10/"),
    "cicd": ("OWASP CI/CD Top 10",
             "https://owasp.org/www-project-top-10-ci-cd-security-risks/"),
    "rekt": ("Rekt DeFi leaderboard", "https://rekt.news/leaderboard/"),
    "ghsa": ("GitHub Security Advisories", "https://github.com/advisories"),
    "nvd": ("NVD / MITRE CVE", "https://nvd.nist.gov/"),
    "immunefi": ("Immunefi reports", "https://immunefi.com/explore/"),
}


# ---------------------------------------------------------------------------
# Checkpoint definitions
# ---------------------------------------------------------------------------

CHECKPOINTS = {
    "pre-hunt": {
        "label": "Pre-hunt baseline — reference frame for the whole session",
        "always": [
            ("fetch", "owasp_web"), ("fetch", "cwe25"), ("fetch", "kev"),
        ],
        "mode_queries": {
            "web": [
                ("search", "OWASP Top 10 2025 web application risks"),
                ("search", "CWE Top 25 2025 most dangerous software weaknesses"),
            ],
            "llm-ai": [
                ("fetch", "llm26"), ("fetch", "agentic26"),
                ("search", "OWASP GenAI LLM Top 10 2026 new entries"),
                ("search", "OWASP Top 10 Agentic Applications ASI01 ASI10"),
            ],
            "solidity": [("search", "smart contract audit findings 2025 2026"),
                         ("fetch", "rekt")],
            "move": [("search", "Move Aptos smart contract vulnerabilities 2025")],
            "solana": [("search", "Solana program vulnerabilities anchor 2025")],
            "cicd": [("fetch", "cicd"),
                     ("search", "GitHub Actions injection poisoned pipeline 2025")],
            "mobile": [("fetch", "mas"),
                       ("search", "OWASP MASVS MASWE mobile weaknesses 2026")],
            "cloud": [("fetch", "cnas"),
                      ("search", "cloud native top 10 kubernetes escape 2025")],
        },
    },
    "post-recon": {
        "label": "Post-recon — CVEs for the exact detected versions",
        "always": [
            ("fetch", "ghsa"), ("fetch", "nvd"),
        ],
        "mode_queries": {
            "web": [("search", "{stack} CVE security advisory")],
            "llm-ai": [("search", "{stack} CVE prompt injection vulnerability")],
            "solidity": [("search", "{stack} exploit audit finding")],
            "move": [("search", "{stack} vulnerability advisory")],
            "solana": [("search", "{stack} vulnerability advisory")],
            "cicd": [("search", "{stack} CVE supply chain")],
            "mobile": [("search", "{stack} CVE android ios vulnerability")],
            "cloud": [("search", "{stack} CVE container vulnerability")],
        },
    },
    "post-maps": {
        "label": "Post-maps — fresh technique payloads for the mapped surface",
        "always": [
            ("map", "maps/asset.md"), ("map", "maps/trust.md"),
            ("map", "maps/authz.md"), ("map", "maps/state.md"),
            ("map", "maps/capability.md"),
        ],
        "wordlists": ["vhosts", "params", "dirs", "payloads"],
        "mode_queries": {
            "web": [("search", "WAF bypass techniques 2026"),
                    ("search", "HTTP request smuggling cache poisoning 2026")],
            "llm-ai": [("search", "RAG poisoning embedding inversion 2026"),
                       ("search", "MCP server security injection 2026")],
            "solidity": [("search", "DeFi exploit reentrancy oracle 2026")],
            "move": [("search", "Aptos Move reentrancy invariant 2026")],
            "solana": [("search", "Solana PDA account confusion 2026")],
            "cicd": [("search", "GitHub Actions expression injection payload 2026")],
            "mobile": [("search", "Android intent redirection iOS URL scheme hijack 2026")],
            "cloud": [("search", "kubernetes RBAC escape cloud metadata SSRF 2026")],
        },
    },
    "post-findings": {
        "label": "Post-findings — bypasses + comparable disclosures for the found classes",
        "always": [
            ("fetch", "kev"),
        ],
        "mode_queries": {
            "web": [("search", "{bug_class} bypass 2026 hackerone disclosed report")],
            "llm-ai": [("search", "{bug_class} OWASP LLM agentic disclosure 2026")],
            "solidity": [("search", "{bug_class} sherlock code4rena finding")],
            "move": [("search", "{bug_class} aptos finding")],
            "solana": [("search", "{bug_class} solana finding")],
            "cicd": [("search", "{bug_class} CI/CD disclosure")],
            "mobile": [("search", "{bug_class} mobile CVE disclosed report")],
            "cloud": [("search", "{bug_class} cloud disclosure")],
        },
    },
    "pre-report": {
        "label": "Pre-report — current program scope/rules + recent similar disclosures",
        "always": [
            ("search", "{target} bug bounty program scope rules"),
            ("search", "{target} disclosed report {bug_class}"),
        ],
        "mode_queries": {},
    },
    "bypass": {
        "label": "Blocker-triggered — latest bypasses for the specific defense blocking a probe",
        "always": [
            ("search", "{defense} {bug_class} bypass 2026"),
            ("search", "{defense} filter evasion payload technique"),
        ],
        "wordlists": ["payloads"],
        "mode_queries": {
            "web": [("search", "{defense} WAF bypass payload 2026")],
            "llm-ai": [("search", "{defense} prompt injection filter bypass 2026")],
            "solidity": [("search", "{defense} {bug_class} mitigation bypass audit")],
            "move": [("search", "{defense} {bug_class} mitigation bypass")],
            "solana": [("search", "{defense} {bug_class} mitigation bypass")],
            "cicd": [("search", "{defense} CI/CD control bypass 2026")],
            "mobile": [("search", "{defense} mobile detection bypass {bug_class}")],
            "cloud": [("search", "{defense} cloud control bypass {bug_class}")],
        },
    },
    "escalation": {
        "label": "Finding-triggered — research the path from Medium/Low to validated High/Critical",
        "always": [
            ("search", "{bug_class} high critical disclosed report bounty 2026"),
            ("search", "{bug_class} chained account-takeover rce 2026"),
            ("search", "{bug_class} {target}"),
        ],
        "mode_queries": {
            "web": [("search", "{bug_class} escalation privilege account takeover hackerone 2026")],
            "llm-ai": [("search", "{bug_class} agentic escalation high critical 2026")],
            "solidity": [("search", "{bug_class} high critical sherlock code4rena 2026")],
            "move": [("search", "{bug_class} high critical aptos 2026")],
            "solana": [("search", "{bug_class} high critical solana 2026")],
            "cicd": [("search", "{bug_class} high critical supply chain 2026")],
            "mobile": [("search", "{bug_class} high critical mobile CVE 2026")],
            "cloud": [("search", "{bug_class} high critical cloud misconfig 2026")],
        },
    },
}


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class ResearchLoop:
    """Deterministic spec of mandatory research tasks per checkpoint + mode."""

    def __init__(self, target: str = "", stack: str = "", bug_classes: str = "",
                 defense: str = ""):
        self.target = target
        self.stack_items = [s.strip() for s in stack.split(",") if s.strip()]
        self.bug_classes = [b.strip() for b in bug_classes.split(",") if b.strip()]
        self.defense = defense.strip()

    def _expand(self, query: str) -> List[str]:
        """Expand {stack}/{target}/{bug_class} placeholders into concrete queries.

        Handles multiple placeholders per query (cartesian product) and drops
        the query entirely when a required placeholder has no supplied value.
        """
        import itertools
        slots: Dict[str, List[str]] = {}
        if "{stack}" in query and self.stack_items:
            slots["{stack}"] = self.stack_items
        if "{target}" in query and self.target:
            slots["{target}"] = [self.target]
        if "{bug_class}" in query and self.bug_classes:
            slots["{bug_class}"] = self.bug_classes
        if "{defense}" in query and self.defense:
            slots["{defense}"] = [self.defense]

        # A placeholder present in the query but with no value => drop it.
        for ph in ("{stack}", "{target}", "{bug_class}", "{defense}"):
            if ph in query and ph not in slots:
                return []

        if not slots:
            return [query]

        keys = list(slots.keys())
        results: List[str] = []
        for combo in itertools.product(*[slots[k] for k in keys]):
            q = query
            for ph, val in zip(keys, combo):
                q = q.replace(ph, val)
            results.append(q)
        return results

    def tasks(self, checkpoint: str, modes: List[str]) -> List[ResearchTask]:
        if checkpoint not in CHECKPOINTS:
            raise ValueError(
                f"unknown checkpoint '{checkpoint}'. Valid: "
                + ", ".join(sorted(CHECKPOINTS)))
        spec = CHECKPOINTS[checkpoint]
        out: List[ResearchTask] = []
        order = 0

        def add(task_type, value, detail=""):
            nonlocal order
            order += 1
            if task_type == "fetch":
                name, url = CANONICAL[value]
                out.append(ResearchTask(
                    checkpoint=checkpoint, order=order, task_type="fetch",
                    source=url, detail=f"{name}: {detail or spec['label']}"))
            elif task_type == "map":
                out.append(ResearchTask(
                    checkpoint=checkpoint, order=order, task_type="map",
                    source=value,
                    detail="refresh this map with the research output"))
            elif task_type == "wordlist":
                out.append(ResearchTask(
                    checkpoint=checkpoint, order=order, task_type="wordlist",
                    source=value,
                    detail=f"generate target-specific {value} wordlist"))
            else:  # search
                out.append(ResearchTask(
                    checkpoint=checkpoint, order=order, task_type="search",
                    query=value, detail=spec["label"]))

        for task_type, value in spec["always"]:
            if task_type == "search":
                for expanded in self._expand(value):
                    add("search", expanded)
            else:
                add(task_type, value)

        for mode in modes:
            if mode not in spec["mode_queries"]:
                continue
            for task_type, query in spec["mode_queries"][mode]:
                if task_type == "fetch":
                    add("fetch", query)
                else:
                    for expanded in self._expand(query):
                        add("search", expanded)

        # Wordlists: only for web-ish fuzz phases (contract audits have no URL surface)
        webish = {"web", "mobile", "cloud", "cicd", "llm-ai"}
        if any(m in webish for m in modes):
            for wl in spec.get("wordlists", []):
                add("wordlist", wl)

        return out

    def render(self, checkpoint: str, modes: List[str]) -> str:
        spec = CHECKPOINTS[checkpoint]
        lines = [
            "=" * 72,
            f"  MANDATORY DEEP-RESEARCH — {checkpoint}",
            f"  {spec['label']}",
            "=" * 72,
        ]
        for t in self.tasks(checkpoint, modes):
            tag = f"[{t.order:02d}] {t.task_type.upper()}"
            if t.task_type == "search":
                lines.append(f"  {tag}  {t.query}")
            elif t.task_type == "fetch":
                lines.append(f"  {tag}  {t.source}   ({t.detail})")
            elif t.task_type == "wordlist":
                lines.append(f"  {tag}  generate {t.source} wordlist via wordlist_gen.py")
            else:
                lines.append(f"  {tag}  write findings back to {t.source}")
        lines.append("=" * 72)
        lines.append("  Execute every task above, then write the results into")
        lines.append("  research/{target}/ and the relevant maps before proceeding.")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Live execution — fetch + search + persist
# ---------------------------------------------------------------------------

USER_AGENT = "bugwolf-research/1.0 (+https://github.com/Gabson0x/bugwolf)"


def _html_to_text(markup: str, max_chars: int = 50000) -> str:
    """Crude but robust HTML → readable-text extraction for research notes."""
    s = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", markup)
    s = re.sub(r"(?i)</?(p|div|section|article|h[1-6]|li|tr|br|ul|ol|table|blockquote|pre)[^>]*>", "\n", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t\r]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n\n", s)
    return s.strip()[:max_chars]


def _slugify(text: str) -> str:
    """URL/name → filesystem-safe slug."""
    base = text.split("://")[-1].split("?")[0].rstrip("/")
    base = base.split("/")[-1] or base
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")
    return slug[:60] or "source"


def _read_lines(path: Path) -> List[str]:
    """Read non-empty lines from a file, returning [] on any failure."""
    try:
        return [l for l in path.read_text().splitlines() if l.strip()]
    except OSError:
        return []


def fetch_url(url: str, timeout: int = 12) -> Dict:
    """Live-fetch a canonical source. Returns {url, final_url, status, text,
    content_type, error}. Never raises — failures are reported in the dict."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "ignore")
            return {
                "url": url,
                "final_url": r.geturl(),
                "status": r.status,
                "text": raw,
                "content_type": r.headers.get("content-type", ""),
                "error": "",
            }
    except Exception as e:
        return {
            "url": url,
            "final_url": url,
            "status": 0,
            "text": "",
            "content_type": "",
            "error": f"{type(e).__name__}: {e}",
        }


def search_web(query: str, limit: int = 5, timeout: int = 12) -> List[Dict]:
    """Live web search via a pluggable backend.

    Prefers SERPER_API_KEY, then a custom RESEARCH_SEARCH_API_URL + key.
    Returns a list of {title, url, snippet}. Returns [] when no provider is
    configured (caller should mark the query as pending for the agent).
    """
    key = os.environ.get("SERPER_API_KEY") or os.environ.get("RESEARCH_SEARCH_API_KEY")
    api_url = os.environ.get("RESEARCH_SEARCH_API_URL", "https://google.serper.dev/search")
    if not key:
        return []
    payload = json.dumps({"q": query, "num": limit}).encode("utf-8")
    req = urllib.request.Request(
        api_url, data=payload,
        headers={"X-API-KEY": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return []
    out: List[Dict] = []
    for org in data.get("organic", [])[:limit]:
        out.append({
            "title": org.get("title", ""),
            "url": org.get("link", ""),
            "snippet": org.get("snippet", ""),
        })
    return out


class ResearchExecutor:
    """Runs the loop's tasks live and persists results under research/{target}/."""

    def __init__(self, target: str = "default", base_dir: Optional[str] = None,
                 run_search: bool = True, limit: int = 5, timeout: int = 12):
        self.target = target or "default"
        self.base = Path(base_dir) if base_dir else ROOT / "research"
        self.run_search = run_search
        self.limit = limit
        self.timeout = timeout

    def _checkpoint_dir(self, checkpoint: str) -> Path:
        safe = re.sub(r"[^\w.\-]+", "_", self.target)
        d = self.base / safe / checkpoint
        d.mkdir(parents=True, exist_ok=True)
        return d

    def execute(self, loop: "ResearchLoop", checkpoint: str,
                modes: List[str]) -> Dict:
        """Fetch + search every task, persist to research/{target}/{checkpoint}/."""
        tasks = loop.tasks(checkpoint, modes)
        cdir = self._checkpoint_dir(checkpoint)
        sources_dir = cdir / "sources"
        sources_dir.mkdir(exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()

        records: List[Dict] = []
        for t in tasks:
            rec = {"order": t.order, "task_type": t.task_type, "checkpoint": checkpoint}
            if t.task_type == "fetch":
                fetched = fetch_url(t.source, timeout=self.timeout)
                rec.update({
                    "source": t.source,
                    "final_url": fetched["final_url"],
                    "status": fetched["status"],
                    "error": fetched["error"],
                })
                if fetched["status"] and fetched["status"] < 400:
                    fname = sources_dir / f"{_slugify(t.source)}.md"
                    fname.write_text(
                        f"# {t.detail}\n\nSource: {t.source}\n"
                        f"Final URL: {fetched['final_url']}\nFetched: {ts}\n\n"
                        f"{_html_to_text(fetched['text'])}")
                    rec["saved_to"] = str(fname.relative_to(self.base))
            elif t.task_type == "search":
                rec["query"] = t.query
                if self.run_search:
                    results = search_web(t.query, limit=self.limit, timeout=self.timeout)
                    rec["results"] = results
                    rec["pending"] = not results
                else:
                    rec["results"] = []
                    rec["pending"] = True
            elif t.task_type == "wordlist":
                from tools.wordlist_gen import (
                    generate as wl_generate, research_terms as wl_research,
                    save_cache as wl_save_cache)
                urls = _read_lines(ROOT / "recon" / self.target / "urls.txt")
                js = _read_lines(ROOT / "recon" / self.target / "jsfiles.txt")
                defense = getattr(loop, "defense", "")
                bug_classes = getattr(loop, "bug_classes", []) or []
                bug_class = bug_classes[0] if bug_classes else ""
                fn = (lambda tgt, m, k, s: wl_research(
                    tgt, m, k, s, defense=defense, bug_class=bug_class)) \
                    if self.run_search else None
                words = wl_generate(self.target, mode=t.source, urls=urls,
                                    js_files=js, research_fn=fn,
                                    defense=defense, bug_class=bug_class)
                wdir = cdir / "wordlists"
                wdir.mkdir(exist_ok=True)
                fname = wdir / f"{t.source}.txt"
                fname.write_text("\n".join(words) + ("\n" if words else ""))
                rec.update({"wordlist_mode": t.source, "count": len(words),
                            "saved_to": str(fname.relative_to(self.base))})
                # also cache to the stable cross-turn location
                try:
                    wl_save_cache(self.target, t.source, words,
                                  cache_root=self.base)
                except Exception:
                    pass
            else:  # map
                rec["map_target"] = t.source
            records.append(rec)

        (cdir / "SUMMARY.md").write_text(self._render_summary(
            checkpoint, modes, ts, records))
        (cdir / "results.json").write_text(json.dumps({
            "schema": "research_execution/1.0",
            "target": self.target,
            "checkpoint": checkpoint,
            "modes": modes,
            "executed_at": ts,
            "records": records,
        }, indent=2))
        return {"checkpoint": checkpoint, "dir": str(cdir), "records": records}

    def _render_summary(self, checkpoint: str, modes: List[str], ts: str,
                        records: List[Dict]) -> str:
        lines = [
            f"# Research Checkpoint: {checkpoint}",
            f"Target: {self.target}",
            f"Modes: {', '.join(modes)}",
            f"Executed: {ts}",
            "",
        ]
        fetches = [r for r in records if r["task_type"] == "fetch"]
        searches = [r for r in records if r["task_type"] == "search"]
        maps = [r for r in records if r["task_type"] == "map"]
        wordlists = [r for r in records if r["task_type"] == "wordlist"]

        lines.append("## Fetched sources")
        for r in fetches:
            if r.get("error"):
                lines.append(f"- [{r.get('status', 0)}] {r['source']} — ERROR: {r['error']}")
            else:
                lines.append(f"- [{r.get('status')}] {r['source']} → {r.get('saved_to', 'saved')}")
        if not fetches:
            lines.append("- (none)")

        lines.append("")
        lines.append("## Search results")
        for r in searches:
            lines.append(f"### {r['query']}")
            if r.get("pending"):
                lines.append("_(pending — no search provider configured; run via the agent's web search)_")
            elif r.get("results"):
                for res in r["results"]:
                    lines.append(f"- [{res['title']}]({res['url']})")
                    if res.get("snippet"):
                        lines.append(f"  {res['snippet']}")
            else:
                lines.append("_(no results)_")
        if not searches:
            lines.append("- (none)")

        lines.append("")
        lines.append("## Map write-backs")
        for r in maps:
            lines.append(f"- {r['map_target']}")
        if not maps:
            lines.append("- (none)")

        lines.append("")
        lines.append("## Generated wordlists")
        for r in wordlists:
            lines.append(f"- {r['wordlist_mode']}: {r.get('count', 0)} words → {r.get('saved_to', 'saved')}")
        if not wordlists:
            lines.append("- (none)")

        lines.append("")
        lines.append("---")
        lines.append("Persisted by tools/research_loop.py --execute.")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Mandatory Deep-Research Loop v1.0.0")
    parser.add_argument("--checkpoint", default="pre-hunt",
                        help="Checkpoint: pre-hunt | post-recon | post-maps | "
                             "post-findings | pre-report | bypass | escalation")
    parser.add_argument("--mode", default="web",
                        help="Comma-separated modes: web, llm-ai, solidity, move, "
                             "solana, cicd, mobile, cloud")
    parser.add_argument("--target", default="", help="Target name for pre-report")
    parser.add_argument("--stack", default="",
                        help="Comma-separated detected versions for CVE research")
    parser.add_argument("--bug-classes", default="",
                        help="Comma-separated found bug classes for post-findings")
    parser.add_argument("--defense", default="",
                        help="Defense/blocker for the bypass checkpoint "
                             "(e.g. 'Cloudflare WAF', '403 filter', 'rate limit')")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit structured JSON")
    parser.add_argument("--execute", action="store_true",
                        help="Execute fetches/searches live and persist to "
                             "research/{target}/{checkpoint}/")
    parser.add_argument("--limit", type=int, default=5,
                        help="Max search results per query (default: 5)")
    parser.add_argument("--no-search", action="store_true",
                        help="Skip search execution (fetches still run)")
    parser.add_argument("--list-checkpoints", action="store_true",
                        help="List checkpoints and exit")
    args = parser.parse_args()

    if args.list_checkpoints:
        for name, spec in CHECKPOINTS.items():
            print(f"  {name:14s} {spec['label']}")
        return

    modes = [m.strip() for m in args.mode.split(",") if m.strip()]
    loop = ResearchLoop(target=args.target, stack=args.stack,
                        bug_classes=args.bug_classes, defense=args.defense)

    if args.execute:
        executor = ResearchExecutor(
            target=args.target, run_search=not args.no_search,
            limit=args.limit)
        result = executor.execute(loop, args.checkpoint, modes)
        summary = {"fetched": sum(1 for r in result["records"]
                                  if r["task_type"] == "fetch" and not r.get("error")),
                   "search_done": sum(1 for r in result["records"]
                                      if r["task_type"] == "search" and not r.get("pending")),
                   "search_pending": sum(1 for r in result["records"]
                                         if r["task_type"] == "search" and r.get("pending")),
                   "maps": sum(1 for r in result["records"] if r["task_type"] == "map"),
                   "wordlists": sum(1 for r in result["records"]
                                    if r["task_type"] == "wordlist")}
        if args.as_json:
            print(json.dumps({
                "schema": "research_execution/1.0",
                "target": args.target,
                "checkpoint": args.checkpoint,
                "modes": modes,
                "dir": result["dir"],
                "summary": summary,
            }, indent=2))
        else:
            print("=" * 72)
            print(f"  RESEARCH EXECUTED — {args.checkpoint}")
            print(f"  Persisted to: {result['dir']}")
            print(f"  fetched: {summary['fetched']}  search done: {summary['search_done']}"
                  f"  search pending: {summary['search_pending']}  maps: {summary['maps']}"
                  f"  wordlists: {summary['wordlists']}")
            print("=" * 72)
        return

    try:
        tasks = loop.tasks(args.checkpoint, modes)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    if args.as_json:
        print(json.dumps({
            "schema": "research_loop/1.0",
            "checkpoint": args.checkpoint,
            "modes": modes,
            "tasks": [t.to_dict() for t in tasks],
        }, indent=2))
        return

    print(loop.render(args.checkpoint, modes))


if __name__ == "__main__":
    main()
