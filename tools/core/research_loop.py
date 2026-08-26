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
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

logger = logging.getLogger("bugwolf.research_loop")
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

_CODE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import CODE_ROOT, target_slug, workspace_root
from tools.adaptive_learning import AdaptiveMemory

ROOT = workspace_root()


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
    # -- dynamic event-driven checkpoints ----------------------------------
    # Optional checkpoints beyond the mandatory 7.  They are *appended* to the
    # current execution (never interleaved into the mandatory sweep) when the
    # campaign context carries a truthy trigger key, and once appended they
    # participate in latest_ready like any other checkpoint — so they add
    # depth without weakening the mandatory-7 semantics.
    "post-chain": {
        "label": "Post-chain — research the discovered chain partners' techniques",
        "always": [
            ("search", "{bug_class} chain partner technique 2026"),
            ("search", "{bug_class} multi-hop chain writeup disclosed"),
        ],
        "mode_queries": {
            "web": [("search", "{bug_class} chain escalation web 2026")],
            "llm-ai": [("search", "{bug_class} agentic chain exploit 2026")],
            "solidity": [("search", "{bug_class} defi chain exploit 2026")],
            "cloud": [("search", "{bug_class} cloud pivot chain 2026")],
        },
    },
    "post-lab-verification": {
        "label": "Post-lab — research the verified finding's full impact window",
        "always": [
            ("search", "{bug_class} verified exploit impact scope 2026"),
            ("search", "{bug_class} post-exploitation persistence 2026"),
        ],
        "mode_queries": {
            "web": [("search", "{bug_class} post-exploitation web 2026")],
            "llm-ai": [("search", "{bug_class} agent memory persistence 2026")],
            "solidity": [("search", "{bug_class} post-exploit fund movement 2026")],
            "cloud": [("search", "{bug_class} post-exploit lateral movement 2026")],
        },
    },
    "blocker-exhausted": {
        "label": "Blocker-exhausted — alternative approaches after a blocked probe",
        "always": [
            ("search", "{defense} alternative technique 2026"),
            ("search", "{bug_class} non-HTTP alternative vector 2026"),
        ],
        "mode_queries": {
            "web": [("search", "{defense} protocol-level bypass 2026")],
            "llm-ai": [("search", "{defense} side-channel injection 2026")],
            "solidity": [("search", "{defense} alternative entrypoint audit 2026")],
            "cloud": [("search", "{defense} alternative cloud vector 2026")],
        },
    },
    # -- hierarchical sub-checkpoints (deep dives) --------------------------
    # These are full checkpoints (runnable standalone) that the mandatory
    # sequence may inject *after their parent* when the campaign context
    # matches.  ``SUB_CHECKPOINTS`` below wires the triggers; the mandatory 7
    # remain required and in order — sub-checkpoints add depth between them.
    "graphql-deep-dive": {
        "label": "Sub-checkpoint (post-maps) — GraphQL surface mapped: batching, introspection, authorization",
        "always": [
            ("search", "GraphQL introspection disabled bypass 2026"),
            ("search", "GraphQL batching alias rate limit bypass 2026"),
            ("search", "GraphQL field duplication DoS depth limit 2026"),
        ],
        "mode_queries": {
            "web": [("search", "GraphQL authorization BOLA resolver 2026 hackerone")],
            "llm-ai": [("search", "GraphQL agentic API attack surface 2026")],
            "mobile": [("search", "GraphQL mobile app API endpoint attack 2026")],
        },
    },
    "waf-profile": {
        "label": "Sub-checkpoint (post-maps) — WAF/defense mapped: profile evasions for the detected stack",
        "always": [
            ("search", "{defense} WAF bypass encoding case 2026"),
            ("search", "{defense} parser differential evasion 2026"),
            ("search", "HTTP/2 request smuggling WAF bypass 2026"),
        ],
        "mode_queries": {
            "web": [("search", "{defense} sqli xss filter bypass payload 2026")],
            "llm-ai": [("search", "{defense} prompt injection filter bypass 2026")],
        },
    },
    "chain-partners": {
        "label": "Sub-checkpoint (post-findings) — look for chain partners for the found classes",
        "always": [
            ("search", "{bug_class} chained with {bug_class} account takeover 2026"),
            ("search", "{bug_class} to RCE chain writeup 2026"),
            ("search", "{bug_class} privilege escalation chain bug bounty 2026"),
        ],
        "mode_queries": {
            "web": [("search", "{bug_class} {bug_class} multi-hop chain hackerone 2026")],
            "llm-ai": [("search", "{bug_class} agent tool abuse chain 2026")],
        },
    },
    "cloud-metadata": {
        "label": "Sub-checkpoint (post-maps) — cloud/SSRF surface mapped: metadata and container escape research",
        "always": [
            ("search", "cloud metadata service SSRF 169.254.169.254 bypass 2026"),
            ("search", "container escape privileged docker socket 2026"),
            ("search", "serverless Lambda privilege escalation 2026"),
        ],
        "mode_queries": {
            "cloud": [("search", "{defense} cloud metadata filter bypass 2026")],
            "web": [("search", "SSRF cloud metadata credential theft 2026")],
        },
    },
}


# ---------------------------------------------------------------------------
# Hierarchical sub-checkpoint triggers
# ---------------------------------------------------------------------------

# parent -> [(sub_checkpoint, context_key, description)]
# A sub-checkpoint is injected right after its parent when the campaign
# context dict has a truthy value for ``context_key`` (e.g. the technology
# fingerprint found a GraphQL endpoint => ``context["graphql"] = True``).
SUB_CHECKPOINTS: Dict[str, List[tuple]] = {
    "post-maps": [
        ("graphql-deep-dive", "graphql",
         "GraphQL endpoint detected in maps/tech fingerprint"),
        ("waf-profile", "waf",
         "WAF/defense detected in tech fingerprint"),
        ("cloud-metadata", "cloud",
         "cloud/SSRF surface detected in maps"),
    ],
    "post-findings": [
        ("chain-partners", "bug_classes",
         "findings recorded — research chain partners for the found classes"),
    ],
}


# Dynamic event-driven checkpoints: checkpoint -> context key that triggers
# appending it to the current execution.  Once triggered they run like any
# other checkpoint and gate latest_ready; the mandatory 7 are never weakened.
DYNAMIC_TRIGGERS: Dict[str, str] = {
    "post-chain": "chain_candidates",
    "post-lab-verification": "lab_verification",
    "blocker-exhausted": "blocker_exhausted",
}


def dynamic_checkpoints_for(context: Optional[Dict]) -> List[str]:
    """Return triggered dynamic checkpoints in registry order (deterministic)."""
    ctx = context or {}
    return [name for name, key in DYNAMIC_TRIGGERS.items() if ctx.get(key)]


def sub_checkpoints_for(checkpoint: str, context: Optional[Dict]) -> List[str]:
    """Return the ordered sub-checkpoints to inject after a parent checkpoint.

    Deterministic: only sub-checkpoints whose context key is truthy fire, and
    the registry order is preserved.  The mandatory sequence itself is never
    altered — sub-checkpoints are additional depth, not replacements.
    """
    ctx = context or {}
    out: List[str] = []
    for sub_name, ctx_key, _desc in SUB_CHECKPOINTS.get(checkpoint, []):
        if ctx.get(ctx_key):
            out.append(sub_name)
    return out


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
MAX_FETCH_BYTES = 2_000_000
MAX_SEARCH_BYTES = 1_000_000

# Every real run uses these in order. The event-driven checkpoints are included
# in the mandatory sweep so bypass/escalation knowledge is not lost merely
# because the first probe did not produce a finding yet.
MANDATORY_RESEARCH_SEQUENCE = (
    "pre-hunt", "post-recon", "post-maps", "bypass",
    "post-findings", "escalation", "pre-report",
)
BEFORE_HUNT_SEQUENCE = MANDATORY_RESEARCH_SEQUENCE[:4]
AFTER_FINDINGS_SEQUENCE = MANDATORY_RESEARCH_SEQUENCE[4:]


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent canonical-source fetches from following cross-host redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if new.scheme not in {"http", "https"} or new.hostname != old.hostname:
            raise urllib.error.URLError("cross-host research redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_RESEARCH_OPENER = urllib.request.build_opener(_SameHostRedirectHandler())


def _offline_search(query: str, limit: int = 5) -> List[Dict]:
    """Search the bundled references when no external provider is configured.

    This keeps the research layer useful and deterministic in Freebuff/offline
    sessions. Results are explicitly marked as bundled references, never as
    live internet research.
    """
    terms = [term.lower() for term in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", query.lower())]
    if not terms:
        return []
    matches = []
    for path in sorted(CODE_ROOT.glob("references/**/*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.lower()
        score = sum(lowered.count(term) for term in terms)
        if score <= 0:
            continue
        lines = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        snippet = " ".join(lines[:3])[:500]
        matches.append((score, path, snippet))
    matches.sort(key=lambda item: (-item[0], str(item[1])))
    return [{
        "title": path.stem.replace("-", " ").replace("_", " ").title(),
        "url": f"bundle://{path.relative_to(CODE_ROOT).as_posix()}",
        "snippet": snippet,
        "source": "bundled_reference",
    } for _, path, snippet in matches[:max(1, limit)]]


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
    """Fetch a canonical source with bounded, same-host redirects."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"url": url, "final_url": url, "status": 0, "text": "",
                "content_type": "", "error": "research sources must use HTTPS"}
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _RESEARCH_OPENER.open(req, timeout=timeout) as r:
            length = r.headers.get("Content-Length")
            if length and int(length) > MAX_FETCH_BYTES:
                raise ValueError("research response exceeds size limit")
            raw_bytes = r.read(MAX_FETCH_BYTES + 1)
            if len(raw_bytes) > MAX_FETCH_BYTES:
                raise ValueError("research response exceeds size limit")
            return {
                "url": url,
                "final_url": r.geturl(),
                "status": r.status,
                "text": raw_bytes.decode("utf-8", "ignore"),
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


def search_web(query: str, limit: int = 5, timeout: int = 12,
               allow_offline: bool = True) -> List[Dict]:
    """Search through the configured provider, then bundled references.

    The fallback is intentionally labelled as local research so the executor
    can distinguish it from live search and the layer no longer appears broken
    merely because SERPER credentials are unavailable.
    """
    key = os.environ.get("SERPER_API_KEY") or os.environ.get("RESEARCH_SEARCH_API_KEY")
    api_url = os.environ.get("RESEARCH_SEARCH_API_URL", "https://google.serper.dev/search")
    if not key and not allow_offline:
        search_web.last_backend = "live_provider_unconfigured"
        return []
    if key:
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" or not parsed.hostname:
            if not allow_offline:
                search_web.last_backend = "invalid_provider"
                return []
            search_web.last_backend = "invalid_provider"
            return _offline_search(query, limit)
        payload = json.dumps({"q": query, "num": limit}).encode("utf-8")
        req = urllib.request.Request(
            api_url, data=payload,
            headers={"X-API-KEY": key, "Content-Type": "application/json"})
        try:
            with _RESEARCH_OPENER.open(req, timeout=timeout) as r:
                if urllib.parse.urlparse(r.geturl()).hostname != parsed.hostname:
                    raise ValueError("cross-host search redirect rejected")
                raw = r.read(MAX_SEARCH_BYTES + 1)
                if len(raw) > MAX_SEARCH_BYTES:
                    raise ValueError("search response exceeds size limit")
                data = json.loads(raw.decode("utf-8", "ignore"))
            out = [{
                "title": org.get("title", ""),
                "url": org.get("link", ""),
                "snippet": org.get("snippet", ""),
                "source": "live_search",
            } for org in data.get("organic", [])[:limit]]
            if out:
                search_web.last_backend = "live_search"
                return out
            if not allow_offline:
                search_web.last_backend = "live_provider_empty"
                return []
        except Exception:
            # In a latest-required run, a failed provider must remain pending;
            # bundled references are not current web results.
            if not allow_offline:
                search_web.last_backend = "live_provider_error"
                return []
    if not allow_offline:
        search_web.last_backend = "live_provider_unconfigured"
        return []
    search_web.last_backend = "bundled_reference"
    return _offline_search(query, limit)


search_web.last_backend = "unknown"


class ResearchExecutor:
    """Runs the loop's tasks live and persists results under research/{target}/."""

    def __init__(self, target: str = "default", base_dir: Optional[str] = None,
                 run_search: bool = True, limit: int = 5, timeout: int = 12):
        self.target = target or "default"
        self.base = Path(base_dir) if base_dir else ROOT / "research"
        self.run_search = run_search
        self.limit = limit
        self.timeout = timeout
        # A custom research base is normally <workspace>/research. Keep the
        # adaptive store beside state in that same workspace for deterministic
        # tests and installed-bundle runs.
        learning_root = self.base.parent if base_dir else ROOT
        self.learning = AdaptiveMemory(self.target, root=learning_root)

    def _checkpoint_dir(self, checkpoint: str) -> Path:
        d = self.base / target_slug(self.target) / checkpoint
        d.mkdir(parents=True, exist_ok=True)
        return d

    def execute(self, loop: "ResearchLoop", checkpoint: str,
                modes: List[str], *, require_latest: bool = False) -> Dict:
        """Fetch + search every task, persist to research/{target}/{checkpoint}/.

        ``require_latest`` disables the bundled-reference fallback for search
        tasks. This is used by mandatory run orchestration so an offline result
        cannot be mistaken for current internet research.
        """
        tasks = loop.tasks(checkpoint, modes)
        approved_learning = self.learning.approved(limit=32)
        approved_ids = [record["technique_id"] for record in approved_learning]
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
                    results = search_web(
                        t.query, limit=self.limit, timeout=self.timeout,
                        allow_offline=not require_latest)
                    rec["results"] = results
                    rec["pending"] = not results
                    backend = getattr(search_web, "last_backend", "unknown")
                    # Tests and integrations may inject a plain callable/mock;
                    # never let adapter metadata make the persisted JSON invalid.
                    rec["research_source"] = (
                        backend if isinstance(backend, str) else "injected_adapter")
                else:
                    rec["results"] = []
                    rec["pending"] = True
            elif t.task_type == "wordlist":
                from tools.wordlist_gen import (
                    generate as wl_generate, research_terms as wl_research,
                    save_cache as wl_save_cache)
                safe_recon_target = target_slug(self.target)
                urls = _read_lines(ROOT / "recon" / safe_recon_target / "urls.txt")
                js = _read_lines(ROOT / "recon" / safe_recon_target / "jsfiles.txt")
                defense = getattr(loop, "defense", "")
                bug_classes = getattr(loop, "bug_classes", []) or []
                bug_class = bug_classes[0] if bug_classes else ""
                fn = (lambda tgt, m, k, s: wl_research(
                    tgt, m, k, s, defense=defense, bug_class=bug_class)) \
                    if self.run_search else None
                words = wl_generate(self.target, mode=t.source, urls=urls,
                                    js_files=js, research_fn=fn,
                                    defense=defense, bug_class=bug_class)
                learned_terms = [
                    term for record in approved_learning
                    for term in record.get("terms", [])
                ]
                if learned_terms:
                    words = list(dict.fromkeys(words + learned_terms))
                applied_ids = [
                    record["technique_id"] for record in approved_learning
                    if any(term in learned_terms for term in record.get("terms", []))
                ]
                wdir = cdir / "wordlists"
                wdir.mkdir(exist_ok=True)
                fname = wdir / f"{t.source}.txt"
                fname.write_text("\n".join(words) + ("\n" if words else ""))
                rec.update({"wordlist_mode": t.source, "count": len(words),
                            "saved_to": str(fname.relative_to(self.base)),
                            "applied_learning": applied_ids})
                self.learning.mark_used(applied_ids, journey=checkpoint)
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
            "learning": {
                "approved_available": approved_ids,
                "reuse_policy": "approved_only",
            },
        }, indent=2))
        search_records = [r for r in records if r["task_type"] == "search"]
        fetch_records = [r for r in records if r["task_type"] == "fetch"]
        latest_ready = (
            all(not r.get("pending") and r.get("research_source") in {
                    "live_search", "injected_adapter"}
                for r in search_records)
            and all(not r.get("error") and 200 <= r.get("status", 0) < 400
                    for r in fetch_records))
        # Bypass checkpoint: when the tech fingerprint reports a WAF/defense,
        # expect a parser-differential payload set (waf-payloads-*.json) to
        # exist alongside the bypass research — recorded, never blocking.
        waf_payloads_expected = False
        waf_payloads_present = False
        if checkpoint == "bypass":
            fingerprint = self.base.parent / "recon" / \
                target_slug(self.target) / \
                "tech-fingerprint.json"
            try:
                fp_data = json.loads(fingerprint.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                fp_data = {}
            blob = json.dumps(fp_data).lower()
            if any(term in blob for term in
                   ("waf", "cloudflare", "akamai", "aws shield", "imperva",
                    "fastly", "modsecurity", "f5")):
                waf_payloads_expected = True
                target_dir = self.base / target_slug(self.target)
                waf_payloads_present = bool(
                    list(target_dir.glob("bypass/waf-payloads-*.json")))
        return {"checkpoint": checkpoint, "dir": str(cdir), "records": records,
                "latest_required": require_latest,
                "latest_ready": latest_ready,
                "waf_payloads_expected": waf_payloads_expected,
                "waf_payloads_present": waf_payloads_present,
                "learning": {
                    "approved_available": approved_ids,
                    "reuse_policy": "approved_only",
                }}

    def execute_sequential(
        self, loop: "ResearchLoop", modes: List[str], *,
        checkpoints: Optional[List[str]] = None,
        stack: str = "", bug_classes: str = "", defense: str = "",
        context: Optional[Dict] = None,
        require_latest: bool = True, run_label: str = "",
        on_checkpoint: Optional[Callable] = None,
    ) -> Dict:
        """Execute mandatory research checkpoints strictly one after another.

        Context is carried forward: exact stack versions feed R2, discovered
        bug classes feed R4/R6/R7, and the blocker context feeds bypass queries.
        A checkpoint failure is recorded and the sequence continues so one
        unavailable source cannot silently skip the later bypass/escalation
        research.

        Hierarchical depth: when ``context`` matches a sub-checkpoint trigger
        (e.g. ``context["graphql"]``), the sub-checkpoint is executed
        immediately after its parent and before the next mandatory checkpoint,
        so the loop dives deeper exactly where the surface demands it.  The
        mandatory 7 are never reordered or dropped.
        """
        selected = list(checkpoints or MANDATORY_RESEARCH_SEQUENCE)
        unknown = [name for name in selected if name not in CHECKPOINTS]
        if unknown:
            raise ValueError(f"unknown research checkpoint(s): {', '.join(unknown)}")
        if not selected:
            raise ValueError("at least one research checkpoint is required")

        current_stack = stack
        current_bug_classes = bug_classes
        current_defense = defense or "current WAF, filter, rate limit"
        ctx = context or {}
        runs: List[Dict] = []
        sequence_number = 0
        # Ordered plan: mandatory sweep (with hierarchical sub-checkpoints
        # injected after their parent) followed by any triggered dynamic
        # event-driven checkpoints appended at the end.
        ordered: List[tuple] = []
        for checkpoint in selected:
            for name in (checkpoint,) + tuple(sub_checkpoints_for(checkpoint, ctx)):
                ordered.append((name, checkpoint if name != checkpoint else ""))
        for name in dynamic_checkpoints_for(ctx):
            ordered.append((name, "dynamic"))
        for name, parent in ordered:
            sequence_number += 1
            phase_loop = ResearchLoop(
                target=self.target, stack=current_stack,
                bug_classes=current_bug_classes, defense=current_defense)
            result = self.execute(
                phase_loop, name, modes, require_latest=require_latest)
            # Fast-path hook (U1): notify a caller after each checkpoint so it
            # can spawn parallel deep-dive research without blocking the main
            # sweep.  Handler failures are logged and never abort the loop.
            if on_checkpoint is not None:
                self._safe_notify(on_checkpoint, result, ctx)
            runs.append({
                "sequence": sequence_number,
                "checkpoint": name,
                "sub_of": parent,
                "dir": result["dir"],
                "latest_required": result["latest_required"],
                "latest_ready": result["latest_ready"],
                "records": len(result["records"]),
                "pending_searches": sum(
                    1 for record in result["records"]
                    if record.get("task_type") == "search" and record.get("pending")),
            })

        target_dir = target_slug(self.target)
        sequence_path = self.base / target_dir / "sequence.json"
        sequence_path.parent.mkdir(parents=True, exist_ok=True)
        latest_ready = all(item["latest_ready"] for item in runs)
        execution = {
            "label": run_label or "custom",
            "sequence": [item["checkpoint"] for item in runs],
            "runs": runs,
            "latest_required": require_latest,
            "latest_ready": latest_ready,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        previous = {}
        if sequence_path.exists():
            try:
                previous = json.loads(sequence_path.read_text())
            except (OSError, TypeError, json.JSONDecodeError):
                previous = {}
        history = list(previous.get("executions", []))
        history.append(execution)
        all_checkpoints = [
            checkpoint for item in history
            for checkpoint in item.get("sequence", [])
        ]
        manifest = {
            "schema": "research_execution/sequential-v1",
            "target": self.target,
            "modes": modes,
            "sequence": all_checkpoints,
            # ``runs`` is the current execution for callers that need the
            # just-completed ordered sweep; ``executions`` remains the full
            # append-only audit history.
            "runs": runs,
            "executions": history,
            "latest_required": any(item.get("latest_required") for item in history),
            "latest_ready": all(item.get("latest_ready", False) for item in history),
            "completed_at": execution["completed_at"],
        }
        sequence_path.write_text(json.dumps(manifest, indent=2))
        return {**manifest, "dir": str(sequence_path.parent),
                "sequence_file": str(sequence_path),
                # Keep the current run available to callers.  The manifest's
                # top-level ``sequence`` is the accumulated audit history, so
                # CLI/reporting code must not infer the current run from it.
                "runs": runs,
                "current_execution": execution}

    @staticmethod
    def _safe_notify(on_checkpoint: Callable, result: Dict,
                     context: Dict) -> None:
        """Invoke the fast-path callback without ever blocking the sweep.

        The callback receives the finished checkpoint result plus the carried
        context (stack/bug classes/defense).  Any exception is logged and
        swallowed — the fast-path engine is advisory by design.
        """
        try:
            on_checkpoint(result, context)
        except Exception as exc:
            logger.warning("fast-path on_checkpoint handler failed: %s", exc)

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


def run_mandatory_research(
    target: str,
    modes: List[str] | str,
    *,
    phase: str = "full",
    base_dir: Optional[str] = None,
    stack: str = "",
    bug_classes: str = "",
    defense: str = "",
    context: Optional[Dict] = None,
    limit: int = 5,
    timeout: int = 12,
    require_latest: bool = True,
    run_search: bool = True,
    on_checkpoint: Optional[Callable] = None,
) -> Dict:
    """Run the mandatory sequential research sweep for a real tool run."""
    if isinstance(modes, str):
        modes = [item.strip() for item in modes.split(",") if item.strip()]
    sequences = {
        "before_hunt": BEFORE_HUNT_SEQUENCE,
        "recon": ("post-recon", "post-maps"),
        "bypass": ("bypass",),
        "after_findings": AFTER_FINDINGS_SEQUENCE,
        "full": MANDATORY_RESEARCH_SEQUENCE,
    }
    if phase not in sequences:
        raise ValueError(f"unknown mandatory research phase: {phase}")
    executor = ResearchExecutor(
        target=target, base_dir=base_dir, run_search=run_search,
        limit=limit, timeout=timeout)
    result = executor.execute_sequential(
        ResearchLoop(target=target, stack=stack,
                     bug_classes=bug_classes, defense=defense),
        modes, checkpoints=list(sequences[phase]),
        stack=stack, bug_classes=bug_classes, defense=defense,
        context=context, require_latest=require_latest, run_label=phase,
        on_checkpoint=on_checkpoint,
    )
    result["phase"] = phase
    return result


def fast_path_signals(result: Dict) -> List[Dict]:
    """Deterministic fast-path triggers derived from one checkpoint result.

    The caller (orchestrator or harness) uses these signals to spawn parallel
    deep-dive research *without* altering the mandatory sweep: the signals
    describe what already became available at this checkpoint (fresh WAF
    payload families, fetched canonical sources, search results), so follow-up
    hypothesis work can run off the main path.  Order is stable.
    """
    signals: List[Dict] = []
    checkpoint = str(result.get("checkpoint", ""))
    if checkpoint == "bypass" and result.get("waf_payloads_present"):
        signals.append({
            "trigger": "waf-bypass-payloads",
            "checkpoint": checkpoint,
            "detail": "parser-differential WAF payload families are ready "
                       "for the detected stack",
            "payload": {"waf_payloads": True},
        })
    records = result.get("records", []) or []
    fresh_fetches = [
        record for record in records
        if record.get("task_type") == "fetch"
        and record.get("status") and 200 <= int(record.get("status", 0)) < 400
    ]
    if fresh_fetches:
        signals.append({
            "trigger": "canonical-source-fresh",
            "checkpoint": checkpoint,
            "detail": f"{len(fresh_fetches)} canonical sources fetched",
            "payload": {"sources": [record.get("source") or ""
                                     for record in fresh_fetches[:8]]},
        })
    searches = [
        record for record in records
        if record.get("task_type") == "search" and record.get("results")
    ]
    if searches:
        signals.append({
            "trigger": "search-signal",
            "checkpoint": checkpoint,
            "detail": f"{len(searches)} search(es) returned results",
            "payload": {"queries": [record.get("query") or ""
                                     for record in searches[:8]]},
        })
    return signals


def mandatory_ordered_subsequence(sequence: List[str]) -> bool:
    """True when ``sequence`` contains the mandatory 7 in order.

    Sub-checkpoints may be interleaved between mandatory checkpoints (they add
    depth), so an exact-equality check would wrongly fail a legitimate deep
    run.  This is the single source of truth mirrored by the stage controller
    so both enforcement points agree on what "the complete ordered sequence"
    means.
    """
    iterator = iter(sequence)
    return all(
        any(item == required for item in iterator)
        for required in MANDATORY_RESEARCH_SEQUENCE
    )


# ---------------------------------------------------------------------------
# Enforcement layer — block stale research, never block fresh research
# ---------------------------------------------------------------------------

class ResearchFreshnessError(RuntimeError):
    """Raised when the mandatory research sequence is missing or stale.

    The stage controller mirrors this check in ``_validate_research``; this
    class exists so orchestrators can gate on freshness programmatically
    without importing the workflow controller.
    """


def verify_sequence(target: str, *, base_dir: Optional[str] = None,
                    require_latest: bool = True) -> Dict[str, Any]:
    """Verify the persisted mandatory research sequence for a target.

    Deterministic report (never raises for a missing/stale manifest):

      - ``sequence_ok``  — current execution covers the exact ordered sequence
      - ``latest_ready`` — freshness of the CURRENT execution only (historical
        offline runs never poison a later live run)
      - ``pending_searches`` — pending searches in the current execution
      - ``ready`` — ``sequence_ok`` and (``latest_ready`` or not ``require_latest``)

    Mirrors ``WorkflowController._validate_research`` so both enforcement
    points always agree.
    """
    target_dir = target_slug(target)
    # Same location execute_sequential persists to: <research-root>/<target>/.
    root = Path(base_dir) if base_dir else ROOT / "research"
    path = root / target_dir / "sequence.json"
    report: Dict[str, Any] = {
        "schema": "research_execution/verify-v1",
        "target": target or "",
        "sequence_file": str(path),
        "ready": False,
        "sequence_ok": False,
        "latest_ready": False,
        "pending_searches": -1,
        "sequence": [],
        "executions": 0,
        "errors": [],
    }
    if not path.is_file():
        report["errors"].append(
            f"no research sequence manifest at {path}; "
            f"run the mandatory sequence first")
        return report
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report["errors"].append(f"invalid research sequence manifest: {exc}")
        return report
    executions = data.get("executions") \
        if isinstance(data.get("executions"), list) else []
    current = executions[-1] if executions else data
    sequence = list(current.get("sequence", []))
    latest_ready = bool(current.get("latest_ready", False))
    runs = current.get("runs", []) if isinstance(current.get("runs"), list) else []
    pending = sum(int(item.get("pending_searches", 0)) for item in runs)
    sub_checkpoints = [
        item.get("checkpoint") for item in runs
        if item.get("sub_of") and item.get("sub_of") != "dynamic"
    ]
    dynamic_checkpoints = [
        item.get("checkpoint") for item in runs if item.get("sub_of") == "dynamic"
    ]
    report.update({
        "sequence": sequence,
        "executions": len(executions) or (1 if not executions and data else 0),
        "latest_ready": latest_ready,
        "pending_searches": pending,
        "sub_checkpoints": sub_checkpoints,
        "dynamic_checkpoints": dynamic_checkpoints,
    })
    report["sequence_ok"] = mandatory_ordered_subsequence(sequence)
    if not report["sequence_ok"]:
        report["errors"].append(
            "current execution is missing the ordered mandatory sequence: "
            + " -> ".join(MANDATORY_RESEARCH_SEQUENCE))
    if not latest_ready:
        report["errors"].append(
            f"latest_ready is false ({pending} pending searches); "
            f"research is not current")
    report["ready"] = report["sequence_ok"] and (
        latest_ready or not require_latest)
    return report


def assert_sequence_current(target: str, *, base_dir: Optional[str] = None,
                            require_latest: bool = True) -> Dict[str, Any]:
    """Raise unless the mandatory research sequence is current.

    ``require_latest=True`` demands fresh live research (raises on
    ``complete_pending``); ``require_latest=False`` only demands the exact
    ordered sequence to have run.  Returns the ``verify_sequence`` report on
    success.
    """
    report = verify_sequence(target, base_dir=base_dir,
                             require_latest=require_latest)
    if not report["ready"]:
        raise ResearchFreshnessError(
            "research not current for target " + (target or "?")
            + ": " + "; ".join(report["errors"]))
    return report


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
    parser.add_argument("--context", default="",
                        help="JSON context dict that triggers hierarchical "
                             "sub-checkpoints and dynamic checkpoints (e.g. "
                             "'{\"graphql\": true, \"waf\": true, "
                             "\"chain_candidates\": true}')")
    parser.add_argument("--list-sub-checkpoints", action="store_true",
                        help="List hierarchical sub-checkpoint triggers and exit")
    parser.add_argument("--list-dynamic-checkpoints", action="store_true",
                        help="List dynamic event-driven checkpoint triggers and exit")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit structured JSON")
    parser.add_argument("--execute", action="store_true",
                        help="Execute fetches/searches live and persist to "
                             "research/{target}/{checkpoint}/")
    parser.add_argument("--limit", type=int, default=5,
                        help="Max search results per query (default: 5)")
    parser.add_argument("--no-search", action="store_true",
                        help="Skip search execution (fetches still run)")
    parser.add_argument("--require-latest", action="store_true",
                        help="Do not use bundled references as a substitute for live search")
    parser.add_argument("--sequential", action="store_true",
                        help="Run the mandatory checkpoint sequence in order")
    parser.add_argument("--phase", choices=["before_hunt", "recon", "bypass",
                        "after_findings", "full"], default="full",
                        help="Sequential phase to run (default: full)")
    parser.add_argument("--list-checkpoints", action="store_true",
                        help="List checkpoints and exit")
    parser.add_argument("--verify-sequence", action="store_true",
                        help="Verify the mandatory research sequence for --target "
                             "and exit non-zero when stale")
    parser.add_argument("--base-dir", default=None,
                        help="Research root override (default: workspace research/)")
    args = parser.parse_args()

    if args.list_checkpoints:
        for name, spec in CHECKPOINTS.items():
            print(f"  {name:14s} {spec['label']}")
        return

    if args.list_sub_checkpoints:
        for parent, subs in SUB_CHECKPOINTS.items():
            for sub_name, ctx_key, desc in subs:
                print(f"  {parent:14s} -> {sub_name:22s} when context[{ctx_key}] "
                      f"({desc})")
        return

    if args.list_dynamic_checkpoints:
        for name, ctx_key in DYNAMIC_TRIGGERS.items():
            print(f"  {name:24s} appended when context[{ctx_key}] "
                  f"({CHECKPOINTS[name]['label']})")
        return

    context = {}
    if args.context:
        try:
            context = json.loads(args.context)
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False,
                              "error": f"--context is not valid JSON: {exc}"},
                             indent=2))
            return 2
        if not isinstance(context, dict):
            print(json.dumps({"ok": False,
                              "error": "--context must be a JSON object"}, indent=2))
            return 2

    if args.verify_sequence:
        if not args.target:
            print(json.dumps({"schema": "research_execution/verify-v1",
                              "ready": False, "errors": ["--verify-sequence requires --target"]},
                             indent=2))
            return 2
        report = verify_sequence(args.target, base_dir=args.base_dir)
        print(json.dumps(report, indent=2))
        return 0 if report["ready"] else 2

    modes = [m.strip() for m in args.mode.split(",") if m.strip()]
    loop = ResearchLoop(target=args.target, stack=args.stack,
                        bug_classes=args.bug_classes, defense=args.defense)

    if args.execute:
        if args.sequential:
            result = run_mandatory_research(
                args.target, modes, phase=args.phase,
                stack=args.stack, bug_classes=args.bug_classes,
                defense=args.defense, context=context, limit=args.limit,
                require_latest=True, run_search=not args.no_search)
        else:
            executor = ResearchExecutor(
                target=args.target, run_search=not args.no_search,
                limit=args.limit)
            result = executor.execute(
                loop, args.checkpoint, modes,
                require_latest=args.require_latest)
        if args.sequential:
            current_execution = result.get("current_execution", {})
            current_sequence = current_execution.get("sequence", result["sequence"])
            current_runs = current_execution.get("runs", result["runs"])
            summary = {
                "sequence": current_sequence,
                "history_sequence": result["sequence"],
                "latest_required": result["latest_required"],
                "latest_ready": result["latest_ready"],
                "sequence_file": result["sequence_file"],
                "pending_searches": sum(
                    item["pending_searches"] for item in current_runs),
            }
        else:
            summary = {"fetched": sum(1 for r in result["records"]
                                      if r["task_type"] == "fetch" and not r.get("error")),
                       "search_done": sum(1 for r in result["records"]
                                          if r["task_type"] == "search" and not r.get("pending")),
                       "search_pending": sum(1 for r in result["records"]
                                             if r["task_type"] == "search" and r.get("pending")),
                       "maps": sum(1 for r in result["records"] if r["task_type"] == "map"),
                       "wordlists": sum(1 for r in result["records"]
                                        if r["task_type"] == "wordlist"),
                       "latest_required": result["latest_required"],
                       "latest_ready": result["latest_ready"]}
        if args.as_json:
            print(json.dumps({
                "schema": ("research_execution/sequential-v1"
                           if args.sequential else "research_execution/1.0"),
                "target": args.target,
                "checkpoint": args.phase if args.sequential else args.checkpoint,
                "modes": modes,
                "dir": result["dir"],
                "summary": summary,
            }, indent=2))
        else:
            print("=" * 72)
            print(f"  RESEARCH EXECUTED — {args.phase if args.sequential else args.checkpoint}")
            print(f"  Persisted to: {result['dir']}")
            if args.sequential:
                print(f"  sequence: {' → '.join(summary['sequence'])}  "
                      f"pending searches: {summary['pending_searches']}  "
                      f"latest ready: {summary['latest_ready']}")
            else:
                print(f"  fetched: {summary['fetched']}  search done: {summary['search_done']}"
                      f"  search pending: {summary['search_pending']}  maps: {summary['maps']}"
                      f"  wordlists: {summary['wordlists']}  latest ready: {summary['latest_ready']}")
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
    raise SystemExit(main())
