#!/usr/bin/env python3
"""
BugWolf Post-Recon Tech-Fingerprint Parser v1.0.0

Turns recon output (dependency manifests, response headers, Dockerfiles, CI
workflows, runtime-version files) into a structured technology stack, and emits
a `name version, name version` CSV that auto-populates the R2 post-recon
research checkpoint:

  python3 tools/research_loop.py --checkpoint post-recon \\
      --stack "$(python3 tools/tech_fingerprint.py --path . --stack-csv)"

Confidence tiers (aligned with references/sis-intelligence.md):
  high   — explicit version string in a manifest/header/runtime file
  medium — framework inferred from an import/marker (no version)
  low    — weak circumstantial signal

Usage:
  python3 tools/tech_fingerprint.py --path .
  python3 tools/tech_fingerprint.py --path . --url https://target.example --json
  python3 tools/tech_fingerprint.py --path . --stack-csv
  python3 tools/tech_fingerprint.py --path . --min-confidence high
"""

import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable

try:
    from tools.runtime_paths import CODE_ROOT, workspace_root
    from tools.safety import AuthorizationError, require_authorized_target
except ImportError:  # direct script execution
    from runtime_paths import CODE_ROOT, workspace_root
    from safety import AuthorizationError, require_authorized_target

ROOT = workspace_root()
sys.path.insert(0, str(CODE_ROOT))

SCAN_EXTS = {".json", ".txt", ".toml", ".lock", ".mod", ".sum", ".yaml", ".yml",
             ".gradle", ".xml", ".csproj", ".rb", ".ex", ".exs", ".dart",
             ".tf", ".hcl", ".lock", ".md", ".cfg", ".ini", ".sh", ".dockerfile"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", "target", ".next", "vendor", ".idea", ".mypy_cache",
             ".terraform"}


@dataclass
class TechComponent:
    name: str
    version: str = ""
    source: str = ""
    confidence: str = "high"  # high | medium | low
    kind: str = "library"     # library | framework | runtime | server | ci | cloud

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def stack_token(self) -> str:
        """`name version` (or just `name`) — the unit research_loop --stack wants."""
        return f"{self.name} {self.version}".strip()


CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _clean_version(v: str) -> str:
    """Strip leading range operators + whitespace; keep the version itself."""
    if not v:
        return ""
    v = v.strip().strip('"').strip("'")
    v = re.sub(r"^[\^~><=*| ]+", "", v)
    v = re.sub(r"[,\s].*$", "", v)  # drop '>= 1.0, < 2.0' tails
    return v[:40]


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_json_deps(text: str, source: str) -> List[TechComponent]:
    """package.json / composer.json style — `"name": "^version"` maps."""
    out: List[TechComponent] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return out
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "require", "require-dev"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if not isinstance(name, str) or not isinstance(ver, str):
                continue
            out.append(TechComponent(
                name=name, version=_clean_version(ver), source=source,
                confidence="high", kind="library"))
    return out


def _parse_requirements(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;]+)?", line)
        if not m:
            continue
        name = m.group(1)
        ver = _clean_version(m.group(3) or "")
        out.append(TechComponent(name=name, version=ver, source=source,
                                 confidence="high", kind="library"))
    return out


def _parse_go_mod(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    # runtime: `go 1.22`
    m = re.search(r"(?m)^\s*go\s+(\d+\.\d+(\.\d+)?)", text)
    if m:
        out.append(TechComponent(name="go", version=m.group(1), source=source,
                                 confidence="high", kind="runtime"))
    # single-line: `require github.com/foo/bar v1.2.3`
    for m in re.finditer(r"^\s*require\s+([\w.\-/]+)\s+(v\d+\.\d+\.\d+(?:[+\-][\w.\-]+)?)\s*$",
                         text, re.M):
        out.append(TechComponent(name=m.group(1), version=m.group(2),
                                 source=source, confidence="high",
                                 kind="library"))
    # require block lines: `    github.com/foo/bar v1.2.3`
    for m in re.finditer(r"^\s*([\w.\-/]+)\s+(v\d+\.\d+\.\d+(?:[+\-][\w.\-]+)?)\s*$",
                         text, re.M):
        out.append(TechComponent(name=m.group(1), version=m.group(2),
                                 source=source, confidence="high",
                                 kind="library"))
    return out


def _parse_cargo(text: str, source: str, is_lock: bool) -> List[TechComponent]:
    out: List[TechComponent] = []
    if is_lock:
        # Cargo.lock: [[package]] name = "x" version = "1.2.3"
        for block in re.finditer(
                r"\[\[package\]\]\s*name\s*=\s*\"([^\"]+)\"\s*version\s*=\s*\"([^\"]+)\"",
                text):
            out.append(TechComponent(name=block.group(1), version=block.group(2),
                                     source=source, confidence="high",
                                     kind="library"))
    else:
        # Cargo.toml: [dependencies] foo = "1.2" / foo = { version = "1.2" }
        for m in re.finditer(r"^\s*([\w\-]+)\s*=\s*(?:\{\s*version\s*=\s*)?\"([^\"]+)\"",
                             text, re.M):
            out.append(TechComponent(name=m.group(1), version=_clean_version(m.group(2)),
                                     source=source, confidence="high",
                                     kind="library"))
    return out


def _parse_pom(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(
            r"<artifactId>([^<]+)</artifactId>\s*(?:<groupId>[^<]*</groupId>\s*)?<version>([^<]+)</version>",
            text):
        out.append(TechComponent(name=m.group(1), version=_clean_version(m.group(2)),
                                 source=source, confidence="high", kind="library"))
    return out


def _parse_gemfile(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(r"(?m)^\s*gem\s+['\"]([\w\-]+)['\"]\s*(?:,\s*['\"]([^'\"]*)['\"])?",
                         text):
        out.append(TechComponent(name=m.group(1), version=_clean_version(m.group(2) or ""),
                                 source=source, confidence="high", kind="library"))
    return out


def _parse_csproj(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
                         text):
        out.append(TechComponent(name=m.group(1), version=m.group(2),
                                 source=source, confidence="high", kind="library"))
    return out


def _parse_pubspec(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^(dependencies|dev_dependencies):", s):
            in_deps = True
            continue
        if in_deps and re.match(r"^[a-z_]+:", s) and not s.startswith(" "):
            in_deps = False
        if in_deps:
            m = re.match(r"^([\w\-]+):\s*[\^~]?([\w.\-]+)", s)
            if m:
                out.append(TechComponent(name=m.group(1), version=m.group(2),
                                         source=source, confidence="high",
                                         kind="library"))
    return out


def _parse_dockerfile(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(r"(?mi)^\s*FROM\s+([^\s:]+)(?::([^\s]+))?", text):
        name = m.group(1).split("/")[-1]
        out.append(TechComponent(name=name, version=m.group(2) or "",
                                 source=source, confidence="high", kind="ci"))
    return out


def _parse_workflow(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(r"(?m)^\s*-?\s*uses:\s*([^\s@]+)(?:@([^\s]+))?", text):
        name = m.group(1).split("/")[-1]
        out.append(TechComponent(name=name, version=m.group(2) or "",
                                 source=source, confidence="high", kind="ci"))
    return out


def _parse_runtime_file(name: str, text: str, source: str) -> List[TechComponent]:
    base = Path(name).name
    # .tool-versions: multiple `runtime version` lines — handle before single-name map
    if base == ".tool-versions":
        out: List[TechComponent] = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out.append(TechComponent(name=parts[0], version=parts[1],
                                         source=source, confidence="high",
                                         kind="runtime"))
        return out
    runtime_name = {
        ".nvmrc": "node", ".node-version": "node", ".python-version": "python",
        ".ruby-version": "ruby", ".terraform-version": "terraform",
    }.get(base, "")
    if not runtime_name:
        return []
    ver = text.strip().splitlines()[0].strip() if text.strip() else ""
    return [TechComponent(name=runtime_name, version=ver, source=source,
                          confidence="high", kind="runtime")]


def _parse_terraform_lock(text: str, source: str) -> List[TechComponent]:
    out: List[TechComponent] = []
    for m in re.finditer(r"provider\s+\"registry.terraform.io/([\w\-]+)/([\w\-]+)\"",
                         text):
        out.append(TechComponent(name=f"terraform-provider-{m.group(2)}",
                                 source=source, confidence="medium", kind="cloud"))
    return out


# filename -> parser. Keys are matched case-insensitively by basename.
MANIFEST_PARSERS: Dict[str, Callable] = {
    "package.json": _parse_json_deps,
    "package-lock.json": _parse_json_deps,
    "composer.json": _parse_json_deps,
    "requirements.txt": _parse_requirements,
    "go.mod": _parse_go_mod,
    "cargo.toml": lambda t, s: _parse_cargo(t, s, False),
    "cargo.lock": lambda t, s: _parse_cargo(t, s, True),
    "pom.xml": _parse_pom,
    "gemfile": _parse_gemfile,
    "gemfile.lock": _parse_gemfile,
    "pubspec.yaml": _parse_pubspec,
    ".terraform.lock.hcl": _parse_terraform_lock,
}

RUNTIME_FILES = {".nvmrc", ".node-version", ".python-version", ".ruby-version",
                 ".terraform-version", ".tool-versions"}

# Framework markers (no version → medium confidence) — fallback when no manifest.
MARKERS = [
    (re.compile(r"(?m)^\s*(?:from|import)\s+django\b"), "django", "framework"),
    (re.compile(r"(?m)^\s*from\s+flask\b"), "flask", "framework"),
    (re.compile(r"(?m)^\s*from\s+fastapi\b"), "fastapi", "framework"),
    (re.compile(r"(?m)require\(\s*['\"]express['\"]\s*\)"), "express", "framework"),
    (re.compile(r"(?m)require\(\s*['\"]@nestjs/"), "nestjs", "framework"),
    (re.compile(r"(?m)^\s*import\s+React\b"), "react", "framework"),
]


def _parse_server_header(name: str, value: str) -> List[TechComponent]:
    """Parse Server / X-Powered-By / X-Generator / X-AspNet-Version headers."""
    out: List[TechComponent] = []
    v = value.strip()
    # Server: nginx/1.18.0  →  name=nginx version=1.18.0
    m = re.match(r"^([A-Za-z0-9._\-]+)/?([\d.]+)?", v)
    if not m:
        return out
    header_name = name.lower()
    kind = "server"
    if header_name == "x-powered-by":
        kind = "framework"
    elif header_name in ("x-generator", "x-aspnet-version", "x-runtime", "via"):
        kind = "server"
    # Normalize a few well-known powered-by values
    pname = m.group(1).lower()
    if pname in ("php", "asp.net", "next.js", "express"):
        kind = "framework"
    out.append(TechComponent(name=pname, version=m.group(2) or "",
                             source=f"header:{name}", confidence="high",
                             kind=kind))
    return out


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------

class TechFingerprinter:
    """Parse a codebase + live headers into a structured technology stack."""

    def __init__(self, min_confidence: str = "low"):
        self.min_rank = CONF_RANK.get(min_confidence, 2)

    def _add(self, components: List[TechComponent], found: Dict[str, TechComponent]):
        for c in components:
            if c.confidence not in CONF_RANK:
                continue
            if CONF_RANK[c.confidence] > self.min_rank:
                continue
            existing = found.get(c.name)
            if existing is None:
                found[c.name] = c
                continue
            # Prefer versioned over unversioned, then higher confidence.
            if (bool(c.version) and not bool(existing.version)) or \
               (bool(c.version) == bool(existing.version) and
                CONF_RANK[c.confidence] < CONF_RANK[existing.confidence]):
                found[c.name] = c

    def scan_path(self, path: str) -> List[TechComponent]:
        root = Path(path)
        found: Dict[str, TechComponent] = {}
        files: List[Path] = []

        if root.is_file():
            files = [root]
        elif root.is_dir():
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                files.append(p)
        else:
            print(f"[!] path not found: {path}", file=sys.stderr)
            return []

        for f in sorted(files):
            base = f.name.lower()
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue

            if base in MANIFEST_PARSERS:
                self._add(MANIFEST_PARSERS[base](text, str(f)), found)
            elif base == "dockerfile" or base.endswith(".dockerfile"):
                self._add(_parse_dockerfile(text, str(f)), found)
            elif base in RUNTIME_FILES:
                self._add(_parse_runtime_file(f.name, text, str(f)), found)
            elif base.endswith(".yml") or base.endswith(".yaml"):
                # only workflow files under .github/
                if ".github" in f.parts:
                    self._add(_parse_workflow(text, str(f)), found)
            # Marker scan on source files as a low-cost fallback
            if f.suffix in {".py", ".js", ".ts", ".jsx", ".tsx", ".rb"}:
                for rx, name, kind in MARKERS:
                    if rx.search(text):
                        c = TechComponent(name=name, source=str(f),
                                          confidence="medium", kind=kind)
                        self._add([c], found)

        return sorted(found.values(), key=lambda c: (c.confidence, c.name))

    def scan_url(self, url: str, *, scope_file: Optional[str] = None) -> List[TechComponent]:
        out: List[TechComponent] = []
        try:
            require_authorized_target(url, scope_file, active=False)
        except AuthorizationError as exc:
            print(f"[!] authorization denied for {url}: {exc}", file=sys.stderr)
            return out
        try:
            import urllib.request
            req = urllib.request.Request(
                url, headers={"User-Agent": "bugwolf-fingerprint/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = resp.headers
        except Exception as e:
            print(f"[!] fetch failed for {url}: {e}", file=sys.stderr)
            return out

        interesting = {"server", "x-powered-by", "x-generator",
                       "x-aspnet-version", "x-runtime", "via"}
        for hdr, value in headers.items():
            if hdr.lower() in interesting:
                out.extend(_parse_server_header(hdr, value))
        return out

    def stack_csv(self, components: List[TechComponent]) -> str:
        """`name version, name version` — ready for research_loop.py --stack."""
        return ", ".join(c.stack_token for c in components)

    def summarize(self, components: List[TechComponent]) -> Dict:
        by_kind: Dict[str, int] = {}
        by_conf: Dict[str, int] = {}
        for c in components:
            by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
            by_conf[c.confidence] = by_conf.get(c.confidence, 0) + 1
        return {"total": len(components), "by_kind": by_kind,
                "by_confidence": by_conf}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Post-Recon Tech-Fingerprint Parser v1.0.0")
    parser.add_argument("--path", help="File or directory to scan (static)")
    parser.add_argument("--url", help="Live URL to fingerprint from headers")
    parser.add_argument("--scope-file", help="Explicit authorization scope for --url")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit structured JSON")
    parser.add_argument("--stack-csv", action="store_true",
                        help="Emit `name version, name version` for research_loop --stack")
    parser.add_argument("--min-confidence", default="low",
                        choices=["high", "medium", "low"],
                        help="Only report components at/above this confidence")
    args = parser.parse_args()

    if not args.path and not args.url:
        parser.error("one of --path or --url is required")

    fp = TechFingerprinter(min_confidence=args.min_confidence)
    components: List[TechComponent] = []
    if args.path:
        components.extend(fp.scan_path(args.path))
    if args.url:
        components.extend(fp.scan_url(args.url, scope_file=args.scope_file))

    # dedupe across path+url
    deduped: Dict[str, TechComponent] = {}
    for c in components:
        existing = deduped.get(c.name)
        if existing is None or (bool(c.version) and not bool(existing.version)):
            deduped[c.name] = c
    components = sorted(deduped.values(), key=lambda c: (c.confidence, c.name))

    if args.stack_csv:
        print(fp.stack_csv(components))
        return

    if args.as_json:
        print(json.dumps({
            "schema": "tech_fingerprint/1.0",
            "summary": fp.summarize(components),
            "components": [c.to_dict() for c in components],
            "stack": fp.stack_csv(components),
        }, indent=2))
        return

    print("=" * 72)
    print("  BUGWOLF TECH-FINGERPRINT v1.0.0")
    print("=" * 72)
    s = fp.summarize(components)
    print(f"  Components: {s['total']}   kinds: {s['by_kind']}   conf: {s['by_confidence']}")
    print("=" * 72)
    if not components:
        print("  No technology stack detected.")
        return
    for c in components:
        ver = f" {c.version}" if c.version else ""
        print(f"  [{c.confidence.upper():5s}] {c.name}{ver}   ({c.kind}, {c.source})")
    print("=" * 72)
    print(f"  --stack: {fp.stack_csv(components)}")


if __name__ == "__main__":
    main()
