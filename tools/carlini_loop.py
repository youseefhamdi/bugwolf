#!/usr/bin/env python3
"""BugWolf Carlini Loop Track — per-file brute-force vulnerability analysis.

Adapted from the 2026 zero-day discovery research (see ENHANCEMENT_PLAN.md):

  * **Carlini Loop** (Anthropic / Claude Code Security, Feb 2026): iterate
    every source file and prompt the model per file with CTF framing ("find
    me an exploitable vulnerability in this file") instead of asking for a
    whole-repository verdict. Fresh eyes per file, linear parallel scale.
  * **nano-analyzer** (AISLE, Apr 2026): the "system over model" result — a
    cheap model that sees *every* file with a per-file security briefing
    beats one brilliant model that only looks where it is told. Three-stage
    pipeline: context generation -> vulnerability scanning -> skeptical
    triage.
  * **NOVA** (Unit 42, Aug 2026): 14,090 confirmed vulns across 3,915 OSS
    projects in 2 months — 92% semantic/logic flaws (access control, path
    traversal, injection, SSRF, prototype pollution), exactly the classes
    this track's sink catalog targets.

This module implements the BugWolf version of that pattern:

  1. ``enumerate_files`` — deterministic, bounded project walk (extension
     filter per surface, skip noise dirs, size/line caps).
  2. ``brief_file`` — offline deterministic *context generation*: imports,
     functions, dangerous sinks, and entry points with line anchors. This is
     the briefing that makes a per-file prompt effective.
  3. ``build_units`` — emit one research unit per file (the standard
     ``build_research_unit`` dispatch format) with CTF framing + the
     briefing, for the harness to execute with full intelligence.
  4. ``offline_scan`` — the deterministic floor: run the existing static
     track analyzers (WebApiTrack/CloudCicdTrack/LlmAgenticTrack/
     MobileBinaryTrack) per file, so the track produces candidates even
     without a model.
  5. ``register_results`` — intake findings back from the harness (JSON or
     JSONL), build ``ResearchCandidate``s, and register them through the
     normal ``ZeroDayResearchEngine`` (novelty dedup + evidence + chain
     synthesis). Skeptical triage: low-confidence / impact-less findings
     stay HYPOTHESIS; nothing is promoted to a zero-day claim.

Output lands in ``research/<target>/carlini-loop/`` (units + intake) and the
standard candidate store ``state/research/<target>/candidates.jsonl``.

Usage:
  # 1. Emit per-file research units for the harness (no network)
  python3 tools/carlini_loop.py --target local-project --path . \
    --emit-units research/local-project/carlini-loop/units.jsonl --json

  # 2. Offline deterministic floor (no model needed)
  python3 tools/carlini_loop.py --target local-project --path . \
    --offline --surface web_api --json

  # 3. Intake harness findings and register through novelty/evidence
  python3 tools/carlini_loop.py --target local-project \
    --register-result research/local-project/carlini-loop/intake.jsonl --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

try:
    from tools.research_model import ResearchCandidate, Surface
except ImportError:
    from research_model import ResearchCandidate, Surface

try:
    from tools.asset_discovery import build_research_unit
except ImportError:
    from asset_discovery import build_research_unit

try:
    from tools.zero_day import ZeroDayResearchEngine, build_ranked_output
except ImportError:
    from zero_day import ZeroDayResearchEngine, build_ranked_output

try:
    from tools.zero_day_tracks import (
        CloudCicdTrack, LlmAgenticTrack, MobileBinaryTrack, WebApiTrack,
    )
except ImportError:
    from zero_day_tracks import (
        CloudCicdTrack, LlmAgenticTrack, MobileBinaryTrack, WebApiTrack,
    )

try:
    from tools.evidence import redact
except ImportError:
    from evidence import redact

ROOT = workspace_root()
OUT_ROOT = ROOT / "research"

# ---------------------------------------------------------------------------
# Bounded project enumeration
# ---------------------------------------------------------------------------

#: Surface -> source extensions. Files outside any list are skipped.
SURFACE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    Surface.WEB_API.value: (
        ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java",
        ".cs", ".sh", ".pl", ".cgi", ".jsp", ".asp", ".aspx",
    ),
    Surface.SMART_CONTRACT.value: (
        ".sol", ".move", ".vy", ".fe", ".rs",
    ),
    Surface.CLOUD_CICD.value: (
        ".yml", ".yaml", ".toml", ".hcl", ".tf", ".jsonnet", ".dockerfile",
    ),
    Surface.LLM_AGENTIC.value: (
        ".md", ".mcp", ".prompt", ".json", ".py", ".js",
    ),
    Surface.MOBILE_BINARY.value: (
        ".xml", ".plist", ".smali", ".kt", ".swift",
    ),
}

#: Directories that are never project source.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "venv", ".venv",
    "env", ".env", "dist", "build", "target", ".tox", ".nox", ".idea",
    ".vscode", "vendor", "bower_components", ".gradle", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".coverage",
}

#: Exact filenames that are never source.
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", ".DS_Store",
    "LICENSE", "LICENSE.txt", "COPYING", "CHANGELOG.md", "README.md",
}

DEFAULT_MAX_FILES = 400
DEFAULT_MAX_BYTES = 512 * 1024      # per file
DEFAULT_MAX_LINES = 4000            # per file


@dataclass
class SourceFile:
    """One bounded source file selected for per-file analysis."""
    path: Path
    relative: str
    surface: str
    size_bytes: int
    line_count: int
    sha256: str
    language: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.relative,
            "surface": self.surface,
            "language": self.language,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "sha256": self.sha256,
        }


def _language_of(path: Path, surface: str) -> str:
    name = path.name.lower()
    if name in ("dockerfile",):
        return "dockerfile"
    ext = path.suffix.lower()
    table = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "react", ".tsx": "react", ".php": "php", ".rb": "ruby",
        ".go": "go", ".java": "java", ".cs": "csharp", ".sh": "shell",
        ".pl": "perl", ".sol": "solidity", ".move": "move", ".vy": "vyper",
        ".rs": "rust", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
        ".tf": "terraform", ".hcl": "hcl", ".md": "markdown",
        ".xml": "xml", ".plist": "plist", ".smali": "smali",
        ".kt": "kotlin", ".swift": "swift", ".json": "json",
        ".jsonnet": "jsonnet", ".mcp": "markdown",
    }
    return table.get(ext, surface)


def enumerate_files(path: str | Path, *,
                    surfaces: Optional[Sequence[str]] = None,
                    max_files: int = DEFAULT_MAX_FILES,
                    max_bytes: int = DEFAULT_MAX_BYTES,
                    max_lines: int = DEFAULT_MAX_LINES) -> List[SourceFile]:
    """Deterministic, bounded walk of a project path.

    Accepts a file or a directory. Files are sorted by relative path for
    stable ordering. Caps bound the walk (never an unbounded scan). Files
    whose extension is not mapped to a requested surface are skipped; with
    no surfaces requested, every mapped extension is accepted.
    """
    root = Path(path).expanduser().resolve()
    if not root.exists():
        return []
    requested = {str(s) for s in (surfaces or SURFACE_EXTENSIONS.keys())}

    def accept(rel: Path) -> Optional[str]:
        name = rel.name
        if name in SKIP_FILES:
            return None
        ext = rel.suffix.lower()
        if not ext:
            return None
        for surface, extensions in SURFACE_EXTENSIONS.items():
            if surface not in requested:
                continue
            if ext in extensions or name == "dockerfile" and surface == Surface.CLOUD_CICD.value:
                return surface
        return None

    found: List[SourceFile] = []
    if root.is_file():
        surface = accept(root)
        if surface:
            found.append(_build_source_file(root, root.name, surface,
                                            max_bytes, max_lines))
    else:
        for rel in sorted(root.rglob("*")):
            if len(found) >= max_files:
                break
            if rel.is_dir():
                continue  # rglob yields dirs; only files are analyzed
            if not rel.is_file():
                continue
            # Skip files under any ignored directory (parts[:-1] = parent dirs).
            if any(part in SKIP_DIRS
                   for part in rel.relative_to(root).parts[:-1]):
                continue
            surface = accept(rel)
            if surface is None:
                continue
            built = _build_source_file(
                rel, str(rel.relative_to(root)), surface, max_bytes, max_lines)
            if built is not None:  # caps-rejected/unreadable files are skipped, never yielded as None
                found.append(built)
    return found


def _build_source_file(path: Path, relative: str, surface: str,
                       max_bytes: int, max_lines: int) -> Optional[SourceFile]:
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size <= 0 or stat.st_size > max_bytes:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    line_count = text.count("\n") + 1
    if line_count > max_lines:
        return None
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return SourceFile(
        path=path, relative=relative, surface=surface,
        size_bytes=stat.st_size, line_count=line_count, sha256=digest,
        language=_language_of(path, surface),
    )


# ---------------------------------------------------------------------------
# Sink catalog — the deterministic context-generation stage
# ---------------------------------------------------------------------------

#: (bug_class, regex, severity, note) — line-anchored dangerous sinks.
#: Mirrors the classes NOVA found in 92% of its 14K findings (access control,
#: path traversal, injection, SSRF, prototype pollution) plus the classic
#: command/eval/deserialization sinks.
SINK_PATTERNS: Sequence[Tuple[str, str, str, str]] = (
    ("command_execution", r"\b(?:exec|system|shell_exec|popen|passthru|proc_open|subprocess(?:\.[A-Za-z_]+)?|os\.system|Runtime\.getRuntime|ProcessBuilder|child_process(?:\.[A-Za-z_]+)?|execSync|spawn)\s*\(", "critical",
     "Command/process execution sink — attacker-controlled input reaching it is RCE."),
    ("code_evaluation", r"\b(?:eval|exec)\s*\(|new\s+Function\s*\(|Function\s*\(|(?<!\.)compile\s*\(|marshal\.loads|pickle\.loads|yaml\.(?:load|unsafe_load)|unserialize|ObjectInputStream|readObject\s*\(", "critical",
     "Dynamic code evaluation / deserialization sink — unsafe deserialization or eval of untrusted data."),
    ("sql_injection", r"\b(?:executeQuery|executeUpdate|\.query\s*\(|\.execute\s*\(|\.raw\s*\(|mysqli?_query|sqlite3|pg_query|\.exec\s*\()|SELECT\s+[^;]*\s+FROM", "high",
     "SQL execution sink — string-built queries from request data are SQLi."),
    ("ssrf", r"\b(?:requests\.(?:get|post|put|request)|urllib(?:\.request)?\.(?:urlopen|Request)|urlopen|fetch\s*\(|axios\.|http\.(?:get|post|request)|Net::HTTP|WebClient|HttpClient|curl_exec)\b", "high",
     "Outbound request sink — attacker-controlled URLs reach it, SSRF candidate."),
    ("file_write", r"\b(?:file_put_contents|fwrite|fputs|writeFile|writeFileSync|\.write\s*\(|open\s*\([^)]*['\"]w|os\.write|Files\.write|\.store\s*\(|saveAs|createWriteStream)\s*\(", "high",
     "File write sink — request-derived path/name reaching it is arbitrary write."),
    ("path_traversal", r"\b(?:readFile|readFileSync|file_get_contents|open\s*\(|\.read\s*\(|Path\.join|path\.join|os\.path\.join|resolve\s*\(|getCanonicalPath|Files\.read|new\s+File\s*\()\s*\(?", "high",
     "Path-building sink — unsanitized user input joined into a filesystem path."),
    ("prototype_pollution", r"\b(?:Object\.assign|\.\.\.\w+\s*,\s*\w+\s*\{|_.merge|\.merge\s*\(|merge\s*\(|extend\s*\(|Object\.prototype|__proto__|constructor\s*\[\s*['\"])", "high",
     "Prototype-pollution sink — recursive merge/assign of untrusted keys."),
    ("header_trust", r"\b(?:X-Forwarded-For|X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|X-Remote-(?:Addr|IP|User)|X-Real-IP|X-Account-Id|X-Tenant-Id|X-User-Id|X-Customer-Id|X-Org-Id)\b", "high",
     "Trusted-header sink — a client-supplied header used for identity/routing decisions."),
    ("template_injection", r"\b(?:render\s*\(|render_template|Template\s*\(|\.format\s*\(|f['\"][^'\"]*\{[^}]*\}|jinja2|nunjucks|ejs\.render|mustache|handlebars|text/template)\b", "high",
     "Template-rendering sink — user data in template expressions is SSTI."),
    ("cache_key_control", r"\b(?:cache[_ -]?key|page[_ -]?key|cacheKey|pageKey|path\s*\+|md5\s*\([^)]*url|sha1\s*\([^)]*path)\b", "high",
     "Cache-key construction — request-derived path/key reaching a write sink (CVE-2026-18051 class)."),
)

#: Entry-point markers — where untrusted input typically enters.
ENTRY_POINT_PATTERNS: Sequence[Tuple[str, str]] = (
    (r"def\s+main\s*\(|function\s+main\s*\(|if\s+__name__\s*==\s*['\"]__main__['\"]", "main"),
    (r"@app\.(?:route|get|post|put|delete|patch)|@router\.|app\.(?:get|post|put|delete|patch|use)\s*\(|router\.(?:get|post|put|delete)\s*\(", "http_handler"),
    (r"do_GET|do_POST|do_PUT|do_DELETE|do_HEAD|do_OPTIONS", "http_handler"),
    (r"def\s+\w+\s*\([^)]*\brequest\b[^)]*\)", "http_handler"),
    (r"def\s+(?:handle|process|on_message|on_event|consume|execute)\s*\(", "message_handler"),
    (r"async\s+def\s+(?:handle|process|execute|run)\s*\(", "async_handler"),
    (r"public\s+(?:static\s+)?void\s+main\s*\(|func\s+main\s*\(|fn\s+main\s*\(", "main"),
    (r"onClick|onPress|onSubmit|onCreate\s*\(", "mobile_callback"),
)


def brief_file(path: Path, relative: str, text: str, *,
               surface: str) -> Dict[str, Any]:
    """Deterministic per-file security briefing (context-generation stage).

    Extracts imports, functions, entry points, and line-anchored dangerous
    sinks. The briefing is what makes a per-file prompt effective: the model
    is handed where to look, not a whole repository. No code is executed and
    no content leaves the machine except this redacted summary.
    """
    lines = text.splitlines()
    imports: List[str] = []
    functions: List[str] = []
    entry_points: List[Dict[str, str]] = []
    sinks: List[Dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if len(stripped) > 240:
            stripped = stripped[:240] + "…"
        if re.match(r"^(?:import|from)\s+\w", stripped) or re.match(
                r"^(?:import|require)\s*[\(\{'\"]", stripped):
            imports.append(stripped[:120])
            continue
        m = re.match(r"^(?:def|async\s+def|function|public\s+(?:static\s+)?\w+\s+\w+|"
                     r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>)\s*"
                     r"([A-Za-z_]\w*)\s*\(", stripped)
        if m:
            functions.append(m.group(1))
        for pattern, kind in ENTRY_POINT_PATTERNS:
            if re.search(pattern, stripped):
                entry_points.append({"line": index, "kind": kind,
                                     "snippet": stripped[:160]})
                break
        for bug_class, pattern, severity, note in SINK_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                sinks.append({
                    "line": index, "bug_class": bug_class,
                    "severity": severity, "note": note,
                    "snippet": stripped[:160],
                })
                break  # one sink per line keeps the briefing bounded

    return {
        "path": relative,
        "surface": surface,
        "language": _language_of(path, surface),
        "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "imports": imports[:80],
        "functions": functions[:80],
        "entry_points": entry_points[:20],
        "sinks": sinks[:60],
    }


def _candidate_for_sink(target: str, file_info: SourceFile,
                        briefing: Dict[str, Any],
                        sink: Dict[str, Any]) -> ResearchCandidate:
    """One candidate per detected sink, located at its source line."""
    location = f"{file_info.relative}:{sink['line']}"
    return ResearchCandidate(
        target=target,
        surface=Surface(file_info.surface),
        bug_class=sink["bug_class"],
        title=f"{file_info.relative}:{sink['line']} — {sink['bug_class']}",
        hypothesis=(
            f"{sink['note']} Sink at line {sink['line']} of "
            f"{file_info.relative}: `{sink['snippet']}`. Trace whether "
            "attacker-controllable input (request/params/headers/env/file "
            "content) reaches it; validate reachability, actor control, and "
            "impact in a lab before any live test."
        ),
        location=location,
        severity=sink["severity"],
        confidence=0.45,  # deterministic signal — must be validated
        trigger_trace="",
        impact_trace="",
        metadata={
            "source": "carlini-loop",
            "mode": "sink_catalog",
            "file_sha256": file_info.sha256,
            "language": file_info.language,
            "line": sink["line"],
            "pattern": sink["bug_class"],
        },
    )


# ---------------------------------------------------------------------------
# Unit emission (harness dispatch)
# ---------------------------------------------------------------------------

def build_units(target: str, files: Sequence[SourceFile], *,
                surface: str) -> List[Dict[str, Any]]:
    """Emit one research unit per file (Carlini Loop dispatch).

    Each unit carries the file briefing as context and a CTF-framed
    objective: "find an exploitable vulnerability in this file." The harness
    executes the unit with full intelligence and registers results back via
    ``--register-result``. Units are advisory dispatch — never execution.
    """
    units: List[Dict[str, Any]] = []
    for file_info in files:
        if file_info.surface != surface:
            continue
        try:
            text = file_info.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        briefing = brief_file(file_info.path, file_info.relative, text,
                              surface=surface)
        units.append(build_research_unit(
            objective=(
                f"Find an exploitable security vulnerability in "
                f"{file_info.relative} ({file_info.language}, "
                f"{file_info.line_count} lines). Assume nothing: the file "
                "may be vulnerable. Trace every untrusted input (request "
                "params, headers, cookies, env, file content, external "
                "messages) to the dangerous sinks in the briefing, then "
                "determine reachability and impact."
            ),
            asset_hostname=target,
            bug_class="carlini-loop",
            endpoint="",
            context={
                "carlini_loop": True,
                "source_file": file_info.to_dict(),
                "briefing": redact(briefing),
                "instructions": (
                    "CTF framing: actively hunt for an exploitable flaw — do "
                    "not default to 'looks safe'. For each candidate report: "
                    "file:line, the untrusted input, the sink it reaches, and "
                    "the impact class. Never fabricate evidence; register only "
                    "what the code actually shows. Return findings through "
                    "the carlini-loop intake schema (see --register-result)."
                ),
            },
            success_criteria=[
                "One or more candidates with file:line, input -> sink -> impact",
                "OR a reasoned verdict that the file has no reachable sink",
            ],
        ))
    return units


# ---------------------------------------------------------------------------
# Offline deterministic floor + result intake
# ---------------------------------------------------------------------------

def offline_scan(target: str, files: Sequence[SourceFile], *,
                 surface: str) -> List[ResearchCandidate]:
    """Deterministic per-file scan (no model): sink catalog + track patterns."""
    candidates: List[ResearchCandidate] = []
    for file_info in files:
        if file_info.surface != surface:
            continue
        try:
            text = file_info.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        briefing = brief_file(file_info.path, file_info.relative, text,
                              surface=surface)
        for sink in briefing["sinks"]:
            candidates.append(_candidate_for_sink(target, file_info, briefing,
                                                  sink))
        # Existing per-surface static analyzers as a second floor.
        if surface == Surface.WEB_API.value:
            candidates.extend(WebApiTrack.static_hypotheses(
                target, text, source=file_info.relative))
        elif surface == Surface.CLOUD_CICD.value:
            candidates.extend(CloudCicdTrack.analyze(
                target, text, source=file_info.relative))
        elif surface == Surface.LLM_AGENTIC.value:
            candidates.extend(LlmAgenticTrack.analyze(
                target, text, source=file_info.relative))
        elif surface == Surface.MOBILE_BINARY.value:
            candidates.extend(MobileBinaryTrack.analyze(
                target, text.encode("utf-8", errors="replace"),
                source=file_info.relative))
    return candidates


def _load_records(path: str | Path) -> List[Dict[str, Any]]:
    """Load JSON or JSONL finding records from the harness."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"intake file not found: {path}")
    raw = p.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []
    records: List[Dict[str, Any]] = []
    if raw.lstrip().startswith("["):
        data = json.loads(raw)
        if isinstance(data, list):
            records = [item for item in data if isinstance(item, dict)]
    else:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
    return records


def register_results(target: str, records: Sequence[Dict[str, Any]], *,
                     default_surface: str = Surface.WEB_API.value,
                     chains: bool = False, max_chains: int = 32,
                     persist_intake: bool = True) -> Dict[str, Any]:
    """Intake harness findings and register through the zero-day engine.

    Every record becomes a ``ResearchCandidate`` (HYPOTHESIS unless the
    record carries trigger+impact traces, in which case it may advance to
    the reproducible/impact-bounded evidence states via the engine). All are
    registered through ``ZeroDayResearchEngine.register`` — evidence store +
    novelty dedup — and optionally chained. Skeptical triage: a record
    without a concrete trigger or impact stays HYPOTHESIS; nothing is
    promoted to a zero-day claim here.
    """
    engine = ZeroDayResearchEngine(target)
    # Idempotence for re-runs: records whose stable candidate_id already
    # exists in the local novelty index were registered before.  The engine's
    # own assess() treats an identical candidate_id as "self" and skips it,
    # so exact re-intake must be filtered here (same contract as the fuzz
    # bridge's (endpoint, state) thread dedup).  Near-matches still flow to
    # the novelty engine and come back as LIKELY_VARIANT.
    try:
        known_ids = {c.candidate_id for c in engine.novelty.index.all()}
    except Exception:
        known_ids = set()
    candidates: List[ResearchCandidate] = []
    skipped_duplicates = 0
    for index, record in enumerate(records):
        location = str(record.get("location") or record.get("path")
                       or record.get("file") or "unknown")
        if record.get("line"):
            location = f"{location}:{record['line']}"
        surface_raw = str(record.get("surface") or default_surface).strip().lower()
        surface = Surface(surface_raw)
        hypothesis = str(record.get("hypothesis")
                         or record.get("description") or "")
        bug_class = str(record.get("bug_class") or "unknown").strip()
        if not hypothesis or not bug_class:
            continue
        trigger = str(record.get("trigger_trace") or record.get("trigger") or "")
        impact = str(record.get("impact_trace") or record.get("impact") or "")
        candidate = ResearchCandidate(
            target=target,
            surface=surface,
            bug_class=bug_class,
            title=str(record.get("title") or f"{bug_class} at {location}"),
            hypothesis=hypothesis,
            location=location,
            severity=str(record.get("severity") or "medium"),
            confidence=max(0.0, min(1.0,
                                    float(record.get("confidence") or 0.0))),
            trigger_trace=trigger,
            impact_trace=impact,
            metadata={
                "source": "carlini-loop",
                "mode": "harness_intake",
                "intake_index": index,
                "intake_kind": record.get("kind", "candidate"),
                **{k: record[k] for k in
                   ("pattern", "line", "file_sha256", "language")
                   if k in record},
            },
        )
        candidate = candidate if candidate.candidate_id not in known_ids \
            else None
        if candidate is None:
            skipped_duplicates += 1
            continue
        candidates.append(candidate)

    registered = engine.register(candidates)
    kept = [c for c in registered
            if c.novelty != "exact_duplicate"]
    if chains and kept:
        registered.extend(engine.chain_candidates(kept, max_chains=max_chains))

    if persist_intake:
        out_dir = OUT_ROOT / target_slug(target) / "carlini-loop"
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "intake.jsonl").open("a", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(redact(record), sort_keys=True,
                                        default=str) + "\n")

    total_duplicates = skipped_duplicates + len(registered) - len(kept)
    return {
        "schema": "bugwolf-carlini-loop-v1",
        "target": target,
        "intake_records": len(records),
        "registered": len(registered),
        "kept": len(kept),
        "novel": len([c for c in registered if c.novelty == "potentially_novel"]),
        "duplicates": total_duplicates,
        "chains": len([c for c in registered if c.metadata.get("chain")]),
        "candidates": [c.to_dict() for c in registered],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf Carlini Loop Track — per-file brute-force "
                    "vulnerability analysis")
    parser.add_argument("--target", required=True,
                        help="Authorized target or local project name")
    parser.add_argument("--path", default=".",
                        help="Project path (file or directory) to walk")
    parser.add_argument("--surface", default=Surface.WEB_API.value,
                        choices=[s.value for s in Surface],
                        help="Surface to analyze (default: web_api)")
    parser.add_argument("--emit-units", metavar="FILE",
                        help="Write per-file research units to FILE (JSONL)")
    parser.add_argument("--offline", action="store_true",
                        help="Run the deterministic offline scan (no model)")
    parser.add_argument("--register-result", metavar="FILE",
                        help="Intake harness findings from FILE (JSON/JSONL)")
    parser.add_argument("--chains", action="store_true",
                        help="Synthesize chained hypotheses from kept candidates")
    parser.add_argument("--max-chains", type=int, default=32,
                        help="Max chained hypotheses (default: 32)")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                        help="Max files to analyze (default: %(default)s)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help="Max bytes per file (default: %(default)s)")
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES,
                        help="Max lines per file (default: %(default)s)")
    parser.add_argument("--top-k", type=int, default=None,
                        help="Validation budget: emit only the top K candidates")
    parser.add_argument("--json", action="store_true",
                        help="Emit strict JSON output")
    args = parser.parse_args()

    try:
        if args.register_result:
            records = _load_records(args.register_result)
            result = register_results(
                args.target, records, default_surface=args.surface,
                chains=args.chains, max_chains=args.max_chains)
        else:
            files = enumerate_files(
                args.path, surfaces=[args.surface],
                max_files=args.max_files, max_bytes=args.max_bytes,
                max_lines=args.max_lines)
            result: Dict[str, Any] = {
                "schema": "bugwolf-carlini-loop-v1",
                "target": args.target,
                "surface": args.surface,
                "files_enumerated": len(files),
                "path": str(Path(args.path).expanduser().resolve()),
            }
            if args.emit_units:
                units = build_units(args.target, files, surface=args.surface)
                out = Path(args.emit_units).expanduser()
                out.parent.mkdir(parents=True, exist_ok=True)
                with out.open("w", encoding="utf-8") as stream:
                    for unit in units:
                        stream.write(json.dumps(unit, sort_keys=True,
                                                default=str) + "\n")
                result["units_emitted"] = len(units)
                result["units_file"] = str(out)
            if args.offline:
                candidates = offline_scan(args.target, files,
                                          surface=args.surface)
                engine = ZeroDayResearchEngine(args.target)
                registered = engine.register(candidates)
                ranked = build_ranked_output(
                    engine, registered, surface=args.surface,
                    top_k=args.top_k)
                ranked["files_enumerated"] = len(files)
                ranked["surface"] = args.surface
                if args.chains:
                    kept = [c for c in registered
                            if c.novelty != "exact_duplicate"]
                    ranked["candidates"].extend(
                        c.to_dict() for c in engine.chain_candidates(
                            kept, max_chains=args.max_chains))
                result["offline"] = ranked
            if not args.emit_units and not args.offline:
                result["note"] = (
                    "Nothing to do: pass --emit-units, --offline, or "
                    "--register-result")
                result["files_enumerated"] = len(files)
    except (ValueError, FileNotFoundError, OSError) as exc:
        if args.json:
            print(json.dumps({"schema": "bugwolf-carlini-loop-v1",
                              "target": args.target, "error": str(exc)},
                             indent=2))
        else:
            print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("=" * 72)
        print(f"CARLINI LOOP: {args.target} | surface {args.surface}")
        print("=" * 72)
        if args.register_result:
            print(f"[*] intake: {result['intake_records']} records -> "
                  f"{result['registered']} registered, "
                  f"{result['novel']} potentially-novel, "
                  f"{result['duplicates']} duplicates")
        else:
            print(f"[*] files enumerated: {result['files_enumerated']}")
            if args.emit_units:
                print(f"[*] units emitted: {result['units_emitted']} -> "
                      f"{result['units_file']}")
            if args.offline:
                ranked = result["offline"]
                print(f"[*] offline candidates: "
                      f"{len(ranked['candidates'])} "
                      f"(mode {ranked['ordering']['mode']})")
                for record in ranked["candidates"]:
                    print(f"  #{record.get('rank', '?')} "
                          f"[{record['novelty']}] {record['candidate_id']} "
                          f"{record['title']} ({record['location']})")
        print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
