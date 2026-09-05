"""Sink catalog — dangerous functions / methods grouped by vuln class.

Each entry maps a vulnerability class to a tuple of ``(pattern, severity)``.
Patterns are regex patterns (the engines ``re.compile`` them); parentheses
and other regex special characters must be escaped in the source.  No
literal ``file://`` / ``gopher://`` payloads are present in this catalog;
sinks describe sinks only — payloads live in the scanner package.

Schema: ``bugwolf-taint-v1``
"""

## Source: taint flow catalog (Phase 3.2 — sinks)
## License: bugwolf-MIT

from __future__ import annotations

import re
from typing import Dict, List, Tuple


SCHEMA = "bugwolf-taint-v1"


Sink = Tuple[str, str]  # (pattern, severity)


SINKS: Dict[str, List[Sink]] = {
    "sqli": [
        (r"cursor\.execute", "critical"),
        (r"cursor\.executemany", "critical"),
        (r"connection\.execute", "critical"),
        (r"session\.execute", "critical"),
        (r"db\.engine\.execute", "critical"),
        (r"Model\.objects\.raw", "critical"),
        (r"objects\.filter", "high"),
        (r"Model\.objects\.create", "high"),
        (r"Model\.objects\.get", "high"),
        (r"django\.db\.connection\.cursor", "critical"),
        (r"django\.db\.utils\.connect", "critical"),
    ],
    "xss": [
        (r"render_template_string", "high"),
        (r"\brender\b", "high"),
        (r"HttpResponse", "medium"),
        (r"JsonResponse", "low"),
        (r"res\.send", "high"),
        (r"res\.write", "high"),
        (r"document\.write", "high"),
        (r"innerHTML", "high"),
        (r"outerHTML", "high"),
        (r"dangerouslySetInnerHTML", "high"),
        (r"\$el\.html", "high"),
    ],
    "command_injection": [
        (r"os\.system", "critical"),
        (r"os\.popen", "critical"),
        (r"subprocess\.call", "critical"),
        (r"subprocess\.run", "critical"),
        (r"subprocess\.Popen", "critical"),
        (r"child_process\.exec", "critical"),
        (r"child_process\.execSync", "critical"),
        (r"child_process\.spawn", "critical"),
        (r"exec\.Command", "critical"),
        (r"Runtime\.exec", "critical"),
        (r"ProcessBuilder\.start", "critical"),
    ],
    "ssti": [
        (r"render_template_string", "critical"),
        (r"\bTemplate\b", "high"),
        (r"Environment\.from_string", "high"),
        (r"\bJinja2\b", "medium"),
        (r"new Function\b", "high"),
        (r"vm\.runInThisContext", "critical"),
    ],
    "lfi": [
        (r"\bopen\b", "medium"),
        (r"file_get_contents", "high"),
        (r"fs\.readFile", "high"),
        (r"fs\.readFileSync", "high"),
        (r"\bFile\(", "medium"),
        (r"new FileInputStream", "medium"),
        (r"\binclude\b", "high"),
        (r"\brequire\b", "high"),
    ],
    "rfi": [
        (r"\binclude\b", "critical"),
        (r"\brequire\b", "critical"),
        (r"\bimport\(", "critical"),
        (r"\bfetch\b", "high"),
        (r"\baxios\b", "high"),
        (r"http\.get", "high"),
        (r"http\.post", "high"),
    ],
    "deserialization": [
        (r"pickle\.loads", "critical"),
        (r"pickle\.load", "critical"),
        (r"yaml\.load", "high"),
        (r"yaml\.UnsafeLoader", "critical"),
        (r"jsonpickle\.decode", "high"),
        (r"ObjectInputStream\.readObject", "critical"),
        (r"XMLDecoder", "critical"),
        (r"\bunserialize\b", "critical"),
    ],
    "ssrf": [
        (r"requests\.get", "high"),
        (r"requests\.post", "high"),
        (r"urllib\.request\.urlopen", "high"),
        (r"\burlopen\b", "high"),
        (r"axios\.get", "high"),
        (r"axios\.post", "high"),
        (r"\bfetch\b", "high"),
        (r"http\.get", "high"),
        (r"net/http\.Get", "high"),
        (r"http\.Client\.Do", "high"),
    ],
    "xxe": [
        (r"etree\.parse", "high"),
        (r"etree\.fromstring", "high"),
        (r"DocumentBuilder\.parse", "high"),
        (r"SAXParser", "high"),
        (r"xml\.parse", "high"),
        (r"DOMParser", "high"),
    ],
    "csrf": [
        # CSRF is generally a missing-guard problem; sinks are state-changing routes.
        (r"@app\.route", "medium"),
        (r"@router\.post", "medium"),
        (r"router\.put", "medium"),
        (r"router\.delete", "medium"),
    ],
    "redirect": [
        (r"\bredirect\b", "medium"),
        (r"HttpResponseRedirect", "medium"),
        (r"res\.redirect", "medium"),
        (r"res\.location", "medium"),
        (r"location\.href", "medium"),
    ],
    "info_disclosure": [
        (r"console\.log", "low"),
        (r"\bprint\b", "low"),
        (r"logger\.error", "low"),
        (r"logger\.info", "low"),
        (r"throw new Error", "low"),
        (r"\braise\b", "low"),
    ],
}


def all_sink_patterns() -> List[str]:
    """Flatten the catalog into a list of patterns."""

    patterns: List[str] = []
    for entries in SINKS.values():
        for pattern, _severity in entries:
            patterns.append(pattern)
    return patterns


def sinks_for(vuln_class: str) -> List[Sink]:
    """Return the sinks for a single vuln class.  Empty list on miss."""

    return SINKS.get(vuln_class, [])


def sink_count() -> int:
    """Return the total number of sink entries in the catalog."""

    return sum(len(v) for v in SINKS.values())


__all__ = ["SINKS", "Sink", "all_sink_patterns", "sinks_for", "sink_count"]


# Additional alias maps used by the vulnerability detector ------------------


SEVERITY_BY_PATTERN: Dict[str, str] = {}


def _build_severity_index() -> None:
    """Populate :data:`SEVERITY_BY_PATTERN` lazily."""

    if SEVERITY_BY_PATTERN:
        return
    for entries in SINKS.values():
        for pattern, severity in entries:
            SEVERITY_BY_PATTERN[pattern] = severity


def severity_for(pattern: str) -> str:
    """Return severity for a regex pattern; ``"medium"`` when unknown."""

    _build_severity_index()
    return SEVERITY_BY_PATTERN.get(pattern, "medium")


def vuln_class_for(pattern: str) -> str:
    """Return the vuln class for ``pattern``.  ``"unknown"`` when missing."""

    for vuln_class, entries in SINKS.items():
        for pat, _sev in entries:
            if pat == pattern:
                return vuln_class
    return "unknown"


def expand(extra: Dict[str, List[Sink]]) -> None:
    """Append ``extra`` sinks at runtime (used by plugin frameworks)."""

    for vuln_class, entries in extra.items():
        SINKS.setdefault(vuln_class, []).extend(entries)
    # Invalidate cached indexes.
    SEVERITY_BY_PATTERN.clear()


__all__.extend(["SEVERITY_BY_PATTERN", "severity_for", "vuln_class_for", "expand"])


# ---------------------------------------------------------------------------
# Per-language sink aliases.
#
# Many sinks appear under slightly different names across languages and
# frameworks.  The :data:`LANGUAGE_ALIASES` mapping below helps the per
# language engines resolve a discovered sink call back to a catalog entry.
# ---------------------------------------------------------------------------


LANGUAGE_ALIASES: Dict[str, Dict[str, str]] = {
    "python": {
        "cursor.execute": "cursor\\.execute",
        "session.execute": "session\\.execute",
        "subprocess.call": "subprocess\\.call",
        "os.system": "os\\.system",
        "open": "\\bopen\\b",
        "render_template_string": "render_template_string",
        "redirect": "\\bredirect\\b",
        "pickle.loads": "pickle\\.loads",
        "requests.get": "requests\\.get",
        "requests.post": "requests\\.post",
        "eval": "\\beval\\b",
        "exec": "\\bexec\\b",
        "__import__": "\\b__import__\\b",
    },
    "javascript": {
        "fetch": "\\bfetch\\b",
        "axios": "\\baxios\\b",
        "child_process.exec": "child_process\\.exec",
        "res.send": "res\\.send",
        "res.redirect": "res\\.redirect",
        "innerHTML": "innerHTML",
        "JSON.parse": "JSON\\.parse",
    },
    "go": {
        "db.Query": "db\\.Query",
        "exec.Command": "exec\\.Command",
        "c.HTML": "c\\.HTML",
        "http.Get": "http\\.Get",
    },
    "rust": {
        "Command::new": "Command::new",
        "sqlx::query": "sqlx::query",
        "fs::write": "fs\\.write",
        "reqwest::get": "reqwest::get",
    },
    "solidity": {
        "selfdestruct": "selfdestruct",
        "delegatecall": "delegatecall",
        "assembly": "assembly",
    },
    "java": {
        "Runtime.exec": "Runtime\\.exec",
        "ProcessBuilder": "ProcessBuilder",
        "executeQuery": "executeQuery",
        "ObjectInputStream": "ObjectInputStream\\.readObject",
    },
}


__all__.append("LANGUAGE_ALIASES")


def alias_for(language: str, sink_name: str) -> str:
    """Resolve ``sink_name`` in ``language`` to its canonical regex pattern."""

    aliases = LANGUAGE_ALIASES.get(language, {})
    if sink_name in aliases:
        return aliases[sink_name]
    return re.escape(sink_name)


def find_match(language: str, sink_text: str) -> Optional[str]:
    """Return the catalog pattern that best matches ``sink_text``."""

    for pattern in all_sink_patterns():
        try:
            if re.search(pattern, sink_text):
                return pattern
        except re.error:
            continue
    return None


__all__.extend(["alias_for", "find_match"])
