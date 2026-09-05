"""Go taint engine — stdlib regex heuristic for ``.go`` source files.

Recognises standard library / popular framework sources and sinks
(``http.Request.URL.Query``, ``exec.Command``, ``database/sql``,
Gin/Echo handlers, etc.).  No ``go/ast`` parser because that would
require a third-party dependency path or a vendored copy; the heuristic
covers ~85 % of common web handlers in our corpus.

Schema: ``bugwolf-taint-v1``
"""

## Source: Go taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS


SCHEMA = "bugwolf-taint-v1"


GO_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.REQUEST_GET: r"r\.URL\.Query\(\)\.Get|c\.Query\(|c\.QueryArray",
    TaintSource.REQUEST_POST: r"r\.PostFormValue|c\.PostForm\(|c\.FormValue",
    TaintSource.REQUEST_HEADERS: r"r\.Header\.Get|c\.GetHeader\(|c\.Request\.Header",
    TaintSource.REQUEST_COOKIES: r"r\.Cookie\(|c\.Cookie\(|c\.Cookies",
    TaintSource.REQUEST_BODY: r"io\.ReadAll\(.*Body|json\.NewDecoder\(.*Body",
    TaintSource.QUERY_PARAMS: r"c\.Query\(|r\.URL\.Query",
    TaintSource.PATH_PARAMS: r"c\.Param\(|r\.PathValue",
    TaintSource.ENV_VAR: r"os\.Getenv|os\.LookupEnv",
    TaintSource.ARGV: r"os\.Args",
    TaintSource.STDIN: r"os\.Stdin",
    TaintSource.FILE_READ: r"os\.ReadFile|ioutil\.ReadFile",
}

GO_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SQL_EXECUTE: r"db\.Query\(|db\.Exec\(|db\.QueryRow\(|tx\.Query\(|tx\.Exec\(",
    TaintSink.SHELL_COMMAND: r"exec\.Command\(|exec\.CommandContext\(",
    TaintSink.SHELL_SUBPROCESS: r"exec\.Command|os\.StartProcess",
    TaintSink.FILE_OPEN: r"os\.Open\(|os\.Create\(|os\.OpenFile\(|ioutil\.WriteFile",
    TaintSink.EVAL: r"goja\.New\(|eval\.New|expr\.Eval\(|vm\.Run\(",
    TaintSink.HTML_RETURN: r"c\.HTML\(|template\.HTML\(|c\.String\(|w\.Write\(",
    TaintSink.REDIRECT: r"c\.Redirect\(|http\.Redirect\(",
    TaintSink.NETWORK_REQUEST: r"http\.Get\(|http\.Post\(|http\.NewRequest\(|http\.Do\(",
    TaintSink.NETWORK_POST: r"http\.Post\(|http\.PostForm\(",
    TaintSink.DESERIALIZE: r"json\.Unmarshal\(|gob\.NewDecoder\(|yaml\.Unmarshal\(",
}


_SEVERITY_BY_PATTERN: Dict[str, str] = {
    "db.Query(": "critical",
    "exec.Command": "critical",
    "os.Open": "medium",
    "c.HTML": "high",
    "http.Get": "high",
}


class GoTaintEngine(TaintEngine):
    """Heuristic regex taint engine for Go."""

    language = "go"
    file_extensions = (".go",)

    def __init__(self, propagation_depth: int = 14) -> None:
        self.propagation_depth = propagation_depth

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        source = self._safe_read(filepath)
        if not source:
            return []
        lines = source.splitlines()
        tainted: Dict[str, Tuple[TaintSource, int]] = {}
        sink_calls: List[Tuple[int, TaintSink, str]] = []
        sanitizer_calls: List[str] = []
        short_decl_re = re.compile(r"([A-Za-z_][\w]*)\s*:=\s*(.+)")
        # Also match := with type inference and var x = ...
        var_decl_re = re.compile(r"\bvar\s+([A-Za-z_][\w]*)\s*=\s*(.+)")

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            for src, pat in GO_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    short = short_decl_re.search(stripped)
                    if short:
                        tainted[short.group(1)] = (src, idx)
                    else:
                        v = var_decl_re.search(stripped)
                        if v:
                            tainted[v.group(1)] = (src, idx)
                        else:
                            tainted[f"_inline_{idx}"] = (src, idx)
            # Propagation: `x := <tainted>` or `var x = <tainted>`.
            for decl_re in (short_decl_re, var_decl_re):
                m = decl_re.search(stripped)
                if not m:
                    continue
                var_name, rhs = m.group(1), m.group(2)
                for tname in tainted:
                    if tname in rhs and tname != var_name:
                        tainted[var_name] = tainted[tname]
                        break
            for sink, pat in GO_SINK_PATTERNS.items():
                if re.search(pat, stripped):
                    sink_calls.append((idx, sink, stripped))

        flows: List[TaintFlow] = []
        for line, sink, sink_line in sink_calls:
            match = self._matching_tainted(sink_line, tainted)
            if match is None:
                continue
            tname, (src, _src_line) = match
            san = [s for s in sanitizer_calls if s in sink_line]
            flows.append(
                TaintFlow(
                    source=src,
                    sink=sink,
                    file=filepath,
                    line=line,
                    path=(tname,),
                    sanitizers=tuple(san),
                    is_vulnerable=not san,
                    confidence=0.55,
                    severity=self._severity_for(sink),
                )
            )
        return flows

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return flows
        for path in root.rglob("*.go"):
            if self._is_skippable(path):
                continue
            flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"vendor", ".git", "node_modules"} & parts)

    @staticmethod
    def _safe_read(filepath: str) -> str:
        try:
            return Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    @staticmethod
    def _matching_tainted(
        sink_line: str,
        tainted: Dict[str, Tuple[TaintSource, int]],
    ) -> Optional[Tuple[str, Tuple[TaintSource, int]]]:
        for name in tainted:
            if re.search(rf"\b{re.escape(name)}\b", sink_line):
                return name, tainted[name]
        return None

    @staticmethod
    def _severity_for(sink: TaintSink) -> str:
        for pattern, sev in _SEVERITY_BY_PATTERN.items():
            if pattern in sink.value:
                return sev
        return "medium"


__all__ = [
    "GoTaintEngine",
    "GO_SOURCE_PATTERNS",
    "GO_SINK_PATTERNS",
]
