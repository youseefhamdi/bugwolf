"""Rust taint engine — stdlib regex heuristic for ``.rs`` source files.

Recognises ``actix-web`` / ``axum`` / ``warp`` request extractors, the
``std::process::Command`` family, ``std::fs`` paths and ``serde_json`` /
``serde_yaml`` deserialisation.

Schema: ``bugwolf-taint-v1``
"""

## Source: Rust taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS


SCHEMA = "bugwolf-taint-v1"


RUST_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.REQUEST_GET: r"web::Query<|Query<|Path<|req\.query\(|req\.uri\(\)\.query\(\)",
    TaintSource.REQUEST_POST: r"web::Form<|web::Json<|Json<|Form<",
    TaintSource.REQUEST_HEADERS: r"web::Header<|Header<|req\.headers",
    TaintSource.REQUEST_COOKIES: r"req\.cookie\(|Cookie<",
    TaintSource.QUERY_PARAMS: r"web::Query<",
    TaintSource.PATH_PARAMS: r"web::Path<|Path<",
    TaintSource.ENV_VAR: r"std::env::var\(|env::var\(|env!",
    TaintSource.ARGV: r"std::env::args\(|env::args\(",
    TaintSource.STDIN: r"io::stdin\(|std::io::stdin",
    TaintSource.FILE_READ: r"fs::read_to_string\(|fs::read\(",
}

RUST_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SQL_EXECUTE: r"\.execute\(|sqlx::query\(|diesel::sql_query",
    TaintSink.SHELL_COMMAND: r"Command::new\(|std::process::Command",
    TaintSink.SHELL_SUBPROCESS: r"Command::new\(|Command::spawn\(|\.output\(\)",
    TaintSink.FILE_OPEN: r"fs::write\(|fs::read\(|fs::open\(|File::create\(",
    TaintSink.EVAL: r"eval\(.*\)|wasmer\.Instance|wasmtime",
    TaintSink.HTML_RETURN: r"HttpResponse::Ok\(\)|format!\(.*\{|tera::Tera|askama::Template",
    TaintSink.REDIRECT: r"HttpResponse::Found\(|Redirect::to\(",
    TaintSink.NETWORK_REQUEST: r"reqwest::get\(|reqwest::Client|ureq::get\(",
    TaintSink.NETWORK_POST: r"reqwest::Client::new\(\)\.post\(|ureq::post\(",
    TaintSink.DESERIALIZE: r"serde_json::from_str\(|bincode::deserialize|serde_yaml::from_str",
}


class RustTaintEngine(TaintEngine):
    """Heuristic regex taint engine for Rust."""

    language = "rust"
    file_extensions = (".rs",)

    def __init__(self, propagation_depth: int = 12) -> None:
        self.propagation_depth = propagation_depth

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        source = self._safe_read(filepath)
        if not source:
            return []
        lines = source.splitlines()
        tainted: Dict[str, Tuple[TaintSource, int]] = {}
        sink_calls: List[Tuple[int, TaintSink, str]] = []
        sanitizer_calls: List[str] = []
        let_re = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_][\w]*)\s*(?::\s*[^=]+)?=\s*(.+?);")
        fn_re = re.compile(r"\bfn\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)")

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            # Sources
            for src, pat in RUST_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    m = let_re.search(stripped)
                    if m:
                        tainted[m.group(1)] = (src, idx)
                    else:
                        tainted[f"_inline_{idx}"] = (src, idx)
            # Propagation
            m = let_re.search(stripped)
            if m:
                var_name, rhs = m.group(1), m.group(2)
                for tname in list(tainted):
                    if tname in rhs and tname != var_name:
                        tainted[var_name] = tainted[tname]
                        break
            # Sinks
            for sink, pat in RUST_SINK_PATTERNS.items():
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
        for path in root.rglob("*.rs"):
            if self._is_skippable(path):
                continue
            flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"target", ".git", "node_modules"} & parts)

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
        if "execute" in sink.value or "Command" in sink.value:
            return "critical"
        if "read" in sink.value or "write" in sink.value:
            return "high"
        return "medium"


__all__ = [
    "RustTaintEngine",
    "RUST_SOURCE_PATTERNS",
    "RUST_SINK_PATTERNS",
]
