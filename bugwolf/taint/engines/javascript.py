"""JavaScript taint engine — stdlib regex / heuristic based.

We deliberately avoid ``esprima`` / ``acorn`` / ``babel`` because Phase 3.2
must run with **no third-party deps**.  Instead we tokenise line-by-line,
match source / sink / sanitizer patterns, and link each sink back to the
most recent matching source on the propagation path.

This is a **best-effort, fast** engine — designed for CI sweeps, not for
deep semantic precision.  Callers needing semantic accuracy should use
the optional Babel bridge in :mod:`bugwolf.taint.dynamic`.

Schema: ``bugwolf-taint-v1``
"""

## Source: JavaScript taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS
from bugwolf.taint.sink_catalog import SINKS


SCHEMA = "bugwolf-taint-v1"


# Patterns --------------------------------------------------------------------

JS_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.REQUEST_GET: r"req\.query|req\.params|req\.query\[",
    TaintSource.REQUEST_POST: r"req\.body|req\.body\[",
    TaintSource.REQUEST_HEADERS: r"req\.headers|req\.headers\[",
    TaintSource.REQUEST_COOKIES: r"req\.cookies|req\.cookies\[",
    TaintSource.QUERY_PARAMS: r"req\.query",
    TaintSource.ENV_VAR: r"process\.env",
    TaintSource.STDIN: r"process\.stdin",
    TaintSource.ARGV: r"process\.argv",
    TaintSource.FILE_READ: r"\.read\(|fs\.readFileSync\(",
}

JS_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SQL_EXECUTE: r"\.query\(|connection\.query\(|pool\.query\(",
    TaintSink.SHELL_COMMAND: r"child_process\.exec\(|child_process\.execSync\(|exec\(",
    TaintSink.SHELL_SUBPROCESS: r"child_process\.spawn\(|child_process\.exec\(|require\(['\"]child_process['\"]\)",
    TaintSink.FILE_OPEN: r"fs\.readFile\(|fs\.open\(|fs\.writeFile\(|fs\.appendFile\(",
    TaintSink.EVAL: r"\beval\(",
    TaintSink.HTML_RETURN: r"res\.send\(|res\.write\(|response\.send\(|response\.write\(|innerHTML\s*=|outerHTML\s*=",
    TaintSink.REDIRECT: r"res\.redirect\(|response\.redirect\(|window\.location\s*=",
    TaintSink.NETWORK_REQUEST: r"fetch\(|axios\.(?:get|post|put|delete|patch|request)\(|http\.get\(|https\.get\(",
    TaintSink.NETWORK_POST: r"axios\.post\(|fetch\(.*POST|axios\(\s*\{",
    TaintSink.DESERIALIZE: r"JSON\.parse\(|yaml\.load\(|serialize-javascript",
}


# Severity helpers ------------------------------------------------------------

_SEVERITY_CACHE: Dict[str, str] = {}


def _severity_for(sink: TaintSink) -> str:
    """Look up severity for a sink in the catalog."""

    if not _SEVERITY_CACHE:
        for entries in SINKS.values():
            for pat, sev in entries:
                _SEVERITY_CACHE[pat] = sev
    return _SEVERITY_CACHE.get(sink.value, "medium")


# Engine ----------------------------------------------------------------------


class JavaScriptTaintEngine(TaintEngine):
    """Heuristic regex taint engine for JavaScript."""

    language = "javascript"
    file_extensions = (".js", ".jsx", ".mjs", ".cjs")

    _VAR_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(.+?);?\s*$")
    _FUNC_ARG_RE = re.compile(r"function\s*\w*\s*\(([^)]*)\)")
    _ARROW_ARG_RE = re.compile(r"\(([^)]*)\)\s*=>")

    def __init__(self, propagation_depth: int = 12) -> None:
        self.propagation_depth = propagation_depth

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        """Return flows for ``filepath``."""

        source = self._safe_read(filepath)
        if not source:
            return []
        lines = source.splitlines()
        tainted: Dict[str, Tuple[TaintSource, int]] = {}
        propagation: Dict[str, List[str]] = {}
        sink_calls: List[Tuple[int, TaintSink, str]] = []
        sanitizer_calls: List[str] = []

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//"):
                continue
            # Sanitizer
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            # Source
            for src, pat in JS_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    var_match = self._VAR_RE.search(stripped)
                    if var_match:
                        var_name = var_match.group(1)
                        tainted[var_name] = (src, idx)
                        propagation[var_name] = []
                    else:
                        # Inline source; record as anonymous.
                        tainted[f"_inline_{idx}"] = (src, idx)
            # Propagation: var x = tainted;
            m = self._VAR_RE.search(stripped)
            if m:
                var_name, rhs = m.group(1), m.group(2)
                if any(name in rhs for name in tainted):
                    tainted[var_name] = next(
                        (info for vname, info in tainted.items() if vname in rhs),
                        (TaintSource.QUERY_PARAMS, idx),
                    )
                    propagation[var_name] = [n for n in tainted if n in rhs]
            # Sink
            for sink, pat in JS_SINK_PATTERNS.items():
                if re.search(pat, stripped):
                    sink_calls.append((idx, sink, stripped))

        flows: List[TaintFlow] = []
        for line, sink, sink_line in sink_calls:
            tainted_arg = self._matching_tainted(sink_line, tainted)
            if tainted_arg is None:
                continue
            tname, (src, src_line) = tainted_arg
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
                    severity=_severity_for(sink),
                )
            )
        return flows

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        """Return flows for every JS file under ``project_root``."""

        flows: List[TaintFlow] = []
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return flows
        for ext in self.file_extensions:
            for path in root.rglob(f"*{ext}"):
                if self._is_skippable(path):
                    continue
                flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"node_modules", ".next", "dist", "build", ".git"} & parts)

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


# Mutation helpers used by the test suite ------------------------------------


def mutate_for_test(engine: JavaScriptTaintEngine, flows: List[TaintFlow]) -> List[TaintFlow]:
    """Return a deterministic mutation of ``flows`` for fuzzing tests."""

    out: List[TaintFlow] = []
    for flow in flows:
        # Swap source/sink order for the mutation test.
        out.append(
            TaintFlow(
                source=flow.sink if hasattr(flow.sink, "value") else TaintSink.SQL_EXECUTE,
                sink=flow.source if hasattr(flow.source, "value") else TaintSink.EVAL,
                file=flow.file,
                line=flow.line,
                path=tuple(reversed(flow.path)),
                sanitizers=flow.sanitizers,
                is_vulnerable=flow.is_vulnerable,
                confidence=flow.confidence,
                severity=flow.severity,
            )
        )
    return out


__all__ = [
    "JavaScriptTaintEngine",
    "JS_SOURCE_PATTERNS",
    "JS_SINK_PATTERNS",
    "mutate_for_test",
    "javascript_taint_summary",
    "extract_destructured_names",
    "extract_template_strings",
]


def javascript_taint_summary(flows: List[TaintFlow]) -> Dict[str, object]:
    """Return a tiny summary dict for ``flows``."""

    if not flows:
        return {"count": 0, "vulnerable": 0}
    vulnerable = sum(1 for f in flows if f.is_vulnerable)
    return {
        "count": len(flows),
        "vulnerable": vulnerable,
        "sources": sorted({f.source.value for f in flows}),
        "sinks": sorted({f.sink.value for f in flows}),
    }


_DESTRUCT_RE = re.compile(
    r"\b(?:const|let|var)\s*\[\s*([A-Za-z_][\w]*)\s*(?:,\s*([A-Za-z_][\w]*)\s*)*\]\s*=\s*(.+?);?"
)


def extract_destructured_names(source: str) -> List[Tuple[str, str]]:
    """Find ``const [a, b] = ...`` style destructures; return ``(a, rhs)``."""

    out: List[Tuple[str, str]] = []
    for line in source.splitlines():
        m = _DESTRUCT_RE.search(line.strip())
        if not m:
            continue
        rhs = m.group(3)
        for grp in m.groups()[:-1]:
            if grp:
                out.append((grp, rhs))
    return out


_TEMPLATE_RE = re.compile(r"`([^`]*)`")


def extract_template_strings(source: str) -> List[str]:
    """Return the static text inside every back-tick template literal."""

    return [m.group(1) for m in _TEMPLATE_RE.finditer(source)]
