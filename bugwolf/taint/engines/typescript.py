"""TypeScript taint engine — extends the JavaScript heuristic with TS-specific
patterns (typed parameters, decorators, type-asserted ``as unknown`` casts,
``@Body``/``@Query`` NestJS / TS-Rest decorators).

Schema: ``bugwolf-taint-v1``
"""

## Source: TypeScript taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.engines.javascript import JavaScriptTaintEngine, _severity_for
from bugwolf.taint.sanitizer_catalog import SANITIZERS


SCHEMA = "bugwolf-taint-v1"


# TypeScript-specific patterns -------------------------------------------------

TS_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.REQUEST_GET: r"@Query\(|@Param\(|req\.query",
    TaintSource.REQUEST_POST: r"@Body\(|req\.body",
    TaintSource.REQUEST_HEADERS: r"@Headers\(|req\.headers",
    TaintSource.REQUEST_COOKIES: r"@Cookies\(|req\.cookies",
    TaintSource.QUERY_PARAMS: r"@Query\(",
    TaintSource.PATH_PARAMS: r"@Param\(",
    TaintSource.ENV_VAR: r"process\.env",
    TaintSource.STDIN: r"process\.stdin",
    TaintSource.ARGV: r"process\.argv",
}

TS_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SQL_EXECUTE: r"\.query\(|createQueryBuilder|getRepository\(.*\)\.query",
    TaintSink.SHELL_COMMAND: r"exec\(|execSync\(|child_process",
    TaintSink.SHELL_SUBPROCESS: r"spawn\(|exec\(",
    TaintSink.FILE_OPEN: r"fs\.(?:readFile|writeFile|appendFile|open)\(",
    TaintSink.EVAL: r"\beval\(|new Function\(",
    TaintSink.HTML_RETURN: r"res\.send\(|res\.json\(|dangerouslySetInnerHTML|innerHTML\s*=",
    TaintSink.REDIRECT: r"res\.redirect\(|window\.location",
    TaintSink.NETWORK_REQUEST: r"fetch\(|axios\.(?:get|post|put|delete|patch|request)\(",
    TaintSink.NETWORK_POST: r"axios\.post\(|fetch\(.*method.*POST",
    TaintSink.DESERIALIZE: r"JSON\.parse\(|yaml\.load\(|deserialize\(",
}


class TypeScriptTaintEngine(TaintEngine):
    """Heuristic regex taint engine for TypeScript source files."""

    language = "typescript"
    file_extensions = (".ts", ".tsx")

    def __init__(self, propagation_depth: int = 12) -> None:
        self.propagation_depth = propagation_depth

    # Inherit JS read / skip helpers ---------------------------------------

    _safe_read = staticmethod(JavaScriptTaintEngine._safe_read)

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"node_modules", ".next", "dist", "build", ".git", "out"} & parts)

    # Override analyse methods to use TS patterns --------------------------

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        source = self._safe_read(filepath)
        if not source:
            return []
        lines = source.splitlines()
        tainted: Dict[str, Tuple[TaintSource, int]] = {}
        propagation: Dict[str, List[str]] = {}
        sink_calls: List[Tuple[int, TaintSink, str]] = []
        sanitizer_calls: List[str] = []
        var_re = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_][\w]*)\s*(?::\s*[^=]+)?=\s*(.+?);?\s*$")

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            # Sources (decorators and runtime access).
            for src, pat in TS_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    m = var_re.search(stripped)
                    if m:
                        tainted[m.group(1)] = (src, idx)
                        propagation[m.group(1)] = []
                    else:
                        tainted[f"_inline_{idx}"] = (src, idx)
            # TypeScript typed parameter binding:
            # e.g.  const id: string = req.query.id as string;
            typed = re.search(r"\b(?:const|let|var)\s+([A-Za-z_][\w]*)\s*:\s*[^=]+=\s*(.+)", stripped)
            if typed:
                var_name, rhs = typed.group(1), typed.group(2)
                if any(name in rhs for name in tainted):
                    tainted[var_name] = next(
                        (info for vname, info in tainted.items() if vname in rhs),
                        (TaintSource.QUERY_PARAMS, idx),
                    )
                    propagation[var_name] = [n for n in tainted if n in rhs]
            m = var_re.search(stripped)
            if m and not typed:
                var_name, rhs = m.group(1), m.group(2)
                if any(name in rhs for name in tainted):
                    tainted[var_name] = next(
                        (info for vname, info in tainted.items() if vname in rhs),
                        (TaintSource.QUERY_PARAMS, idx),
                    )
                    propagation[var_name] = [n for n in tainted if n in rhs]
            for sink, pat in TS_SINK_PATTERNS.items():
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
                    confidence=0.6,
                    severity=_severity_for(sink),
                )
            )
        return flows

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
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
    def _matching_tainted(
        sink_line: str,
        tainted: Dict[str, Tuple[TaintSource, int]],
    ) -> Optional[Tuple[str, Tuple[TaintSource, int]]]:
        for name in tainted:
            if re.search(rf"\b{re.escape(name)}\b", sink_line):
                return name, tainted[name]
        return None


__all__ = [
    "TypeScriptTaintEngine",
    "TS_SOURCE_PATTERNS",
    "TS_SINK_PATTERNS",
]
