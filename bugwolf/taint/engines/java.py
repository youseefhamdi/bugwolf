"""Java taint engine — stdlib regex heuristic for ``.java`` source files.

Recognises Spring / Servlet / JAX-RS request extractors (``@RequestParam``,
``@RequestBody``, ``HttpServletRequest.getParameter``) and the canonical
sinks (JDBC ``execute``, ``Runtime.exec``, ``ProcessBuilder``, JPA
``EntityManager``, etc.).

Schema: ``bugwolf-taint-v1``
"""

## Source: Java taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS


SCHEMA = "bugwolf-taint-v1"


JAVA_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.REQUEST_GET: r"@RequestParam|getParameter\(",
    TaintSource.REQUEST_POST: r"@RequestBody|@ModelAttribute|getParameterValues\(",
    TaintSource.REQUEST_HEADERS: r"@RequestHeader|getHeader\(",
    TaintSource.REQUEST_COOKIES: r"@CookieValue|getCookies\(",
    TaintSource.REQUEST_BODY: r"@RequestBody|getInputStream\(|getReader\(",
    TaintSource.QUERY_PARAMS: r"@RequestParam|getParameter\(",
    TaintSource.PATH_PARAMS: r"@PathVariable|@MatrixVariable",
    TaintSource.ENV_VAR: r"System\.getenv\(|System\.getProperty\(",
    TaintSource.ARGV: r"args\[\d+\]|String\[\]\s+args",
    TaintSource.STDIN: r"System\.in|System\.console\(",
    TaintSource.FILE_READ: r"Files\.newInputStream|Files\.readAllBytes|Files\.readAllLines|Scanner\(.*System\.in\)",
}

JAVA_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SQL_EXECUTE: r"\.executeQuery\(|PreparedStatement.*execute|\.executeUpdate\(|createNativeQuery\(",
    TaintSink.SQL_ALCHEMY: r"createNativeQuery\(|EntityManager.*createQuery",
    TaintSink.SHELL_COMMAND: r"Runtime\.getRuntime\(\)\.exec\(|Runtime\.exec\(",
    TaintSink.SHELL_SUBPROCESS: r"ProcessBuilder\(|new ProcessBuilder",
    TaintSink.FILE_OPEN: r"new File\(|new FileInputStream\(|new FileOutputStream\(|Paths\.get\(",
    TaintSink.EVAL: r"ScriptEngine.*eval\(|GroovyShell.*evaluate\(|NashornScriptEngine",
    TaintSink.HTML_RETURN: r"PrintWriter|getWriter\(\)\.write\(|ResponseEntity|@ResponseBody",
    TaintSink.REDIRECT: r"sendRedirect\(|HttpServletResponse.*setStatus",
    TaintSink.NETWORK_REQUEST: r"new URL\(|HttpURLConnection|HttpClient\.newBuilder",
    TaintSink.NETWORK_POST: r"HttpClient\.send|HttpURLConnection.*setRequestMethod",
    TaintSink.DESERIALIZE: r"ObjectInputStream\(|XMLDecoder\(|readObject\(|Yaml\.load\(|fromString\(",
}


class JavaTaintEngine(TaintEngine):
    """Heuristic regex taint engine for Java."""

    language = "java"
    file_extensions = (".java",)

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
        var_re = re.compile(
            r"\b(?:String|int|long|double|float|boolean|Object|var|List<[^>]+>|Map<[^>]+>)\s+([A-Za-z_][\w]*)\s*(?:=\s*([^;]+))?"
        )

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            for src, pat in JAVA_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    m = var_re.search(stripped)
                    if m and m.group(1):
                        tainted[m.group(1)] = (src, idx)
                    else:
                        tainted[f"_inline_{idx}"] = (src, idx)
            # Propagation.
            m = var_re.search(stripped)
            if m and m.group(2):
                var_name, rhs = m.group(1), m.group(2)
                for tname in list(tainted):
                    if tname in rhs and tname != var_name:
                        tainted[var_name] = tainted[tname]
                        break
            for sink, pat in JAVA_SINK_PATTERNS.items():
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
                    severity=self._severity_for(sink),
                )
            )
        return flows

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return flows
        for path in root.rglob("*.java"):
            if self._is_skippable(path):
                continue
            flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"target", "build", "out", ".git", "node_modules"} & parts)

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
        if "execute" in sink.value or "exec" in sink.value:
            return "critical"
        if "SQL" in sink.value or "deserialize" in sink.value.lower():
            return "high"
        return "medium"


__all__ = [
    "JavaTaintEngine",
    "JAVA_SOURCE_PATTERNS",
    "JAVA_SINK_PATTERNS",
]
