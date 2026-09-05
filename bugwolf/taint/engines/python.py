"""Python taint engine — stdlib :mod:`ast` based static analysis.

Strategy:

  1. Parse the file with ``ast.parse(source, filename=filepath)``.
  2. Walk the AST to record **sources** (the right-hand side of an
     assignment, or the call argument of an ``ast.Call`` matching a known
     source pattern).
  3. Walk again to record **propagation steps**: every time a tainted
     variable is read (``ast.Name``) or an attribute is loaded
     (``ast.Attribute``), mark the LHS as tainted.
  4. Walk a third time to record **sinks**: calls to dangerous functions
     that receive tainted arguments.
  5. For each sink, BFS-propagate the taint from the sink argument back
     to every recorded source, building a :class:`TaintFlow`.

Everything is **stub-safe**: any parse failure, missing file, or IO error
yields an empty list — never raises.

Schema: ``bugwolf-taint-v1``
"""

## Source: Python taint engine (Phase 3.2 — ast based)
## License: bugwolf-MIT

from __future__ import annotations

import ast
import os
import re
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS
from bugwolf.taint.sink_catalog import SINKS


SCHEMA = "bugwolf-taint-v1"


# Regex helpers ---------------------------------------------------------------

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


# Sources ---------------------------------------------------------------------

PY_SOURCE_PATTERNS: Dict[str, str] = {
    TaintSource.REQUEST_GET: r"\brequest\.(?:GET|args)\b",
    TaintSource.REQUEST_POST: r"\brequest\.(?:POST|form|values)\b",
    TaintSource.REQUEST_HEADERS: r"\brequest\.(?:headers|META)\b",
    TaintSource.REQUEST_COOKIES: r"\brequest\.cookies\b",
    TaintSource.REQUEST_BODY: r"\brequest\.(?:body|data|json|json_body)\b",
    TaintSource.QUERY_PARAMS: r"\brequest\.args\b",
    TaintSource.PATH_PARAMS: r"\brequest\.view_args\b",
    TaintSource.FILE_UPLOAD: r"\brequest\.files\b",
    TaintSource.ENV_VAR: r"\bos\.environ\b",
    TaintSource.DATABASE: r"\.execute\b",
    TaintSource.FILE_READ: r"\.read\b",
    TaintSource.STDIN: r"\bsys\.stdin\b",
    TaintSource.ARGV: r"\bsys\.argv\b",
}


# Sinks -----------------------------------------------------------------------

PY_SINK_PATTERNS: Dict[str, str] = {
    TaintSink.SQL_EXECUTE: r"\b(?:cursor|cur|conn|connection|db\.engine)\.execute\b",
    TaintSink.SQL_ALCHEMY: r"\bsession\.execute\b",
    TaintSink.SHELL_COMMAND: r"\b(?:os\.system|os\.popen)\b",
    TaintSink.SHELL_SUBPROCESS: r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b",
    TaintSink.FILE_OPEN: r"\b(?:open|file\()\b",
    TaintSink.FILE_PATH: r"\bos\.path\.join\b",
    TaintSink.TEMPLATE_RENDER: r"\brender_template_string\b",
    TaintSink.HTML_RETURN: r"\breturn\b",
    TaintSink.REDIRECT: r"\b(?:redirect|HttpResponseRedirect)\b",
    TaintSink.EVAL: r"\beval\b",
    TaintSink.EXEC: r"\bexec\b",
    TaintSink.IMPORT: r"\b__import__\b",
    TaintSink.DESERIALIZE: r"\b(?:pickle\.loads?|yaml\.load)\b",
    TaintSink.NETWORK_REQUEST: r"\brequests\.(?:get|put|delete|head|patch|request)\b",
    TaintSink.NETWORK_POST: r"\brequests\.post\b",
}


# Severity mapping ------------------------------------------------------------

_SINK_SEVERITY: Dict[str, str] = {}


def _load_severity() -> None:
    """Populate ``_SINK_SEVERITY`` from the sink catalog."""

    if _SINK_SEVERITY:
        return
    for entries in SINKS.values():
        for pattern, severity in entries:
            _SINK_SEVERITY[pattern] = severity


# Helpers ---------------------------------------------------------------------


def _safe_read(filepath: str) -> str:
    """Return file contents or ``""`` on any IO failure."""

    try:
        return Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _line_of(source: str, lineno: int) -> str:
    """Return the 1-indexed ``source`` line for ``lineno``.  ``""`` if absent."""

    lines = source.splitlines()
    if 0 < lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _call_name(node: ast.Call) -> str:
    """Return a printable dotted name for an :class:`ast.Call`."""

    func = node.func
    parts: List[str] = []
    cur: Any = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _expr_dotted(node: ast.AST) -> str:
    """Render an expression as a dotted-name string.  Best effort."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _expr_dotted(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return _call_name(node) + "(...)"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return repr(node.value)
    return "<expr>"


# Taint propagation record ----------------------------------------------------


class _TaintState:
    """Mutable propagation state for a single file."""

    __slots__ = (
        "sources",
        "tainted",
        "propagation",
        "sink_calls",
        "sanitizers_seen",
        "filepath",
    )

    def __init__(self, filepath: str) -> None:
        self.sources: Dict[str, Tuple[TaintSource, int]] = {}
        self.tainted: Set[str] = set()
        self.propagation: Dict[str, Set[str]] = {}
        self.sink_calls: List[Tuple[ast.Call, TaintSink, str]] = []
        self.sanitizers_seen: Set[str] = set()
        self.filepath = filepath


# AST visitors ----------------------------------------------------------------


class _SourceVisitor(ast.NodeVisitor):
    """Walk the AST to record source variable bindings."""

    def __init__(self, state: _TaintState) -> None:
        self.state = state

    def visit_Assign(self, node: ast.Assign) -> None:
        src_pattern = _match_source(_expr_dotted(node.value))
        if src_pattern is not None:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.state.sources[tgt.id] = (src_pattern, node.lineno)
                elif isinstance(tgt, ast.Tuple) or isinstance(tgt, ast.List):
                    for elt in tgt.elts:
                        if isinstance(elt, ast.Name):
                            self.state.sources[elt.id] = (src_pattern, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            src_pattern = _match_source(_expr_dotted(node.value))
            if src_pattern is not None and isinstance(node.target, ast.Name):
                self.state.sources[node.target.id] = (src_pattern, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        for sname, pattern in SANITIZERS.items():
            if re.search(pattern, name):
                self.state.sanitizers_seen.add(sname)
            elif pattern.endswith("\\("):
                # pattern is written for a function-with-args; test against
                # the call name with an appended ``(``.
                if re.search(pattern[:-2], name + "("):
                    self.state.sanitizers_seen.add(sname)
        # Source call (e.g. ``request.args.get('id')``).
        src_pattern = _match_source(name)
        if src_pattern is not None:
            self.state.sources[f"call@{node.lineno}"] = (src_pattern, node.lineno)
        self.generic_visit(node)


class _PropagationVisitor(ast.NodeVisitor):
    """Walk the AST to propagate taint through assignments / attributes."""

    def __init__(self, state: _TaintState) -> None:
        self.state = state

    def visit_Assign(self, node: ast.Assign) -> None:
        # If RHS is a tainted expression, mark the LHS as tainted.
        rhs_taint = self._expr_taint(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                if rhs_taint:
                    self.state.tainted.add(tgt.id)
                    self.state.propagation.setdefault(tgt.id, set()).update(rhs_taint)
                # Also if the LHS itself appears in the source table (was a
                # source binding) make sure it's tainted.
                if tgt.id in self.state.sources:
                    self.state.tainted.add(tgt.id)
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                for elt in tgt.elts:
                    if isinstance(elt, ast.Name):
                        if rhs_taint:
                            self.state.tainted.add(elt.id)
                            self.state.propagation.setdefault(elt.id, set()).update(rhs_taint)
                        if elt.id in self.state.sources:
                            self.state.tainted.add(elt.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            rhs_taint = self._expr_taint(node.value)
            if rhs_taint:
                self.state.tainted.add(node.target.id)
                self.state.propagation.setdefault(node.target.id, set()).update(rhs_taint)
            if node.target.id in self.state.sources:
                self.state.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Record sink invocations.
        name = _call_name(node)
        sink_match = _match_sink(name)
        if sink_match is not None:
            self.state.sink_calls.append((node, sink_match, name))
        # Detect sanitizer invocations.
        for sname, pattern in SANITIZERS.items():
            if re.search(pattern, name):
                self.state.sanitizers_seen.add(sname)
            elif pattern.endswith("\\("):
                if re.search(pattern[:-2], name + "("):
                    self.state.sanitizers_seen.add(sname)
        self.generic_visit(node)

    def _expr_taint(self, expr: ast.AST) -> Set[str]:
        """Return the set of source-variable names flowing into ``expr``."""

        found: Set[str] = set()
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in self.state.tainted:
                found.add(sub.id)
        return found


class _ArgumentVisitor(ast.NodeVisitor):
    """Walk call arguments to identify tainted ones."""

    def __init__(self, state: _TaintState) -> None:
        self.state = state

    def taint_arguments(self, call: ast.Call) -> Set[str]:
        tainted: Set[str] = set()
        for arg in (*call.args, *call.keywords):
            if isinstance(arg, ast.keyword):
                sub = arg.value
            else:
                sub = arg
            for name in ast.walk(sub):
                if isinstance(name, ast.Name) and name.id in self.state.tainted:
                    tainted.add(name.id)
        return tainted


# Additional AST helpers -----------------------------------------------------


class _ReturnVisitor(ast.NodeVisitor):
    """Collect the names returned from a function (best effort)."""

    def __init__(self) -> None:
        self.returns: List[ast.AST] = []

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.returns.append(node.value)
        self.generic_visit(node)


class _DecoratorVisitor(ast.NodeVisitor):
    """Detect Flask / Django / FastAPI route decorators."""

    def __init__(self) -> None:
        self.routes: List[Tuple[str, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                name = _call_name(decorator)
                if any(p in name for p in ("app.route", "router.", "@router",
                                            "bp.route", "url", "path")):
                    self.routes.append((node.name, node.lineno))
            elif isinstance(decorator, ast.Attribute):
                name = _expr_dotted(decorator)
                if any(p in name for p in ("app.route", "router.",
                                            "bp.route", "url", "path")):
                    self.routes.append((node.name, node.lineno))
        self.generic_visit(node)


# Matching helpers ------------------------------------------------------------


def _match_source(expr_str: str) -> Optional[TaintSource]:
    """Return the matching :class:`TaintSource` for ``expr_str`` or ``None``."""

    for src, pattern in PY_SOURCE_PATTERNS.items():
        if re.search(pattern, expr_str):
            return src
    return None


def _match_sink(call_str: str) -> Optional[TaintSink]:
    """Return the matching :class:`TaintSink` for ``call_str`` or ``None``."""

    for sink, pattern in PY_SINK_PATTERNS.items():
        if re.search(pattern, call_str):
            return sink
    return None


# Engine ----------------------------------------------------------------------


class PythonTaintEngine(TaintEngine):
    """Stdlib-AST based taint engine for Python source files."""

    language = "python"
    file_extensions = (".py",)

    def __init__(self, propagation_depth: int = 20) -> None:
        self.propagation_depth = propagation_depth
        _load_severity()

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        """Return all taint flows for ``filepath``."""

        try:
            source = _safe_read(filepath)
            if not source:
                return []
            tree = ast.parse(source, filename=filepath)
        except (OSError, SyntaxError, ValueError):
            return []

        state = _TaintState(filepath)
        # Pass 1 — discover sources.
        _SourceVisitor(state).visit(tree)
        # Pass 2 — propagate taint & discover sinks.
        _PropagationVisitor(state).visit(tree)
        # Pass 3 — materialise flows.
        return self._build_flows(state)

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        """Return all taint flows under ``project_root``."""

        flows: List[TaintFlow] = []
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return flows
        for path in root.rglob("*.py"):
            if self._is_skippable(path):
                continue
            flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"__pycache__", ".venv", "venv", ".tox", ".git"} & parts)

    # Flow materialisation -----------------------------------------------------

    def _build_flows(self, state: _TaintState) -> List[TaintFlow]:
        out: List[TaintFlow] = []
        arg_visitor = _ArgumentVisitor(state)
        for call, sink, name in state.sink_calls:
            tainted_args = arg_visitor.taint_arguments(call)
            if not tainted_args:
                continue
            for tainted in tainted_args:
                src_info = state.sources.get(tainted)
                if src_info is None:
                    # Variable was propagated into but never sourced from a
                    # known source — skip.
                    continue
                source, source_line = src_info
                propagation = self._collect_propagation(state, tainted)
                sanitizers = self._sanitizers_for(state, propagation)
                is_vuln = len(sanitizers) == 0
                severity = self._severity_for(sink)
                confidence = self._confidence(state, propagation)
                out.append(
                    TaintFlow(
                        source=source,
                        sink=sink,
                        file=state.filepath,
                        line=call.lineno,
                        path=tuple(propagation),
                        sanitizers=tuple(sorted(sanitizers)),
                        is_vulnerable=is_vuln,
                        confidence=confidence,
                        severity=severity,
                    )
                )
        return out

    @staticmethod
    def _collect_propagation(state: _TaintState, varname: str) -> List[str]:
        seen: Set[str] = set()
        queue: Deque[str] = deque([varname])
        result: List[str] = []
        while queue:
            cur = queue.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            result.append(cur)
            for nxt in state.propagation.get(cur, ()):
                if nxt not in seen:
                    queue.append(nxt)
        return result

    @staticmethod
    def _sanitizers_for(state: _TaintState, propagation: Iterable[str]) -> Set[str]:
        seen = set()
        for _v in propagation:
            seen.update(state.sanitizers_seen)
        return seen

    @staticmethod
    def _severity_for(sink: TaintSink) -> str:
        # Map the canonical sink enum name back to severity in the catalog.
        for entries in SINKS.values():
            for pattern, severity in entries:
                if pattern == sink.value:
                    return severity
        return "medium"

    @staticmethod
    def _confidence(state: _TaintState, propagation: List[str]) -> float:
        # Short propagation → higher confidence.  Sanitizers reduce confidence.
        base = max(0.3, 1.0 - 0.05 * len(propagation))
        if state.sanitizers_seen:
            base -= 0.15
        return round(max(0.1, min(0.99, base)), 3)


# Cross-file import tracking --------------------------------------------------


class PythonImportGraph:
    """Simple import graph built by parsing each ``.py`` file with :mod:`ast`."""

    def __init__(self) -> None:
        self.edges: Dict[str, Set[str]] = {}

    def add_file(self, filepath: str) -> None:
        source = _safe_read(filepath)
        if not source:
            return
        try:
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, ValueError):
            return
        names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module.split(".")[0])
        if names:
            self.edges.setdefault(filepath, set()).update(names)

    def neighbours(self, filepath: str) -> Set[str]:
        return self.edges.get(filepath, set())


__all__ = [
    "PythonTaintEngine",
    "PythonImportGraph",
    "PY_SOURCE_PATTERNS",
    "PY_SINK_PATTERNS",
]


# Convenience helpers ---------------------------------------------------------


def detect_routes(filepath: str) -> List[Tuple[str, int]]:
    """Return ``(function_name, lineno)`` for every Flask/Django route."""

    source = _safe_read(filepath)
    if not source:
        return []
    try:
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, ValueError):
        return []
    visitor = _DecoratorVisitor()
    visitor.visit(tree)
    return visitor.routes


def collect_return_names(filepath: str) -> List[str]:
    """Return every name referenced in a ``return`` statement."""

    source = _safe_read(filepath)
    if not source:
        return []
    try:
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, ValueError):
        return []
    visitor = _ReturnVisitor()
    visitor.visit(tree)
    names: List[str] = []
    for ret in visitor.returns:
        for sub in ast.walk(ret):
            if isinstance(sub, ast.Name):
                names.append(sub.id)
    return names


def collect_called_functions(filepath: str) -> List[str]:
    """Return the dotted-name of every call site in ``filepath``."""

    source = _safe_read(filepath)
    if not source:
        return []
    try:
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, ValueError):
        return []
    out: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            out.append(_call_name(node))
    return out


def count_tainted_variables(flows: List[TaintFlow]) -> Dict[str, int]:
    """Count how many times each source name appears across ``flows``."""

    counts: Dict[str, int] = {}
    for flow in flows:
        for step in flow.path:
            counts[step] = counts.get(step, 0) + 1
    return counts


def taint_summary(flows: List[TaintFlow]) -> Dict[str, object]:
    """Return a small dict describing the flow list."""

    if not flows:
        return {"count": 0, "vulnerable": 0}
    vulnerable = sum(1 for f in flows if f.is_vulnerable)
    return {
        "count": len(flows),
        "vulnerable": vulnerable,
        "files": sorted({f.file for f in flows}),
        "sources": sorted({f.source.value for f in flows}),
        "sinks": sorted({f.sink.value for f in flows}),
    }
