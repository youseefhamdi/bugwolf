"""BugWolf Phase 3.2 — Taint Flow Analysis Engine.

Net-new module.  Provides a multi-language taint propagation framework
that maps user-controlled **sources** to dangerous **sinks** across the
seven most common web/mobile/blockchain languages:

  * Python    — stdlib :mod:`ast` based engine
  * JavaScript / TypeScript — stdlib regex/heuristic engines
  * Go / Rust / Java         — stdlib regex/heuristic engines
  * Solidity                 — stdlib regex engine

The module ships a :class:`TaintEngine` ABC and seven concrete engine
implementations, plus the supporting infrastructure required to:

  * walk a project and identify cross-file flows (``CrossFileTaintAnalyzer``)
  * build a flow graph (``TaintFlowGraph``)
  * categorise flows into vulnerability classes (``VulnerabilityDetector``)
  * render a markdown report (``TaintReport``)
  * attach optional runtime instrumentation hooks
    (``DynamicTaintInstrument``, ``DynamicTaintProbe``, ``ShadowMemory``)

All components are **stub-safe**: a missing or unreadable file always
yields an empty result.  No third-party dependencies.

Schemas:
  * ``bugwolf-taint-v1`` — emitted by every file in this package
"""

## Source: taint flow engine ABC (Phase 3.2)
## License: bugwolf-MIT

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple


SCHEMA = "bugwolf-taint-v1"


class TaintSource(str, Enum):
    """Canonical user-controlled taint sources."""

    REQUEST_GET = "request.GET"
    REQUEST_POST = "request.POST"
    REQUEST_HEADERS = "request.headers"
    REQUEST_COOKIES = "request.cookies"
    REQUEST_BODY = "request.body"
    QUERY_PARAMS = "request.args"
    PATH_PARAMS = "request.view_args"
    FILE_UPLOAD = "request.files"
    ENV_VAR = "os.environ"
    DATABASE = "db.execute"
    FILE_READ = "file.read"
    STDIN = "sys.stdin"
    ARGV = "sys.argv"


class TaintSink(str, Enum):
    """Canonical dangerous sinks (sensitive operations)."""

    SQL_EXECUTE = "cursor.execute"
    SHELL_COMMAND = "os.system"
    SHELL_SUBPROCESS = "subprocess.call"
    FILE_OPEN = "open"
    FILE_PATH = "os.path.join"
    TEMPLATE_RENDER = "render_template_string"
    HTML_RETURN = "return"
    REDIRECT = "redirect"
    EVAL = "eval"
    EXEC = "exec"
    IMPORT = "__import__"
    DESERIALIZE = "pickle.loads"
    NETWORK_REQUEST = "requests.get"
    NETWORK_POST = "requests.post"
    SQL_ALCHEMY = "session.execute"


@dataclass(frozen=True)
class TaintFlow:
    """A single source → ... → sink taint propagation chain."""

    source: TaintSource
    sink: TaintSink
    file: str
    line: int
    path: Tuple[str, ...] = field(default_factory=tuple)
    sanitizers: Tuple[str, ...] = field(default_factory=tuple)
    is_vulnerable: bool = True
    confidence: float = 0.5
    severity: str = "medium"

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source.value,
            "sink": self.sink.value,
            "file": self.file,
            "line": self.line,
            "path": list(self.path),
            "sanitizers": list(self.sanitizers),
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "severity": self.severity,
        }


class TaintEngine(ABC):
    """Abstract base for every language-specific taint engine."""

    language: str = "unknown"

    @abstractmethod
    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        """Return all taint flows discovered in ``filepath``.

        ``STUB-SAFE``: missing/unreadable files yield ``[]``.
        """

    @abstractmethod
    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        """Return all taint flows discovered under ``project_root``."""

    def file_extensions(self) -> Tuple[str, ...]:
        """File extensions this engine handles.  Override per language."""

        return ()


__all__ = [
    "SCHEMA",
    "TaintSource",
    "TaintSink",
    "TaintFlow",
    "TaintEngine",
]


def __getattr__(name: str) -> object:  # pragma: no cover - lazy re-export
    """Lazily re-export symbols from sub-modules on demand."""

    if name in {"PythonTaintEngine"}:
        from bugwolf.taint.engines.python import PythonTaintEngine

        return PythonTaintEngine
    if name in {"JavaScriptTaintEngine"}:
        from bugwolf.taint.engines.javascript import JavaScriptTaintEngine

        return JavaScriptTaintEngine
    if name in {"TypeScriptTaintEngine"}:
        from bugwolf.taint.engines.typescript import TypeScriptTaintEngine

        return TypeScriptTaintEngine
    if name in {"GoTaintEngine"}:
        from bugwolf.taint.engines.go import GoTaintEngine

        return GoTaintEngine
    if name in {"RustTaintEngine"}:
        from bugwolf.taint.engines.rust import RustTaintEngine

        return RustTaintEngine
    if name in {"SolidityTaintEngine"}:
        from bugwolf.taint.engines.solidity import SolidityTaintEngine

        return SolidityTaintEngine
    if name in {"JavaTaintEngine"}:
        from bugwolf.taint.engines.java import JavaTaintEngine

        return JavaTaintEngine
    if name == "CrossFileTaintAnalyzer":
        from bugwolf.taint.cross_file import CrossFileTaintAnalyzer

        return CrossFileTaintAnalyzer
    if name == "TaintFlowGraph":
        from bugwolf.taint.flow_builder import TaintFlowGraph

        return TaintFlowGraph
    if name == "VulnerabilityDetector":
        from bugwolf.taint.vulnerability_detector import VulnerabilityDetector

        return VulnerabilityDetector
    if name == "VulnerabilityReport":
        from bugwolf.taint.vulnerability_detector import VulnerabilityReport

        return VulnerabilityReport
    if name == "TaintReport":
        from bugwolf.taint.report import TaintReport

        return TaintReport
    if name in {"DynamicTaintInstrument", "DynamicTaintProbe", "ShadowMemory"}:
        from bugwolf.taint.dynamic import (  # noqa: WPS433
            DynamicTaintInstrument,
            DynamicTaintProbe,
            ShadowMemory,
        )

        return {"DynamicTaintInstrument": DynamicTaintInstrument,
                "DynamicTaintProbe": DynamicTaintProbe,
                "ShadowMemory": ShadowMemory}[name]
    raise AttributeError(name)
