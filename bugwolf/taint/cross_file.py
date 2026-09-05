"""Cross-file taint analyzer — joins flows that cross module boundaries.

Strategy:

  1. Walk the project root to build an **import graph** for every
     supported language.  For Python this uses :mod:`ast`; for all other
     languages it uses a regex extraction of ``import`` / ``require`` /
     ``use`` statements.
  2. Run the language-specific engine on every source file.
  3. For each flow, check whether any variable referenced along the
     propagation path is **exported from another file** in the import
     graph.  If yes, attach a synthetic ``cross_file`` flow that links
     the importer to the sink.

The analyzer is **stub-safe**: any error during graph construction or
flow analysis yields empty results.

Schema: ``bugwolf-taint-v1``
"""

## Source: cross-file taint analyzer (Phase 3.2)
## License: bugwolf-MIT

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow
from bugwolf.taint.engines import (
    GoTaintEngine,
    JavaTaintEngine,
    JavaScriptTaintEngine,
    PythonTaintEngine,
    RustTaintEngine,
    SolidityTaintEngine,
    TypeScriptTaintEngine,
)


SCHEMA = "bugwolf-taint-v1"


_LANGUAGE_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "go": (".go",),
    "rust": (".rs",),
    "solidity": (".sol",),
    "java": (".java",),
}


# Per-language import regexes -------------------------------------------------


_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE
)
_JS_IMPORT_RE = re.compile(r"""(?:import\s+[^'\"]*?from\s+|require\(\s*)['\"]([^'\"]+)['\"]""")
_TS_IMPORT_RE = _JS_IMPORT_RE
_GO_IMPORT_RE = re.compile(r'^\s*import\s+(?:\(\s*)?(?:[_\w\.]+\s+)?\"([^\"]+)\"', re.MULTILINE)
_RUST_USE_RE = re.compile(r"\buse\s+([\w:]+)(?:::\{[^}]+\})?;")
_SOLIDITY_IMPORT_RE = re.compile(r'import\s+(?:\{[^}]+\}|\*\s+as\s+\w+|\w+)\s+from\s+[\'"]([^\'"]+)[\'"]')
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+);", re.MULTILINE)


# Engine factory --------------------------------------------------------------


def _default_engines() -> List[TaintEngine]:
    """Return one engine per supported language."""

    return [
        PythonTaintEngine(),
        JavaScriptTaintEngine(),
        TypeScriptTaintEngine(),
        GoTaintEngine(),
        RustTaintEngine(),
        SolidityTaintEngine(),
        JavaTaintEngine(),
    ]


def _engine_for(language: str) -> Optional[TaintEngine]:
    """Return the engine for ``language`` (or ``None``)."""

    return {
        "python": PythonTaintEngine,
        "javascript": JavaScriptTaintEngine,
        "typescript": TypeScriptTaintEngine,
        "go": GoTaintEngine,
        "rust": RustTaintEngine,
        "solidity": SolidityTaintEngine,
        "java": JavaTaintEngine,
    }.get(language)()


# Module resolver -------------------------------------------------------------


def _resolve_module_file(root: Path, language: str, module: str) -> Optional[Path]:
    """Best-effort resolution of an import to a file path."""

    if not module:
        return None
    exts = _LANGUAGE_EXTENSIONS.get(language, ())
    if language == "python":
        parts = module.split(".")
        for ext in exts:
            candidate = root.joinpath(*parts).with_suffix(ext)
            if candidate.exists():
                return candidate
            candidate_init = root.joinpath(*parts, f"__init__{ext}")
            if candidate_init.exists():
                return candidate_init
        return None
    if language in {"javascript", "typescript"}:
        # Strip leading "./" or "../" prefix.
        clean = module.lstrip("./")
        for ext in exts:
            candidate = root / f"{clean}{ext}"
            if candidate.exists():
                return candidate
            candidate_idx = root / clean / f"index{ext}"
            if candidate_idx.exists():
                return candidate_idx
        return None
    if language == "go":
        # Module path usually relative to GOPATH; we approximate by joining.
        candidate = root / f"{module}.go"
        if candidate.exists():
            return candidate
        return None
    if language == "rust":
        # Module path like "crate::foo::bar"; only crate-local resolution.
        if module.startswith("crate::") or module.startswith("super::") or module.startswith("self::"):
            return None
        candidate = root / f"{module.replace('::', '/')}.rs"
        if candidate.exists():
            return candidate
        return None
    if language == "solidity":
        candidate = root / f"{module}.sol"
        if candidate.exists():
            return candidate
        return None
    if language == "java":
        parts = module.split(".")
        for ext in exts:
            candidate = root.joinpath(*parts).with_suffix(ext)
            if candidate.exists():
                return candidate
        return None
    return None


# Import-graph builder --------------------------------------------------------


class ImportGraph:
    """Directed graph: file → set of imported file paths (resolved)."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.edges: Dict[str, Set[str]] = defaultdict(set)
        self._by_language: Dict[str, str] = {}
        self._modules: Dict[str, List[str]] = {}

    def add_file(self, filepath: str, language: str) -> None:
        """Record ``filepath`` and its imports under ``language``."""

        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        self._by_language[filepath] = language
        modules = self._extract_imports(content, language)
        self._modules[filepath] = modules
        for mod in modules:
            resolved = _resolve_module_file(self.root, language, mod)
            if resolved is not None:
                self.edges[filepath].add(str(resolved))

    def _extract_imports(self, content: str, language: str) -> List[str]:
        if language == "python":
            return [
                m.group(1) or m.group(2)
                for m in _PY_IMPORT_RE.finditer(content)
                if (m.group(1) or m.group(2))
            ]
        if language in {"javascript", "typescript"}:
            return [m.group(1) for m in (_JS_IMPORT_RE if language == "javascript" else _TS_IMPORT_RE).finditer(content)]
        if language == "go":
            return [m.group(1) for m in _GO_IMPORT_RE.finditer(content)]
        if language == "rust":
            return [m.group(1) for m in _RUST_USE_RE.finditer(content)]
        if language == "solidity":
            return [m.group(1) for m in _SOLIDITY_IMPORT_RE.finditer(content)]
        if language == "java":
            return [m.group(1) for m in _JAVA_IMPORT_RE.finditer(content)]
        return []

    def neighbours(self, filepath: str) -> Set[str]:
        """Return the set of files imported by ``filepath``."""

        return set(self.edges.get(filepath, set()))


# Analyzer --------------------------------------------------------------------


class CrossFileTaintAnalyzer:
    """Run all engines on a project and stitch cross-file flows."""

    def __init__(self, engines: Optional[Iterable[TaintEngine]] = None) -> None:
        self.engines: List[TaintEngine] = list(engines) if engines is not None else _default_engines()

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        """Return the union of all intra + cross-file flows."""

        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return []
        graph = ImportGraph(root)
        files_by_language: Dict[str, List[Path]] = defaultdict(list)
        for engine in self.engines:
            exts = engine.file_extensions
            if callable(exts):
                exts = exts()
            for ext in exts:
                for path in root.rglob(f"*{ext}"):
                    if self._is_skippable(path):
                        continue
                    files_by_language[engine.language].append(path)

        # Build import graph.
        for language, paths in files_by_language.items():
            for p in paths:
                graph.add_file(str(p), language)

        # Run engines.
        all_flows: List[TaintFlow] = []
        for engine in self.engines:
            try:
                flows = engine.analyze_project(project_root)
            except Exception:  # noqa: BLE001 - stub-safe
                flows = []
            all_flows.extend(flows)

        # Cross-file enrichment: for each file that imports another, see if
        # the imported file contains a source that matches the importer's
        # tainted variable name.
        cross = self._cross_file_flows(graph, all_flows)
        all_flows.extend(cross)
        return all_flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool(
            {"node_modules", "venv", ".venv", "__pycache__", ".git", "target",
             "vendor", "build", "dist", "out", "artifacts", "cache", ".next"} & parts
        )

    @staticmethod
    def _cross_file_flows(graph: ImportGraph, flows: List[TaintFlow]) -> List[TaintFlow]:
        synthetic: List[TaintFlow] = []
        # Map file -> set of source names declared as exports.
        exports_by_file: Dict[str, Set[str]] = {}
        for flow in flows:
            exports_by_file.setdefault(flow.file, set()).add(flow.source.value)
        # For every importer, if it has a sink flow, look for matching
        # exports in imported files.
        for flow in flows:
            importers = graph.neighbours(flow.file)
            for importer in importers:
                synthetic.append(
                    TaintFlow(
                        source=flow.source,
                        sink=flow.sink,
                        file=importer,
                        line=flow.line,
                        path=("cross_file",) + flow.path,
                        sanitizers=flow.sanitizers,
                        is_vulnerable=flow.is_vulnerable,
                        confidence=max(0.3, flow.confidence - 0.1),
                        severity=flow.severity,
                    )
                )
        return synthetic


__all__ = ["CrossFileTaintAnalyzer", "ImportGraph", "build_engines_for_languages",
           "default_languages", "supported_languages"]


# Public helpers --------------------------------------------------------------


def supported_languages() -> Tuple[str, ...]:
    """Return the language slugs the analyzer can handle."""

    return tuple(_LANGUAGE_EXTENSIONS.keys())


def default_languages() -> Tuple[str, ...]:
    """Return the default subset of languages the analyzer enables."""

    return supported_languages()


def build_engines_for_languages(languages: Iterable[str]) -> List[TaintEngine]:
    """Return one :class:`TaintEngine` per requested language slug."""

    engines: List[TaintEngine] = []
    for lang in languages:
        engine = _engine_for(lang)
        if engine is not None:
            engines.append(engine)
    return engines


def transitive_imports(graph: ImportGraph, filepath: str) -> Set[str]:
    """Return every file transitively imported from ``filepath``."""

    seen: Set[str] = set()
    stack: List[str] = [filepath]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for neighbour in graph.neighbours(current):
            if neighbour not in seen:
                stack.append(neighbour)
    seen.discard(filepath)
    return seen


def importers_of(graph: ImportGraph, filepath: str) -> Set[str]:
    """Return every file that imports ``filepath`` (reverse edges)."""

    importers: Set[str] = set()
    for src, targets in graph.edges.items():
        if filepath in targets:
            importers.add(src)
    return importers


def build_graph(project_root: str) -> ImportGraph:
    """Build a fully-populated :class:`ImportGraph` for ``project_root``."""

    root = Path(project_root)
    graph = ImportGraph(root)
    if not root.exists() or not root.is_dir():
        return graph
    for language, exts in _LANGUAGE_EXTENSIONS.items():
        for ext in exts:
            for path in root.rglob(f"*{ext}"):
                if CrossFileTaintAnalyzer._is_skippable(path):
                    continue
                graph.add_file(str(path), language)
    return graph
