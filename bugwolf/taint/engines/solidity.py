"""Solidity taint engine — stdlib regex heuristic for ``.sol`` source files.

Focuses on the canonical high-impact sinks for smart contracts:

  * ``address payable`` transfers invoked on user-controlled inputs
  * ``call{value:}`` raw invocations
  * ``selfdestruct`` / ``delegatecall`` / ``assembly`` low-level ops
  * ``require`` / ``assert`` weak authentication (informational)

Schema: ``bugwolf-taint-v1``
"""

## Source: Solidity taint engine (Phase 3.2 — heuristic)
## License: bugwolf-MIT

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bugwolf.taint import SCHEMA, TaintEngine, TaintFlow, TaintSink, TaintSource
from bugwolf.taint.sanitizer_catalog import SANITIZERS


SCHEMA = "bugwolf-taint-v1"


SOLIDITY_SOURCE_PATTERNS: Dict[TaintSource, str] = {
    TaintSource.QUERY_PARAMS: r"function\s+\w+\([^)]*\)\s*(?:public|external)[^;]*\{|msg\.sender|msg\.value|msg\.data",
    TaintSource.REQUEST_BODY: r"abi\.decode\(|calldataload\(",
    TaintSource.ENV_VAR: r"block\.timestamp|block\.number|tx\.origin",
    TaintSource.ARGV: r"constructor\s*\([^)]*\)|function\s+\w+\([^)]*\)\s*(?:public|external)",
}

SOLIDITY_SINK_PATTERNS: Dict[TaintSink, str] = {
    TaintSink.SHELL_COMMAND: r"selfdestruct\(|suicide\(|delegatecall\(|callcode\(",
    TaintSink.EVAL: r"assembly\s*\{|inline\s+assembly",
    TaintSink.HTML_RETURN: r"emit\s+\w+\(.*\);|\.transfer\(|\.send\(",
    TaintSink.NETWORK_REQUEST: r"address\(.*\)\.call\{value:|\.call\(|\.delegatecall\(",
    TaintSink.FILE_OPEN: r"new\s+\w+Contract\(|create\(|create2\(",
}


class SolidityTaintEngine(TaintEngine):
    """Heuristic regex taint engine for Solidity."""

    language = "solidity"
    file_extensions = (".sol",)

    def __init__(self, propagation_depth: int = 10) -> None:
        self.propagation_depth = propagation_depth

    def analyze_file(self, filepath: str) -> List[TaintFlow]:
        source = self._safe_read(filepath)
        if not source:
            return []
        lines = source.splitlines()
        tainted: Dict[str, Tuple[TaintSource, int]] = {}
        sink_calls: List[Tuple[int, TaintSink, str]] = []
        sanitizer_calls: List[str] = []
        var_decl_re = re.compile(
            r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping\([^)]+\))\s+(?:public\s+|private\s+|internal\s+)?([A-Za-z_][\w]*)\s*(?:=\s*([^;]+))?"
        )
        for_decl_re = re.compile(r"\bfor\s*\([^;]+;\s*([^;]+);\s*[^)]+\)")

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for sname, pat in SANITIZERS.items():
                if re.search(pat, stripped):
                    sanitizer_calls.append(sname)
            for src, pat in SOLIDITY_SOURCE_PATTERNS.items():
                if re.search(pat, stripped):
                    m = var_decl_re.search(stripped)
                    if m and m.group(1):
                        tainted[m.group(1)] = (src, idx)
                    else:
                        tainted[f"_inline_{idx}"] = (src, idx)
            # Propagation via memory / storage local.
            m = var_decl_re.search(stripped)
            if m:
                var_name, rhs = m.group(1), m.group(2) or ""
                for tname in list(tainted):
                    if tname in rhs and tname != var_name:
                        tainted[var_name] = tainted[tname]
                        break
            for sink, pat in SOLIDITY_SINK_PATTERNS.items():
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
                    confidence=0.5,
                    severity=self._severity_for(sink),
                )
            )
        return flows

    def analyze_project(self, project_root: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        root = Path(project_root)
        if not root.exists() or not root.is_dir():
            return flows
        for path in root.rglob("*.sol"):
            if self._is_skippable(path):
                continue
            flows.extend(self.analyze_file(str(path)))
        return flows

    @staticmethod
    def _is_skippable(path: Path) -> bool:
        parts = set(path.parts)
        return bool({"node_modules", "artifacts", "cache", ".git"} & parts)

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
        if sink in {
            TaintSink.SHELL_COMMAND,
            TaintSink.EVAL,
            TaintSink.NETWORK_REQUEST,
        }:
            return "critical"
        return "high"


__all__ = [
    "SolidityTaintEngine",
    "SOLIDITY_SOURCE_PATTERNS",
    "SOLIDITY_SINK_PATTERNS",
]
