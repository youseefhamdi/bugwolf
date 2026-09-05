"""Search index over the methodology corpus.

Walks the pattern YAML directory, parses each file via PyYAML, and exposes
free-text search (``search``), bug-class filtering (``search_by_bug_class``)
and direct lookup (``search_by_id``).

Pure stdlib + PyYAML. No NumPy, no sklearn.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from bugwolf.methodology.vector_index import VectorIndex

log = logging.getLogger(__name__)

PATTERN_SCHEMA = "bugwolf-methodology-pattern-v1"
CHAIN_SCHEMA = "bugwolf-methodology-chain-v1"

_REQUIRED_PATTERN_KEYS = {
    "schema",
    "id",
    "bug_class",
    "category",
    "severity",
    "title",
    "description",
    "detection",
    "remediation",
    "references",
    "bounty_range",
    "h100_proven",
}

_FORBIDDEN_LITERALS = ("file://", "gopher://")


@dataclass(frozen=True)
class PatternRecord:
    """A single bug pattern loaded from a YAML file."""

    pattern_id: str
    bug_class: str
    category: str
    severity: str
    title: str
    description: str
    detection_method: str
    detection_endpoint: str
    detection_signature: str
    remediation: str
    references: tuple
    bounty_range: str
    h100_proven: bool
    source_path: str
    extra: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ChainSpec:
    """A multi-step exploit chain loaded from a YAML file."""

    chain_id: str
    title: str
    bounty: str
    prerequisites: tuple
    steps: tuple
    final_severity: str
    references: tuple
    source_path: str
    extra: dict = field(default_factory=dict)


def _coerce_str(value, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _coerce_tuple(value) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _parse_pattern(raw: dict, source_path: str) -> Optional[PatternRecord]:
    if not isinstance(raw, dict):
        return None
    if raw.get("schema") != PATTERN_SCHEMA:
        return None
    missing = _REQUIRED_PATTERN_KEYS - set(raw.keys())
    if missing:
        log.warning("pattern %s missing keys: %s", source_path, sorted(missing))
        return None
    detection = raw.get("detection") or {}
    if not isinstance(detection, dict):
        log.warning("pattern %s detection not a dict", source_path)
        return None
    extra = {
        k: v
        for k, v in raw.items()
        if k
        not in {
            "schema",
            "id",
            "bug_class",
            "category",
            "severity",
            "title",
            "description",
            "detection",
            "remediation",
            "references",
            "bounty_range",
            "h100_proven",
        }
    }
    return PatternRecord(
        pattern_id=_coerce_str(raw.get("id")),
        bug_class=_coerce_str(raw.get("bug_class")),
        category=_coerce_str(raw.get("category")),
        severity=_coerce_str(raw.get("severity")),
        title=_coerce_str(raw.get("title")),
        description=_coerce_str(raw.get("description")),
        detection_method=_coerce_str(detection.get("method"), "GET"),
        detection_endpoint=_coerce_str(detection.get("endpoint")),
        detection_signature=_coerce_str(detection.get("signature")),
        remediation=_coerce_str(raw.get("remediation")),
        references=_coerce_tuple(raw.get("references")),
        bounty_range=_coerce_str(raw.get("bounty_range")),
        h100_proven=bool(raw.get("h100_proven", False)),
        source_path=source_path,
        extra=extra,
    )


def _parse_chain(raw: dict, source_path: str) -> Optional[ChainSpec]:
    if not isinstance(raw, dict):
        return None
    if raw.get("schema") != CHAIN_SCHEMA:
        return None
    required = {"schema", "id", "title", "bounty", "steps", "final_severity"}
    missing = required - set(raw.keys())
    if missing:
        log.warning("chain %s missing keys: %s", source_path, sorted(missing))
        return None
    extra = {
        k: v
        for k, v in raw.items()
        if k not in {"schema", "id", "title", "bounty", "prerequisites", "steps", "final_severity", "references"}
    }
    prereqs = raw.get("prerequisites") or []
    prereq_ids = tuple(_coerce_str(p.get("id")) for p in prereqs if isinstance(p, dict))
    steps_raw = raw.get("steps") or []
    steps = tuple(
        (
            int(s.get("order", idx + 1)),
            _coerce_str(s.get("description")),
        )
        for idx, s in enumerate(steps_raw)
        if isinstance(s, dict)
    )
    return ChainSpec(
        chain_id=_coerce_str(raw.get("id")),
        title=_coerce_str(raw.get("title")),
        bounty=_coerce_str(raw.get("bounty")),
        prerequisites=prereq_ids,
        steps=steps,
        final_severity=_coerce_str(raw.get("final_severity")),
        references=_coerce_tuple(raw.get("references")),
        source_path=source_path,
        extra=extra,
    )


class MethodologySearch:
    """TF-IDF index over bug patterns + chain catalog.

    Use:
        search = MethodologySearch(root_path)
        search.index()
        results = search.search("ssrf imds aws", top_k=5)
    """

    def __init__(self, root_path: Path | str) -> None:
        self.root_path = Path(root_path)
        self._patterns: List[PatternRecord] = []
        self._chains: List[ChainSpec] = []
        self._pattern_by_id: Dict[str, PatternRecord] = {}
        self._chain_by_id: Dict[str, ChainSpec] = {}
        self._index: VectorIndex = VectorIndex()
        self._indexed: bool = False

    @property
    def patterns(self) -> List[PatternRecord]:
        return list(self._patterns)

    @property
    def chains(self) -> List[ChainSpec]:
        return list(self._chains)

    def index(self) -> None:
        """Walk the root, parse YAML, build the TF-IDF index."""
        self._patterns = []
        self._chains = []
        self._pattern_by_id = {}
        self._chain_by_id = {}
        self._index = VectorIndex()

        patterns_dir = self.root_path / "patterns"
        if patterns_dir.is_dir():
            for yaml_path in sorted(patterns_dir.rglob("*.yaml")):
                self._load_pattern_file(yaml_path)
            for yml_path in sorted(patterns_dir.rglob("*.yml")):
                self._load_pattern_file(yml_path)

        chains_dir = self.root_path / "chains"
        if chains_dir.is_dir():
            for yaml_path in sorted(chains_dir.rglob("*.yaml")):
                self._load_chain_file(yaml_path)
            for yml_path in sorted(chains_dir.rglob("*.yml")):
                self._load_chain_file(yml_path)

        self._indexed = True

    def _load_pattern_file(self, yaml_path: Path) -> None:
        try:
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            log.warning("YAML parse error in %s: %s", yaml_path, exc)
            return
        except OSError as exc:
            log.warning("read error %s: %s", yaml_path, exc)
            return
        if not isinstance(raw, list):
            raw = [raw]
        for entry in raw:
            rec = _parse_pattern(entry, str(yaml_path))
            if rec is None:
                continue
            self._patterns.append(rec)
            self._pattern_by_id[rec.pattern_id] = rec
            blob = " ".join(
                [
                    rec.title,
                    rec.description,
                    rec.detection_signature,
                    rec.bug_class,
                    rec.category,
                    rec.remediation,
                ]
            )
            self._index.add(rec.pattern_id, blob)

    def _load_chain_file(self, yaml_path: Path) -> None:
        try:
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            log.warning("YAML parse error in %s: %s", yaml_path, exc)
            return
        except OSError as exc:
            log.warning("read error %s: %s", yaml_path, exc)
            return
        if not isinstance(raw, list):
            raw = [raw]
        for entry in raw:
            rec = _parse_chain(entry, str(yaml_path))
            if rec is None:
                continue
            self._chains.append(rec)
            self._chain_by_id[rec.chain_id] = rec

    def search(self, query: str, *, top_k: int = 5) -> List[PatternRecord]:
        """Free-text search; returns ranked PatternRecord list."""
        if not self._indexed:
            self.index()
        hits = self._index.query(query, top_k=top_k)
        out: List[PatternRecord] = []
        for pid, _score in hits:
            rec = self._pattern_by_id.get(pid)
            if rec is not None:
                out.append(rec)
        return out

    def search_by_bug_class(self, bug_class: str) -> List[PatternRecord]:
        """Return all patterns matching the bug_class field exactly."""
        if not self._indexed:
            self.index()
        target = bug_class.strip().lower()
        return [p for p in self._patterns if p.bug_class.lower() == target]

    def search_by_id(self, pattern_id: str) -> Optional[PatternRecord]:
        """Direct lookup by pattern id."""
        if not self._indexed:
            self.index()
        return self._pattern_by_id.get(pattern_id)

    def get_chain(self, chain_id: str) -> Optional[ChainSpec]:
        if not self._indexed:
            self.index()
        return self._chain_by_id.get(chain_id)

    def has_forbidden_literal(self) -> List[PatternRecord]:
        """Return patterns whose detection.signature contains forbidden literals."""
        offenders: List[PatternRecord] = []
        for p in self._patterns:
            sig = p.detection_signature.lower()
            if any(lit in sig for lit in _FORBIDDEN_LITERALS):
                offenders.append(p)
        return offenders


SearchIndex = MethodologySearch


def contains_forbidden_literal(text: str) -> bool:
    """True if the given text contains a forbidden literal payload."""
    lowered = (text or "").lower()
    return any(lit in lowered for lit in _FORBIDDEN_LITERALS)


def compile_signature(signature: str):
    """Compile a pattern signature; returns ``None`` on bad regex."""
    try:
        return re.compile(signature)
    except re.error:
        return None