## Source: BugWolf Phase 3.5 (in-house) — H100 chain YAML bundle
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.h100 — 12 H100 chain YAML specs.

The bundle is shipped as a flat directory of YAML files with a minimal
parser in :func:`load_all`. Each YAML conforms to the
``bugwolf-chain-h100-v1`` schema:

    schema: bugwolf-chain-h100-v1
    id: <chain_id>
    title: <human title>
    bounty: <"$25K H100" etc>
    prerequisites: [{id: ...}]
    steps:
      - order: 1
        description: ...
        protocol: http
        technique: ...
        evidence: {...}
    final_severity: critical|high|medium|low
    references: [...]

The module is STUB-SAFE — a malformed YAML yields an empty chain
record rather than raising.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCHEMA = "bugwolf-chain-v1"
H100_SCHEMA = "bugwolf-chain-h100-v1"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class H100Prerequisite:
    id: str
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": str(self.id), "description": str(self.description)}


@dataclass(frozen=True)
class H100Step:
    order: int
    description: str
    protocol: str
    technique: str = ""
    preconditions: Tuple[str, ...] = field(default_factory=tuple)
    evidence: Dict[str, Any] = field(default_factory=dict)
    destructive: bool = False
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "order": int(self.order),
            "description": str(self.description),
            "protocol": str(self.protocol),
            "technique": str(self.technique),
            "preconditions": list(self.preconditions),
            "evidence": dict(self.evidence),
            "destructive": bool(self.destructive),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class H100Chain:
    schema: str
    id: str
    title: str
    bounty: str
    prerequisites: Tuple[H100Prerequisite, ...]
    steps: Tuple[H100Step, ...]
    final_severity: str
    references: Tuple[str, ...] = field(default_factory=tuple)
    rationale: str = ""
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": str(self.schema),
            "id": str(self.id),
            "title": str(self.title),
            "bounty": str(self.bounty),
            "prerequisites": [p.to_dict() for p in self.prerequisites],
            "steps": [s.to_dict() for s in self.steps],
            "final_severity": str(self.final_severity),
            "references": list(self.references),
            "rationale": str(self.rationale),
            "source_path": str(self.source_path),
        }


# ---------------------------------------------------------------------------
# Tiny YAML parser (stdlib-only)
# ---------------------------------------------------------------------------

_INDENT_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<body>.*)$")


def _tokenize(text: str) -> List[Tuple[int, str]]:
    """Tokenize the line-oriented subset of YAML we emit.

    Returns ``(indent, line_body)`` pairs. Empty / comment-only lines
    are dropped. Strings are NOT unquoted — :func:`_coerce` does that.
    """
    tokens: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _INDENT_RE.match(raw)
        if not m:
            continue
        indent = len(m.group("indent").expandtabs(2))
        body = m.group("body").rstrip()
        tokens.append((indent, body))
    return tokens


def _coerce(value: str) -> Any:
    """Coerce a YAML scalar to a Python value (str/int/float/bool/null)."""
    s = value.strip()
    if not s:
        return ""
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1]
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1]
    if s == "null" or s == "~":
        return None
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_coerce(part) for part in _split_flow(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        if not inner:
            return {}
        out: Dict[str, Any] = {}
        for part in _split_flow(inner):
            if ":" not in part:
                continue
            k, _, v = part.partition(":")
            out[k.strip()] = _coerce(v.strip())
        return out
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return s


def _split_flow(s: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    current = ""
    for ch in s:
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    if current:
        parts.append(current)
    return parts


def _parse_yaml_subset(text: str) -> Any:
    """Parse the YAML subset we emit (maps, lists, scalars, flow style)."""
    tokens = _tokenize(text)
    pos = [0]

    def parse(indent: int) -> Any:
        if pos[0] >= len(tokens):
            return None
        cur_indent, body = tokens[pos[0]]
        if cur_indent < indent:
            return None
        if body.startswith("- "):
            return parse_list(indent)
        if body.startswith("-:"):
            # bare "-: value" — treat as list with single empty-key map
            pos[0] += 1
            return [{**{}}]
        return parse_map(indent)

    def parse_list(indent: int) -> List[Any]:
        out_list: List[Any] = []
        while pos[0] < len(tokens):
            cur_indent, body = tokens[pos[0]]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                # skip unexpected indent (defensive)
                pos[0] += 1
                continue
            if not body.startswith("- "):
                break
            rest = body[2:]
            pos[0] += 1
            if ":" in rest and not rest.startswith('"') and not rest.startswith("'"):
                key, _, value = rest.partition(":")
                value = value.strip()
                # Inline map start: build a single-item map then merge
                if value == "":
                    sub = parse_map(indent + 2)
                    out_list.append({key.strip(): sub})
                else:
                    out_list.append({key.strip(): _coerce(value)})
            else:
                # list item scalar
                if pos[0] < len(tokens) and tokens[pos[0]][0] > indent:
                    sub = parse(tokens[pos[0]][0])
                    if isinstance(sub, dict):
                        out_list.append({rest.strip(): sub})
                    else:
                        out_list.append(sub)
                else:
                    out_list.append(_coerce(rest))
        return out_list

    def parse_map(indent: int) -> Dict[str, Any]:
        out_map: Dict[str, Any] = {}
        while pos[0] < len(tokens):
            cur_indent, body = tokens[pos[0]]
            if cur_indent < indent:
                break
            if cur_indent > indent:
                pos[0] += 1
                continue
            if body.startswith("- "):
                break
            if ":" not in body:
                pos[0] += 1
                continue
            key, _, value = body.partition(":")
            key = key.strip()
            value = value.strip()
            if value == "":
                pos[0] += 1
                # Nested structure at greater indent
                if pos[0] < len(tokens) and tokens[pos[0]][0] > indent:
                    out_map[key] = parse(tokens[pos[0]][0])
                else:
                    out_map[key] = None
            else:
                pos[0] += 1
                out_map[key] = _coerce(value)
        return out_map

    return parse(0)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent


def _build_chain(parsed: Dict[str, Any], source: Path) -> H100Chain:
    """Turn a parsed mapping into an :class:`H100Chain`."""
    if not isinstance(parsed, dict):
        return H100Chain(
            schema=str(parsed.get("schema", H100_SCHEMA)) if isinstance(parsed, dict) else H100_SCHEMA,
            id="", title="", bounty="",
            prerequisites=(), steps=(),
            final_severity="low",
            source_path=str(source),
        )
    prereqs: List[H100Prerequisite] = []
    for entry in parsed.get("prerequisites", []) or []:
        if isinstance(entry, dict):
            prereqs.append(H100Prerequisite(
                id=str(entry.get("id", "")),
                description=str(entry.get("description", "")),
            ))
    steps: List[H100Step] = []
    for entry in parsed.get("steps", []) or []:
        if isinstance(entry, dict):
            steps.append(H100Step(
                order=int(entry.get("order", 0) or 0),
                description=str(entry.get("description", "")),
                protocol=str(entry.get("protocol", "")),
                technique=str(entry.get("technique", "")),
                preconditions=tuple(str(x) for x in (entry.get("preconditions") or ())),
                evidence=dict(entry.get("evidence") or {}) if isinstance(entry.get("evidence"), dict) else {},
                destructive=bool(entry.get("destructive", False)),
                references=tuple(str(x) for x in (entry.get("references") or ())),
            ))
    return H100Chain(
        schema=str(parsed.get("schema", H100_SCHEMA)),
        id=str(parsed.get("id", source.stem)),
        title=str(parsed.get("title", "")),
        bounty=str(parsed.get("bounty", "")),
        prerequisites=tuple(prereqs),
        steps=tuple(steps),
        final_severity=str(parsed.get("final_severity", "high")),
        references=tuple(str(x) for x in (parsed.get("references") or ())),
        rationale=str(parsed.get("rationale", "")),
        source_path=str(source),
    )


def _load_one(path: Path) -> H100Chain:
    """Load a single YAML file. STUB-SAFE."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return H100Chain(
            schema=H100_SCHEMA,
            id=path.stem, title="", bounty="",
            prerequisites=(), steps=(), final_severity="low",
            source_path=str(path),
        )
    try:
        parsed = _parse_yaml_subset(text)
    except Exception:  # noqa: BLE001
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    return _build_chain(parsed, path)


def list_h100_yamls() -> Tuple[Path, ...]:
    """Return the sorted list of YAML files shipped with this package."""
    if not _HERE.exists():
        return tuple()
    return tuple(sorted(p for p in _HERE.glob("*.yaml")))


def load_all() -> Tuple[H100Chain, ...]:
    """Load every H100 chain YAML in the package."""
    out: List[H100Chain] = []
    for p in list_h100_yamls():
        out.append(_load_one(p))
    return tuple(out)


def load_by_id(chain_id: str) -> Optional[H100Chain]:
    """Return the chain whose ``id`` matches ``chain_id`` (or ``None``)."""
    for c in load_all():
        if c.id == chain_id or c.id.replace("-", "_") == chain_id:
            return c
    return None


def get_chain_count() -> int:
    """Return the number of H100 YAMLs shipped in this directory."""
    return len(list_h100_yamls())


__all__ = [
    "SCHEMA",
    "H100_SCHEMA",
    "H100Chain",
    "H100Step",
    "H100Prerequisite",
    "list_h100_yamls",
    "load_all",
    "load_by_id",
    "get_chain_count",
]
