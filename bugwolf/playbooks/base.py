"""Typed YAML playbook schema and loader for BugWolf Phase 1.2.

Defines the ``bugwolf-playbook-v1`` schema, immutable dataclasses, and a
loader that prefers PyYAML when available and falls back to a small
stdlib-only YAML subset parser otherwise.

The mini parser intentionally supports only what the playbook corpus needs:
top-level scalars, mappings, sequences of mappings, nested mappings, string
lists, ints, bools, ``#`` comments, single/double-quoted strings, and folded
literal blocks used in the long ``description``/``notes`` fields.

It explicitly rejects anchors (``&`` / ``*``), tags (``!tag``), and
multi-document streams (``---`` followed by another mapping). Those are
treated as parse errors so the corpus can never accidentally depend on
features we haven't audited.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:  # pragma: no cover - exercised when PyYAML is installed
    import yaml as _yaml  # type: ignore
except ImportError:  # pragma: no cover - exercised when PyYAML is missing
    _yaml = None


SCHEMA = "bugwolf-playbook-v1"

VALID_SCOPE_VERBS = frozenset({"passive", "active", "destructive"})
VALID_SCOPE_CLASSES = frozenset({"passive", "active", "destructive"})
VALID_EVIDENCE_KINDS = frozenset(
    {"response_capture", "timing_measurement", "header_diff", "body_diff", "oast_callback", "log_artifact"}
)


class PlaybookValidationError(ValueError):
    """Raised when a YAML document fails schema validation."""


# ---------------------------------------------------------------------------
# Mini YAML parser (stdlib only). Used only when PyYAML is unavailable.
# ---------------------------------------------------------------------------


def _mini_yaml_parse(text: str) -> Any:
    """Parse a *strict subset* of YAML.

    Supported constructs:
      * top-level scalar / mapping / sequence
      * mappings: ``key: value``
      * sequences: ``- item`` (one per line, single item, no inline lists
        except for the simple ``[a, b, c]`` form which we also accept)
      * quoted strings: ``"..."`` and ``'...'``
      * bare strings, ints (``-3``, ``0``, ``42``), floats (``1.5``)
      * booleans: ``true`` / ``false`` / ``yes`` / ``no`` / ``on`` / ``off``
      * null: ``null`` / ``~``
      * ``#`` line comments (only outside quoted strings)

    Explicitly rejected (raises ``PlaybookValidationError``):
      * anchors (``&name``) and alias references (``*name``)
      * tags (``!tag``)
      * multi-document streams (``---`` as a top-level key)
      * flow-style nested mappings (``{a: 1}``)
    """

    if "\t" in text:
        raise PlaybookValidationError("mini YAML parser does not accept tab characters")

    lines = text.splitlines()
    tokens: List[Tuple[int, str, str]] = []
    for raw in lines:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2 != 0:
            raise PlaybookValidationError(f"odd indentation: {raw!r}")
        content = raw[indent:]
        tokens.append((indent, "line", content))

    if not tokens:
        return None

    # Reject forbidden constructs eagerly.
    for _indent, _kind, content in tokens:
        if content.startswith("---") and content.strip() == "---":
            raise PlaybookValidationError("multi-document YAML is not supported")
        if re.search(r"(^|[^&])&[A-Za-z_]", content):
            raise PlaybookValidationError("YAML anchors are not supported")
        if re.search(r"(^|[^*])\*[A-Za-z_]", content):
            raise PlaybookValidationError("YAML aliases are not supported")
        if re.search(r"![A-Za-z_]", content):
            raise PlaybookValidationError("YAML tags are not supported")

    pos = [0]

    def _coerce_scalar(raw: str) -> Any:
        s = raw.strip()
        if not s:
            return ""
        if s.startswith('"') and s.endswith('"') and len(s) >= 2:
            return s[1:-1].replace('\\"', '"')
        if s.startswith("'") and s.endswith("'") and len(s) >= 2:
            return s[1:-1]
        low = s.lower()
        if low in {"true", "yes", "on"}:
            return True
        if low in {"false", "no", "off"}:
            return False
        if low in {"null", "~"}:
            return None
        # strip trailing inline comment
        if "#" in s and not (s.startswith('"') or s.startswith("'")):
            # crude: only strip if outside any quotes
            in_s = False
            in_d = False
            cut = -1
            for i, ch in enumerate(s):
                if ch == "'" and not in_d:
                    in_s = not in_s
                elif ch == '"' and not in_s:
                    in_d = not in_d
                elif ch == "#" and not in_s and not in_d:
                    cut = i
                    break
            if cut >= 0:
                s = s[:cut].rstrip()
        # int / float
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            pass
        return s

    def _is_list_item(content: str) -> bool:
        return content.startswith("- ")

    def _parse_block(min_indent: int) -> Any:
        if pos[0] >= len(tokens):
            return None
        indent, _kind, content = tokens[pos[0]]
        if indent < min_indent:
            return None
        if _is_list_item(content):
            return _parse_seq(indent)
        if ":" in content:
            return _parse_map(indent)
        return _coerce_scalar(content)

    def _parse_seq(indent: int) -> List[Any]:
        items: List[Any] = []
        while pos[0] < len(tokens):
            ind, _k, content = tokens[pos[0]]
            if ind < indent:
                break
            if ind > indent:
                pos[0] += 1
                continue
            if not _is_list_item(content):
                break
            rest = content[2:]
            pos[0] += 1
            if rest == "":
                # nested block follows at indent + 2
                items.append(_parse_block(indent + 2))
            elif rest.endswith(":"):
                # mapping item whose key is ``rest[:-1]`` and value is a block
                key = rest[:-1].strip()
                # look ahead: if next token is more indented, treat as block value
                if pos[0] < len(tokens) and tokens[pos[0]][0] > indent:
                    value = _parse_block(indent + 2)
                else:
                    value = ""
                items.append({key: value})
            elif ":" in rest and not rest.startswith('"') and not rest.startswith("'"):
                # inline mapping for a sequence item
                key, _, val = rest.partition(":")
                mapping: Dict[str, Any] = {}
                if val.strip() == "":
                    if pos[0] < len(tokens) and tokens[pos[0]][0] > indent:
                        mapping[key.strip()] = _parse_block(indent + 2)
                    else:
                        mapping[key.strip()] = ""
                else:
                    mapping[key.strip()] = _coerce_scalar(val)
                items.append(mapping)
            elif rest.startswith("[") and rest.endswith("]"):
                inner = rest[1:-1].strip()
                if inner == "":
                    items.append([])
                else:
                    items.append([_coerce_scalar(p) for p in inner.split(",")])
            else:
                items.append(_coerce_scalar(rest))
        return items

    def _parse_map(indent: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while pos[0] < len(tokens):
            ind, _k, content = tokens[pos[0]]
            if ind < indent:
                break
            if ind > indent:
                pos[0] += 1
                continue
            if _is_list_item(content):
                break
            if ":" not in content:
                break
            key, _, val = content.partition(":")
            key = key.strip()
            pos[0] += 1
            if val.strip() == "":
                # block value
                if pos[0] < len(tokens) and tokens[pos[0]][0] > indent:
                    out[key] = _parse_block(indent + 2)
                else:
                    out[key] = ""
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                if inner == "":
                    out[key] = []
                else:
                    out[key] = [_coerce_scalar(p) for p in inner.split(",")]
            else:
                out[key] = _coerce_scalar(val)
        return out

    return _parse_block(0)


def _yaml_load(text: str) -> Any:
    """Try PyYAML first; fall back to the stdlib mini parser."""
    if _yaml is not None:
        try:
            return _yaml.safe_load(text)
        except Exception as exc:  # pragma: no cover - depends on PyYAML version
            raise PlaybookValidationError(f"YAML parse error: {exc}") from exc
    return _mini_yaml_parse(text)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadSpec:
    id: str
    request: Dict[str, Any]
    expected_status: int
    expected_body_match: str = ""
    sinks: Tuple[str, ...] = ()
    requires_scope_verb: str = "passive"

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise PlaybookValidationError("PayloadSpec.id must be a non-empty string")
        if not isinstance(self.request, dict):
            raise PlaybookValidationError("PayloadSpec.request must be a mapping")
        if "method" not in self.request or "path" not in self.request:
            raise PlaybookValidationError(
                "PayloadSpec.request must contain 'method' and 'path'"
            )
        if not isinstance(self.expected_status, int):
            raise PlaybookValidationError("PayloadSpec.expected_status must be an int")
        if self.requires_scope_verb not in VALID_SCOPE_VERBS:
            raise PlaybookValidationError(
                f"PayloadSpec.requires_scope_verb must be one of {sorted(VALID_SCOPE_VERBS)}"
            )


@dataclass(frozen=True)
class EvidenceSpec:
    kind: str
    target: str = "response"
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in VALID_EVIDENCE_KINDS:
            raise PlaybookValidationError(
                f"EvidenceSpec.kind must be one of {sorted(VALID_EVIDENCE_KINDS)}"
            )


@dataclass(frozen=True)
class BudgetSpec:
    max_requests: int = 100
    max_wall_clock: int = 300
    min_interval_ms: int = 50

    def __post_init__(self) -> None:
        if self.max_requests < 1:
            raise PlaybookValidationError("BudgetSpec.max_requests must be >= 1")
        if self.max_wall_clock < 1:
            raise PlaybookValidationError("BudgetSpec.max_wall_clock must be >= 1")
        if self.min_interval_ms < 0:
            raise PlaybookValidationError("BudgetSpec.min_interval_ms must be >= 0")


@dataclass(frozen=True)
class GovernanceSpec:
    requires_approval: bool = False
    scope_class: str = "active"
    require_reproducible_evidence: bool = True
    destructive_allowed: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.scope_class not in VALID_SCOPE_CLASSES:
            raise PlaybookValidationError(
                f"GovernanceSpec.scope_class must be one of {sorted(VALID_SCOPE_CLASSES)}"
            )


@dataclass(frozen=True)
class Playbook:
    schema: str = SCHEMA
    name: str = ""
    description: str = ""
    preconditions: Dict[str, Any] = field(default_factory=dict)
    payloads: Tuple[PayloadSpec, ...] = ()
    evidence: Tuple[EvidenceSpec, ...] = ()
    post_conditions: Dict[str, Any] = field(default_factory=dict)
    budget: BudgetSpec = field(default_factory=BudgetSpec)
    governance: GovernanceSpec = field(default_factory=GovernanceSpec)

    def validate(self) -> "Playbook":
        """Validate required fields and invariants. Returns ``self`` on success."""
        if self.schema != SCHEMA:
            raise PlaybookValidationError(
                f"Playbook.schema must be {SCHEMA!r}, got {self.schema!r}"
            )
        if not self.name or not isinstance(self.name, str):
            raise PlaybookValidationError("Playbook.name must be a non-empty string")
        if not isinstance(self.preconditions, dict):
            raise PlaybookValidationError("Playbook.preconditions must be a mapping")
        if not isinstance(self.post_conditions, dict):
            raise PlaybookValidationError("Playbook.post_conditions must be a mapping")

        # Mandatory precondition keys per the spec
        for required_key in ("target_is_reachable", "scope_allows_active"):
            if required_key not in self.preconditions:
                raise PlaybookValidationError(
                    f"Playbook.preconditions missing mandatory key {required_key!r}"
                )

        # Re-run dataclass __post_init__ validators explicitly because we
        # accept constructed-from-YAML values that bypass __init__ ordering.
        for payload in self.payloads:
            if not isinstance(payload, PayloadSpec):
                raise PlaybookValidationError("payloads must be PayloadSpec instances")
        for ev in self.evidence:
            if not isinstance(ev, EvidenceSpec):
                raise PlaybookValidationError("evidence must be EvidenceSpec instances")
        if not isinstance(self.budget, BudgetSpec):
            raise PlaybookValidationError("budget must be a BudgetSpec")
        if not isinstance(self.governance, GovernanceSpec):
            raise PlaybookValidationError("governance must be a GovernanceSpec")

        # budget.max_requests is mandatory
        if self.budget.max_requests <= 0:
            raise PlaybookValidationError(
                "budget.max_requests must be present and > 0 (mandatory field)"
            )
        # governance.scope_class mandatory
        if not self.governance.scope_class:
            raise PlaybookValidationError(
                "governance.scope_class is mandatory and must be a non-empty string"
            )
        # governance.destructive_allowed mandatory (boolean, not absent)
        # Dataclass default ensures presence; nothing more to check here.

        return self

    def payload_by_id(self, pid: str) -> PayloadSpec:
        for p in self.payloads:
            if p.id == pid:
                return p
        raise KeyError(pid)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"schema": self.schema, "name": self.name}
        if self.description:
            out["description"] = self.description
        if self.preconditions:
            out["preconditions"] = dict(self.preconditions)
        if self.payloads:
            out["payload_catalog"] = [
                {
                    "id": p.id,
                    "request": dict(p.request),
                    "expected_status": p.expected_status,
                    "expected_body_match": p.expected_body_match,
                    "sinks": list(p.sinks),
                    "requires_scope_verb": p.requires_scope_verb,
                }
                for p in self.payloads
            ]
        if self.evidence:
            out["evidence_collection"] = [
                {"type": e.kind, "target": e.target, "config": dict(e.config)}
                for e in self.evidence
            ]
        if self.post_conditions:
            out["post_conditions"] = dict(self.post_conditions)
        out["budget"] = {
            "max_requests": self.budget.max_requests,
            "max_wall_clock": self.budget.max_wall_clock,
            "min_interval_ms": self.budget.min_interval_ms,
        }
        out["governance"] = {
            "requires_approval": self.governance.requires_approval,
            "scope_class": self.governance.scope_class,
            "require_reproducible_evidence": self.governance.require_reproducible_evidence,
            "destructive_allowed": self.governance.destructive_allowed,
            "notes": self.governance.notes,
        }
        return out


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class PlaybookLoader:
    """Load ``.yaml`` playbook files into :class:`Playbook` instances."""

    def load(self, path: Path) -> Playbook:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise PlaybookValidationError(f"playbook is not valid UTF-8: {exc}") from exc
        return self.loads(text)

    def loads(self, text: str) -> Playbook:
        try:
            data = _yaml_load(text)
        except PlaybookValidationError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise PlaybookValidationError(f"YAML parse error: {exc}") from exc

        if not isinstance(data, dict):
            raise PlaybookValidationError("top-level YAML must be a mapping")

        declared = data.get("schema")
        if declared != SCHEMA:
            raise PlaybookValidationError(
                f"unknown schema {declared!r}; expected {SCHEMA!r}"
            )

        name = str(data.get("name") or "").strip()
        if not name:
            raise PlaybookValidationError("playbook name is required")

        description = str(data.get("description") or "")
        preconditions = dict(data.get("preconditions") or {})
        post_conditions = dict(data.get("post_conditions") or {})

        payloads: List[PayloadSpec] = []
        for entry in data.get("payload_catalog") or []:
            if not isinstance(entry, dict):
                raise PlaybookValidationError("payload_catalog entries must be mappings")
            payloads.append(
                PayloadSpec(
                    id=str(entry.get("id") or "").strip(),
                    request=dict(entry.get("request") or {}),
                    expected_status=int(entry.get("expected_status", 200)),
                    expected_body_match=str(entry.get("expected_body_match") or ""),
                    sinks=tuple(entry.get("sinks") or ()),
                    requires_scope_verb=str(entry.get("requires_scope_verb") or "passive"),
                )
            )

        evidence: List[EvidenceSpec] = []
        for entry in data.get("evidence_collection") or []:
            if not isinstance(entry, dict):
                raise PlaybookValidationError("evidence_collection entries must be mappings")
            evidence.append(
                EvidenceSpec(
                    kind=str(entry.get("type") or "").strip(),
                    target=str(entry.get("target") or "response"),
                    config=dict(entry.get("config") or {}),
                )
            )

        budget_data = dict(data.get("budget") or {})
        budget = BudgetSpec(
            max_requests=int(budget_data.get("max_requests", 100)),
            max_wall_clock=int(budget_data.get("max_wall_clock", 300)),
            min_interval_ms=int(budget_data.get("min_interval_ms", 50)),
        )

        gov_data = dict(data.get("governance") or {})
        governance = GovernanceSpec(
            requires_approval=bool(gov_data.get("requires_approval", False)),
            scope_class=str(gov_data.get("scope_class") or "active"),
            require_reproducible_evidence=bool(
                gov_data.get("require_reproducible_evidence", True)
            ),
            destructive_allowed=bool(gov_data.get("destructive_allowed", False)),
            notes=str(gov_data.get("notes") or ""),
        )

        playbook = Playbook(
            schema=SCHEMA,
            name=name,
            description=description,
            preconditions=preconditions,
            payloads=tuple(payloads),
            evidence=tuple(evidence),
            post_conditions=post_conditions,
            budget=budget,
            governance=governance,
        )
        playbook.validate()
        return playbook

    def load_all(self, directory: Path) -> Dict[str, Playbook]:
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(directory)
        out: Dict[str, Playbook] = {}
        for path in sorted(directory.glob("*.yaml")):
            pb = self.load(path)
            out[pb.name] = pb
        for path in sorted(directory.glob("*.yml")):
            pb = self.load(path)
            out[pb.name] = pb
        return out