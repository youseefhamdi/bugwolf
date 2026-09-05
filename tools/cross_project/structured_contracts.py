#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter structured_contracts.py:1-820 (1.5.k)
## Source: BugWolf runtime/contracts.py (Phase 0 in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

STRUCTURED_CONTRACTS + redact_argv + exit-code semantics.

  * :class:`Contract`              — input/output schema with validator
  * :func:`redact_argv`            — strip secrets from an argv list
  * :class:`ExitCode`              — canonical exit-code semantics
  * :func:`validate_against`       — generic value-vs-schema validator

All three pieces are independent but commonly bundled: a contract
declares what a tool accepts and returns; argv is the actual invocation
shape; exit codes are how the tool signals success / partial / failure /
governance-block.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Mapping, Sequence


SCHEMA = "bugwolf-structured-contracts/v1"


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

class ExitCode(IntEnum):
    """Canonical exit-code semantics used across every bugwolf tool.

    The orchestrator inspects the exit code to decide whether to retry,
    quarantine, or report the result upstream.  The four values map to
    the natural language:

      SUCCESS      — 0  — the tool ran end-to-end, no findings, no faults
      PARTIAL      — 1  — the tool ran but produced partial results
                            (some probes failed, others succeeded)
      FAILURE      — 2  — the tool could not complete; results unusable
      GOV_BLOCKED  — 3  — a governance / scope / approval gate refused
                            the request; no attempt was made
    """

    SUCCESS = 0
    PARTIAL = 1
    FAILURE = 2
    GOV_BLOCKED = 3


# ---------------------------------------------------------------------------
# Contract dataclass + validator
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Contract:
    """A typed input/output contract.

    ``schema`` is a flat mapping of field-name -> type-string.  The
    validator currently supports:

      * ``"string"``           — str
      * ``"int"``              — int
      * ``"float"``            — float
      * ``"bool"``             — bool
      * ``"list[str]"``        — list of strings
      * ``"list[int]"``        — list of ints
      * ``"dict"``             — mapping
      * ``"enum:<a|b|c>"``     — string in the enumerated set
      * ``"regex:<pattern>"``  — string matching the regex

    Validation is best-effort: it does NOT recurse into nested dicts.
    """

    name: str
    schema: Mapping[str, str]
    description: str = ""
    required: tuple = ()
    extra_fields_allowed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "schema_fields": dict(self.schema),
            "description": self.description,
            "required": list(self.required),
            "extra_fields_allowed": bool(self.extra_fields_allowed),
        }

    def validate(self, value: Mapping[str, Any]) -> List[str]:
        """Return a list of error strings (empty == valid)."""
        errors: List[str] = []
        if not isinstance(value, Mapping):
            return [f"{self.name}: value is not a mapping"]
        for req in self.required:
            if req not in value:
                errors.append(f"{self.name}: missing required field {req!r}")
        for key, val in value.items():
            spec = self.schema.get(key)
            if spec is None:
                if not self.extra_fields_allowed:
                    errors.append(f"{self.name}: unknown field {key!r}")
                continue
            errors.extend(_check_field(self.name, key, val, spec))
        return errors


def _check_field(contract: str, key: str, value: Any, spec: str) -> List[str]:
    if spec == "string":
        return [] if isinstance(value, str) else \
            [f"{contract}.{key}: expected string, got {type(value).__name__}"]
    if spec == "int":
        return [] if isinstance(value, int) and not isinstance(value, bool) else \
            [f"{contract}.{key}: expected int, got {type(value).__name__}"]
    if spec == "float":
        return [] if isinstance(value, (int, float)) and not isinstance(value, bool) else \
            [f"{contract}.{key}: expected float, got {type(value).__name__}"]
    if spec == "bool":
        return [] if isinstance(value, bool) else \
            [f"{contract}.{key}: expected bool, got {type(value).__name__}"]
    if spec == "dict":
        return [] if isinstance(value, Mapping) else \
            [f"{contract}.{key}: expected dict, got {type(value).__name__}"]
    if spec.startswith("list["):
        inner = spec[5:-1]
        if not isinstance(value, list):
            return [f"{contract}.{key}: expected list, got {type(value).__name__}"]
        out: List[str] = []
        for idx, item in enumerate(value):
            out.extend(_check_field(contract, f"{key}[{idx}]", item, inner))
        return out
    if spec.startswith("enum:"):
        choices = set(spec[5:].split("|"))
        if value in choices:
            return []
        return [f"{contract}.{key}: expected one of {sorted(choices)}, got {value!r}"]
    if spec.startswith("regex:"):
        pattern = spec[6:]
        if not isinstance(value, str):
            return [f"{contract}.{key}: expected string for regex"]
        if re.fullmatch(pattern, value):
            return []
        return [f"{contract}.{key}: value {value!r} does not match regex"]
    return [f"{contract}.{key}: unknown schema spec {spec!r}"]


def validate_against(contract: Contract, value: Mapping[str, Any]) -> List[str]:
    """Convenience wrapper for :meth:`Contract.validate`."""
    return contract.validate(value)


# ---------------------------------------------------------------------------
# redact_argv — strip secrets from argv before logging
# ---------------------------------------------------------------------------

_SECRET_TOKENS = (
    re.compile(r"(?i)(token|secret|password|apikey|api[_\-]?key)\s*[=:]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9+/=]{40,}\b"),     # generic long secret
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), # openai key
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),     # github pat
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),        # aws key
)


def redact_argv(argv: Sequence[str]) -> List[str]:
    """Return a copy of ``argv`` with secret-shaped tokens replaced.

    The function NEVER mutates the input list.  The replacement string
    is ``"<redacted>"``.
    """
    redacted: List[str] = []
    for arg in argv:
        new = arg
        for pat in _SECRET_TOKENS:
            new = pat.sub("<redacted>", new)
        redacted.append(new)
    return redacted


# ---------------------------------------------------------------------------
# Pre-baked contracts (used by other modules)
# ---------------------------------------------------------------------------

FINDING_CONTRACT = Contract(
    name="finding",
    schema={
        "id": "string",
        "bug_class": "string",
        "severity": "enum:low|medium|high|critical",
        "endpoint": "string",
        "method": "string",
        "evidence": "string",
        "reproducer": "string",
        "confidence": "enum:tentative|firm|confirmed",
    },
    required=("id", "bug_class", "severity", "endpoint", "method", "evidence"),
    description="Canonical finding schema shared across all scanners.",
)


PLAYBOOK_CONTRACT = Contract(
    name="playbook",
    schema={
        "name": "string",
        "target": "string",
        "steps": "list[string]",
        "tools": "list[string]",
        "flags": "dict",
        "dry_run": "bool",
    },
    required=("name", "target", "steps"),
    description="YAML playbook contract.",
)


SCAN_RESULT_CONTRACT = Contract(
    name="scan_result",
    schema={
        "schema": "string",
        "scanner": "string",
        "findings": "list[dict]",
        "duration_ms": "int",
        "errors": "list[string]",
    },
    required=("scanner", "findings"),
    description="Top-level scan result envelope.",
)


__all__ = [
    "SCHEMA", "ExitCode",
    "Contract", "validate_against",
    "redact_argv",
    "FINDING_CONTRACT", "PLAYBOOK_CONTRACT", "SCAN_RESULT_CONTRACT",
]