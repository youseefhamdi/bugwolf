## Source: BugWolf Phase 3.5 (in-house) — chain validator
## License: bugwolf-MIT
## Port: 2026-09-05

"""
bugwolf.chain.validator — ChainValidator.

Pre-flight checks on a :class:`CrossProtocolChain` or
:class:`CrossTargetChain` before PoC generation or reporting.  The
validator is STUB-SAFE — it never raises; on any internal error it
returns :class:`ChainValidationResult` with a single ``internal_error``
issue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple, Union

from bugwolf.chain.builder import (
    CANONICAL_PROTOCOLS,
    CrossProtocolChain,
    CrossTargetChain,
    Chain,
    FORBIDDEN_METHODS,
    SCHEMA,
    Unavailable,
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainValidationResult:
    """Outcome of a :meth:`ChainValidator.validate` call."""

    is_valid: bool
    issues: Tuple[str, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)
    chain: Union[CrossProtocolChain, CrossTargetChain, None] = None
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "is_valid": bool(self.is_valid),
            "issues": list(self.issues),
            "warnings": list(self.warnings),
            "chain": self.chain.to_dict() if self.chain is not None else None,
            "diagnostics": dict(self.diagnostics),
        }


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class ChainValidator:
    """Validates a chain against scope, ordering, and evidence rules."""

    def __init__(self, *,
                 allowed_severities: Sequence[str] = ("high", "critical"),
                 require_evidence: bool = True,
                 require_references: bool = False):
        self.allowed_severities = tuple(s.lower() for s in allowed_severities)
        self.require_evidence = bool(require_evidence)
        self.require_references = bool(require_references)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, chain: Chain) -> ChainValidationResult:
        """Return a :class:`ChainValidationResult`.

        The check covers:
          * membership in scope (basic — protocol allowlist)
          * destructive verb flagging
          * evidence-block requirements
          * ordering correctness (1-indexed, no gaps, no duplicates)
        """
        try:
            if isinstance(chain, Unavailable):
                return ChainValidationResult(
                    is_valid=False,
                    issues=("chain is unavailable",),
                    warnings=("validation skipped",),
                    chain=None,
                )
            if isinstance(chain, CrossProtocolChain):
                return self._validate_cross_protocol(chain)
            if isinstance(chain, CrossTargetChain):
                return self._validate_cross_target(chain)
            return ChainValidationResult(
                is_valid=False,
                issues=("unsupported chain type",),
                chain=None,
            )
        except Exception as exc:  # noqa: BLE001
            return ChainValidationResult(
                is_valid=False,
                issues=("internal_error", str(exc)),
                chain=None,
            )

    # ------------------------------------------------------------------
    # Cross-protocol
    # ------------------------------------------------------------------

    def _validate_cross_protocol(self, chain: CrossProtocolChain) -> ChainValidationResult:
        issues: List[str] = []
        warnings: List[str] = []

        if not chain.source_protocol or not chain.target_protocol:
            issues.append("empty source/target protocol")
        if chain.source_protocol == chain.target_protocol:
            issues.append("source and target protocols are identical")
        for label in (chain.source_protocol, chain.target_protocol):
            if label and label not in CANONICAL_PROTOCOLS:
                warnings.append(f"protocol {label!r} is not in canonical set")

        if not chain.steps:
            issues.append("chain has no steps")

        # Ordering correctness
        if chain.steps:
            orders = [s.order for s in chain.steps]
            if sorted(orders) != list(range(1, len(orders) + 1)):
                issues.append(f"step ordering is not 1..N (got {orders})")
            if len(set(orders)) != len(orders):
                issues.append("duplicate step orders detected")

        # Destructive verb flagging
        for s in chain.steps:
            if s.destructive:
                warnings.append(
                    f"step {s.order} is marked destructive — must be explicitly approved"
                )

        # Evidence-block requirements
        if self.require_evidence:
            for s in chain.steps:
                if not s.evidence:
                    issues.append(f"step {s.order} missing evidence block")

        # Forbidden methods
        for s in chain.steps:
            if isinstance(s.technique, str) and s.technique.upper() in FORBIDDEN_METHODS:
                issues.append(f"step {s.order} uses forbidden method {s.technique!r}")

        # Confidence floor
        if chain.confidence < 0.3:
            warnings.append(
                f"confidence is low ({chain.confidence:.2f}); chain may be noisy"
            )

        # References optional
        if self.require_references and not chain.references:
            issues.append("chain has no references")

        is_valid = not issues
        return ChainValidationResult(
            is_valid=is_valid,
            issues=tuple(issues),
            warnings=tuple(warnings),
            chain=chain,
            diagnostics={"schema": SCHEMA, "validator": "cross_protocol"},
        )

    # ------------------------------------------------------------------
    # Cross-target
    # ------------------------------------------------------------------

    def _validate_cross_target(self, chain: CrossTargetChain) -> ChainValidationResult:
        issues: List[str] = []
        warnings: List[str] = []

        if not chain.primary_target:
            issues.append("primary_target is empty")
        if not chain.lateral_targets:
            warnings.append("no lateral targets — chain is single-target")
        if any(t == chain.primary_target for t in chain.lateral_targets):
            issues.append("lateral_targets contains the primary target")

        if not chain.steps:
            issues.append("chain has no steps")
        if chain.steps:
            orders = [s.order for s in chain.steps]
            if sorted(orders) != list(range(1, len(orders) + 1)):
                issues.append(f"step ordering is not 1..N (got {orders})")
            if len(set(orders)) != len(orders):
                issues.append("duplicate step orders detected")

        if chain.total_severity not in {"info", "low", "medium", "high", "critical"}:
            issues.append(f"invalid total_severity {chain.total_severity!r}")
        elif chain.total_severity not in self.allowed_severities:
            warnings.append(
                f"severity {chain.total_severity!r} is outside the allowed set "
                f"{self.allowed_severities}"
            )

        for s in chain.steps:
            if s.destructive:
                warnings.append(
                    f"step {s.order} is marked destructive — must be explicitly approved"
                )

        if self.require_evidence:
            for s in chain.steps:
                if not s.evidence:
                    issues.append(f"step {s.order} missing evidence block")

        if self.require_references and not chain.references:
            issues.append("chain has no references")

        is_valid = not issues
        return ChainValidationResult(
            is_valid=is_valid,
            issues=tuple(issues),
            warnings=tuple(warnings),
            chain=chain,
            diagnostics={"schema": SCHEMA, "validator": "cross_target"},
        )


__all__ = [
    "SCHEMA",
    "ChainValidationResult",
    "ChainValidator",
]
