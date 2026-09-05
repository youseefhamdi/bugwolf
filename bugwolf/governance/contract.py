"""Skill request / result contracts (Phase 1.4 — Governance Core).

Frozen dataclasses that ride the boundary between a skill adapter and the
runtime.  Frozen = the contract can't be mutated after construction, so
the SHA-256 over the contract is stable for the lifetime of the request.

The contracts are deliberately minimal: schema, request_id, target,
action_class, scope_ref, payload_ref, issued_at / completed_at.  The
skill adapter is free to add its own metadata OUTSIDE these fields
(e.g. via a sidecar metadata dict that the adapter hashes separately).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

SCHEMA = "bugwolf-governance-v1"

SKILL_REQUEST_SCHEMA = "bugwolf-skill-request/v1"
SKILL_RESULT_SCHEMA = "bugwolf-skill-result/v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SkillRequest:
    """A signed request handed to a skill adapter."""

    schema: str
    request_id: str
    target: str
    action_class: str
    scope_ref: str
    payload_ref: str
    issued_at: str

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        target: str,
        action_class: str,
        scope_ref: str,
        payload_ref: str,
        issued_at: Optional[str] = None,
        schema: str = SKILL_REQUEST_SCHEMA,
    ) -> "SkillRequest":
        if not request_id:
            raise ValueError("SkillRequest requires request_id")
        if not target:
            raise ValueError("SkillRequest requires target")
        if not action_class:
            raise ValueError("SkillRequest requires action_class")
        return cls(
            schema=schema,
            request_id=str(request_id),
            target=str(target),
            action_class=str(action_class),
            scope_ref=str(scope_ref or ""),
            payload_ref=str(payload_ref or ""),
            issued_at=str(issued_at or _utc_now_iso()),
        )


@dataclass(frozen=True)
class SkillResult:
    """The skill adapter's reply to a :class:`SkillRequest`."""

    schema: str
    request_id: str
    status: str
    evidence_ref: str
    findings_count: int
    completed_at: str

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        status: str,
        evidence_ref: str = "",
        findings_count: int = 0,
        completed_at: Optional[str] = None,
        schema: str = SKILL_RESULT_SCHEMA,
    ) -> "SkillResult":
        if not request_id:
            raise ValueError("SkillResult requires request_id")
        if not status:
            raise ValueError("SkillResult requires status")
        return cls(
            schema=schema,
            request_id=str(request_id),
            status=str(status),
            evidence_ref=str(evidence_ref or ""),
            findings_count=int(findings_count or 0),
            completed_at=str(completed_at or _utc_now_iso()),
        )


__all__ = [
    "SCHEMA",
    "SKILL_REQUEST_SCHEMA",
    "SKILL_RESULT_SCHEMA",
    "SkillRequest",
    "SkillResult",
]