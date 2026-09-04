#!/usr/bin/env python3
"""Understanding Layer primitives: assumptions, artifacts, the model store.

Every U-stage produces ONE ``UArtifact``.  Artifacts are hash-chained: each
records the hash of its input artifacts, and U9 records the chain — so a
model can be audited ("what did U4 actually see?") and recomputed
incrementally (only stages whose inputs changed recompute).

Persistence layout per target: ``state/targets/<slug>/model/`` (master plan
§8.1 output column).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.runtime_paths import runtime_path, target_slug

SCHEMA = "bugwolf-understanding/v1"
STAGES = ("U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8", "U9")
STAGE_FILES = {
    "U1": "u1-business.json",
    "U2": "u2-census.json",
    "U3": "u3-logic.json",
    "U4": "u4-identity.json",
    "U5": "u5-data.json",
    "U6": "u6-trust.json",
    "U7": "u7-capabilities.json",
    "U8": "u8-assumptions.jsonl",
    "U9": "u9-target-model.json",
}
ASSUMPTION_ORIGINS = ("observed", "inferred", "documented")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(payload: Any) -> str:
    """Stable content hash (the chain link)."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class Assumption:
    """One stated assumption — the U8 ledger's unit and the hunt's target.

    Every stage writes its assumptions with an origin, a confidence, and a
    dispro plan (the exact mutation or probe that would break it).  The
    plan's LLM pass adds the ``challenge`` ("what must the devs believe
    for this to hold?"); deterministic code fills a default.
    """

    stage: str
    statement: str
    origin: str = "inferred"          # observed | inferred | documented
    confidence: float = 0.4           # 0..1 (1 = directly observed)
    dispro_plan: str = ""
    evidence: str = ""
    status: str = "open"              # open | confirmed | disproven
    challenge: str = ""
    assumption_id: str = ""

    def __post_init__(self) -> None:
        if self.origin not in ASSUMPTION_ORIGINS:
            raise ValueError(f"bad assumption origin: {self.origin}")
        if not self.challenge:
            self.challenge = (f"What must the developers believe for this "
                              f"to hold? {self.statement}")
        if not self.assumption_id:
            self.assumption_id = canonical_hash(
                {"stage": self.stage, "statement": self.statement})[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assumption_id": self.assumption_id, "stage": self.stage,
            "statement": self.statement, "origin": self.origin,
            "confidence": round(self.confidence, 2),
            "dispro_plan": self.dispro_plan, "evidence": self.evidence,
            "status": self.status, "challenge": self.challenge,
        }


@dataclass
class UArtifact:
    """One stage's output, chained to its inputs."""

    stage: str
    target: str
    data: Dict[str, Any] = field(default_factory=dict)
    assumptions: List[Assumption] = field(default_factory=list)
    markdown: str = ""
    inputs: Dict[str, str] = field(default_factory=dict)   # stage -> hash
    generated_at: str = field(default_factory=_now)
    artifact_hash: str = ""

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ValueError(f"bad stage: {self.stage}")
        if not self.artifact_hash:
            self.artifact_hash = canonical_hash({
                "stage": self.stage, "target": self.target,
                "data": self.data,
                "assumptions": [a.to_dict() for a in self.assumptions],
                "inputs": self.inputs,
            })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA, "stage": self.stage, "target": self.target,
            "generated_at": self.generated_at, "inputs": dict(self.inputs),
            "artifact_hash": self.artifact_hash,
            "data": self.data,
            "assumptions": [a.to_dict() for a in self.assumptions],
        }


class ModelStore:
    """Strict sequential persistence for one target's model artifacts."""

    def __init__(self, target: str, *, root: Optional[str | Path] = None,
                 project_root: Optional[str | Path] = None) -> None:
        self.target = target
        self.dir = runtime_path("state", "targets", target_slug(target),
                                "model", root=project_root)
        if root is not None:                      # explicit test override
            self.dir = Path(root)
        self.dir.mkdir(parents=True, exist_ok=True)

    # -- paths ---------------------------------------------------------------

    def stage_path(self, stage: str) -> Path:
        return self.dir / STAGE_FILES[stage]

    def brief_path(self) -> Path:
        return self.dir / "hunting-brief.md"

    # -- load / save ----------------------------------------------------------

    def load(self, stage: str) -> Optional[UArtifact]:
        path = self.stage_path(stage)
        if not path.is_file():
            return None
        if stage == "U8":
            return self._load_u8(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if raw.get("schema") != SCHEMA or raw.get("stage") != stage:
            return None
        assumptions = [Assumption(**a) for a in raw.get("assumptions", [])]
        return UArtifact(stage=stage, target=raw.get("target", ""),
                         data=raw.get("data", {}), assumptions=assumptions,
                         inputs=raw.get("inputs", {}),
                         generated_at=raw.get("generated_at", ""),
                         artifact_hash=raw.get("artifact_hash", ""))

    def _load_u8(self, path: Path) -> Optional[UArtifact]:
        """U8 = the plan's JSONL seed list + a meta sidecar (inputs/hash).

        The seed list stays hand-editable (operators may annotate status);
        a hand-edited list (meta gone or stale) loads with empty inputs,
        which forces the pipeline to recompute — the safe direction.
        """
        assumptions: List[Assumption] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                assumptions.append(Assumption(**json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        meta_path = path.with_suffix(".meta.json")
        meta: Dict[str, Any] = {}
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta = {}
        return UArtifact(stage="U8", target=meta.get("target", ""),
                         data=meta.get("data", {}),
                         assumptions=assumptions,
                         inputs=meta.get("inputs", {}),
                         generated_at=meta.get("generated_at", ""),
                         artifact_hash=meta.get("artifact_hash", ""))

    def load_assumptions(self) -> List[Assumption]:
        """All assumptions recorded across stages (the U8 input)."""
        out: List[Assumption] = []
        for stage in STAGES[:8]:
            artifact = self.load(stage)
            if artifact:
                out.extend(artifact.assumptions)
        return out

    def save(self, artifact: UArtifact) -> Path:
        path = self.stage_path(artifact.stage)
        if artifact.stage == "U8":
            with path.open("w", encoding="utf-8") as fh:
                for assumption in artifact.assumptions:
                    fh.write(json.dumps(assumption.to_dict()) + "\n")
            meta = {
                "schema": SCHEMA, "stage": "U8",
                "target": artifact.target,
                "inputs": artifact.inputs,
                "artifact_hash": artifact.artifact_hash,
                "generated_at": artifact.generated_at,
                "data": {k: v for k, v in artifact.data.items()
                         if k != "ranked"},
            }
            path.with_suffix(".meta.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8")
        else:
            path.write_text(json.dumps(artifact.to_dict(), indent=2),
                            encoding="utf-8")
        return path

    # -- chaining / incremental recompute --------------------------------------

    def stage_hash(self, stage: str) -> str:
        artifact = self.load(stage)
        return artifact.artifact_hash if artifact else ""

    def needs_recompute(self, stage: str,
                        inputs: Dict[str, str]) -> bool:
        """True unless the stored artifact exists with the SAME inputs.

        Incremental semantics (master plan §8.2): only stages whose input
        hashes changed recompute.  A stored artifact whose recorded hash no
        longer matches its content (tamper/hand-edit) also recomputes.
        """
        artifact = self.load(stage)
        if artifact is None:
            return True
        if artifact.inputs != inputs:
            return True
        if artifact.stage != "U8":
            fresh = UArtifact(stage=artifact.stage, target=artifact.target,
                              data=artifact.data,
                              assumptions=artifact.assumptions,
                              inputs=artifact.inputs)
            if fresh.artifact_hash != artifact.artifact_hash:
                return True
        return False

    def chain(self) -> List[Dict[str, str]]:
        """The stage->hash chain U9 seals into the target model."""
        out = []
        for stage in STAGES:
            digest = self.stage_hash(stage)
            if digest:
                out.append({"stage": stage, "hash": digest})
        return out
