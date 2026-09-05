"""
Immutable-review binding (adapted from machinist foreman.md:183).

Machinist's principle:
  'Approval applies only to the reviewed SHA. If the branch moves, review again.'

Bugwolf's current refutation collapses chain_findings into one record,
losing the per-finding SHA binding (audit M-16 finding).

This module:
  1. Binds each refutation verdict to a specific engagement hash + timestamp
  2. Detects engagement-hash drift
  3. Forces re-review when the engagement state changes
"""
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class DriftStatus(Enum):
    """Result of comparing current engagement state to recorded review state."""
    NO_DRIFT = "NO_DRIFT"
    MINOR_DRIFT = "MINOR_DRIFT"      # Evidence changed but verdict still valid
    MAJOR_DRIFT = "MAJOR_DRIFT"      # Engagement scope changed; verdict invalidated


@dataclass
class EngagementFingerprint:
    """Hash of all inputs that affect a refutation verdict.

    Following machinist foreman.md:183:
      'Approval applies only to the reviewed SHA. If the branch moves,
       review again.'
    """
    engagement_scope_hash: str      # SHA-256 of scope file
    evidence_block_hash: str       # SHA-256 of evidence/observation logs
    config_hash: str                # SHA-256 of MissionSpec/TaskSpec
    timestamp: float

    def composite_hash(self) -> str:
        h = hashlib.sha256()
        h.update(self.engagement_scope_hash.encode())
        h.update(b"|")
        h.update(self.evidence_block_hash.encode())
        h.update(b"|")
        h.update(self.config_hash.encode())
        h.update(b"|")
        h.update(str(self.timestamp).encode())
        return h.hexdigest()

    def to_dict(self) -> dict:
        return {
            "engagement_scope_hash": self.engagement_scope_hash,
            "evidence_block_hash": self.evidence_block_hash,
            "config_hash": self.config_hash,
            "timestamp": self.timestamp,
            "composite_hash": self.composite_hash(),
        }


@dataclass
class ImmutableReview:
    """A refutation verdict bound to a specific engagement fingerprint.

    Per audit M-16 (tools/refutation.py:448-459 chain_findings collapse):
    Each review records its own fingerprint so re-review is triggered on drift.
    """
    review_id: str
    verdict: str  # CONFIRMED / KILLED / DEMOTED / LEAD / NEEDS_MANUAL
    fingerprint: EngagementFingerprint
    finding_id: str
    reviewer_role: str  # "judge" (per self-correction article)
    ground_truth_used: str
    specific_issues: list[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "review_id": self.review_id,
            "verdict": self.verdict,
            "fingerprint": self.fingerprint.to_dict(),
            "finding_id": self.finding_id,
            "reviewer_role": self.reviewer_role,
            "ground_truth_used": self.ground_truth_used,
            "specific_issues": list(self.specific_issues),
            "confidence": self.confidence,
        }


class DriftDetector:
    """Detect if current engagement state has drifted from a recorded review."""

    def __init__(self, target_slug: str, state_dir: Optional[Path] = None):
        self.target_slug = target_slug
        self.state_dir = state_dir or Path("state") / "sessions" / target_slug
        self.reviews_file = self.state_dir / "immutable_reviews.jsonl"
        self.logger = logging.getLogger("bugwolf.immutable_review")

    def compute_fingerprint(self) -> EngagementFingerprint:
        """Compute current engagement fingerprint."""
        from tools.runtime.scope import _contract_path
        from tools.engagement_context import current_evidence_block

        scope_hash = "unavailable"
        evidence_hash = "unavailable"
        config_hash = "unavailable"
        try:
            scope_file = _contract_path()
            if scope_file.exists():
                scope_hash = hashlib.sha256(scope_file.read_bytes()).hexdigest()
        except Exception as exc:
            self.logger.debug(f"scope hash unavailable: {exc}")

        try:
            evidence_block = current_evidence_block()
            evidence_hash = hashlib.sha256(
                json.dumps(evidence_block, sort_keys=True).encode()
            ).hexdigest()
        except Exception as exc:
            self.logger.debug(f"evidence hash unavailable: {exc}")

        try:
            from tools.runtime.contracts import current_mission_spec
            spec = current_mission_spec()
            config_hash = hashlib.sha256(
                spec.encode() if isinstance(spec, str) else json.dumps(spec, sort_keys=True).encode()
            ).hexdigest()
        except Exception as exc:
            self.logger.debug(f"config hash unavailable: {exc}")

        return EngagementFingerprint(
            engagement_scope_hash=scope_hash,
            evidence_block_hash=evidence_hash,
            config_hash=config_hash,
            timestamp=time.time(),
        )

    def record_review(self, review: ImmutableReview) -> None:
        """Append review to immutable_reviews.jsonl (append-only log)."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self.reviews_file.open("a") as f:
            f.write(json.dumps(review.to_dict()) + "\n")
        self.logger.info(
            f"immutable_review.record review_id={review.review_id} "
            f"verdict={review.verdict} fingerprint={review.fingerprint.composite_hash()[:12]}"
        )

    def check_drift(self, review_id: str) -> DriftStatus:
        """Compare current state to recorded review's fingerprint.

        Returns NO_DRIFT / MINOR_DRIFT / MAJOR_DRIFT.
        Per machinist foreman.md:183: if state moves, verdict is invalid.
        """
        if not self.reviews_file.exists():
            return DriftStatus.NO_DRIFT

        # Find the review
        review = None
        for line in self.reviews_file.read_text().splitlines():
            if not line:
                continue
            data = json.loads(line)
            if data.get("review_id") == review_id:
                review = data
                break

        if review is None:
            self.logger.warning(f"immutable_review.not_found review_id={review_id}")
            return DriftStatus.MAJOR_DRIFT

        recorded_fingerprint = review["fingerprint"]
        current_fingerprint = self.compute_fingerprint()

        # Compare critical fields
        scope_changed = (
            recorded_fingerprint["engagement_scope_hash"]
            != current_fingerprint.engagement_scope_hash
            and current_fingerprint.engagement_scope_hash != "unavailable"
        )
        config_changed = (
            recorded_fingerprint["config_hash"]
            != current_fingerprint.config_hash
            and current_fingerprint.config_hash != "unavailable"
        )

        if scope_changed or config_changed:
            self.logger.warning(
                f"immutable_review.drift MAJOR review_id={review_id} "
                f"scope_changed={scope_changed} config_changed={config_changed}"
            )
            return DriftStatus.MAJOR_DRIFT

        evidence_changed = (
            recorded_fingerprint["evidence_block_hash"]
            != current_fingerprint.evidence_block_hash
            and current_fingerprint.evidence_block_hash != "unavailable"
        )
        if evidence_changed:
            self.logger.info(
                f"immutable_review.drift MINOR review_id={review_id}"
            )
            return DriftStatus.MINOR_DRIFT

        return DriftStatus.NO_DRIFT