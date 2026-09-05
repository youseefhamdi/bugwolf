"""Evidence verifier (Phase 1.4 — Governance Core).

Full SHA-256 + canonical JSON integrity for the audit trail.  The verifier
reads a list of chain entries (already parsed dicts), recomputes the
canonical digest of every entry minus its ``entry_hash``, and compares
the result against the stored hash.  The chain link check additionally
walks ``previous_hash`` against the previously-verified ``entry_hash``.

The 4 audit-cited compliance rules (Phase 0 L-9 + M-9/M-10 + GPG-sign of
pair) are satisfied by the *combination* of:

  * canonical-JSON serialization (here) ;
  * full SHA-256 (here) ;
  * ``sign_with_gpg(prev_hash, entry_hash)`` (gpg_signer.py).

Each entry is expected to have at least::

    {
        "sequence":      int,          # monotonic 0-based or 1-based
        "previous_hash": "<sha256>",   # hex string, "" for genesis
        "entry_hash":    "<sha256>",   # SHA-256 over canonical(entry - entry_hash)
    }

Other fields are carried in the digest but ignored by the verifier beyond
their canonical serialization.

No external deps; stdlib only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from ._canonical import SCHEMA as _SCHEMA, canonical_bytes

SCHEMA = "bugwolf-governance-v1"


@dataclass
class IntegrityReport:
    """Result of a chain verification run."""

    is_valid: bool = True
    verified_entries: int = 0
    tampered_entries: int = 0
    sequence_gaps: int = 0
    hash_chain_intact: bool = True
    errors: List[str] = field(default_factory=list)
    schema: str = _SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "is_valid": self.is_valid,
            "verified_entries": self.verified_entries,
            "tampered_entries": self.tampered_entries,
            "sequence_gaps": self.sequence_gaps,
            "hash_chain_intact": self.hash_chain_intact,
            "errors": list(self.errors),
        }


class EvidenceVerifier:
    """Verify a chain of canonical-JSON hash-linked dicts."""

    schema = _SCHEMA

    def __init__(self, *, expected_first_sequence: int = 0) -> None:
        self._expected_first_sequence = int(expected_first_sequence)

    def compute_digest(self, entry: Dict[str, Any]) -> str:
        """Compute the canonical SHA-256 of ``entry`` (entry_hash is included).

        For verification, callers strip ``entry_hash`` first and then call
        ``compute_digest``.  This method returns the digest of the FULL
        canonical form — useful for tagging outgoing records with a
        ``preview_hash`` while still letting the verifier recompute the
        chain-hash from the same canonical bytes.
        """
        return _sha256(canonical_bytes(entry))

    def compute_chain_digest(self, entry: Dict[str, Any]) -> str:
        """SHA-256 over the canonical form with ``entry_hash`` stripped.

        This is the form the chain stores under ``entry_hash``.
        """
        unsigned = _strip_chain_metadata(entry)
        return _sha256(canonical_bytes(unsigned))

    def verify_chain(self, entries: List[Dict[str, Any]]) -> IntegrityReport:
        """Verify a list of entries in chain order.

        Returns an :class:`IntegrityReport`.  Verification is FAIL-CLOSED:
        any single tamper or sequence gap flips ``is_valid`` to False.
        """
        report = IntegrityReport()
        expected_sequence = self._expected_first_sequence
        previous_hash = ""

        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                report.is_valid = False
                report.tampered_entries += 1
                report.hash_chain_intact = False
                report.errors.append(f"Entry {index}: not a dict")
                return report

            stored_hash = entry.get("entry_hash")
            if not isinstance(stored_hash, str) or not stored_hash:
                report.is_valid = False
                report.tampered_entries += 1
                report.hash_chain_intact = False
                report.errors.append(f"Entry {index}: missing entry_hash")
                return report

            declared_prev = entry.get("previous_hash", "")
            if declared_prev != previous_hash:
                report.is_valid = False
                report.hash_chain_intact = False
                report.errors.append(
                    f"Entry {index}: previous_hash does not match chain tip "
                    f"(expected {previous_hash!r}, got {declared_prev!r})")
                # continue verification so we report ALL problems

            declared_sequence = entry.get("sequence")
            if declared_sequence != expected_sequence:
                report.sequence_gaps += 1
                report.is_valid = False
                report.errors.append(
                    f"Entry {index}: expected sequence {expected_sequence}, "
                    f"got {declared_sequence!r}")

            unsigned = _strip_chain_metadata(entry)
            expected_hash = _sha256(canonical_bytes(unsigned))
            if stored_hash != expected_hash:
                report.is_valid = False
                report.tampered_entries += 1
                report.hash_chain_intact = False
                report.errors.append(
                    f"Entry {index}: entry_hash mismatch "
                    f"(expected {expected_hash}, got {stored_hash})")

            previous_hash = str(stored_hash)
            expected_sequence += 1
            report.verified_entries += 1

        return report

    # --- convenience constructors ------------------------------------------

    @staticmethod
    def build_entry(
        body: Dict[str, Any],
        *,
        previous_hash: str,
        sequence: int,
    ) -> Dict[str, Any]:
        """Build a chain entry dict: body + sequence + previous_hash + entry_hash."""
        body = dict(body)
        entry = {
            **body,
            "sequence": int(sequence),
            "previous_hash": str(previous_hash or ""),
        }
        entry["entry_hash"] = EvidenceVerifier().compute_chain_digest(entry)
        return entry


def _strip_chain_metadata(entry: Dict[str, Any]) -> Dict[str, Any]:
    unsigned: Dict[str, Any] = {}
    for k, v in entry.items():
        if k in ("entry_hash",):
            continue
        unsigned[k] = v
    return unsigned


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = ["SCHEMA", "EvidenceVerifier", "IntegrityReport"]