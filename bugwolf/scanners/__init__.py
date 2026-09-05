"""BugWolf Phase 2.1 — Scanner Library.

This package defines the contract every scanner must implement and a small
collection of dataclasses that ride the boundary between the harness, the
transport, and a finding sink.

Contract:

    class MyScanner(Scanner):
        name             = "my-scanner"
        bug_class        = "rce"          # stable slug; see bugwolf/scanners/registry.py
        default_severity = "high"         # one of: low / medium / high / critical
        PAYLOADS         = ("a", "b",)    # at least one entry

        def scan(self, target, transport):
            ...

``transport(method, url, headers=None, body=None) -> dict`` is an opaque
callable that the orchestrator injects.  It MUST return a JSON-able dict
that the scanner can analyse.  In unit tests the harness uses a mock
transport that simply echoes the request back so that signal-detection
works without any network IO.

Schemas:
  * ScannerContract  = "bugwolf-scanner-contract/v1"
  * FindingSchema    = "bugwolf-finding/v1"

No third-party dependencies; stdlib only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


SCANNER_CONTRACT_SCHEMA = "bugwolf-scanner-contract/v1"
FINDING_SCHEMA = "bugwolf-finding/v1"


TransportFn = Callable[..., Dict[str, Any]]
"""
A transport callable with the signature::

    transport(method, url, headers=None, body=None) -> dict

The orchestrator injects the concrete transport.  In unit tests this is a
mock that echoes the request back so signal-detection logic can be
exercised without network IO.
"""


@dataclass(frozen=True)
class Finding:
    """A single observation emitted by a scanner.

    Attributes:
        schema:    Stable schema tag (FINDING_SCHEMA).
        scanner:   The ``name`` of the scanner that produced this finding.
        bug_class: Stable slug identifying the bug taxonomy entry.
        severity:  One of ``low`` / ``medium`` / ``high`` / ``critical``.
        target:    The URL / endpoint / asset the finding applies to.
        evidence:  Short string (≤160 chars) of raw evidence.
        detail:    Free-form detail dict (headers, snippets, payloads).
        confidence: 0.0–1.0 confidence score (default 0.5).
    """

    schema: str
    scanner: str
    bug_class: str
    severity: str
    target: str
    evidence: str
    detail: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5

    @classmethod
    def create(
        cls,
        *,
        scanner: str,
        bug_class: str,
        severity: str,
        target: str,
        evidence: str,
        detail: Optional[Dict[str, Any]] = None,
        confidence: float = 0.5,
        schema: str = FINDING_SCHEMA,
    ) -> "Finding":
        sev = str(severity).lower()
        if sev not in ("low", "medium", "high", "critical"):
            raise ValueError(f"invalid severity: {severity!r}")
        ev = str(evidence or "")
        if len(ev) > 160:
            ev = ev[:157] + "..."
        c = max(0.0, min(1.0, float(confidence)))
        return cls(
            schema=schema,
            scanner=str(scanner),
            bug_class=str(bug_class),
            severity=sev,
            target=str(target),
            evidence=ev,
            detail=dict(detail or {}),
            confidence=c,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "scanner": self.scanner,
            "bug_class": self.bug_class,
            "severity": self.severity,
            "target": self.target,
            "evidence": self.evidence,
            "detail": dict(self.detail),
            "confidence": self.confidence,
        }


class Scanner(ABC):
    """Abstract base for all BugWolf scanners.

    Subclasses must define:

      * ``name``             (str)
      * ``bug_class``        (str)
      * ``default_severity`` (one of low / medium / high / critical)
      * ``PAYLOADS``         (tuple, ≥1 entry)
      * ``scan(target, transport)`` returning ``List[Finding]``
    """

    schema = SCANNER_CONTRACT_SCHEMA

    #: Stable scanner identifier (kebab-case preferred).
    name: str = ""
    #: Stable bug taxonomy slug.
    bug_class: str = ""
    #: Severity used when the scanner has no finer signal.
    default_severity: str = "medium"
    #: Tuple of payloads the scanner is willing to send.  Must be ≥1 entry.
    PAYLOADS: Tuple[str, ...] = ()

    @abstractmethod
    def scan(self, target: str, transport: TransportFn) -> List[Finding]:
        """Run the scanner against ``target``.

        ``transport`` is the injected transport callable.  Scanners must
        NOT perform network IO of their own — they must call transport.

        Returns a list of :class:`Finding` instances; empty list means
        "no signal" or "shell-mode, transport unavailable".
        """
        raise NotImplementedError


# A small helper used by most scanners to materialise a Finding.
def make_finding(
    scanner: Scanner,
    *,
    target: str,
    evidence: str,
    severity: Optional[str] = None,
    bug_class: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    confidence: float = 0.7,
) -> Finding:
    """Construct a Finding from the given scanner instance."""
    return Finding.create(
        scanner=scanner.name,
        bug_class=bug_class or scanner.bug_class,
        severity=severity or scanner.default_severity,
        target=target,
        evidence=evidence,
        detail=detail,
        confidence=confidence,
    )


__all__ = [
    "SCANNER_CONTRACT_SCHEMA",
    "FINDING_SCHEMA",
    "TransportFn",
    "Finding",
    "Scanner",
    "make_finding",
]