#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter scan_identifiers.py:1-200 (1.5.f)
## Source: BugWolf guard.identify (Phase 0 in-house)
## License: MIT (sister project) + bugwolf-MIT
## Port: 2026-09-05

Fail-closed repo-leak guard.

Scans committed files for AWS keys, GitHub tokens, and similar
identifiers that should never appear in a public repository.  The guard
is FAIL-CLOSED: if a regex match is found, the file is flagged and the
caller MUST treat the commit as leaked.

This module is intentionally minimal (no external deps); it is the
last line of defence before a commit is published.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Sequence, Tuple


SCHEMA = "bugwolf-identifier-scan/v1"


# Subset of patterns used by the in-repo guard (the 80-pattern scanner
# lives in :mod:`tools.cross_project.secret_scan`).
_IDENTIFIER_PATTERNS: Sequence[Tuple[str, re.Pattern, str]] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("aws_secret_inline", re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?key)?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"), "high"),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "critical"),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "critical"),
    ("stripe_live_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    ("jwt_inline", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "medium"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24}"), "high"),
    ("discord_webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"), "high"),
    ("ssh_pass_inline", re.compile(r"sshpass\s+-p\s+\S+"), "high"),
)


@dataclass(frozen=True)
class LeakedIdentifier:
    """One identifier leak detected in a file."""

    file_path: str
    pattern_name: str
    severity: str
    line: int
    snippet: str
    sha256: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "file_path": self.file_path,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "line": self.line,
            "snippet": self.snippet[:256],
            "sha256": self.sha256,
            "extra": dict(self.extra),
        }


class IdentifierScanner:
    """Fail-closed repo-leak guard."""

    SCHEMA = SCHEMA
    PATTERN_COUNT: int = len(_IDENTIFIER_PATTERNS)

    def __init__(self, *,
                 patterns: Optional[Sequence[Tuple[str, re.Pattern, str]]] = None) -> None:
        self._patterns = list(patterns or _IDENTIFIER_PATTERNS)

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def scan(self, content: str, *,
             file_path: str = "<unknown>") -> List[LeakedIdentifier]:
        """Scan ``content`` (one file's text) for identifier leaks.

        The caller passes the file path so the resulting records can be
        traced back to the offending commit.
        """
        import hashlib
        out: List[LeakedIdentifier] = []
        for line_idx, line in enumerate(content.splitlines(), start=1):
            for name, regex, severity in self._patterns:
                m = regex.search(line)
                if not m:
                    continue
                snippet = m.group(0)
                out.append(LeakedIdentifier(
                    file_path=file_path,
                    pattern_name=name,
                    severity=severity,
                    line=line_idx,
                    snippet=snippet,
                    sha256=hashlib.sha256(snippet.encode("utf-8",
                                                         errors="ignore")).hexdigest(),
                ))
        return out

    def scan_paths(self, files: Mapping[str, str]) -> List[LeakedIdentifier]:
        """Convenience: scan a ``{path: content}`` map."""
        out: List[LeakedIdentifier] = []
        for path, content in files.items():
            out.extend(self.scan(content, file_path=path))
        return out


__all__ = ["SCHEMA", "LeakedIdentifier", "IdentifierScanner"]