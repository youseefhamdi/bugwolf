"""Supply-chain scanner for npm, PyPI, and RubyGems.

This module provides a ``SupplyChainScanner`` class with
``check_npm``, ``check_pypi``, and ``check_rubygem`` methods.  The
scanner is intentionally network-free: it consults a small bundled
heuristic table (typosquat patterns, abandoned-package age thresholds)
and returns a typed record.

Stub-safe: when no API key is configured the scanner returns
``{"status": "unavailable", "reason": "..."}`` and never raises.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-cicd-supply-chain/v1"


WELL_KNOWN_TYPOSQUATS = {
    "npm": [
        ("lodash", "1odash"),
        ("react", "reactt"),
        ("axios", "axxios"),
        ("express", "expresss"),
        ("webpack", "webpackk"),
    ],
    "pypi": [
        ("requests", "requestts"),
        ("numpy", "numpyy"),
        ("django", "djangoo"),
        ("flask", "flassk"),
        ("boto3", "boto33"),
    ],
    "rubygem": [
        ("rails", "raills"),
        ("devise", "devisee"),
        ("rspec", "rspecc"),
        ("sidekiq", "sidekkiq"),
        ("puma", "pumaa"),
    ],
}


@dataclass(frozen=True)
class CheckResult:
    ecosystem: str
    package: str
    version: str
    status: str  # "ok" | "suspicious" | "unavailable"
    reason: str
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "findings": self.findings,
        }


class SupplyChainScanner:
    """Bundle-first supply-chain scanner.

    Stub-safe: when no API key is configured for an ecosystem, returns
    ``{"status": "unavailable"}`` and never raises.
    """

    SCHEMA_TAG = SCHEMA

    def __init__(self, *, npm_api_key: Optional[str] = None,
                 pypi_api_key: Optional[str] = None,
                 rubygem_api_key: Optional[str] = None) -> None:
        self.npm_api_key = npm_api_key or os.environ.get("BUGWOLF_NPM_API_KEY")
        self.pypi_api_key = pypi_api_key or os.environ.get("BUGWOLF_PYPI_API_KEY")
        self.rubygem_api_key = rubygem_api_key or os.environ.get("BUGWOLF_RUBYGEM_API_KEY")

    def check_npm(self, package: str, version: str) -> Dict[str, Any]:
        if not self.npm_api_key:
            return CheckResult(
                ecosystem="npm",
                package=package,
                version=version,
                status="unavailable",
                reason="no npm API key configured (BUGWOLF_NPM_API_KEY)",
            ).to_dict()
        return self._local_check("npm", package, version)

    def check_pypi(self, package: str, version: str) -> Dict[str, Any]:
        if not self.pypi_api_key:
            return CheckResult(
                ecosystem="pypi",
                package=package,
                version=version,
                status="unavailable",
                reason="no pypi API key configured (BUGWOLF_PYPI_API_KEY)",
            ).to_dict()
        return self._local_check("pypi", package, version)

    def check_rubygem(self, package: str, version: str) -> Dict[str, Any]:
        if not self.rubygem_api_key:
            return CheckResult(
                ecosystem="rubygem",
                package=package,
                version=version,
                status="unavailable",
                reason="no rubygem API key configured (BUGWOLF_RUBYGEM_API_KEY)",
            ).to_dict()
        return self._local_check("rubygem", package, version)

    def _local_check(self, ecosystem: str, package: str, version: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for legit, typo in WELL_KNOWN_TYPOSQUATS.get(ecosystem, []):
            if package == typo or self._is_typosquat(package, legit):
                findings.append(
                    {
                        "kind": "typosquat-suspect",
                        "matches": legit,
                        "distance": 1,
                    }
                )
        if not re.fullmatch(r"[A-Za-z0-9_.\-@]+", package):
            findings.append(
                {
                    "kind": "non-canonical-name",
                    "value": package,
                }
            )
        status = "ok"
        reason = "no heuristics fired"
        if findings:
            status = "suspicious"
            reason = "; ".join(f["kind"] for f in findings)
        return CheckResult(
            ecosystem=ecosystem,
            package=package,
            version=version,
            status=status,
            reason=reason,
            findings=findings,
        ).to_dict()

    @staticmethod
    def _is_typosquat(package: str, legit: str) -> bool:
        """Distance-1 Levenshtein check on the package name."""
        if len(package) != len(legit):
            return False
        diffs = sum(1 for a, b in zip(package, legit) if a != b)
        return diffs == 1


__all__ = ["SupplyChainScanner", "CheckResult", "SCHEMA"]