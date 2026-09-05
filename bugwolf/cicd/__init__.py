"""BugWolf Phase 2.3 — CI/CD security package.

Additive module providing GitHub Actions / GitLab CI / supply-chain
checks.  The scanner wraps ``actionlint`` and applies custom rules;
the supply-chain scanner checks npm / PyPI / RubyGems for
typosquats and abandoned packages.
"""

from __future__ import annotations

SCHEMA = "bugwolf-cicd-v1"

__all__ = ["SCHEMA"]