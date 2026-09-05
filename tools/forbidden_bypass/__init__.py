#!/usr/bin/env python3
"""
## Source: Forbidra + Scrapling + gobypass403 + NoMoreForbidden + zero_fours + letmepass (Appendix H)
## License: MIT (each upstream project)
## Port: 2026-09-05

Forbidden-bypass engine for bug bounty engagements.

Submodules (one per upstream capability):
  * engine                  - 17-module orchestrator + registry
  * cve_middleware_subrequest - CVE-2025-29927 (Next.js middleware bypass)
  * cve_smuggling           - CVE-2021-40346 (HAProxy integer overflow smuggling)
  * cve_haproxy_fragment    - CVE-2023-45539 (HAProxy URL fragment ACL)
  * unicode_bypass          - Unicode normalization + truncation maps
  * raw_request_fuzz        - letmepass -r raw-request injection
  * race_403                - zero_fours race-condition bypass
  * body_bypass             - JSON/form/XML privilege escalation + prototype pollution
  * cname_host_bypass       - CNAME-based host header fuzzing

All probes route through ``tools.runtime.scope.check_url`` so they cannot
reach a host outside the operator's declared scope.
"""

from .engine import ForbiddenBypassEngine, BypassModule, BypassResult
from .cve_middleware_subrequest import CVE202529927
from .cve_smuggling import CVE202140346
from .cve_haproxy_fragment import CVE202345539
from .unicode_bypass import UnicodeNormalization, UnicodeTruncation
from .raw_request_fuzz import RawRequestFuzzer
from .race_403 import Race403, RaceResult
from .body_bypass import BodyBypass
from .cname_host_bypass import CnameHostBypass

__all__ = [
    "ForbiddenBypassEngine",
    "BypassModule",
    "BypassResult",
    "CVE202529927",
    "CVE202140346",
    "CVE202345539",
    "UnicodeNormalization",
    "UnicodeTruncation",
    "RawRequestFuzzer",
    "Race403",
    "RaceResult",
    "BodyBypass",
    "CnameHostBypass",
]