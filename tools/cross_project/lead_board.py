#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter lead_board.py:1-560 (1.5.d)
## Source: HackGATE routing/lead_router.py:22-310
## License: MIT (sister projects)
## Port: 2026-09-05

URL/tech -> hunt-skill routing (Lead Board).

The Lead Board is the project's "what skill to run next" lookup table:
given a partial lead (URL + tech fingerprint + tags), it returns an
ordered list of :class:`HuntSkill` objects the orchestrator should try.

Also includes :meth:`detect_stale_highs` — a periodic housekeeping pass
that flags HIGH-severity leads older than ``max_age_days`` so they can
be either promoted to a finding or downgraded.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "bugwolf-lead-board/v1"


# ---------------------------------------------------------------------------
# Skill catalogue
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class HuntSkill:
    """A routable hunt skill entry."""

    name: str
    bug_class: str
    severity: Severity
    techs: Tuple[str, ...]
    url_patterns: Tuple[str, ...]
    requires_scope_verb: str = "GET"
    description: str = ""

    def matches(self, lead: Mapping[str, object]) -> bool:
        tech = str(lead.get("tech") or "").lower()
        url = str(lead.get("url") or "")
        tags = {str(t).lower() for t in (lead.get("tags") or [])}
        tech_match = not self.techs or tech in {t.lower() for t in self.techs}
        url_match = not self.url_patterns or any(
            _glob_match(pat, url) for pat in self.url_patterns)
        class_match = (not lead.get("bug_class")) or \
            str(lead.get("bug_class")).lower() == self.bug_class.lower()
        tag_match = (not tags) or bool(tags & set(self.techs))
        return bool(tech_match and url_match and class_match) or tag_match

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "bug_class": self.bug_class,
            "severity": self.severity.value,
            "techs": list(self.techs),
            "url_patterns": list(self.url_patterns),
            "requires_scope_verb": self.requires_scope_verb,
            "description": self.description,
        }


def _glob_match(pattern: str, url: str) -> bool:
    import fnmatch
    if not pattern:
        return True
    return fnmatch.fnmatchcase(url, pattern)


# ---------------------------------------------------------------------------
# Built-in catalogue (43 entries)
# ---------------------------------------------------------------------------

_CATALOGUE: Tuple[HuntSkill, ...] = (
    HuntSkill("xss_reflected", "xss", Severity.HIGH,
              ("php", "java", "node", "python", "ruby"),
              ("*?*", "*/search*", "*/query*"),
              description="Reflected XSS via query parameters"),
    HuntSkill("xss_stored", "xss", Severity.HIGH,
              ("php", "java", "node", "python"),
              ("*/comment*", "*/post*", "*/review*"),
              description="Stored XSS in user-generated content"),
    HuntSkill("xss_dom", "xss", Severity.HIGH,
              ("javascript", "node"),
              ("*#*", "*?*"),
              description="DOM-based XSS via fragment / hash"),
    HuntSkill("sqli_error", "sqli", Severity.CRITICAL,
              ("php", "java", "node", "python", "ruby", "dotnet"),
              ("*?id=*", "*?page=*"),
              description="SQL injection detected via DB error messages"),
    HuntSkill("sqli_time", "sqli", Severity.HIGH,
              ("*",),
              ("*",),
              description="SQL injection via time-based blind"),
    HuntSkill("ssrf_basic", "ssrf", Severity.HIGH,
              ("python", "java", "ruby", "php", "node", "go"),
              ("*/fetch*", "*/proxy*", "*/image*"),
              description="SSRF via URL-fetch parameter"),
    HuntSkill("ssrf_cloud", "ssrf", Severity.CRITICAL,
              ("aws", "gcp", "azure"),
              ("*169.254*", "*metadata*"),
              description="Cloud metadata SSRF (169.254.169.254)"),
    HuntSkill("lfi_path", "lfi", Severity.HIGH,
              ("php", "java", "node", "python", "ruby"),
              ("*?file=*", "*?path=*", "*?page=*"),
              description="Path traversal in file/include parameter"),
    HuntSkill("rfi_include", "rfi", Severity.CRITICAL,
              ("php",),
              ("*?include=*", "*?page=*"),
              description="Remote file include via include param"),
    HuntSkill("open_redirect", "open_redirect", Severity.MEDIUM,
              ("*",),
              ("*?redirect=*", "*?next=*", "*?return=*"),
              description="Unvalidated redirect via param"),
    HuntSkill("auth_bypass", "auth_bypass", Severity.CRITICAL,
              ("*",),
              ("*/admin*", "*/login*", "*/api/*"),
              description="Authentication bypass / missing check"),
    HuntSkill("idor_numeric", "idor", Severity.HIGH,
              ("*",),
              ("*?id=*", "*?user=*", "*/users/*"),
              description="Insecure direct object reference by numeric id"),
    HuntSkill("idor_uuid", "idor", Severity.HIGH,
              ("*",),
              ("*/resource/*", "*/file/*"),
              description="IDOR via UUID guessable reference"),
    HuntSkill("race_condition", "race", Severity.HIGH,
              ("*",),
              ("*/transfer*", "*/coupon*", "*/redeem*"),
              description="TOCTOU race condition in business logic"),
    HuntSkill("graphql_introspect", "graphql", Severity.MEDIUM,
              ("graphql", "node", "python", "ruby"),
              ("*/graphql*", "*/graphiql*"),
              description="GraphQL introspection enabled"),
    HuntSkill("graphql_batching", "graphql", Severity.HIGH,
              ("graphql",),
              ("*/graphql*",),
              description="GraphQL batching enables brute force"),
    HuntSkill("oauth_csrf", "oauth", Severity.HIGH,
              ("oauth",),
              ("*/oauth/*", "*/authorize*"),
              description="OAuth state param absent (CSRF)"),
    HuntSkill("jwt_none_alg", "jwt", Severity.CRITICAL,
              ("jwt",),
              ("*",),
              description="JWT alg=none acceptance"),
    HuntSkill("jwt_weak_secret", "jwt", Severity.CRITICAL,
              ("jwt",),
              ("*",),
              description="JWT signed with weak HS256 secret"),
    HuntSkill("cookie_missing_secure", "cookie", Severity.LOW,
              ("*",),
              ("*",),
              description="Session cookie missing Secure attribute"),
    HuntSkill("cookie_missing_httponly", "cookie", Severity.LOW,
              ("*",),
              ("*",),
              description="Session cookie missing HttpOnly attribute"),
    HuntSkill("cors_wildcard", "cors", Severity.MEDIUM,
              ("*",),
              ("*/api/*",),
              description="CORS Access-Control-Allow-Origin: *"),
    HuntSkill("cors_origin_reflect", "cors", Severity.HIGH,
              ("*",),
              ("*/api/*",),
              description="CORS reflects arbitrary Origin header"),
    HuntSkill("subdomain_takeover", "subdomain_takeover", Severity.HIGH,
              ("aws", "github", "heroku", "azure", "shopify"),
              ("*",),
              description="Dangling DNS for third-party service"),
    HuntSkill("exposed_git", "info_disclosure", Severity.MEDIUM,
              ("*",),
              ("*/.git/*", "*/.git"),
              description="Exposed .git directory"),
    HuntSkill("exposed_env", "info_disclosure", Severity.HIGH,
              ("*",),
              ("*/.env", "*/env"),
              description=".env file served publicly"),
    HuntSkill("swagger_exposed", "info_disclosure", Severity.LOW,
              ("*",),
              ("*/swagger*", "*/openapi*", "*/api-docs*"),
              description="API docs exposed without auth"),
    HuntSkill("admin_path_open", "info_disclosure", Severity.MEDIUM,
              ("*",),
              ("*/admin*", "*/actuator*", "*/wp-admin*"),
              description="Admin endpoint reachable without auth"),
    HuntSkill("deserialization_java", "deserialization", Severity.CRITICAL,
              ("java",),
              ("*",),
              description="Java deserialization gadget endpoint"),
    HuntSkill("deserialization_python", "deserialization", Severity.CRITICAL,
              ("python",),
              ("*",),
              description="Python pickle/YAML load gadget endpoint"),
    HuntSkill("ssrf_aws_imdsv1", "ssrf", Severity.CRITICAL,
              ("aws",),
              ("*",),
              description="AWS IMDSv1 reachable"),
    HuntSkill("iam_overpermissive", "iam", Severity.HIGH,
              ("aws", "gcp", "azure"),
              ("*",),
              description="IAM policy grants excessive permissions"),
    HuntSkill("s3_public_bucket", "s3", Severity.HIGH,
              ("aws",),
              ("*.s3.amazonaws.com",),
              description="S3 bucket policy permits public read"),
    HuntSkill("azure_blob_public", "azure_blob", Severity.HIGH,
              ("azure",),
              ("*.blob.core.windows.net",),
              description="Azure blob container is publicly listable"),
    HuntSkill("password_reuse", "credential", Severity.HIGH,
              ("*",),
              ("*/login*", "*/auth*"),
              description="Password reuse across services"),
    HuntSkill("default_creds", "credential", Severity.HIGH,
              ("*",),
              ("*/admin*", "*/login*"),
              description="Default credentials accepted"),
    HuntSkill("rate_limit_missing", "rate_limit", Severity.MEDIUM,
              ("*",),
              ("*/login*", "*/api/*"),
              description="Endpoint lacks rate limit"),
    HuntSkill("debug_endpoint", "info_disclosure", Severity.MEDIUM,
              ("*",),
              ("*/debug*", "*/trace*", "*/actuator*"),
              description="Debug/trace endpoint exposed"),
    HuntSkill("insecure_deserialization_yaml", "deserialization", Severity.CRITICAL,
              ("python", "ruby", "java"),
              ("*",),
              description="YAML.load / unsafe YAML parsing"),
    HuntSkill("xxe_basic", "xxe", Severity.HIGH,
              ("java", "dotnet", "python"),
              ("*",),
              description="XML external entity injection"),
    HuntSkill("xpath_injection", "injection", Severity.HIGH,
              ("java", "dotnet", "python"),
              ("*",),
              description="XPath injection via unsanitized input"),
    HuntSkill("header_stripping_proxy", "smuggling", Severity.HIGH,
              ("nginx", "haproxy", "envoy"),
              ("*",),
              description="Header smuggling via proxy frontend"),
    HuntSkill("cache_poisoning", "cache_poisoning", Severity.HIGH,
              ("*",),
              ("*",),
              description="Web cache poisoning via unkeyed header"),
)


# ---------------------------------------------------------------------------
# Stale-high detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StaleLead:
    lead_id: str
    age_days: float
    severity: Severity
    title: str = ""


@dataclass(frozen=True)
class Lead:
    """A hunting lead tracked by the board."""

    lead_id: str
    title: str
    url: str
    tech: str = ""
    severity: Severity = Severity.INFO
    bug_class: str = ""
    tags: Tuple[str, ...] = field(default_factory=tuple)
    created_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    last_updated_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> Dict[str, object]:
        return {
            "lead_id": self.lead_id,
            "title": self.title,
            "url": self.url,
            "tech": self.tech,
            "severity": self.severity.value,
            "bug_class": self.bug_class,
            "tags": list(self.tags),
            "created_at_ms": self.created_at_ms,
            "last_updated_ms": self.last_updated_ms,
        }


class LeadBoard:
    """Skill-routing + stale-high housekeeping."""

    SCHEMA = SCHEMA

    def __init__(self, catalogue: Optional[Sequence[HuntSkill]] = None) -> None:
        self._catalogue: Tuple[HuntSkill, ...] = tuple(catalogue or _CATALOGUE)
        self._leads: Dict[str, Lead] = {}

    # -- catalogue API -------------------------------------------------------

    def catalogue(self) -> List[HuntSkill]:
        return list(self._catalogue)

    def add_skill(self, skill: HuntSkill) -> None:
        self._catalogue = self._catalogue + (skill,)

    # -- routing API ---------------------------------------------------------

    def route(self, lead: Mapping[str, object]) -> List[HuntSkill]:
        """Return every catalogue skill that matches ``lead`` (ordered by severity)."""
        rank = {Severity.CRITICAL: 4, Severity.HIGH: 3,
                Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
        matches = [s for s in self._catalogue if s.matches(lead)]
        matches.sort(key=lambda s: (rank.get(s.severity, 0), s.name), reverse=True)
        return matches

    # -- lead lifecycle ------------------------------------------------------

    def upsert_lead(self, lead: Lead) -> None:
        now = int(time.time() * 1000)
        self._leads[lead.lead_id] = dataclasses_replace(lead, last_updated_ms=now) \
            if lead.lead_id in self._leads else lead

    def list_leads(self, *, severity: Optional[Severity] = None) -> List[Lead]:
        rows = list(self._leads.values())
        if severity is not None:
            rows = [r for r in rows if r.severity == severity]
        return rows

    # -- housekeeping --------------------------------------------------------

    def detect_stale_highs(self, board: Optional[Iterable[Lead]] = None,
                           *, max_age_days: float = 7.0,
                           now_ms: Optional[int] = None) -> List[StaleLead]:
        """Flag HIGH+ leads older than ``max_age_days``."""
        now = int(now_ms if now_ms is not None else time.time() * 1000)
        rows = list(board) if board is not None else list(self._leads.values())
        out: List[StaleLead] = []
        for lead in rows:
            if lead.severity not in (Severity.HIGH, Severity.CRITICAL):
                continue
            age_days = (now - lead.last_updated_ms) / (1000 * 86400)
            if age_days > max_age_days:
                out.append(StaleLead(
                    lead_id=lead.lead_id, age_days=age_days,
                    severity=lead.severity, title=lead.title,
                ))
        return out


def dataclasses_replace(lead: Lead, **changes: object) -> Lead:
    """Local ``dataclasses.replace`` shim — same API, avoids the import."""
    import dataclasses as _dc
    return _dc.replace(lead, **changes)


__all__ = [
    "SCHEMA", "Severity", "HuntSkill", "Lead", "StaleLead", "LeadBoard",
]