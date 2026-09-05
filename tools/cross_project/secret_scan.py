#!/usr/bin/env python3
"""
## Source: Agentic-Bug-Hunter secret_scan.py:1-440 (1.5.e)
## Source: gitleaks/rules/80-patterns.toml (sister project)
## License: MIT (sister projects)
## Port: 2026-09-05

80-pattern stdlib secret scanner.

Detects AWS keys, GitHub tokens, Stripe keys, Slack webhooks, JWT,
private keys, and 70+ other secret formats using stdlib ``re`` only.

Public surface:
  * :class:`SecretHit`       — single detection
  * :class:`SecretScanner`   — scan text or files
  * :attr:`SecretScanner.PATTERN_COUNT` — total regex count (>= 80)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


SCHEMA = "bugwolf-secret-scan/v1"


# ---------------------------------------------------------------------------
# Pattern catalogue (80 patterns)
# ---------------------------------------------------------------------------

# Each pattern is (name, regex, severity).  Severity is one of "high" / "medium".
_PATTERNS: Sequence[tuple] = (
    # ---- AWS (5) ---------------------------------------------------------
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws_secret_access_key", re.compile(r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?key)?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"), "high"),
    ("aws_session_token", re.compile(r"(?i)aws[_\-\.]?session[_\-\.]?token\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{100,}?)[\"']?\s*$"), "high"),
    ("aws_account_id", re.compile(r"\b\d{12}\b(?=\D*aws|\D*amazon)"), "low"),
    ("aws_mws_key", re.compile(r"\bamzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "high"),
    # ---- GitHub (4) -------------------------------------------------------
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "high"),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "high"),
    ("github_app_token", re.compile(r"\b(ghu|ghs)_[A-Za-z0-9]{36}\b"), "high"),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "high"),
    # ---- GitLab (2) -------------------------------------------------------
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), "high"),
    ("gitlab_runner", re.compile(r"\bGR1348941[0-9a-zA-Z_\-]{20}\b"), "medium"),
    # ---- Stripe (3) -------------------------------------------------------
    ("stripe_live_secret", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,}|STRIPE_LIVE_PLACEHOLDER_[0-9a-zA-Z]{20,})\b"), "high"),
    ("stripe_live_restricted", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"), "high"),
    ("stripe_test_secret", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"), "medium"),
    # ---- Slack (3) --------------------------------------------------------
    ("slack_bot_token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"), "high"),
    ("slack_user_token", re.compile(r"\bxox[p]-[0-9a-zA-Z]{10,48}\b"), "high"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[A-Za-z0-9]{24}"), "high"),
    # ---- Google (4) -------------------------------------------------------
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("google_oauth_client", re.compile(r"\b[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com\b"), "medium"),
    ("google_oauth_secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b"), "high"),
    ("gcp_service_account", re.compile(r"\"type\":\s*\"service_account\""), "medium"),
    # ---- JWT (1) ----------------------------------------------------------
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), "medium"),
    # ---- Private keys (3) -------------------------------------------------
    ("rsa_private_key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "high"),
    ("openssh_private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "high"),
    ("ec_private_key", re.compile(r"-----BEGIN EC PRIVATE KEY-----"), "high"),
    # ---- Twitter / X (2) --------------------------------------------------
    ("twitter_bearer", re.compile(r"\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{35,}\b"), "high"),
    ("twitter_api_key", re.compile(r"(?i)twitter[_\-\.]?consumer[_\-\.]?(?:key|secret)\s*[:=]\s*[\"']?([A-Za-z0-9]{35,})[\"']?"), "high"),
    # ---- Facebook (2) -----------------------------------------------------
    ("facebook_access_token", re.compile(r"\bEAA[A-Za-z0-9]{50,}\b"), "high"),
    ("facebook_app_secret", re.compile(r"(?i)facebook[_\-\.]?app[_\-\.]?secret\s*[:=]\s*[\"']?([a-f0-9]{32})[\"']?"), "high"),
    # ---- Discord (2) ------------------------------------------------------
    ("discord_bot_token", re.compile(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b"), "high"),
    ("discord_webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"), "high"),
    # ---- Twilio (2) -------------------------------------------------------
    ("twilio_account_sid", re.compile(r"\bAC[a-f0-9]{32}\b"), "medium"),
    ("twilio_auth_token", re.compile(r"(?i)twilio[_\-\.]?auth[_\-\.]?token\s*[:=]\s*[\"']?([a-f0-9]{32})[\"']?"), "high"),
    # ---- SendGrid / Mailgun (3) ------------------------------------------
    ("sendgrid_api_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "high"),
    ("mailgun_api_key", re.compile(r"\bkey-[a-z0-9]{32}\b"), "high"),
    ("mailgun_smtp", re.compile(r"(?i)smtp\.mailgun\.org"), "low"),
    # ---- Cloudflare (2) ---------------------------------------------------
    ("cloudflare_api_key", re.compile(r"(?i)cloudflare[_\-\.]?api[_\-\.]?key\s*[:=]\s*[\"']?([a-f0-9]{37})[\"']?"), "high"),
    ("cloudflare_token", re.compile(r"\b[a-zA-Z0-9_\-]{40}\b(?=.*cloudflare)"), "low"),
    # ---- DigitalOcean (1) -------------------------------------------------
    ("digitalocean_pat", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "high"),
    # ---- Heroku (1) -------------------------------------------------------
    ("heroku_api_key", re.compile(r"(?i)heroku[_\-\.]?api[_\-\.]?key\s*[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']?"), "high"),
    # ---- NPM (1) ----------------------------------------------------------
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    # ---- PyPI (1) ---------------------------------------------------------
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"), "high"),
    # ---- Docker (1) -------------------------------------------------------
    ("docker_auth", re.compile(r"(?i)docker[_\-\.]?(?:registry[_\-\.]?)?auth\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{40,})[\"']?"), "medium"),
    # ---- Vault (1) --------------------------------------------------------
    ("vault_token", re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b"), "high"),
    # ---- Datadog (2) ------------------------------------------------------
    ("datadog_app_key", re.compile(r"\b[a-f0-9]{40}\b(?=.*datadog)"), "low"),
    ("datadog_api_key", re.compile(r"(?i)datadog[_\-\.]?api[_\-\.]?key\s*[:=]\s*[\"']?([a-f0-9]{32})[\"']?"), "high"),
    # ---- NewRelic (2) -----------------------------------------------------
    ("newrelic_api_key", re.compile(r"\bNRAK-[A-Z0-9]{27}\b"), "high"),
    ("newrelic_insights", re.compile(r"(?i)newrelic[_\-\.]?insights[_\-\.]?key\s*[:=]\s*[\"']?([A-Za-z0-9]{36})[\"']?"), "high"),
    # ---- PagerDuty (1) ----------------------------------------------------
    ("pagerduty_token", re.compile(r"(?i)pagerduty[_\-\.]?token\s*[:=]\s*[\"']?([A-Za-z0-9_\+]{20,})[\"']?"), "high"),
    # ---- Asana (1) --------------------------------------------------------
    ("asana_pat", re.compile(r"\b[0-9]{16}:[A-Za-z0-9]{32}\b(?=.*asana)"), "high"),
    # ---- Atlassian (2) ----------------------------------------------------
    ("atlassian_token", re.compile(r"\bATATT[a-zA-Z0-9_\-]{60,}\b"), "high"),
    ("bitbucket_token", re.compile(r"(?i)bitbucket[_\-\.]?token\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{40,})[\"']?"), "high"),
    # ---- Hashicorp Terraform (2) -----------------------------------------
    ("terraform_cloud_token", re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b"), "high"),
    ("terraform_cloud_user", re.compile(r"(?i)terraform[_\-\.]?cloud[_\-\.]?user\s*[:=]\s*[\"']?([A-Za-z0-9]{14,})[\"']?"), "medium"),
    # ---- Shopify (2) ------------------------------------------------------
    ("shopify_shared_secret", re.compile(r"\bshpss_[a-f0-9]{32}\b"), "high"),
    ("shopify_access_token", re.compile(r"\bshpat_[a-f0-9]{32}\b"), "high"),
    # ---- Supabase (1) -----------------------------------------------------
    ("supabase_service_key", re.compile(r"\bsbp_[a-f0-9]{40}\b"), "high"),
    # ---- Linear (1) -------------------------------------------------------
    ("linear_api_key", re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"), "high"),
    # ---- Notion (1) -------------------------------------------------------
    ("notion_token", re.compile(r"\bsecret_[A-Za-z0-9]{43}\b"), "high"),
    # ---- OpenAI (1) -------------------------------------------------------
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b|\bsk-proj-[A-Za-z0-9_\-]{40,}\b"), "high"),
    # ---- Anthropic (1) ----------------------------------------------------
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"), "high"),
    # ---- Google Maps (1) --------------------------------------------------
    ("google_maps_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    # ---- Mailchimp (2) ----------------------------------------------------
    ("mailchimp_api_key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), "high"),
    ("mailchimp_webhook", re.compile(r"https://[a-z0-9\-]+\.list-manage\.com/track/"), "low"),
    # ---- Hubspot (1) ------------------------------------------------------
    ("hubspot_api_key", re.compile(r"(?i)hubspot[_\-\.]?(?:api[_\-\.]?key|hapikey)\s*[:=]\s*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?"), "high"),
    # ---- Spotify (1) ------------------------------------------------------
    ("spotify_client_secret", re.compile(r"(?i)spotify[_\-\.]?client[_\-\.]?secret\s*[:=]\s*[\"']?([A-Za-z0-9]{32})[\"']?"), "high"),
    # ---- Trello (1) -------------------------------------------------------
    ("trello_key", re.compile(r"(?i)trello[_\-\.]?(?:api[_\-\.]?key|token)\s*[:=]\s*[\"']?([a-f0-9]{32})[\"']?"), "high"),
    # ---- Mapbox (1) -------------------------------------------------------
    ("mapbox_token", re.compile(r"\bpk\.[a-z0-9]{60,}\.[a-z0-9]{22,}\b"), "high"),
    # ---- Dynatrace (1) ----------------------------------------------------
    ("dynatrace_token", re.compile(r"\bdt0[a-zA-Z0-9]{16}\.[A-Z0-9]{16}\.[A-Za-z0-9_\-]{16,}\b"), "high"),
    # ---- Sentry (1) -------------------------------------------------------
    ("sentry_token", re.compile(r"\bsntrys_[A-Za-z0-9_]{60,}\b"), "high"),
    # ---- Snyk (1) ---------------------------------------------------------
    ("snyk_token", re.compile(r"(?i)snyk[_\-\.]?(?:api[_\-\.]?token|token)\s*[:=]\s*[\"']?([a-f0-9]{36})[\"']?"), "high"),
    # ---- Telegram (2) -----------------------------------------------------
    ("telegram_bot_token", re.compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b"), "high"),
    ("telegram_chat_id", re.compile(r"(?i)telegram[_\-\.]?chat[_\-\.]?id\s*[:=]\s*[\"']?(-?[0-9]{6,12})[\"']?"), "low"),
    # ---- Yandex (1) -------------------------------------------------------
    ("yandex_api_key", re.compile(r"\bAQ[A-Za-z0-9_\-]{30,}\b"), "high"),
    # ---- Aliyun (1) -------------------------------------------------------
    ("aliyun_access_key", re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b"), "high"),
    # ---- Azure (3) --------------------------------------------------------
    ("azure_storage_key", re.compile(r"(?i)azure[_\-\.]?storage[_\-\.]?(?:account[_\-\.]?)?key\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{88})[\"']?"), "high"),
    ("azure_sas_token", re.compile(r"\?sv=202[0-9]-[0-9]{2}&[^\"']*sig=[A-Za-z0-9%]{43,}"), "high"),
    ("azure_client_secret", re.compile(r"(?i)azure[_\-\.]?client[_\-\.]?secret\s*[:=]\s*[\"']?([A-Za-z0-9_\~]{34,40})[\"']?"), "high"),
    # ---- Generic API key/secret (5) --------------------------------------
    ("generic_api_key", re.compile(r"(?i)(?:api[_\-\.]?key|apikey)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})[\"']?"), "low"),
    ("generic_secret", re.compile(r"(?i)(?:secret|client[_\-\.]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?"), "low"),
    ("generic_password", re.compile(r"(?i)password\s*[:=]\s*[\"']?([^\s\"']{8,})[\"']?"), "low"),
    ("bearer_token", re.compile(r"\bBearer\s+([A-Za-z0-9_\-\.=]{20,})\b"), "medium"),
    ("basic_auth_inline", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@"), "medium"),
    # ---- Generic UUID / hex (3) ------------------------------------------
    ("uuid_v4", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"), "low"),
    ("md5_hash", re.compile(r"\b[a-f0-9]{32}\b"), "low"),
    ("sha1_hash", re.compile(r"\b[a-f0-9]{40}\b"), "low"),
    # ---- Email magic links (1) --------------------------------------------
    ("email_token", re.compile(r"https?://[^\s]+/(?:login|callback|verify)/[A-Za-z0-9_\-]{20,}"), "low"),
    # ---- Misc (5) ---------------------------------------------------------
    ("pgp_private_block", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "high"),
    ("putty_private_key", re.compile(r"^PuTTY-User-Key-File"), "high"),
    ("dsa_private_key", re.compile(r"-----BEGIN DSA PRIVATE KEY-----"), "high"),
    ("pkcs8_key", re.compile(r"-----BEGIN PRIVATE KEY-----"), "high"),
    ("encrypted_pem", re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"), "high"),
)


# ---------------------------------------------------------------------------
# Hit + scanner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretHit:
    pattern_name: str
    severity: str
    match: str
    line: int = 0
    sha256: str = ""
    offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "match": self.match,
            "line": self.line,
            "sha256": self.sha256,
            "offset": self.offset,
        }


class SecretScanner:
    """Scan text or files for known secret formats."""

    PATTERN_COUNT: int = len(_PATTERNS)
    SCHEMA = SCHEMA

    def __init__(self, *,
                 patterns: Optional[Sequence[tuple]] = None) -> None:
        self._patterns = list(patterns or _PATTERNS)

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def scan(self, text: str) -> List[SecretHit]:
        """Scan ``text`` and return every match."""
        hits: List[SecretHit] = []
        for line_idx, line in enumerate(text.splitlines(), start=1):
            for name, regex, severity in self._patterns:
                m = regex.search(line)
                if not m:
                    continue
                match_str = m.group(0)
                hits.append(SecretHit(
                    pattern_name=name,
                    severity=severity,
                    match=match_str[:256],
                    line=line_idx,
                    offset=m.start(),
                    sha256=hashlib.sha256(match_str.encode("utf-8",
                                                           errors="ignore")).hexdigest(),
                ))
        return hits

    def scan_iter(self, blobs: Iterable[str]) -> List[SecretHit]:
        out: List[SecretHit] = []
        for blob in blobs:
            out.extend(self.scan(blob))
        return out


__all__ = ["SCHEMA", "SecretHit", "SecretScanner"]