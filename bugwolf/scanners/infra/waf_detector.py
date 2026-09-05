"""WAF detection scanner (recognises 4+ common WAF fingerprints)."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


WAF_FINGERPRINTS = (
    {"vendor": "Cloudflare",
     "header_keys": ("cf-ray", "cf-cache-status", "cf-request-id"),
     "cookie_keys": ("__cfduid", "cf_bm"),
     "server_keys": ("cloudflare",)},
    {"vendor": "Akamai",
     "header_keys": ("x-akamai-request-id", "akamai-origin-hop", "x-akamai-pragma"),
     "cookie_keys": ("akamai", "ak_bmsc", "bm_sz"),
     "server_keys": ("akamai",)},
    {"vendor": "AWS WAF",
     "header_keys": ("x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop"),
     "cookie_keys": ("aws-waf-token",),
     "server_keys": ("awselb", "amazons3")},
    {"vendor": "Imperva",
     "header_keys": ("x-iinfo", "x-cdn", "x-incap"),
     "cookie_keys": ("incap_ses", "visid_incap"),
     "server_keys": ("imperva", "incapsula")},
    {"vendor": "Sucuri",
     "header_keys": ("x-sucuri-id", "x-sucuri-cache"),
     "cookie_keys": ("sucuri",),
     "server_keys": ("sucuri",)},
    {"vendor": "F5 BIG-IP",
     "header_keys": ("x-cnection", "x-wa-info"),
     "cookie_keys": ("bigipserver", "f5_cspm"),
     "server_keys": ("big-ip", "f5")},
)


def _pid(vendor: str) -> str:
    return "waf-detect-" + hashlib.sha256(vendor.encode()).hexdigest()[:10]


class WAFDetectorScanner(Scanner):
    name = "waf_detector"
    description = "Detects commercial WAF/CDN in front of the origin"
    bug_class = "waf_detection"
    default_severity = "informational"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "url" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        url = target.get("url", "")
        try:
            resp = transport("GET", url, headers=None, body=None)
        except Exception:
            resp = None
        if not isinstance(resp, dict):
            return findings
        headers = {str(k).lower(): str(v).lower() for k, v in
                   (resp.get("headers") or {}).items()}
        cookies = str(headers.get("set-cookie", "")).lower()
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        server_blob = server + " " + powered
        for fp in WAF_FINGERPRINTS:
            header_hit = any(h in headers for h in fp["header_keys"])
            cookie_hit = any(c in cookies for c in fp["cookie_keys"])
            server_hit = any(s in server_blob for s in fp["server_keys"])
            if header_hit or cookie_hit or server_hit:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method="GET",
                    evidence=f"WAF/CDN vendor: {fp['vendor']} (header={header_hit}, "
                             f"cookie={cookie_hit}, server={server_hit})",
                    reproducer=f"GET {url}",
                    remediation="WAF identified — tune the bypass encoder to the vendor's signature set.",
                    payload_id=_pid(fp["vendor"]),
                    extra={
                        "vendor": fp["vendor"],
                        "header_hit": header_hit,
                        "cookie_hit": cookie_hit,
                        "server_hit": server_hit,
                    },
                ))
        return findings


def waf_fingerprints() -> List[Dict[str, Any]]:
    return [dict(fp) for fp in WAF_FINGERPRINTS]


__all__ = ["WAFDetectorScanner", "WAF_FINGERPRINTS", "waf_fingerprints"]
