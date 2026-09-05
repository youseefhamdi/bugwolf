"""Subdomain takeover scanner via CNAME fingerprints (5+ common services)."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


CNAME_FINGERPRINTS = (
    {"service": "AWS S3",           "cname_suffix": ".s3.amazonaws.com",
     "http_body": "NoSuchBucket", "nxdomain_hint": "BucketName"},
    {"service": "GitHub Pages",     "cname_suffix": ".github.io",
     "http_body": "There isn't a GitHub Pages site here", "nxdomain_hint": ""},
    {"service": "Heroku",           "cname_suffix": ".herokuapp.com",
     "http_body": "No such app", "nxdomain_hint": ""},
    {"service": "Azure CloudApp",   "cname_suffix": ".cloudapp.net",
     "http_body": "404 Web Site not found", "nxdomain_hint": ""},
    {"service": "Azure CloudApps",  "cname_suffix": ".azurewebsites.net",
     "http_body": "404 Web Site not found", "nxdomain_hint": ""},
    {"service": "Shopify",          "cname_suffix": ".myshopify.com",
     "http_body": "Sorry, this shop is currently unavailable", "nxdomain_hint": ""},
    {"service": "Fastly",           "cname_suffix": ".fastly.net",
     "http_body": "Fastly error: unknown domain", "nxdomain_hint": ""},
    {"service": "Pantheon",         "cname_suffix": ".pantheonsite.io",
     "http_body": "404 Unknown Site", "nxdomain_hint": ""},
)


def _pid(service: str) -> str:
    return "takeover-" + hashlib.sha256(service.encode()).hexdigest()[:10]


class SubdomainTakeoverScanner(Scanner):
    name = "subdomain_takeover"
    description = "Subdomain takeover via dangling CNAME fingerprints"
    bug_class = "subdomain_takeover"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "host" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        host = target.get("host", "")
        cname = target.get("cname", "")
        nxdomain = bool(target.get("nxdomain"))
        if not host:
            return findings
        url = "https://" + host
        try:
            resp = transport("GET", url, headers=None, body=None)
        except Exception:
            resp = None
        rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
        for fp in CNAME_FINGERPRINTS:
            match_cname = fp["cname_suffix"] and (
                cname.endswith(fp["cname_suffix"]) or host.endswith(fp["cname_suffix"]))
            match_body = fp["http_body"] and fp["http_body"] in rbody
            if (match_cname and match_body) or (nxdomain and match_cname):
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=self.default_severity,
                    endpoint=url,
                    method="GET",
                    evidence=f"CNAME -> {fp['service']} ({fp['cname_suffix']}) with takeover fingerprint",
                    reproducer=f"host {host}  cname {cname}  body match={match_body}",
                    remediation="Remove the dangling DNS record, or reclaim the third-party resource before attackers do.",
                    payload_id=_pid(fp["service"]),
                    extra={"service": fp["service"], "nxdomain": nxdomain},
                ))
        return findings


def cname_fingerprints() -> List[Dict[str, str]]:
    return [dict(fp) for fp in CNAME_FINGERPRINTS]


__all__ = ["SubdomainTakeoverScanner", "CNAME_FINGERPRINTS", "cname_fingerprints"]
