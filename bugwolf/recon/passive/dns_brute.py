"""DNS brute force via a small embedded wordlist.

Stub-safe: if no wordlist is provided, falls back to a tiny embedded
list.  Always returns ``[]`` on network failure.

No API key required.
"""

from __future__ import annotations

from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


_DEFAULT_WORDS = (
    "www", "mail", "smtp", "imap", "pop", "pop3", "ns1", "ns2",
    "ns3", "vpn", "vpn1", "vpn2", "api", "api1", "api2", "api3",
    "dev", "stage", "staging", "test", "uat", "qa", "sandbox",
    "blog", "shop", "store", "app", "apps", "auth", "login",
    "admin", "dashboard", "internal", "intranet", "cdn",
    "static", "assets", "media", "img", "images", "files",
    "beta", "alpha", "edge", "lb", "lb1", "lb2", "gw", "gateway",
    "m", "mobile", "wap", "old", "new", "legacy", "demo",
    "docs", "doc", "wiki", "kb", "help", "support",
    "mx", "mta", "mx1", "mx2", "smtp1", "smtp2",
    "git", "gitlab", "github", "ci", "jenkins", "jira",
    "status", "monitor", "metrics", "grafana", "prometheus",
    "db", "db1", "db2", "redis", "postgres", "mysql",
    "ldap", "ad", "okta", "sso", "id", "identity",
    "s3", "bucket", "cloudfront", "azure", "gcp",
    "k8s", "kube", "kubernetes", "rancher", "eks", "aks", "gke",
    "ftp", "sftp", "ssh", "shell", "jump", "jumphost", "bastion",
    "vpn", "wireguard", "openvpn",
)


class DnsBruteModule(PassiveModule):
    name = "dns_brute"
    kind = "subdomain"
    requires_key = False
    env_var = ""

    def __init__(self, *, wordlist: Optional[List[str]] = None,
                 api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)
        self._wordlist = list(wordlist) if wordlist else list(_DEFAULT_WORDS)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        target = target.strip().strip(".")
        if not target:
            return []
        out: List[PassiveFinding] = []
        seen = set()
        now = self.now_iso()
        for word in self._wordlist[: int(budget)]:
            host = f"{word}.{target}"
            if host in seen:
                continue
            seen.add(host)
            ip = self.safe_resolve(host)
            if not ip:
                continue
            out.append(PassiveFinding(
                kind="subdomain",
                value=host,
                source=self.name,
                confidence=0.7,
                seen_at=now,
                extra={"ip": ip, "word": word},
            ))
        return out


__all__ = ["DnsBruteModule"]