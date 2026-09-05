"""Subdomain permutations / alterations.

Generates a list of likely subdomains by inserting/omitting common
labels (e.g. ``www1``, ``api-staging``, ``m-test``).  Does NOT perform
DNS lookups here — the orchestrator can pipe the list into
``DnsBruteModule`` to validate.

No API key required.  Deterministic, in-memory.
"""

from __future__ import annotations

from typing import List, Optional

from .. import PassiveFinding
from ..passive_base import PassiveModule


_BASES = ("api", "app", "auth", "admin", "blog", "cdn", "dev",
          "docs", "mail", "m", "mobile", "shop", "staging",
          "static", "test", "uat", "vpn", "www", "beta")

_SUFFIXES = ("1", "2", "3", "-1", "-2", "-3", "-01", "-stg", "-prod",
             "-dev", "-uat", "-test", "-beta", "-legacy", "-old", "-new",
             "-v1", "-v2", "-v3", "-internal", "-external")

_HOST_LABELS = ("internal", "private", "corp", "lan", "wan")


class SubdomainAltsModule(PassiveModule):
    name = "subdomain_alts"
    kind = "subdomain"
    requires_key = False
    env_var = ""

    def __init__(self, *, api_key: Optional[str] = None) -> None:
        super().__init__(api_key=api_key)

    def _enrich(self, target: str, *, budget: int) -> List[PassiveFinding]:
        now = self.now_iso()
        out: List[PassiveFinding] = []
        seen = set()
        target = target.strip().strip(".")
        if not target:
            return []
        for base in _BASES:
            for suf in _SUFFIXES:
                host = f"{base}{suf}.{target}"
                if host in seen:
                    continue
                seen.add(host)
                out.append(PassiveFinding(
                    kind="subdomain",
                    value=host,
                    source=self.name,
                    confidence=0.2,
                    seen_at=now,
                    extra={"base": base, "suffix": suf,
                           "validated": False},
                ))
                if len(out) >= int(budget):
                    return out
        for label in _HOST_LABELS:
            host = f"{label}.{target}"
            if host in seen:
                continue
            seen.add(host)
            out.append(PassiveFinding(
                kind="subdomain",
                value=host,
                source=self.name,
                confidence=0.2,
                seen_at=now,
                extra={"base": label, "suffix": "",
                       "validated": False},
            ))
            if len(out) >= int(budget):
                break
        return out


__all__ = ["SubdomainAltsModule"]