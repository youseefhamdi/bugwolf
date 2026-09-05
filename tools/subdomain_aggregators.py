#!/usr/bin/env python3
"""
## Source: bugwolf PLAN_AUDIT.md -- free recon API list (Phase 2.y)
## Source: jsmon.io documentation (https://subdomains.jsmon.sh/api/domain/<d>)
## Source: crt.name documentation (https://crt.name/v1/search?apex=<d>)
## License: bugwolf-internal + MIT-equivalent (each upstream public API)
## Port: 2026-09-05

Free subdomain-aggregator clients.

Two free sources -- no API key, no authentication:
  * https://subdomains.jsmon.sh/api/domain/<domain>  -- plain-text list
  * https://crt.name/v1/search?apex=<domain>        -- JSON envelope

We aggregate across both via :meth:`SubdomainAggregator.aggregate`,
which dedupes and sorts. The transport uses ``urllib`` from the stdlib
(no external HTTP dep). Every network error is caught and returns an
empty list (STUB-safe).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List


LOG = logging.getLogger("bugwolf.subdomain_aggregators")

JSMON_URL = "https://subdomains.jsmon.sh/api/domain/{domain}"
CRT_NAME_URL = "https://crt.name/v1/search?apex={domain}"

# Hard timeout (seconds) -- prevent a hung remote from blocking the run.
HTTP_TIMEOUT = 10

USER_AGENT_HEADER = ("User-Agent", "bugwolf/2.0 (+free-recon)")


class SubdomainAggregator:
    """Free subdomain-aggregator client (jsmon + crt.name)."""

    def __init__(self, *, timeout: int = HTTP_TIMEOUT):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._timeout = timeout

    # -- single sources ------------------------------------------------------

    def fetch_jsmon(self, domain: str) -> List[str]:
        """Hit ``subdomains.jsmon.sh`` and return the raw text list."""
        if not domain:
            return []
        url = JSMON_URL.format(domain=urllib.parse.quote(domain))
        try:
            req = urllib.request.Request(url, headers=dict([USER_AGENT_HEADER]))
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
            LOG.warning("jsmon fetch failed for %s: %s", domain, exc)
            return []
        except Exception as exc:    # pragma: no cover - defensive
            LOG.warning("jsmon unexpected error for %s: %s", domain, exc)
            return []

        out: List[str] = []
        for line in data.splitlines():
            line = line.strip().lower()
            if line and "." in line:
                out.append(line)
        return out

    def fetch_crt_name(self, domain: str) -> List[str]:
        """Hit ``crt.name`` and return the JSON-parsed subdomain list."""
        if not domain:
            return []
        url = CRT_NAME_URL.format(domain=urllib.parse.quote(domain))
        try:
            req = urllib.request.Request(url, headers=dict([USER_AGENT_HEADER]))
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
            LOG.warning("crt.name fetch failed for %s: %s", domain, exc)
            return []
        except Exception as exc:    # pragma: no cover - defensive
            LOG.warning("crt.name unexpected error for %s: %s", domain, exc)
            return []

        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            LOG.warning("crt.name JSON parse failed for %s: %s", domain, exc)
            return []

        names: List[str] = []
        # crt.name returns a list of dicts with ``name`` / ``value`` keys.
        if isinstance(payload, list):
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                for key in ("name", "value", "common_name", "dNSName"):
                    val = entry.get(key)
                    if isinstance(val, str):
                        names.append(val.lower())
                        break
        elif isinstance(payload, dict):
            # Some crt.name versions return {"results": [...]}.
            inner = payload.get("results") or payload.get("data") or []
            if isinstance(inner, list):
                for entry in inner:
                    if not isinstance(entry, dict):
                        continue
                    for key in ("name", "value", "common_name", "dNSName"):
                        val = entry.get(key)
                        if isinstance(val, str):
                            names.append(val.lower())
                            break
        return names

    # -- aggregation ---------------------------------------------------------

    def aggregate(self, domains: List[str]) -> Dict[str, List[str]]:
        """Return ``{domain: [sorted_unique_subdomains]}`` across sources."""
        if not isinstance(domains, (list, tuple)):
            raise TypeError("domains must be a list/tuple")
        out: Dict[str, List[str]] = {}
        for d in domains:
            if not isinstance(d, str) or not d:
                continue
            jsmon = set(self.fetch_jsmon(d))
            crt = set(self.fetch_crt_name(d))
            merged = sorted(jsmon | crt)
            out[d] = merged
        return out

    def fetch_single(self, domain: str) -> List[str]:
        """Single-source fetch (jsmon first, fall back to crt.name)."""
        if not domain:
            return []
        jsmon = self.fetch_jsmon(domain)
        if jsmon:
            return sorted(set(jsmon))
        return sorted(set(self.fetch_crt_name(domain)))

    def timeout(self) -> int:
        return self._timeout