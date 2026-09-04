#!/usr/bin/env python3
"""Shipped intel channels (INTEGRATION_PLAN Phase E, v1.28).

Four channels, each with an ordered backend list where ``direct`` (the
bugwolf replay engine itself, scope-gated) is preferred and a documented
third party (r.jina.ai reader) is FALLBACK-ONLY:

  github_public  — org/repo facts feeding U1 (stack) and U2 (endpoints
                   leaked in public issues/READMEs)
  site_docs      — docs/changelog/pricing pages feeding U1/U2
  rss_feed       — product-cadence facts feeding U1 (new surfaces)
  jobs_page      — stack-from-job-posts feeding U1

Every channel is credential-free (v1 opsec gate).  The third-party
backend is documented in docs/INTEL_TRANSPARENCY.md (release-tested).
"""

from __future__ import annotations

import json
import time
from typing import Tuple
from urllib.parse import urlparse

from tools.intel.base import IntelChannel, JINA_PREFIX


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _direct_fetch(url: str) -> Tuple[int, str]:
    """The preferred backend: bugwolf's own replay engine (scope-gated,
    governed, byte-exact — the same transport every lane uses)."""
    from urllib.parse import urlparse as _up
    host = _up(url).netloc or str(url)
    path = _up(url).path or "/"
    raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           "User-Agent: BugWolf-Intel/1\r\n"
           "Accept: text/html,application/json,application/rss+xml\r\n"
           "Connection: close\r\n\r\n").encode("latin-1")
    from tools.runtime.replay.engine import replay_raw
    report = replay_raw(raw, host=url if "://" in url else f"https://{url}")
    return (report.status or 0), (report.body_preview or "")


def _jina_fetch(url: str) -> Tuple[int, str]:
    """Documented third-party fallback: the r.jina.ai reader.  What
    crosses and who sees it is stated in docs/INTEL_TRANSPARENCY.md."""
    import urllib.request
    request = urllib.request.Request(
        f"{JINA_PREFIX}{url}",
        headers={"User-Agent": "BugWolf-Intel/1", "Accept": "text/plain"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status, response.read(200_000).decode(
            "utf-8", "replace")


class _IntelChannel(IntelChannel):
    """Shared direct-then-jina failover implementation."""

    backends = ["direct", "jina"]
    tier = 0

    def fetch_backend(self, url: str, backend: str) -> Tuple[int, str]:
        if backend == "direct":
            return _direct_fetch(url)
        if backend == "jina":
            return _jina_fetch(url)
        raise ValueError(f"unknown backend {backend!r}")

    def check(self, config=None):  # real probe without network in tests
        return super().check(config)


class GithubPublicChannel(_IntelChannel):
    name = "github_public"
    description = "public GitHub org/repo facts (stack, endpoints in issues)"
    tier = 0

    def can_handle(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        return host == "github.com" or host.endswith(".github.com")

    def probe_url(self) -> str:
        return "https://api.github.com/zen"


class SiteDocsChannel(_IntelChannel):
    name = "site_docs"
    description = "target docs/changelog/pricing pages (surface freshness)"
    tier = 0

    def can_handle(self, url: str) -> bool:
        return url.startswith(("http://", "https://"))

    def probe_url(self) -> str:
        return "https://example.com/"


class RssFeedChannel(_IntelChannel):
    name = "rss_feed"
    description = "product blog/changelog feeds (new surfaces, cadence)"
    tier = 0

    def can_handle(self, url: str) -> bool:
        return url.startswith(("http://", "https://")) and \
            ("feed" in url or url.endswith((".xml", "/rss")))

    def parse(self, body: str) -> list:
        """Stdlib-XML feed digest: (title, link) pairs — a FACT digest,
        not the raw XML, rides into the model."""
        import re
        import xml.etree.ElementTree as ET
        items: list = []
        try:
            root = ET.fromstring(body)
            for item in root.iter():
                if item.tag.rsplit("}", 1)[-1] != "item":
                    continue
                title = link = ""
                for child in item:
                    tag = child.tag.rsplit("}", 1)[-1]
                    if tag == "title":
                        title = (child.text or "").strip()
                    elif tag == "link":
                        link = (child.text or "").strip()
                if title:
                    items.append({"title": title[:120], "link": link[:200]})
                if len(items) >= 20:
                    break
        except ET.ParseError:
            pass
        return items


class JobsPageChannel(_IntelChannel):
    name = "jobs_page"
    description = "target job posts (stack signals from requirements)"
    tier = 0

    def can_handle(self, url: str) -> bool:
        return url.startswith(("http://", "https://")) and \
            "job" in url.lower()


def build_channels() -> list:
    return [GithubPublicChannel(), SiteDocsChannel(), RssFeedChannel(),
            JobsPageChannel()]


def intel_digest(target: str, *, base_url: str = "",
                 config: dict = None) -> dict:
    """Collect external-intel facts for a target (U1/U2 intake shape).

    Every result carries provenance (channel, backend, url, fetched_at).
    A dead channel is a recorded fact, never a crash.  This function is
    called ONLY when the lane is explicitly enabled.
    """
    host = urlparse(base_url or target).netloc or str(target)
    slug = host.split(".")[0] if host else target
    probes = {
        "github_public": f"https://github.com/{slug}",
        "site_docs": (base_url or target) + "/docs",
        "rss_feed": (base_url or target) + "/feed",
        "jobs_page": (base_url or target) + "/jobs",
    }
    facts = []
    for channel in build_channels():
        # Unknown/custom channels default to a target-rooted probe URL
        # instead of KeyError-ing the digest (fail-open registry).
        url = probes.get(channel.name, (base_url or target))
        if not channel.can_handle(url):
            facts.append({"channel": channel.name, "status": "skipped",
                          "reason": "probe URL not in channel scope",
                          "fetched_at": _now_iso()})
            continue
        try:
            result = channel.fetch(url, config)
            fact = dict(result)
            fact["status"] = "ok"
            if channel.name == "rss_feed":
                fact["items"] = channel.parse(str(result.get("body", "")))
            facts.append(fact)
        except Exception as exc:  # noqa: BLE001 - dead channel = dead fact
            facts.append({"channel": channel.name, "status": "error",
                          "reason": f"{type(exc).__name__}",
                          "fetched_at": _now_iso()})
    return {"schema": "bugwolf-intel/v1", "target": target,
            "generated_at": _now_iso(), "facts": facts}
