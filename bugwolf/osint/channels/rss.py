"""Generic RSS / Atom aggregator.

Parses any RFC-compliant feed using stdlib ``xml.etree.ElementTree``.
Stub-safe: invalid XML / network errors → ``[]``.

No third-party deps.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Optional
from urllib.parse import urlparse

from .. import OSINTFinding
from ..channel_base import ChannelBase


class RssChannel(ChannelBase):
    name = "rss"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, feeds: Optional[List[str]] = None,
                 credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)
        self._feeds = list(feeds or [])

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        urls = self._feeds or [
            f"https://news.google.com/rss/search?q={_quote(target)}",
        ]
        out: List[OSINTFinding] = []
        for feed_url in urls:
            body = self.http_get(feed_url, timeout=6.0, headers={
                "User-Agent": "bugwolf-osint/1",
            })
            if not body:
                continue
            out.extend(self._parse_feed(body, target, budget))
            if len(out) >= int(budget):
                break
        return out[: int(budget)]

    def _parse_feed(self, body: str, target: str,
                    budget: int) -> List[OSINTFinding]:
        out: List[OSINTFinding] = []
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return out
        for item in root.iter("item"):
            title = str(item.findtext("title") or "").strip()
            link = str(item.findtext("link") or "").strip()
            pub = str(item.findtext("pubDate") or "").strip()
            author = str(item.findtext("author") or "").strip()
            if not title and not link:
                continue
            out.append(self.finding(
                value=title,
                url=link,
                author=author,
                timestamp=pub,
                confidence=0.45,
                extra={"source_feed": urlparse(link).netloc},
            ))
            if len(out) >= int(budget):
                break
        # Atom fallback
        for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
            title = str(entry.findtext("{http://www.w3.org/2005/Atom}title") or "").strip()
            link_el = entry.find("{http://www.w3.org/2005/Atom}link")
            link = (link_el.get("href") if link_el is not None else "") or ""
            pub = str(entry.findtext("{http://www.w3.org/2005/Atom}published") or "").strip()
            author_el = entry.find("{http://www.w3.org/2005/Atom}author")
            author = (author_el.findtext("{http://www.w3.org/2005/Atom}name") if author_el is not None else "") or ""
            if not title and not link:
                continue
            out.append(self.finding(
                value=title,
                url=link,
                author=author,
                timestamp=pub,
                confidence=0.45,
                extra={"source_feed": urlparse(link).netloc,
                       "atom": True},
            ))
            if len(out) >= int(budget):
                break
        return out


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


__all__ = ["RssChannel"]