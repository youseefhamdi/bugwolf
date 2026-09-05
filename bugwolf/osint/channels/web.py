"""Generic web scraper — HTML title + meta tags.

Fetches ``https://<target>/`` and parses ``<title>``, ``<meta name=
"description">``, ``<meta property="og:*">`` using stdlib
``html.parser``.

Stub-safe: network errors / parse errors → ``[]``.
"""

from __future__ import annotations

import html.parser
from typing import List, Optional

from .. import OSINTFinding
from ..channel_base import ChannelBase


class _MetaParser(html.parser.HTMLParser):
    """Tiny HTML parser that extracts ``<title>`` and meta tags."""

    def __init__(self) -> None:
        super().__init__()
        self.title_parts: List[str] = []
        self.in_title = False
        self.metas: List[Dict[str, str]] = []
        self._current_attrs: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list) -> None:
        ats = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            self.metas.append(ats)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


class WebChannel(ChannelBase):
    name = "web"
    kind = "post"
    requires_credential = False
    env_var = ""

    def __init__(self, *, urls: Optional[List[str]] = None,
                 credential: Optional[str] = None) -> None:
        super().__init__(credential=credential)
        self._urls = list(urls or [])

    def _scrape(self, target: str, *, budget: int) -> List[OSINTFinding]:
        urls = self._urls or [f"https://{target}/"]
        out: List[OSINTFinding] = []
        for url in urls[: int(budget)]:
            body = self.http_get(url, timeout=6.0, headers={
                "User-Agent": "bugwolf-osint/1",
            })
            if not body:
                continue
            parser = _MetaParser()
            try:
                parser.feed(body)
            except Exception:  # noqa: BLE001
                continue
            title = "".join(parser.title_parts).strip()
            description = ""
            og_title = ""
            for m in parser.metas:
                if m.get("name", "").lower() == "description" and not description:
                    description = m.get("content", "")
                if m.get("property", "").lower() == "og:title" and not og_title:
                    og_title = m.get("content", "")
            value = og_title or title or url
            out.append(self.finding(
                value=value,
                url=url,
                author="",
                confidence=0.4,
                extra={
                    "title": title,
                    "description": description,
                },
            ))
        return out


__all__ = ["WebChannel"]