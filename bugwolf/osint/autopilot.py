"""OSINT autopilot — concurrent channel sweep with dedup.

:class:`OSINTAutopilot` runs every available OSINT channel against a
target with budget enforcement, then deduplicates results by
``url + content-hash`` and returns an :class:`OSINTReport`.

Stub-safe: every channel is wrapped in try/except — failures are
captured into ``OSINTReport.errors`` and never propagate.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Any, Dict, Iterable, List, Optional

from .channels import (
    BilibiliChannel,
    ExaSearchChannel,
    FacebookChannel,
    GithubChannel,
    InstagramChannel,
    LinkedInChannel,
    RedditChannel,
    RssChannel,
    TwitterChannel,
    V2EXChannel,
    WebChannel,
    XiaohongshuChannel,
    XiaoyuzhouChannel,
    XueqiuChannel,
    YoutubeChannel,
)


SCHEMA = "bugwolf-osint-autopilot-v1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _content_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _default_channels() -> List[Any]:
    """Return one instance of every available channel."""
    return [
        RedditChannel(),
        TwitterChannel(),
        GithubChannel(),
        InstagramChannel(),
        LinkedInChannel(),
        FacebookChannel(),
        YoutubeChannel(),
        BilibiliChannel(),
        XiaohongshuChannel(),
        XiaoyuzhouChannel(),
        XueqiuChannel(),
        V2EXChannel(),
        RssChannel(),
        WebChannel(),
        ExaSearchChannel(),
    ]


class OSINTAutopilot:
    """Concurrent OSINT autopilot.

    Parameters
    ----------
    target:
        The OSINT query — username, email, domain, etc.
    channels:
        Optional list of channel instances.  When ``None``, the autopilot
        uses :func:`_default_channels` (15 built-in scrapers).
    max_concurrent:
        Maximum channels to run in parallel (default 4).
    budget_per_channel:
        How many findings each channel may return (default 50).
    """

    def __init__(
        self,
        target: str,
        *,
        channels: Optional[Iterable[Any]] = None,
        max_concurrent: int = 4,
        budget_per_channel: int = 50,
    ) -> None:
        if not target or not isinstance(target, str):
            raise ValueError("target must be a non-empty string")
        self.target = target.strip()
        self.max_concurrent = max(1, int(max_concurrent))
        self.budget_per_channel = max(1, int(budget_per_channel))
        if channels is None:
            self.channels: List[Any] = _default_channels()
        else:
            self.channels = list(channels)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _channel_name(channel: Any) -> str:
        return str(getattr(channel, "name", channel.__class__.__name__))

    def _scrape_one(self, channel: Any) -> tuple:
        """Scrape one channel.  Always returns ``(name, items, error)``."""
        name = self._channel_name(channel)
        try:
            items = channel.scrape(self.target,
                                   budget=self.budget_per_channel)
        except Exception as exc:  # noqa: BLE001
            return name, [], repr(exc)
        return name, list(items or []), ""

    # -- main entry --------------------------------------------------------

    def run(self, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Execute all channels concurrently and return a deduped report."""
        started = _now_iso()
        findings: List[Any] = []
        errors: List[str] = []
        channels_used: List[str] = []

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as pool:
            future_to_name: Dict[Future[Any], str] = {}
            for ch in self.channels:
                channels_used.append(self._channel_name(ch))
                fut = pool.submit(self._scrape_one, ch)
                future_to_name[fut] = self._channel_name(ch)

            deadline = None
            if timeout is not None:
                import time as _time
                deadline = _time.monotonic() + float(timeout)
            for fut in list(future_to_name.keys()):
                try:
                    name, items, err = fut.result(timeout=2.0)
                except Exception as exc:  # noqa: BLE001
                    errors.append(repr(exc))
                    continue
                if err:
                    errors.append(f"{name}: {err}")
                findings.extend(items)
                if deadline is not None:
                    import time as _time
                    if _time.monotonic() > deadline:
                        break

        deduped = self._dedupe(findings)

        finished = _now_iso()
        return {
            "schema": SCHEMA,
            "target": self.target,
            "started_at": started,
            "finished_at": finished,
            "findings": [self._finding_to_dict(f) for f in deduped],
            "channels_used": channels_used,
            "errors": errors,
            "raw_count": len(findings),
            "dedup_count": len(deduped),
        }

    # -- dedup -------------------------------------------------------------

    @staticmethod
    def _dedupe(findings: List[Any]) -> List[Any]:
        """Deduplicate findings by ``url + content_hash(value)``.

        Returns findings in first-seen order so the deduplicated list is
        stable across runs.
        """
        seen: set = set()
        out: List[Any] = []
        for f in findings:
            url = str(getattr(f, "url", "") or "")
            value = str(getattr(f, "value", "") or "")
            key = (url, _content_hash(value))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _finding_to_dict(finding: Any) -> Dict[str, Any]:
        if hasattr(finding, "__dataclass_fields__"):
            import dataclasses
            return dataclasses.asdict(finding)
        return {
            "kind": str(getattr(finding, "kind", "")),
            "value": str(getattr(finding, "value", "")),
            "source": str(getattr(finding, "source", "")),
            "url": str(getattr(finding, "url", "")),
            "author": str(getattr(finding, "author", "")),
            "timestamp": str(getattr(finding, "timestamp", "")),
            "confidence": float(getattr(finding, "confidence", 0.0)),
            "extra": dict(getattr(finding, "extra", {}) or {}),
        }


__all__ = ["OSINTAutopilot", "SCHEMA"]