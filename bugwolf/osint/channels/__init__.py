"""OSINT channel scrapers — 15 platforms, all stub-safe.

Every channel inherits :class:`ChannelBase` and exposes::

    class XxxChannel(ChannelBase):
        name = "xxx"
        kind = "post" | "profile" | "comment" | "image"
        def __init__(self, *, credential: Optional[str] = None) -> None: ...
        def scrape(self, target: str, *, budget: int = 50) -> List[OSINTFinding]: ...

Stub-safe: if a credential is missing or the network is unreachable,
:py:meth:`ChannelBase.scrape` returns ``[]`` instead of raising.

No third-party deps.
"""

from __future__ import annotations

from .. import OSINTFinding  # re-exported
from ..channel_base import ChannelBase

# Re-export each Channel class so callers can ``from bugwolf.osint.channels
# import RedditChannel`` without dropping into the submodule.
from .reddit import RedditChannel  # noqa: F401
from .twitter import TwitterChannel  # noqa: F401
from .github import GithubChannel  # noqa: F401
from .instagram import InstagramChannel  # noqa: F401
from .linkedin import LinkedInChannel  # noqa: F401
from .facebook import FacebookChannel  # noqa: F401
from .youtube import YoutubeChannel  # noqa: F401
from .bilibili import BilibiliChannel  # noqa: F401
from .xiaohongshu import XiaohongshuChannel  # noqa: F401
from .xiaoyuzhou import XiaoyuzhouChannel  # noqa: F401
from .xueqiu import XueqiuChannel  # noqa: F401
from .v2ex import V2EXChannel  # noqa: F401
from .rss import RssChannel  # noqa: F401
from .web import WebChannel  # noqa: F401
from .exa_search import ExaSearchChannel  # noqa: F401


__all__ = [
    "ChannelBase",
    "OSINTFinding",
    "RedditChannel",
    "TwitterChannel",
    "GithubChannel",
    "InstagramChannel",
    "LinkedInChannel",
    "FacebookChannel",
    "YoutubeChannel",
    "BilibiliChannel",
    "XiaohongshuChannel",
    "XiaoyuzhouChannel",
    "XueqiuChannel",
    "V2EXChannel",
    "RssChannel",
    "WebChannel",
    "ExaSearchChannel",
]