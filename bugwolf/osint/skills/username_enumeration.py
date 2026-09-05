"""OSINT skill: ``username_enumeration``.

Walk a list of well-known platforms and report whether the given
username is registered.  Stub-safe: returns an empty result when no
network is available.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from ..skills_base import _empty_result, _skill_result


_PLATFORMS = (
    "github", "twitter", "instagram", "facebook", "youtube",
    "reddit", "tiktok", "linkedin", "medium", "stackoverflow",
    "gitlab", "bitbucket", "pinterest", "tumblr", "twitch",
    "v2ex", "xueqiu", "bilibili",
)

_URL_TEMPLATES = {
    "github": "https://github.com/{u}",
    "twitter": "https://twitter.com/{u}",
    "instagram": "https://www.instagram.com/{u}/",
    "facebook": "https://www.facebook.com/{u}",
    "youtube": "https://www.youtube.com/@{u}",
    "reddit": "https://www.reddit.com/user/{u}",
    "tiktok": "https://www.tiktok.com/@{u}",
    "linkedin": "https://www.linkedin.com/in/{u}",
    "medium": "https://medium.com/@{u}",
    "stackoverflow": "https://stackoverflow.com/users/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "bitbucket": "https://bitbucket.org/{u}/",
    "pinterest": "https://www.pinterest.com/{u}/",
    "tumblr": "https://{u}.tumblr.com",
    "twitch": "https://www.twitch.tv/{u}",
    "v2ex": "https://www.v2ex.com/member/{u}",
    "xueqiu": "https://xueqiu.com/u/{u}",
    "bilibili": "https://space.bilibili.com/{u}",
}


def _http_status(url: str, *, timeout: float = 4.0) -> int:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "bugwolf-osint/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except Exception:  # noqa: BLE001
        return 0


def run(query: str, *, budget: int = 50, **_: Any) -> Dict[str, Any]:
    """Probe ``query`` (a username) across ``_PLATFORMS``.

    Returns ``{schema, skill, query, items, count, reason}``.  Each item
    has ``platform``, ``url``, ``status`` (HTTP code or 0).
    """
    username = (query or "").strip()
    if not username:
        return _empty_result("username_enumeration", query, reason="empty query")

    items: List[Dict[str, Any]] = []
    for platform in _PLATFORMS[: int(budget)]:
        template = _URL_TEMPLATES.get(platform)
        if not template:
            continue
        url = template.format(u=quote(username, safe=""))
        status = _http_status(url)
        items.append({"platform": platform, "url": url, "status": status})
    return _skill_result("username_enumeration", query, items=items)


__all__ = ["run"]