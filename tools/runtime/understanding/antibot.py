#!/usr/bin/env python3
"""Antibot honesty for the U-layer fetcher (INTEGRATION_PLAN Phase F,
v1.29).

A bot-wall challenge page passes ``status == 200 with content`` — without
detection it silently poisons U1's business-lens inference with challenge
boilerplate.  Heuristics ported from Agent-Reach
``agent_reach/channels/web.py::_is_antibot_page`` (MIT, attributed) and
extended: a challenged page becomes an honest FACT (recorded beside the
model, listed in the Hunting Brief) instead of junk text, and is excluded
from U1's text intake.

Deterministic, pure, stdlib-only; a detection is a fact, never a crash.
"""

from __future__ import annotations

import re
from typing import Dict

# The fact shape recorded for a challenged surface.
ANTIBOT_FACT: Dict[str, object] = {
    "fact": "surface behind bot-wall",
    "kind": "antibot",
}

_MARKERS = (
    # Cloudflare block / challenge (AR's cloudflare_block)
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"checking your browser", re.IGNORECASE),
    re.compile(r"attention required", re.IGNORECASE),
    re.compile(r"cf-browser-verification|cf_chl", re.IGNORECASE),
    # Generic captcha-challenge structure (AR's challenge_structure)
    re.compile(r"captcha", re.IGNORECASE),
    re.compile(r"verify you are human|are you a robot", re.IGNORECASE),
    # Jina reader warning format (AR's jina_captcha_warning)
    re.compile(r"warning:\s+.*requiring captcha", re.IGNORECASE),
)

# Challenge pages are boilerplate-heavy and content-light.  The volume
# guard measures the WHOLE body's text (not just the marker sample): a
# real page that merely MENTIONS captcha has rich content and passes.
_MAX_CHALLENGE_TEXT_LEN = 2000


def is_antibot_page(body: str) -> bool:
    """True when the fetched body looks like a bot-wall challenge, not
    real content (AR's heuristic set + a content-volume guard)."""
    if not body:
        return False
    sample = body[:4000]
    if not any(marker.search(sample) for marker in _MARKERS):
        return False
    # Marker present AND content-light => challenge.  A real page that
    # merely MENTIONS captcha (a security blog post) has rich content and
    # passes through.
    text_len = len(re.sub(r"<[^>]+>|\s+", "", body[:20000]))
    return text_len <= _MAX_CHALLENGE_TEXT_LEN
