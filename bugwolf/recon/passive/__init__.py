"""Passive intel modules for the recon subsystem.

Each module exposes a class with the same surface::

    class XxxModule:
        name = "xxx"
        kind = "subdomain" | "ip" | "email" | "credential" | "endpoint"
        def __init__(self, *, api_key: Optional[str] = None) -> None: ...
        def enrich(self, target: str, *, budget: int = 50) -> List[PassiveFinding]: ...

Stub-safe: if a required credential (API key, network access, import) is
missing, ``enrich()`` returns ``[]`` instead of raising.  Tests inspect
the ``reason`` field on the returned ``PassiveFinding`` to verify the
fail-closed behaviour.

No third-party deps.
"""

from __future__ import annotations

from .. import PassiveFinding  # re-exported
from ..passive_base import PassiveModule

# Re-export each Module class so callers can ``from bugwolf.recon.passive
# import CrtShModule``.
from .crt_sh import CrtShModule  # noqa: F401
from .dns_brute import DnsBruteModule  # noqa: F401
from .wayback import WaybackModule  # noqa: F401
from .shodan import ShodanModule  # noqa: F401
from .censys import CensysModule  # noqa: F401
from .github_search import GithubSearchModule  # noqa: F401
from .google_dorks import GoogleDorksModule  # noqa: F401
from .email_patterns import EmailPatternsModule  # noqa: F401
from .subdomain_alts import SubdomainAltsModule  # noqa: F401


__all__ = [
    "PassiveModule",
    "PassiveFinding",
    "CrtShModule",
    "DnsBruteModule",
    "WaybackModule",
    "ShodanModule",
    "CensysModule",
    "GithubSearchModule",
    "GoogleDorksModule",
    "EmailPatternsModule",
    "SubdomainAltsModule",
]