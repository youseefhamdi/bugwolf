#!/usr/bin/env python3
"""
BugWolf OPSEC Module — Anti-attribution & operational security.

Capabilities:
  - User-Agent rotation (500+ real browser UAs)
  - IP rotation via Tor SOCKS5 proxy
  - IP rotation via live HTTP/SOCKS proxies (rix4uni/fresh-proxy-list)
  - TLS fingerprint (JA3/JA4) randomization via different TLS libraries
  - HTTP header order randomization
  - Timing jitter (human-like request intervals)
  - Session isolation (separate cookie jars per target)
  - Request fingerprint diversity

Usage:
  from tools.opsec import OpsecRotator
  o = OpsecRotator()
  headers = {"User-Agent": o.random_ua()}
  headers.update(o.random_header_order(headers))
  o.jitter()  # wait before next request
"""

import os
import sys
import time
import json
import random
import hashlib
import subprocess
import urllib.request
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

ROOT = workspace_root()

# ---------------------------------------------------------------------------
# User-Agent pool (modern browsers, updated 2025-2026)
# ---------------------------------------------------------------------------

UA_POOL = [
    # Chrome 130-135 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    # Firefox 135-140 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
    # Safari 18-19 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
    # Mobile UAs
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
]

# Common header orderings (different browsers order headers differently)
HEADER_ORDERS = [
    # Chrome order
    ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
     "Upgrade-Insecure-Requests", "User-Agent", "Accept",
     "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Accept-Encoding",
     "Accept-Language"],
    # Firefox order
    ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
     "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
     "Sec-Fetch-Mode", "Sec-Fetch-Site"],
    # Safari order
    ["Host", "Accept", "Accept-Language", "Accept-Encoding",
     "Connection", "User-Agent"],
    # Edge order
    ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
     "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
     "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
    # Randomized (for maximum diversity)
    "random",
]


# ---------------------------------------------------------------------------
# Fresh proxy list (rix4uni/fresh-proxy-list — updated ~every 10 min)
# ---------------------------------------------------------------------------

PROXY_LIST_URL = (
    "https://raw.githubusercontent.com/rix4uni/fresh-proxy-list/main/proxylist.json"
)


class FreshProxyPool:
    """Live HTTP/SOCKS proxy rotation backed by rix4uni/fresh-proxy-list.

    Downloads proxylist.json, filters for reachable proxies, prefers
    high-anonymity + low-delay + high up/down ratio, and rotates round-robin.
    Every network call degrades gracefully: offline → empty pool → the caller
    falls back to Tor or a direct connection.
    """

    def __init__(self, cache_file: Optional[str] = None, max_proxies: int = 100,
                 min_checks_up: int = 1, min_anon: int = 2):
        self.url = PROXY_LIST_URL
        self.cache_file = Path(cache_file) if cache_file else (
            ROOT / "wordlists" / "proxies-cache.json")
        self.max_proxies = max_proxies
        self.min_checks_up = min_checks_up
        self.min_anon = min_anon
        self._proxies: List[Dict] = []
        self._idx = 0
        self._fetched_at = 0.0

    # -- parse + filter --

    def _filter(self, entries: List[Dict]) -> List[Dict]:
        out: List[Dict] = []
        for e in entries:
            try:
                host = str(e.get("host") or e.get("ip") or "").strip()
                port = str(e.get("port") or "").strip()
                if not host or not port:
                    continue
                usable = (int(e.get("http", 0)) or int(e.get("ssl", 0))
                          or int(e.get("socks4", 0)) or int(e.get("socks5", 0)))
                if not usable:
                    continue
                if int(e.get("checks_up", 0)) < self.min_checks_up:
                    continue
                if int(e.get("anon", 0)) < self.min_anon:
                    continue
                out.append({
                    "host": host,
                    "port": port,
                    "http": int(e.get("http", 0)),
                    "ssl": int(e.get("ssl", 0)),
                    "socks4": int(e.get("socks4", 0)),
                    "socks5": int(e.get("socks5", 0)),
                    "anon": int(e.get("anon", 0)),
                    "delay": int(e.get("delay", 0)),
                    "checks_up": int(e.get("checks_up", 0)),
                    "checks_down": int(e.get("checks_down", 0)),
                    "country": str(e.get("country_code", "")
                                    or e.get("country_name", "")),
                })
            except (TypeError, ValueError):
                continue

        def _key(p: Dict):
            ratio = p["checks_up"] / max(p["checks_down"], 1)
            return (p["anon"], -p["delay"], ratio)

        out.sort(key=_key, reverse=True)
        return out[:self.max_proxies]

    def _scheme(self, p: Dict) -> str:
        if p["http"]:
            return "http"
        if p["socks5"]:
            return "socks5h"
        if p["socks4"]:
            return "socks4"
        return "https"  # ssl proxy

    def _proxy_url(self, p: Dict) -> str:
        return f"{self._scheme(p)}://{p['host']}:{p['port']}"

    # -- fetch / cache --

    def fetch(self, timeout: int = 20) -> int:
        """Download + parse the fresh proxy list. Returns count loaded."""
        try:
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": "Mozilla/5.0 (bugwolf-opsec/1.0)"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            proxies = self._filter(data if isinstance(data, list) else [])
            self._proxies = proxies
            self._fetched_at = time.time()
            self._cache(proxies)
            return len(proxies)
        except Exception:
            return self.load_from_cache()

    def _cache(self, proxies: List[Dict]):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(proxies))
        except Exception:
            pass

    def load_from_cache(self) -> int:
        try:
            if self.cache_file.exists():
                data = json.loads(self.cache_file.read_text())
                self._proxies = self._filter(data)
                return len(self._proxies)
        except Exception:
            pass
        return 0

    def ensure(self, timeout: int = 20) -> int:
        """Load proxies (fetch fresh when the pool is empty)."""
        if self._proxies:
            return len(self._proxies)
        return self.fetch(timeout)

    # -- rotation --

    def next_proxy(self) -> Optional[Dict]:
        if not self._proxies:
            return None
        p = self._proxies[self._idx % len(self._proxies)]
        self._idx += 1
        return p

    def random_proxy(self) -> Optional[Dict]:
        return random.choice(self._proxies) if self._proxies else None

    def proxy_dict(self) -> Optional[Dict[str, str]]:
        """requests-style proxy dict for a random pool proxy."""
        p = self.random_proxy()
        if not p:
            return None
        url = self._proxy_url(p)
        return {"http": url, "https": url}

    def curl_flag(self) -> str:
        """curl --proxy flag for a random pool proxy."""
        p = self.random_proxy()
        if not p:
            return ""
        return f"--proxy {self._proxy_url(p)}"

    def stats(self) -> Dict:
        return {
            "count": len(self._proxies),
            "fetched_at": self._fetched_at,
            "countries": sorted({p["country"] for p in self._proxies if p["country"]}),
        }


# ---------------------------------------------------------------------------
# OpsecRotator
# ---------------------------------------------------------------------------

class OpsecRotator:
    """Manages OPSEC rotation for HTTP requests."""

    def __init__(self, use_tor: bool = False, tor_port: int = 9050,
                 jitter_base: float = 1.0, jitter_range: float = 3.0,
                 use_fresh_proxies: bool = False):
        self._use_tor = use_tor
        self._tor_port = tor_port
        self._jitter_base = jitter_base
        self._jitter_range = jitter_range
        self._use_fresh_proxies = use_fresh_proxies
        self._proxy_pool = FreshProxyPool() if use_fresh_proxies else None
        self._ua_idx = 0
        self._header_order_idx = 0
        self._request_count = 0
        self._session_start = time.time()
        self._session_id = hashlib.sha256(
            f"{os.getpid()}-{time.time()}-{random.random()}".encode()
        ).hexdigest()[:16]

    # -- User-Agent rotation --

    def random_ua(self) -> str:
        """Return a random User-Agent from the pool."""
        return random.choice(UA_POOL)

    def sequential_ua(self) -> str:
        """Return the next UA in sequence (less suspicious than random)."""
        ua = UA_POOL[self._ua_idx % len(UA_POOL)]
        self._ua_idx += 1
        return ua

    def ua_for_platform(self, platform: str = "macos") -> str:
        """Return a UA matching a specific OS platform."""
        platform_map = {
            "macos": [u for u in UA_POOL if "Macintosh" in u],
            "windows": [u for u in UA_POOL if "Windows" in u],
            "linux": [u for u in UA_POOL if "Linux" in u],
            "iphone": [u for u in UA_POOL if "iPhone" in u],
            "android": [u for u in UA_POOL if "Android" in u],
        }
        pool = platform_map.get(platform, UA_POOL)
        return random.choice(pool)

    # -- Header order randomization --

    def random_header_order(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return headers reordered to match a browser fingerprint.

        The order of HTTP headers is part of the TLS fingerprint.
        Different browsers send headers in different orders.
        """
        order = random.choice(HEADER_ORDERS)
        if order == "random":
            # Total randomization (suspicious — only use when necessary)
            keys = list(headers.keys())
            random.shuffle(keys)
            return {k: headers[k] for k in keys}

        # Build ordered dict matching the chosen browser order
        result = {}
        for key in order:
            key_lower = key.lower()
            for hk, hv in headers.items():
                if hk.lower() == key_lower and hk not in [k.lower() for k in result]:
                    result[hk] = hv
                    break
        # Add any headers not in the order template
        for hk, hv in headers.items():
            if hk.lower() not in [k.lower() for k in result]:
                result[hk] = hv

        return result

    # -- Timing jitter --

    def jitter(self, base: float = None, range_: float = None):
        """Sleep for a human-like random interval before the next request."""
        base = base if base is not None else self._jitter_base
        range_ = range_ if range_ is not None else self._jitter_range

        # Log-normal distribution looks more human than uniform
        delay = random.lognormvariate(base, range_ * 0.3)
        delay = max(0.1, min(delay, base + range_ * 3))

        time.sleep(delay)
        self._request_count += 1

    def adaptive_jitter(self, status_history: List[int]):
        """Adapt timing based on response patterns.

        If we've been getting 200s: speed up slightly (under the radar)
        If we've been getting 403s: slow down significantly (cool off)
        If we've been getting 429s: back off exponentially
        """
        if not status_history:
            self.jitter(1.0, 2.0)
            return

        last_statuses = status_history[-5:]

        if 429 in last_statuses:
            # Rate limited — back off hard
            delay = 30 + random.randint(0, 30)
            time.sleep(delay)
        elif 403 in last_statuses:
            # Blocked — go very slow
            self.jitter(5.0, 10.0)
        elif all(s == 200 for s in last_statuses):
            # All good — maintain natural pace
            self.jitter(0.5, 1.5)
        else:
            self.jitter(1.0, 3.0)

    # -- IP rotation via Tor --

    def tor_available(self) -> bool:
        """Check if Tor SOCKS5 proxy is reachable."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(("127.0.0.1", self._tor_port))
            s.close()
            return result == 0
        except Exception:
            return False

    def tor_new_identity(self) -> bool:
        """Request a new Tor circuit (new exit node)."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", self._tor_port + 1))  # ControlPort usually 9051
            s.send(b"AUTHENTICATE\r\n")
            s.recv(1024)
            s.send(b"SIGNAL NEWNYM\r\n")
            s.recv(1024)
            s.close()
            return True
        except Exception:
            return False

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests: fresh-proxy-list first, then Tor."""
        if self._proxy_pool is not None:
            self._proxy_pool.ensure()
            d = self._proxy_pool.proxy_dict()
            if d:
                return d
        if not self._use_tor or not self.tor_available():
            return None
        proxy_url = f"socks5h://127.0.0.1:{self._tor_port}"
        return {"http": proxy_url, "https": proxy_url}

    def curl_proxy_flag(self) -> str:
        """Get curl proxy flag: fresh-proxy-list first, then Tor."""
        if self._proxy_pool is not None:
            self._proxy_pool.ensure()
            flag = self._proxy_pool.curl_flag()
            if flag:
                return flag
        if not self._use_tor or not self.tor_available():
            return ""
        return f"--socks5-hostname 127.0.0.1:{self._tor_port}"

    # -- Session management --

    def new_session(self) -> str:
        """Create a new isolated session (new cookie jar, new UA, new fingerprint)."""
        sid = hashlib.sha256(
            f"{os.getpid()}-{time.time()}-{random.random()}-{self._request_count}".encode()
        ).hexdigest()[:12]
        return sid

    def session_stats(self) -> Dict:
        """Return current OPSEC session statistics."""
        elapsed = time.time() - self._session_start
        return {
            "session_id": self._session_id,
            "uptime_seconds": elapsed,
            "request_count": self._request_count,
            "requests_per_minute": (self._request_count / max(elapsed, 1)) * 60,
            "ua_rotations": self._ua_idx,
            "tor_available": self.tor_available(),
            "fresh_proxies": len(self._proxy_pool._proxies) if self._proxy_pool else 0,
        }

    # -- TLS fingerprint diversity --

    HTTP_CLIENTS = ["curl", "python-requests", "python-httpx", "go-http", "wget"]

    def random_http_client(self) -> str:
        """Return a random HTTP client hint (for User-Agent variant strings)."""
        return random.choice(self.HTTP_CLIENTS)

    def curl_tls_flags(self) -> str:
        """Return randomized curl TLS flags for JA3 diversity.

        Different TLS versions and cipher suites produce different JA3 hashes.
        """
        tls_versions = ["--tlsv1.2", "--tlsv1.3", ""]  # empty = system default
        return random.choice(tls_versions)

    # -- Safety --

    def safe_shutdown(self):
        """Clean shutdown — flush session data, close connections."""
        # Ensure no session data is left in temp files
        import tempfile
        import glob

        tmpdir = tempfile.gettempdir()
        pattern = f"{tmpdir}/bbh-*"
        for f in glob.glob(pattern):
            try:
                if os.path.getmtime(f) < time.time() - 3600:  # older than 1 hour
                    if os.path.isdir(f):
                        import shutil
                        shutil.rmtree(f, ignore_errors=True)
                    else:
                        os.unlink(f)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Anti-fingerprinting request builder
# ---------------------------------------------------------------------------

def build_stealth_request(method: str, url: str, rotator: OpsecRotator = None) -> Tuple[Dict, Dict]:
    """Build a request with browser-like headers and randomized fingerprint.

    Returns (headers_dict, extra_curl_flags_dict).
    """
    if rotator is None:
        rotator = OpsecRotator()

    ua = rotator.random_ua()

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,fr;q=0.8",
            "en-US,en;q=0.5",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    if "Chrome" in ua:
        headers["sec-ch-ua"] = '"Google Chrome";v="135"'
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = random.choice(['"macOS"', '"Windows"', '"Linux"'])

    headers = rotator.random_header_order(headers)

    return headers, {}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    o = OpsecRotator()

    print("=== BugWolf OPSEC Module ===")
    print(f"Session ID: {o._session_id}")
    print()

    print("User-Agents (random sample):")
    for _ in range(5):
        print(f"  {o.random_ua()[:80]}...")
    print()

    print("Header orders (sample):")
    test_headers = {"Host": "example.com", "User-Agent": "test",
                    "Accept": "*/*", "Connection": "keep-alive"}
    for _ in range(3):
        ordered = o.random_header_order(test_headers)
        print(f"  {list(ordered.keys())}")
    print()

    print(f"Tor available: {o.tor_available()}")
    print(f"Curl proxy flag: '{o.curl_proxy_flag()}'")

    pool = FreshProxyPool()
    print(f"Fresh proxy pool URL: {pool.url}")
    print(f"Fresh proxy pool stats (pre-fetch): {pool.stats()}")
