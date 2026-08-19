#!/usr/bin/env python3
"""Tests for the OPSEC module's fresh-proxy-list integration."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.opsec import FreshProxyPool, OpsecRotator, PROXY_LIST_URL


SAMPLE = [
    {"host": "1.2.3.4", "port": "8080", "http": "1", "ssl": "0", "socks4": "0",
     "socks5": "0", "anon": "4", "delay": "100", "checks_up": "50",
     "checks_down": "2", "country_code": "US", "country_name": "United States"},
    {"host": "5.6.7.8", "port": "1080", "http": "0", "ssl": "0", "socks4": "0",
     "socks5": "1", "anon": "2", "delay": "9000", "checks_up": "1",
     "checks_down": "0", "country_code": "FR", "country_name": "France"},
    # low anonymity — dropped by default min_anon=2
    {"host": "9.9.9.9", "port": "80", "http": "0", "ssl": "1", "socks4": "0",
     "socks5": "0", "anon": "1", "delay": "50", "checks_up": "10",
     "checks_down": "0", "country_code": "DE", "country_name": "Germany"},
    # no usable protocol — dropped
    {"host": "8.8.8.8", "port": "80", "http": "0", "ssl": "0", "socks4": "0",
     "socks5": "0", "anon": "4", "delay": "50", "checks_up": "10",
     "checks_down": "0", "country_code": "", "country_name": ""},
    # low anonymity — dropped
    {"host": "7.7.7.7", "port": "80", "http": "1", "ssl": "0", "socks4": "0",
     "socks5": "0", "anon": "1", "delay": "50", "checks_up": "10",
     "checks_down": "0", "country_code": "", "country_name": ""},
]


class _FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestFreshProxyPoolFiltering(unittest.TestCase):

    def test_filter_drops_unusable_and_low_anon(self):
        pool = FreshProxyPool(min_anon=2)
        filtered = pool._filter(SAMPLE)
        hosts = {p["host"] for p in filtered}
        self.assertEqual(hosts, {"1.2.3.4", "5.6.7.8"})

    def test_filter_sorts_high_anon_first(self):
        pool = FreshProxyPool(min_anon=2)
        filtered = pool._filter(SAMPLE)
        self.assertEqual(filtered[0]["host"], "1.2.3.4")  # anon=4 beats anon=2

    def test_scheme_selection(self):
        pool = FreshProxyPool()
        self.assertEqual(pool._scheme({"http": 1, "socks5": 0, "socks4": 0}), "http")
        self.assertEqual(pool._scheme({"http": 0, "socks5": 1, "socks4": 0}), "socks5h")
        self.assertEqual(pool._scheme({"http": 0, "socks5": 0, "socks4": 1}), "socks4")
        self.assertEqual(pool._scheme({"http": 0, "socks5": 0, "socks4": 0}), "https")

    def test_proxy_url(self):
        pool = FreshProxyPool()
        self.assertEqual(
            pool._proxy_url({"host": "1.2.3.4", "port": "8080",
                             "http": 1, "socks5": 0, "socks4": 0}),
            "http://1.2.3.4:8080")


class TestFreshProxyPoolFetch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "proxies-cache.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_fetch_filters_and_caches(self):
        pool = FreshProxyPool(cache_file=str(self.cache), min_anon=2)
        with mock.patch("tools.opsec.urllib.request.urlopen") as urlopen:
            urlopen.return_value = _FakeResp(json.dumps(SAMPLE).encode("utf-8"))
            count = pool.fetch(timeout=5)
        self.assertEqual(count, 2)
        self.assertTrue(self.cache.exists())
        self.assertEqual(len(pool._proxies), 2)

    def test_fetch_offline_falls_back_to_cache(self):
        # seed cache
        pool = FreshProxyPool(cache_file=str(self.cache), min_anon=2)
        pool._cache(pool._filter(SAMPLE))
        # now simulate offline
        pool._proxies = []
        with mock.patch("tools.opsec.urllib.request.urlopen",
                        side_effect=Exception("offline")):
            count = pool.fetch(timeout=5)
        self.assertEqual(count, 2)
        self.assertEqual(len(pool._proxies), 2)

    def test_ensure_fetches_only_when_empty(self):
        pool = FreshProxyPool(cache_file=str(self.cache), min_anon=2)
        with mock.patch.object(pool, "fetch", return_value=2) as fetch:
            pool._proxies = [{"host": "x", "port": "80"}]
            self.assertEqual(pool.ensure(), 1)
            fetch.assert_not_called()


class TestRotatorProxyIntegration(unittest.TestCase):

    def test_rotator_uses_pool_before_tor(self):
        r = OpsecRotator(use_fresh_proxies=True)
        r._proxy_pool = mock.Mock()
        r._proxy_pool.ensure.return_value = 3
        r._proxy_pool.proxy_dict.return_value = {
            "http": "http://1.2.3.4:8080", "https": "http://1.2.3.4:8080"}
        self.assertEqual(r.get_proxy_dict(),
                         {"http": "http://1.2.3.4:8080",
                          "https": "http://1.2.3.4:8080"})

    def test_rotator_pool_empty_falls_back_to_none_without_tor(self):
        r = OpsecRotator(use_fresh_proxies=True)
        r._proxy_pool = mock.Mock()
        r._proxy_pool.ensure.return_value = 0
        r._proxy_pool.proxy_dict.return_value = None
        r._use_tor = False
        self.assertIsNone(r.get_proxy_dict())

    def test_default_rotator_has_no_pool(self):
        r = OpsecRotator()
        self.assertIsNone(r._proxy_pool)
        self.assertEqual(r.session_stats()["fresh_proxies"], 0)

    def test_pool_url_is_fresh_proxy_list(self):
        self.assertEqual(PROXY_LIST_URL,
                         "https://raw.githubusercontent.com/rix4uni/"
                         "fresh-proxy-list/main/proxylist.json")


if __name__ == "__main__":
    unittest.main()
