"""Bounded online NVD fetch mode: strict timeouts, no retries, offline-safe."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.nvd_ingester import NVDIngester, fetch_recent


class NVDIngesterFetchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.catalog_path = self.root / "advisories.json"
        self.ingester = NVDIngester()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _feed(self, count: int = 2) -> dict:
        vulns = []
        for i in range(count):
            vulns.append({
                "cve": {
                    "id": f"CVE-2026-{1000 + i:04d}",
                    "published": f"2026-08-0{i + 1}T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": f"Example {i} path traversal in product-x"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                }
            })
        return {"vulnerabilities": vulns}

    @mock.patch("tools.nvd_ingester._http_get_json")
    def test_fetch_recent_ingests_bounded_window(self, mock_get: mock.Mock) -> None:
        mock_get.return_value = self._feed(2)
        result = fetch_recent(self.catalog_path, days=30, max_records=10)
        self.assertEqual(result["ingested"], 2)
        self.assertEqual(result["fetched"], 2)
        self.assertTrue(Path(result["catalog_path"]).is_file())

    @mock.patch("tools.nvd_ingester._http_get_json")
    def test_fetch_recent_caps_at_max_records(self, mock_get: mock.Mock) -> None:
        mock_get.return_value = self._feed(5)
        result = fetch_recent(self.catalog_path, days=30, max_records=3)
        self.assertEqual(result["fetched"], 5)
        self.assertEqual(result["ingested"], 3)

    @mock.patch("tools.nvd_ingester._http_get_json")
    def test_fetch_recent_is_offline_safe(self, mock_get: mock.Mock) -> None:
        mock_get.side_effect = OSError("no network")
        result = fetch_recent(self.catalog_path, days=30, max_records=10)
        self.assertEqual(result["ingested"], 0)
        self.assertEqual(result["error"], "no network")
        self.assertFalse(Path(result["catalog_path"]).is_file())

    @mock.patch("tools.nvd_ingester._http_get_json")
    def test_fetch_recent_uses_strict_timeout(self, mock_get: mock.Mock) -> None:
        mock_get.return_value = self._feed(1)
        fetch_recent(self.catalog_path, days=30, max_records=10, timeout=7)
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["timeout"], 7)

    def test_http_get_json_parses_response(self) -> None:
        response = mock.Mock()
        response.status = 200
        response.read.return_value = b'{"vulnerabilities": []}'
        with mock.patch("urllib.request.urlopen", return_value=response):
            from tools.nvd_ingester import _http_get_json
            data = _http_get_json("https://example.invalid/feed", timeout=5)
        self.assertEqual(data, {"vulnerabilities": []})


if __name__ == "__main__":
    unittest.main()