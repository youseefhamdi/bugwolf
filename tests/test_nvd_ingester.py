#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.nvd_ingester import NVDIngester, normalize_nvd_cve
from tools.novelty_pipeline import AdvisoryCatalog


class TestNVDIngester(unittest.TestCase):
    def test_normalizes_nvd_cve_entry(self):
        record = normalize_nvd_cve({
            "id": "CVE-2026-0001",
            "descriptions": [{"lang": "en", "value": "Reentrancy in Vault contract leads to loss"},
                             {"lang": "de", "value": "Reentrancy im Vault"}],
            "published": "2026-01-01T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        })
        self.assertEqual(record.cve_id, "CVE-2026-0001")
        self.assertEqual(record.severity, "critical")
        self.assertIn("reentrancy", record.keywords)
        self.assertIn("vault", record.keywords)

    def test_ingest_writes_catalog_and_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = Path(tmp) / "feed.json"
            feed.write_text(json.dumps({"vulnerabilities": [{
                "cve": {"id": "CVE-2026-0002",
                        "descriptions": [{"lang": "en", "value": "SQL injection in search"}],
                        "published": "2026-02-01T00:00:00Z",
                        "metrics": {}},
            }]}))
            ingester = NVDIngester()
            catalog_path = Path(tmp) / "advisories.json"
            result = ingester.ingest_file(feed, catalog_path)
            self.assertEqual(result["ingested"], 1)
            catalog = AdvisoryCatalog.load(catalog_path)
            self.assertEqual(len(catalog.records), 1)
            self.assertEqual(catalog.records[0].cve_id, "CVE-2026-0002")


if __name__ == "__main__":
    unittest.main()