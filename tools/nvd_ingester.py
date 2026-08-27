#!/usr/bin/env python3
"""Bounded NVD/CVE feed ingestion into the local advisory catalog.

The ingester accepts a local NVD 2.0-style feed file (JSON) and normalizes
each CVE into an ``AdvisoryRecord``. Offline file ingestion is the default;
``fetch_recent`` adds an optional bounded online mode that pulls a limited
window from the NVD API with a strict timeout and no retry loop, degrading
gracefully when the network is unavailable. Egress is therefore always
under operator control.

Severity is mapped from CVSS v3 base scores. Keywords are derived from the
English description so the novelty pipeline can match candidate text.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.novelty_pipeline import AdvisoryCatalog, AdvisoryRecord
from tools.reliability import atomic_write_json

_TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{2,}")
_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "which", "lead",
    "leads", "allows", "allow", "could", "can", "may", "into", "via", "due",
    "such", "vulnerability", "vulnerabilities", "attackers", "attacker",
    "remote", "local", "affected", "product", "products", "version",
    "versions", "information", "arbitrary", "result", "results", "cause",
    "caused", "including", "before", "after", "when", "while", "have", "has",
    "been", "were", "was", "are", "is", "not", "also", "other", "more",
}

_CVSS_TO_SEVERITY = [
    (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"),
]


def _keywords(text: str) -> List[str]:
    seen = set()
    out = []
    for token in _TOKEN_RE.findall(text.lower()):
        if token not in _STOPWORDS and token not in seen:
            seen.add(token)
            out.append(token)
        if len(out) >= 16:
            break
    return out


def normalize_nvd_cve(entry: Dict[str, Any]) -> AdvisoryRecord:
    """Convert one NVD 2.0 ``cve`` object into an AdvisoryRecord."""
    descriptions = entry.get("descriptions") or []
    description = ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            description = str(item.get("value") or "")
            break
    if not description and descriptions:
        description = str(descriptions[0].get("value") or "") if isinstance(descriptions[0], dict) else ""
    metrics = entry.get("metrics") or {}
    score = 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            score = max(score, float(data.get("baseScore") or 0.0))
    return AdvisoryRecord(
        cve_id=str(entry.get("id") or ""),
        keywords=_keywords(description),
        description=description[:500],
        severity=_severity(score),
        source="nvd",
        published=str(entry.get("published") or ""),
    )


def _severity(score: float) -> str:
    for threshold, label in _CVSS_TO_SEVERITY:
        if score >= threshold:
            return label
    return "info"


class NVDIngester:
    """Normalize a local NVD 2.0 feed file into the advisory catalog."""

    def ingest_file(self, feed_path: str | Path, catalog_path: str | Path) -> Dict[str, Any]:
        data = json.loads(Path(feed_path).read_text(encoding="utf-8"))
        entries = data.get("vulnerabilities") if isinstance(data, dict) else data
        records = _normalize_entries(entries)
        return _merge_catalog(records, catalog_path)

    def ingest_feed(self, data: Dict[str, Any], catalog_path: str | Path, *,
                    max_records: int = 0) -> Dict[str, Any]:
        """Normalize an already-loaded NVD 2.0 feed object."""
        entries = data.get("vulnerabilities") if isinstance(data, dict) else data
        records = _normalize_entries(entries, max_records=max_records)
        return _merge_catalog(records, catalog_path)


def _normalize_entries(entries: Any, *, max_records: int = 0) -> List[AdvisoryRecord]:
    records: List[AdvisoryRecord] = []
    for item in entries or []:
        if max_records and len(records) >= max_records:
            break
        if not isinstance(item, dict):
            continue
        cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
        if not cve or not cve.get("id"):
            continue
        records.append(normalize_nvd_cve(cve))
    return records


def _merge_catalog(records: List[AdvisoryRecord], catalog_path: str | Path) -> Dict[str, Any]:
    catalog = AdvisoryCatalog(records)
    if Path(catalog_path).is_file():
        existing = AdvisoryCatalog.load(catalog_path)
        catalog = AdvisoryCatalog(existing.records + records)
    catalog.write(catalog_path)
    return {"ingested": len(records), "total": len(catalog.records),
            "catalog_path": str(Path(catalog_path).resolve())}


def _http_get_json(url: str, *, timeout: float) -> Any:
    """Fetch a URL with a strict timeout and return parsed JSON."""
    response = urllib.request.urlopen(url, timeout=timeout)
    try:
        return json.loads(response.read().decode("utf-8"))
    finally:
        response.close()


def fetch_recent(catalog_path: str | Path, *, days: int = 30,
                 max_records: int = 500, timeout: float = 15.0) -> Dict[str, Any]:
    """Optionally fetch a bounded recent NVD window and merge it into the catalog.

    Defaults to offline behavior: if the fetch fails for any reason (no
    network, timeout, HTTP error), the catalog is left untouched and the
    error is reported in the result. There is no retry loop.
    """
    import datetime as _dt
    start = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=max(1, days)))
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
        "&pubEndDate=" + _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        + f"&resultsPerPage={max(1, min(int(max_records), 2000))}"
    )
    try:
        data = _http_get_json(url, timeout=timeout)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return {"fetched": 0, "ingested": 0, "error": str(exc),
                "catalog_path": str(Path(catalog_path).resolve())}
    entries = data.get("vulnerabilities") if isinstance(data, dict) else data
    fetched = len([e for e in entries or [] if isinstance(e, dict)])
    ingester = NVDIngester()
    result = ingester.ingest_feed(data, catalog_path, max_records=max_records)
    return {"fetched": fetched, **result}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf NVD advisory ingestion")
    parser.add_argument("--feed", default="", help="local NVD 2.0 JSON feed file")
    parser.add_argument("--fetch", action="store_true",
                        help="fetch a bounded recent window from the NVD API")
    parser.add_argument("--catalog", default="state/advisories.json",
                        help="advisory catalog path to write")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--max-records", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.fetch:
            result = fetch_recent(args.catalog, days=args.days,
                                  max_records=args.max_records, timeout=args.timeout)
        elif args.feed:
            result = NVDIngester().ingest_file(args.feed, args.catalog)
        else:
            parser.error("provide --feed <file> or --fetch")
    except (ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())