#!/usr/bin/env python3
"""BugWolf Historical Asset Delta - passive-DNS / certificate-transparency churn tracker.

Tracks an operator-declared target's asset surface (subdomains, hosts, URLs,
certificate observations) across timestamped snapshots and derives the churn
categories that matter for hunting:

  * ``added``      - assets present in the latest snapshot that were absent
                    from the FIRST snapshot (late arrivals + brand new);
                     the campaign's first snapshot (fresh deployments, new CT
                     log entries);
  * ``reattached`` - assets that disappeared and later returned (DNS churn,
                     hosting changes - high-signal recon leads);
  * ``removed``    - assets present in the FIRST snapshot but gone from the
                    latest (fresh NXDOMAIN / takeover candidates);
                     (NXDOMAIN / dangling-resource takeover candidates);
  * ``forgotten``  - assets ever seen that are absent from the latest snapshot
                     (the long tail a fresh recon run would silently drop).

API (contract-tested by ``tests/test_week3_cloud_mobile_recon.py``):

  * ``compute_delta(target, snapshots)``   - snapshots =
    ``[{"as_of": "2026-01", "assets": ["api.example.com", ...]}, ...]``;
    returns a ``HistoricalDelta`` with ``added/removed/reattached/forgotten``
    (each an ``AssetSet`` with ``.assets`` / ``.count``), ``total_tracked``,
    and a deterministic ``to_dict()``.
  * ``ingest_historical(target, records, base_dir=...)`` - merge historical
    records (``{"name": ..., "first_seen": ..., "last_seen": ...}``) into a
    per-target history file; returns ``{name: AssetObservation}`` with
    min(first_seen) / max(last_seen) per asset.
  * ``history_path(base_dir, target)``     - the per-target history file.
  * ``_load_snapshot(path)``               - parse a JSONL/JSON/text snapshot
    file into ``{"as_of": ..., "assets": [...]}``.

Asset canonicalization is deterministic: case-folded, trailing dots stripped,
URLs reduced to their host, empty/comment/wildcard tokens skipped - so
``API.Example.COM`` and ``api.example.com.`` are the same asset.

Design discipline (per DEPENDENCIES.md leaf rules): stdlib only, fully
offline (no target contact), imports only ``tools.runtime_paths``; snapshots
are immutable input data and the delta is pure derived state, so results are
reproducible run-to-run.

Usage:
  python3 tools/recon/historical_asset_delta.py --target acme.com \\
      --load-snapshot recon/acme/subdomains/passive.txt
  python3 tools/recon/historical_asset_delta.py --target acme.com \\
      --delta snap-old.json snap-new.json --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

try:
    from tools.runtime_paths import runtime_path, target_slug
except ImportError:  # direct script execution
    from runtime_paths import runtime_path, target_slug  # type: ignore

SCHEMA = "bugwolf-historical-asset-delta/v1"


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonical_asset(raw: Any) -> str:
    """Deterministic canonical form of one asset observation ('' = skip).

    Case-folded, trailing dot stripped, URLs reduced to the host, wildcard /
    empty / comment tokens skipped.
    """
    text = str(raw or "").strip().strip('"').strip("'")
    if not text or text.startswith("#"):
        return ""
    if "://" in text:
        try:
            from urllib.parse import urlparse
            host = (urlparse(text).hostname or "").lower()
        except ValueError:
            return ""
        return host.rstrip(".")
    token = text.split()[0].rstrip(".").lower()
    if token in {"", "*", "localhost"} or token.startswith("*."):
        return ""
    return token


def _assets_from_snapshot_entry(entry: Any) -> List[str]:
    """Extract asset strings from one snapshot entry (str/dict)."""
    if isinstance(entry, str):
        return [entry]
    if isinstance(entry, dict):
        value = (entry.get("name") or entry.get("host") or entry.get("domain")
                 or entry.get("subdomain") or entry.get("url") or entry.get("value"))
        return [str(value)] if value else []
    return []


# ---------------------------------------------------------------------------
# Snapshot loading
# ---------------------------------------------------------------------------


def _load_snapshot(path: Union[str, Path]) -> Dict[str, Any]:
    """Parse a snapshot file (JSONL records, JSON, or plain text).

    Returns ``{"as_of": ..., "assets": [...]}`` - assets are canonical and
    sorted; ``as_of`` falls back to the file stem when the data carries no
    timestamp.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    assets: List[str] = []
    as_of = p.stem

    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    as_of = str(record.get("as_of") or record.get("date") or as_of)
                    raw_assets = record.get("assets")
                    if isinstance(raw_assets, list):
                        assets.extend(_assets_from_snapshot_entry(raw_assets))
                    else:
                        assets.extend(_assets_from_snapshot_entry(record))
        else:
            if isinstance(data, dict):
                as_of = str(data.get("as_of") or data.get("date") or as_of)
                raw_assets = data.get("assets")
                if isinstance(raw_assets, list):
                    assets.extend(_assets_from_snapshot_entry(raw_assets))
                else:
                    for value in data.values():
                        if isinstance(value, list):
                            assets.extend(_assets_from_snapshot_entry(value))
            elif isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict) and entry.get("as_of"):
                        as_of = str(entry["as_of"])
                    assets.extend(_assets_from_snapshot_entry(entry))
    else:
        assets.extend(text.splitlines())

    canonical = sorted({canonical_asset(a) for a in assets} - {""})
    return {"as_of": as_of, "assets": canonical}


# ---------------------------------------------------------------------------
# Delta
# ---------------------------------------------------------------------------


@dataclass
class AssetSet:
    """One churn category: sorted canonical assets + count."""

    label: str
    assets: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.assets)

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "assets": list(self.assets), "count": self.count}


@dataclass
class HistoricalDelta:
    """Deterministic churn delta across a snapshot history."""

    target: str
    added: AssetSet
    removed: AssetSet
    reattached: AssetSet
    forgotten: AssetSet
    total_tracked: int
    window: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "window": list(self.window),
            "total_tracked": self.total_tracked,
            "added": self.added.to_dict(),
            "removed": self.removed.to_dict(),
            "reattached": self.reattached.to_dict(),
            "forgotten": self.forgotten.to_dict(),
        }


def _snapshot_sets(snapshots: Sequence[Any]) -> List[Dict[str, Any]]:
    """Normalize snapshot inputs to ``[{"as_of", "set"}, ...]`` (order kept)."""
    normalized: List[Dict[str, Any]] = []
    for snap in snapshots:
        if isinstance(snap, (str, Path)):
            loaded = _load_snapshot(snap)
            normalized.append({"as_of": str(loaded.get("as_of") or ""),
                               "set": set(loaded["assets"])})
            continue
        if not isinstance(snap, dict):
            continue
        raw = snap.get("assets")
        if isinstance(raw, str):
            raw = [raw]
        values: List[str] = []
        for entry in raw or []:
            values.extend(_assets_from_snapshot_entry(entry))
        normalized.append({
            "as_of": str(snap.get("as_of") or snap.get("date") or ""),
            "set": {canonical_asset(v) for v in values} - {""},
        })
    return normalized


def compute_delta(target: str, snapshots: Sequence[Any]) -> HistoricalDelta:
    """Churn categories across the full snapshot history.

    Categories (relative to the latest snapshot):
      * ``added``      - present now, absent from the FIRST snapshot
                         (staging-style late arrivals plus brand-new assets);
      * ``reattached`` - present now, was seen before, but missing from the
                         immediately-previous snapshot (DNS churn);
      * ``removed``    - present in the FIRST snapshot, missing now
                         (fresh NXDOMAIN / takeover candidates);
      * ``forgotten``  - ever seen, absent now (never silently dropped).
    """
    snaps = _snapshot_sets(snapshots)
    if not snaps:
        return HistoricalDelta(target=target, added=AssetSet("added"),
                               removed=AssetSet("removed"),
                               reattached=AssetSet("reattached"),
                               forgotten=AssetSet("forgotten"),
                               total_tracked=0, window=[])

    first = snaps[0]["set"]
    latest = snaps[-1]["set"]
    prev = snaps[-2]["set"] if len(snaps) > 1 else set()
    ever_before = set().union(*(s["set"] for s in snaps[:-1])) if len(snaps) > 1 else set()
    ever_all = ever_before | latest

    # added: arrived after the first snapshot (late arrivals + brand new).
    added = sorted(latest - first)
    # reattached: seen before, dropped in the immediately-previous snapshot, back now.
    reattached = sorted((latest & ever_before) - prev) if len(snaps) > 1 else []
    # removed: known at baseline, gone from the latest snapshot.
    removed = sorted(first - latest) if len(snaps) > 1 else []
    forgotten = sorted(ever_all - latest)

    window = [s["as_of"] for s in snaps]
    return HistoricalDelta(
        target=target,
        added=AssetSet("added", added),
        removed=AssetSet("removed", removed),
        reattached=AssetSet("reattached", reattached),
        forgotten=AssetSet("forgotten", forgotten),
        total_tracked=len(ever_all),
        window=window,
    )


# ---------------------------------------------------------------------------
# Historical record merge (first_seen / last_seen per asset)
# ---------------------------------------------------------------------------


@dataclass
class AssetObservation:
    """One asset's merged observation window."""

    name: str
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "source": self.source}


def history_path(base_dir: Union[str, Path], target: str) -> Path:
    """Per-target append-only history file under ``base_dir``."""
    slug = target_slug(target)
    return Path(base_dir) / "recon-history" / f"{slug}.jsonl"


def _record_value(record: Dict[str, Any]) -> str:
    value = (record.get("name") or record.get("host") or record.get("domain")
             or record.get("subdomain") or record.get("url") or record.get("value"))
    return canonical_asset(value) if value else ""


def _record_date(record: Dict[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        if record.get(key):
            return str(record[key])
    return ""


def ingest_historical(target: str, records: Iterable[Dict[str, Any]], *,
                      base_dir: Optional[Union[str, Path]] = None
                      ) -> Dict[str, AssetObservation]:
    """Merge historical observation records into the per-target history.

    Every record is appended to ``history_path(base_dir, target)`` (one JSON
    line per record - history is never rewritten), and the merged view is
    returned: one ``AssetObservation`` per asset with the earliest
    ``first_seen`` and the latest ``last_seen`` across all records.
    """
    if base_dir is None:
        base_dir = runtime_path("state", "recon")
    path = history_path(base_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)

    merged: Dict[str, AssetObservation] = {}
    with open(path, "a", encoding="utf-8") as fh:
        for record in records:
            if not isinstance(record, dict):
                continue
            name = _record_value(record)
            if not name:
                continue
            first_seen = _record_date(record, ("first_seen", "seen", "date", "as_of"))
            last_seen = _record_date(record, ("last_seen", "seen", "date", "as_of"))
            source = str(record.get("source") or record.get("origin") or "historical")
            line = {"schema": SCHEMA, "target": target, "name": name,
                    "first_seen": first_seen, "last_seen": last_seen,
                    "source": source}
            fh.write(json.dumps(line, sort_keys=True, default=str) + "\n")

            obs = merged.get(name)
            if obs is None:
                merged[name] = AssetObservation(name=name, first_seen=first_seen,
                                                last_seen=last_seen, source=source)
                continue
            if first_seen and (not obs.first_seen or first_seen < obs.first_seen):
                obs.first_seen = first_seen
            if last_seen and (not obs.last_seen or last_seen > obs.last_seen):
                obs.last_seen = last_seen
            if source and source != "historical":
                obs.source = source
    return merged


def load_history(base_dir: Union[str, Path], target: str) -> Dict[str, AssetObservation]:
    """Read the merged observation view from a persisted history file."""
    path = history_path(base_dir, target)
    if not path.is_file():
        return {}
    merged: Dict[str, AssetObservation] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        name = str(record.get("name") or "")
        if not name:
            continue
        first_seen = str(record.get("first_seen") or "")
        last_seen = str(record.get("last_seen") or "")
        obs = merged.get(name)
        if obs is None:
            merged[name] = AssetObservation(name=name, first_seen=first_seen,
                                            last_seen=last_seen,
                                            source=str(record.get("source") or ""))
            continue
        if first_seen and (not obs.first_seen or first_seen < obs.first_seen):
            obs.first_seen = first_seen
        if last_seen and (not obs.last_seen or last_seen > obs.last_seen):
            obs.last_seen = last_seen
    return merged


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive-DNS / CRT churn tracker (offline, deterministic)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--load-snapshot", dest="load_snapshot",
                        help="parse a snapshot file and print its canonical assets")
    parser.add_argument("--ingest-records", dest="ingest_records",
                        help="JSON/JSONL historical records to merge into history")
    parser.add_argument("--base-dir", help="history base directory override")
    parser.add_argument("--delta", nargs="*", metavar="SNAPSHOT",
                        help="compute delta from snapshot files/JSON (default: latest vs previous)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    base_dir = args.base_dir or runtime_path("state", "recon")

    if args.load_snapshot:
        snap = _load_snapshot(args.load_snapshot)
        print(json.dumps(snap, indent=2))
        return 0

    if args.ingest_records:
        records: List[Dict[str, Any]] = []
        text = Path(args.ingest_records).read_text(encoding="utf-8", errors="replace")
        try:
            loaded = json.loads(text)
            records = loaded if isinstance(loaded, list) else [loaded]
        except ValueError:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
        obs = ingest_historical(args.target, records, base_dir=base_dir)
        payload = {name: o.to_dict() for name, o in sorted(obs.items())}
        print(json.dumps(payload, indent=2))
        return 0

    if args.delta is not None:
        if args.delta:
            snaps = [_load_snapshot(s) for s in args.delta]
        else:
            hist_dir = Path(base_dir) / "snapshots"
            snaps = [_load_snapshot(p) for p in sorted(hist_dir.glob("*.json*"))]
        delta = compute_delta(args.target, snaps)
        print(json.dumps(delta.to_dict(), indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
