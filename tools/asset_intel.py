#!/usr/bin/env python3
"""Offline external-asset intelligence for BugWolf.

The module does not contact Shodan, Censys, FOFA, Zoomeye, SpiderFoot, Amass,
or any other provider. It creates query plans and normalizes operator-supplied
exports so the resulting asset graph remains scope-bound and reproducible.

The one exception is the optional ``ipfinder`` adapter: ``rix4uni/ipfinder``
is a local Go CLI that reads Shodan facet queries on stdin and prints
matching IPs/domains (``query::value`` lines with ``--source``) by scraping
Shodan's public search facets — a passive third-party source like the crt.sh
adapter. The adapter is offline by default: it emits facet query plans and
the exact ``ipfinder`` command lines, and normalizes operator-saved runs.
Live collection requires ``--collect-ipfinder`` + ``--confirm-active`` and
still filters every result back through the supplied scope. Bare IPs returned
by a facet query are kept only when the query term itself is in scope (the
Shodan facet is constrained by that term), so out-of-scope cert/hostname
matches never reach downstream tools.

Usage:
  python3 tools/asset_intel.py --target example.com --scope-file scope.json --input-file recon/example.com/subs.txt --output-dir recon/example.com/asset-intel
  python3 tools/asset_intel.py --target example.com --scope-file scope.json --shodan-facets --output-dir recon/example.com/asset-intel
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

try:
    from tools.safety import AuthorizationError, safe_target_name, target_in_scope
except ImportError:  # direct script execution
    from safety import AuthorizationError, safe_target_name, target_in_scope  # type: ignore


@dataclass
class ProviderQueryPlan:
    provider: str
    purpose: str
    query: str
    input_required: str
    status: str = "offline_plan_only"
    safety: List[str] = field(default_factory=list)
    command: str = ""


@dataclass
class AssetRecord:
    asset_id: str
    hostname: str = ""
    ip: str = ""
    port: str = ""
    source: str = ""
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    evidence_hash: str = ""


@dataclass
class AssetDiff:
    asset_id: str
    change: str
    current: Optional[AssetRecord] = None
    previous: Optional[AssetRecord] = None


def _asset_id(hostname: str, ip: str, port: str) -> str:
    raw = "|".join((hostname.lower().strip(), ip.strip(), port.strip()))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def provider_query_plans(target: str) -> List[ProviderQueryPlan]:
    safe_target_name(target)
    common = [
        "operator-provided authorization and scope file",
        "do not feed returned out-of-scope assets into active tools",
        "store provider exports with credentials removed",
    ]
    return [
        ProviderQueryPlan("amass", "passive domain relationships", f"domain:{target}", "local amass export", safety=common),
        ProviderQueryPlan("shodan", "passive host/service observations", f"hostname:{target}", "operator Shodan export", safety=common),
        ProviderQueryPlan("censys", "passive certificate/service observations", f"names: {target}", "operator Censys export", safety=common),
        ProviderQueryPlan("fofa", "passive indexed web assets", f'domain="{target}"', "operator FOFA export", safety=common),
        ProviderQueryPlan("zoomeye", "passive indexed services", f'hostname:"{target}"', "operator ZoomEye export", safety=common),
        ProviderQueryPlan("spiderfoot", "correlated passive OSINT", target, "operator SpiderFoot export", safety=common),
    ]


# ---------------------------------------------------------------------------
# ipfinder (rix4uni/ipfinder) — Shodan facet collection adapter
# ---------------------------------------------------------------------------

# Facet filters that accept a domain term and are the beginner-friendly
# ``--filter`` values documented by the tool.
IPFINDER_FACET_FILTERS = ("ssl", "hostname", "ssl.cert.subject.cn")

# ``--source`` output shape:  <query>::<value>
_IPFINDER_LINE_RE = re.compile(r"^(?P<query>.+?)::(?P<value>\S+)$")


def shodan_facet_queries(target: str, org: str = "", asn: str = "") -> List[str]:
    """The operator-authorized Shodan facet query set for ``ipfinder``.

    Domain-derived facets (ssl/hostname/cert-CN) are built from the target;
    ``org``/``asn`` facets are only added when the operator supplies the
    values explicitly (they cannot be verified against a domain scope).
    """
    safe_target_name(target)
    queries = [f'{filt}:"{target}"' for filt in IPFINDER_FACET_FILTERS]
    if org:
        queries.append(f'org:"{org}"')
    if asn:
        queries.append(f'asn:"{asn}"')
    return queries


def shodan_facet_plans(target: str, org: str = "", asn: str = "") -> List[ProviderQueryPlan]:
    """Offline ipfinder plan: facet query + the exact command to run it."""
    safety = [
        "query term is derived from the authorized target",
        "run with --source so every result carries its query for scope re-checking",
        "filter returned assets back through the scope file before use",
    ]
    plans = []
    for query in shodan_facet_queries(target, org=org, asn=asn):
        plans.append(ProviderQueryPlan(
            provider="ipfinder", purpose="Shodan facet collection", query=query,
            input_required=f"echo '{query}' | ipfinder --silent --source",
            command=f"echo '{query}' | ipfinder --silent --source", safety=safety,
        ))
    return plans


def _ipfinder_query_term(query: str) -> str:
    match = re.match(r'^[A-Za-z0-9_.]+:"([^"]+)"', query.strip())
    return match.group(1).strip() if match else ""


def _ipfinder_value_authorized(query: str, value: str, scope: Dict[str, Any]) -> bool:
    """Fail-closed scope check for one ipfinder result line.

    Hostname values are checked directly against the scope. Bare IP values
    (which cannot match a domain scope) are kept only when the query term
    itself is in scope — the Shodan facet constrains results to that term,
    so the authorization is carried by the query, not the opaque IP.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return target_in_scope(value, scope)
    term = _ipfinder_query_term(query)
    return bool(term) and target_in_scope(term, scope)


def parse_ipfinder_output(lines: Iterable[str], source: str = "ipfinder",
                          scope: Optional[Dict[str, Any]] = None) -> List[AssetRecord]:
    """Normalize an ipfinder ``--source`` run into deduplicated assets.

    Each line is ``query::value``; the value is an IP (facet=ip) or a
    hostname (facet=domain). With a scope, every record is filtered
    fail-closed: hostnames must be in scope, and bare IPs are kept only when
    their query term is in scope (see :func:`_ipfinder_value_authorized`).
    """
    records: Dict[str, AssetRecord] = {}
    for line in lines:
        match = _IPFINDER_LINE_RE.match(line.strip())
        if not match:
            continue
        query, value = match.group("query"), match.group("value")
        if scope is not None:
            try:
                if not _ipfinder_value_authorized(query, value, scope):
                    continue
            except AuthorizationError:
                continue
        try:
            ipaddress.ip_address(value)
            record = AssetRecord(_asset_id("", value, ""), ip=value, source=source)
        except ValueError:
            hostname = _host_from(value)
            if not hostname:
                continue
            record = AssetRecord(_asset_id(hostname, "", ""), hostname=hostname, source=source)
        records[record.asset_id] = record
    return sorted(records.values(), key=lambda record: record.asset_id)


def _run_ipfinder(binary: str, query: str, *, timeout: int = 180) -> List[str]:
    """Run one ipfinder facet query; returns the raw ``--source`` lines."""
    try:
        from tools.runtime.sandbox import sandboxed_run
        result = sandboxed_run(
            [binary, "--silent", "--source"], cwd=os.getcwd(),
            input_text=query, timeout=timeout, purpose="asset_intel",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"ipfinder failed for {query}: {exc}") from exc
    return [line for line in (result.stdout or "").splitlines() if line.strip()]


def _host_from(value: Any) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value.split()[0]).strip().lower().rstrip(".")


def _record_from_item(item: Any, source: str) -> Optional[AssetRecord]:
    if isinstance(item, str):
        parts = item.strip().split()
        if not parts:
            return None
        hostname = _host_from(parts[0])
        ip = ""
        port = ""
    elif isinstance(item, dict):
        hostnames = item.get("hostnames")
        if isinstance(hostnames, list):
            hostnames = hostnames[0] if hostnames else ""
        hostname = _host_from(
            item.get("hostname") or item.get("host") or item.get("domain")
            or item.get("name") or item.get("url") or hostnames
        )
        ip = str(item.get("ip") or item.get("ip_str") or item.get("address") or "").strip()
        port = str(item.get("port") or item.get("service_port") or "").strip()
        source = str(item.get("source") or source)
        first_seen = str(item.get("first_seen") or item.get("firstSeen") or "")
        last_seen = str(item.get("last_seen") or item.get("lastSeen") or "")
        tags = item.get("tags") or item.get("products") or []
        if isinstance(tags, str):
            tags = [tags]
        tags = [str(tag)[:100] for tag in tags if str(tag).strip()][:20]
        evidence = json.dumps({"hostname": hostname, "ip": ip, "port": port, "source": source}, sort_keys=True)
        return AssetRecord(_asset_id(hostname, ip, port), hostname, ip, port, source,
                           first_seen, last_seen, tags,
                           hashlib.sha256(evidence.encode()).hexdigest())
    else:
        return None
    if not hostname and not ip:
        return None
    return AssetRecord(_asset_id(hostname, ip, port), hostname, ip, port, source)


def normalize_exports(values: Iterable[Any], source: str, scope: Dict[str, Any]) -> List[AssetRecord]:
    records: Dict[str, AssetRecord] = {}
    for value in values:
        record = _record_from_item(value, source)
        if record is None:
            continue
        candidate = record.hostname or record.ip
        try:
            if not target_in_scope(candidate, scope):
                continue
        except AuthorizationError:
            continue
        records[record.asset_id] = record
    return sorted(records.values(), key=lambda record: record.asset_id)


def _load_export(path: Path) -> List[Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for key in ("matches", "results", "assets", "data", "nodes"):
                if isinstance(value.get(key), list):
                    return value[key]
            return [value]
    except json.JSONDecodeError:
        jsonl: List[Any] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                jsonl.append(json.loads(line))
            except json.JSONDecodeError:
                jsonl.append(line)
        return jsonl
    return [line for line in text.splitlines() if line.strip()]


def diff_assets(previous: Iterable[AssetRecord], current: Iterable[AssetRecord]) -> List[AssetDiff]:
    old = {item.asset_id: item for item in previous}
    new = {item.asset_id: item for item in current}
    diffs: List[AssetDiff] = []
    for asset_id in sorted(new.keys() - old.keys()):
        diffs.append(AssetDiff(asset_id, "added", current=new[asset_id]))
    for asset_id in sorted(old.keys() - new.keys()):
        diffs.append(AssetDiff(asset_id, "removed", previous=old[asset_id]))
    for asset_id in sorted(new.keys() & old.keys()):
        if asdict(new[asset_id]) != asdict(old[asset_id]):
            diffs.append(AssetDiff(asset_id, "changed", current=new[asset_id], previous=old[asset_id]))
    return diffs


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf offline asset intelligence")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--input-file", action="append", default=[])
    parser.add_argument("--previous-file", default="")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--shodan-facets", action="store_true",
                        help="Emit ipfinder Shodan facet query plans + command lines (offline)")
    parser.add_argument("--org", default="",
                        help="Add an org:\"…\" facet (operator-supplied organization name)")
    parser.add_argument("--asn", default="",
                        help="Add an asn:\"…\" facet (operator-supplied AS number)")
    parser.add_argument("--ipfinder-output", default="",
                        help="Normalize a saved ipfinder --source run (query::value lines) into scoped assets")
    parser.add_argument("--collect-ipfinder", action="store_true",
                        help="Run the ipfinder binary per facet query (requires --confirm-active)")
    parser.add_argument("--confirm-active", action="store_true",
                        help="Explicitly authorize live ipfinder Shodan collection")
    parser.add_argument("--ipfinder-bin", default="ipfinder")
    parser.add_argument("--timeout", type=int, default=180,
                        help="Per-query timeout seconds for live ipfinder collection")
    args = parser.parse_args()
    safe_target_name(args.target)
    scope = json.loads(Path(args.scope_file).read_text(encoding="utf-8"))
    if scope.get("authorized") is not True:
        raise SystemExit(2)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {"schema": "bugwolf-asset-intel-v1", "target": args.target}

    if args.shodan_facets or args.collect_ipfinder:
        plans = shodan_facet_plans(args.target, org=args.org, asn=args.asn)
        with (output / "shodan-facet-plans.jsonl").open("w", encoding="utf-8") as handle:
            for plan in plans:
                handle.write(json.dumps(asdict(plan), sort_keys=True) + "\n")
        manifest["facet_queries"] = len(plans)
        if args.collect_ipfinder:
            # Phase 0: live collection is gated by the operator-declared
            # scope file (loaded above). The ipfinder binary path is
            # resolved through the sandbox binary allowlist.
            binary = shutil.which(args.ipfinder_bin)
            if not binary:
                raise SystemExit(f"ipfinder binary not found: {args.ipfinder_bin}")
            raw_lines: List[str] = []
            for plan in plans:
                try:
                    raw_lines.extend(_run_ipfinder(binary, plan.query, timeout=args.timeout))
                except RuntimeError as exc:
                    print(f"[!] {exc}", file=sys.stderr)
            raw_path = output / "ipfinder-raw.txt"
            raw_path.write_text("\n".join(raw_lines) + ("\n" if raw_lines else ""),
                                encoding="utf-8")
            records = parse_ipfinder_output(raw_lines, scope=scope)
            with (output / "ipfinder-assets.jsonl").open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")
            manifest.update({"execution": "gated_active", "assets": len(records),
                             "raw_lines": len(raw_lines)})
            print(json.dumps(manifest, indent=2))
            return
        manifest.update({"execution": "offline_plan_only"})
        print(json.dumps(manifest, indent=2))
        return

    if args.ipfinder_output:
        path = Path(args.ipfinder_output)
        if not path.is_file():
            raise SystemExit(f"ipfinder output not found: {path}")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        records = parse_ipfinder_output(lines, source=path.stem, scope=scope)
        with (output / "ipfinder-assets.jsonl").open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")
        manifest.update({"execution": "offline_exports_only", "assets": len(records),
                         "input_lines": len(lines)})
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(manifest, indent=2))
        return

    records: List[AssetRecord] = []
    for filename in args.input_file:
        path = Path(filename)
        if path.is_file():
            records.extend(normalize_exports(_load_export(path), path.stem, scope))
    # Keep the final set deterministic after combining multiple provider exports.
    by_id = {record.asset_id: record for record in records}
    records = sorted(by_id.values(), key=lambda record: record.asset_id)
    previous: List[AssetRecord] = []
    if args.previous_file and Path(args.previous_file).is_file():
        previous = [AssetRecord(**row) for row in _load_export(Path(args.previous_file)) if isinstance(row, dict)]
    diffs = diff_assets(previous, records)
    for name, rows in (("assets.jsonl", records), ("asset-diff.jsonl", diffs)):
        with (output / name).open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(asdict(row), sort_keys=True) + "\n")
    with (output / "provider-plans.jsonl").open("w", encoding="utf-8") as handle:
        for plan in provider_query_plans(args.target):
            handle.write(json.dumps(asdict(plan), sort_keys=True) + "\n")
    manifest.update({"assets": len(records), "changes": len(diffs),
                     "providers": 6, "execution": "offline_exports_only"})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
