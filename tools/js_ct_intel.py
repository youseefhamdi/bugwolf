#!/usr/bin/env python3
"""BugWolf passive CT and JavaScript intelligence pipeline.

This module turns the useful parts of the referenced 2026 methodology into a
bounded, evidence-friendly phase:

* date-aware certificate-transparency records from crt.name, with crt.sh
  fallback;
* scope-filtered URL and subdomain inputs;
* optional katana/hakrawler collection behind the existing active gate;
* local LinkFinder, beautifier, and grep adapters when installed;
* built-in offline extraction for endpoints, source maps, workflow signals, and
  redacted secret *indicators* (secret values are never written).

It does not validate credentials, claim takeovers, exploit findings, or submit
reports. Outputs are hypotheses and intelligence requiring human validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

try:
    from tools.methodology_playbook import build_workflow_plans
    from tools.safety import (
        AuthorizationError,
        require_authorized_target,
        safe_target_name,
        target_in_scope,
    )
except ImportError:  # direct script execution
    from methodology_playbook import build_workflow_plans  # type: ignore
    from safety import (  # type: ignore
        AuthorizationError,
        require_authorized_target,
        safe_target_name,
        target_in_scope,
    )

try:
    from tools.js_token_forge import (
        analyze_text as analyze_token_forge,
        build_plans as build_token_forge_plans,
    )
except ImportError:  # direct script execution
    from js_token_forge import (  # type: ignore
        analyze_text as analyze_token_forge,
        build_plans as build_token_forge_plans,
    )


MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 20


@dataclass
class CertificateRecord:
    name: str
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    raw_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    tool: str
    available: bool
    executed: bool = False
    output_file: str = ""
    error: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_default(value: Any) -> str:
    return str(value)


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, default=_json_default) + "\n")
            count += 1
    return count


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_scope_filter(values: Iterable[str], scope: Dict[str, Any]) -> List[str]:
    """Keep only hosts/URLs accepted by the existing scope implementation."""
    kept: List[str] = []
    seen = set()
    for value in values:
        candidate = str(value).strip()
        if not candidate or candidate in seen:
            continue
        try:
            allowed = target_in_scope(candidate, scope)
        except AuthorizationError:
            allowed = False
        if allowed:
            kept.append(candidate)
            seen.add(candidate)
    return kept


def _fetch_json(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> Any:
    request = Request(url, headers={"User-Agent": "BugWolf-CT-Research/1.0"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310: fixed HTTPS sources below
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeded the bounded CT response size")
    return json.loads(payload.decode("utf-8", errors="replace"))


def _first(item: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _names_from_value(value: Any) -> List[str]:
    if isinstance(value, str):
        return [part.strip().lstrip("*.").lower() for part in re.split(r"[,\n]", value) if part.strip()]
    if isinstance(value, list):
        result: List[str] = []
        for part in value:
            result.extend(_names_from_value(part))
        return result
    return []


def _records_from_payload(payload: Any, source: str) -> List[CertificateRecord]:
    """Normalize the known crt.name/crt.sh response shapes."""
    if isinstance(payload, dict):
        for key in ("results", "data", "certificates", "items", "records"):
            if key in payload and isinstance(payload[key], (list, dict)):
                return _records_from_payload(payload[key], source)
        payload = [payload]
    if not isinstance(payload, list):
        return []

    records: List[CertificateRecord] = []
    for item in payload:
        if isinstance(item, str):
            names = _names_from_value(item)
            first_seen = last_seen = ""
            raw: Dict[str, Any] = {}
        elif isinstance(item, dict):
            names = []
            for key in (
                "name_value", "name", "domain", "domains", "common_name",
                "commonName", "subject_cn", "subject", "cn",
            ):
                names.extend(_names_from_value(item.get(key)))
            # crt.sh's not_before is the earliest certificate date available in
            # that record; crt.name may expose actual first_seen/last_seen.
            first_seen = _first(item, "first_seen", "firstSeen", "first_seen_at", "not_before", "notBefore")
            last_seen = _first(item, "last_seen", "lastSeen", "last_seen_at", "not_after", "notAfter")
            raw = {
                key: item[key]
                for key in ("id", "issuer_name", "issuer", "serial_number", "not_before", "not_after")
                if key in item
            }
        else:
            continue
        for name in names:
            if name and not name.startswith("*." ):
                records.append(CertificateRecord(name, first_seen, last_seen, source, raw))
    return records


def collect_certificate_records(
    target: str,
    scope: Dict[str, Any],
    *,
    fetcher: Callable[[str], Any] = _fetch_json,
) -> List[CertificateRecord]:
    """Collect and scope-filter CT records from crt.name, then crt.sh."""
    safe_target_name(target)
    encoded_target = quote(target, safe="")
    urls = (
        ("crt.name", f"https://crt.name/v1/search?apex={encoded_target}&dates=1"),
        ("crt.sh", f"https://crt.sh/?q={quote('%.' + target, safe='')}&output=json"),
    )
    collected: List[CertificateRecord] = []
    for source, url in urls:
        try:
            payload = fetcher(url)
            collected.extend(_records_from_payload(payload, source))
        except Exception:
            # One public source being unavailable must not discard the other.
            continue

    filtered: Dict[str, CertificateRecord] = {}
    for record in collected:
        try:
            if not target_in_scope(record.name, scope):
                continue
        except AuthorizationError:
            continue
        key = record.name.lower().rstrip(".")
        old = filtered.get(key)
        if old is None:
            filtered[key] = record
        else:
            # Prefer the source with date metadata and retain the broadest date range.
            if not old.first_seen and record.first_seen:
                old.first_seen = record.first_seen
            if not old.last_seen and record.last_seen:
                old.last_seen = record.last_seen
            if old.source != record.source:
                old.source = old.source + "," + record.source
    return sorted(filtered.values(), key=lambda item: (item.name, item.first_seen))


def _redacted(value: str, *, label: str = "value") -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"<redacted:{label}:sha256={digest}:len={len(value)}>"


SECRET_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("secret_assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{12,})")),
)


def _redact_secrets(text: str) -> tuple[str, List[Dict[str, Any]]]:
    indicators: List[Dict[str, Any]] = []
    redacted = text
    for label, pattern in SECRET_PATTERNS:
        for match in list(pattern.finditer(text)):
            whole = match.group(0)
            indicators.append({
                "type": label,
                "fingerprint": _redacted(whole, label=label),
            })
            redacted = redacted.replace(whole, _redacted(whole, label=label))
    return redacted, indicators


def _extract_js_signals(text: str) -> Dict[str, Any]:
    absolute = set(re.findall(r"https?://[^\s\"'`<>\\]+", text, re.IGNORECASE))
    relative = set(re.findall(r"[\"'`](/(?:api|graphql|oauth|auth|admin|internal|v[0-9])[A-Za-z0-9_?&=./:%{}-]*)[\"'`]", text, re.IGNORECASE))
    source_maps = set(re.findall(r"[^\s\"'`]+\.js\.map(?:\?[^\s\"'`]*)?", text, re.IGNORECASE))
    domains = set()
    for url in absolute:
        host = urlparse(url).hostname
        if host:
            domains.add(host.lower())
    return {
        "absolute_urls": sorted(absolute),
        "relative_endpoints": sorted(relative),
        "domains": sorted(domains),
        "source_maps": sorted(source_maps),
        "network_calls": sorted(set(re.findall(
            r"\b(fetch|axios|XMLHttpRequest|WebSocket|graphql|grpc)\b", text, re.IGNORECASE))),
        "workflow_terms": sorted(set(re.findall(
            r"(?i)\b(signup|signin|login|logout|verify|reset|checkout|purchase|subscribe|cancel|upgrade|downgrade|coupon|invite|role|admin|impersonat|upload|download|refund|transfer)\w*\b", text))),
    }


def _run_local_command(argv: Sequence[str], *, timeout: int, input_text: str = "") -> tuple[str, str, int]:
    try:
        result = subprocess.run(
            list(argv), input=input_text, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
        return result.stdout, result.stderr, result.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", str(exc), 124


def _linkfinder_output(path: Path, destination: Path, *, timeout: int = DEFAULT_TIMEOUT) -> ToolResult:
    command: Optional[List[str]] = None
    executable = shutil.which("linkfinder")
    if executable:
        command = [executable, "-i", str(path), "-o", "cli"]
    elif _module_available("linkfinder"):
        command = [sys.executable, "-m", "linkfinder", "-i", str(path), "-o", "cli"]
    if command is None:
        return ToolResult("linkfinder", False)
    stdout, stderr, code = _run_local_command(command, timeout=timeout)
    if stdout:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(stdout, encoding="utf-8")
    return ToolResult("linkfinder", True, True, str(destination), error=(stderr[-500:] if code else ""))


def _module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _beautify(path: Path, destination: Path, *, timeout: int = DEFAULT_TIMEOUT) -> ToolResult:
    executable = shutil.which("js-beautify")
    if executable:
        command = [executable, str(path)]
        tool = "js-beautify"
    else:
        executable = shutil.which("prettier")
        if not executable:
            return ToolResult("js-beautifier", False)
        command = [executable, "--parser", "babel", str(path)]
        tool = "prettier"
    stdout, stderr, code = _run_local_command(command, timeout=timeout)
    if code or not stdout.strip():
        return ToolResult(tool, True, True, error=stderr[-500:])
    destination.write_text(stdout, encoding="utf-8")
    return ToolResult(tool, True, True, str(destination))


def _grep_hits(path: Path, *, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    grep = shutil.which("grep")
    if not grep:
        return []
    pattern = r"api[_-]?key|secret|password|token|bearer|admin|internal|debug|graphql|sourceMappingURL"
    stdout, _, _ = _run_local_command([grep, "-Ein", pattern, str(path)], timeout=timeout)
    hits = []
    for line in stdout.splitlines()[:200]:
        redacted, indicators = _redact_secrets(line)
        hits.append({"file": str(path), "line": redacted[:1000], "secret_indicators": indicators})
    return hits


def _workflow_hypotheses(urls: Iterable[str]) -> List[Dict[str, Any]]:
    patterns = {
        "verification_bypass": r"(?i)(verify|confirmation|activate|reset)",
        "payment_or_subscription_sequence": r"(?i)(checkout|purchase|payment|subscribe|upgrade|downgrade|coupon|refund)",
        "state_replay_or_idempotency": r"(?i)(cancel|resend|retry|confirm|submit|transfer|invite)",
        "privileged_surface": r"(?i)(admin|backoffice|dashboard|manage|impersonat|internal)",
        "file_boundary": r"(?i)(upload|download|export|import|attachment|media)",
    }
    rows = []
    seen = set()
    for url in urls:
        for category, pattern in patterns.items():
            if re.search(pattern, url) and (category, url) not in seen:
                seen.add((category, url))
                rows.append({
                    "category": category,
                    "location": url,
                    "hypothesis": "Model the intended workflow, then compare skipped, repeated, reordered, and role-specific transitions.",
                    "status": "hypothesis_only",
                })
    return rows


def analyze_javascript(
    target: str,
    urls: Iterable[str],
    js_dir: Path,
    output_dir: Path,
    *,
    scope: Optional[Dict[str, Any]] = None,
    run_tools: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Analyze local JS artifacts and write redacted, deterministic outputs."""
    output_dir.mkdir(parents=True, exist_ok=True)
    beautified_dir = output_dir / "beautified"
    beautified_dir.mkdir(exist_ok=True)
    safe_urls = list(dict.fromkeys(str(url).strip() for url in urls if str(url).strip()))
    js_files = sorted(path for path in js_dir.rglob("*") if path.is_file() and path.suffix.lower() in {".js", ".mjs", ".cjs"}) if js_dir.is_dir() else []

    endpoint_set = set()
    analyses: List[Dict[str, Any]] = []
    secret_rows: List[Dict[str, Any]] = []
    grep_rows: List[Dict[str, Any]] = []
    tool_results: List[ToolResult] = []
    forge_findings: List = []
    for path in js_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            analyses.append({"file": str(path), "error": str(exc)[:300]})
            continue
        signals = _extract_js_signals(text)
        endpoint_set.update(signals["absolute_urls"])
        endpoint_set.update(signals["relative_endpoints"])
        redacted_text, indicators = _redact_secrets(text)
        if indicators:
            secret_rows.append({"file": str(path), "indicators": indicators})
        forge_findings.extend(analyze_token_forge(text, str(path)))
        analyses.append({
            "file": str(path),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "bytes": len(text.encode("utf-8")),
            "signals": signals,
            "secret_indicator_count": len(indicators),
        })
        if run_tools:
            link_destination = output_dir / "linkfinder" / (path.stem + ".txt")
            link_result = _linkfinder_output(path, link_destination, timeout=timeout)
            tool_results.append(link_result)
            if link_result.output_file and Path(link_result.output_file).is_file():
                link_text = Path(link_result.output_file).read_text(encoding="utf-8", errors="replace")
                link_signals = _extract_js_signals(link_text)
                endpoint_set.update(link_signals["absolute_urls"])
                endpoint_set.update(link_signals["relative_endpoints"])
            destination = beautified_dir / (path.stem + ".beautified.js")
            tool_results.append(_beautify(path, destination, timeout=timeout))
            grep_rows.extend(_grep_hits(path, timeout=timeout))

    forge_plans = build_token_forge_plans(forge_findings)
    _write_jsonl(output_dir / "js-analysis.jsonl", analyses)
    _write_jsonl(output_dir / "js-secrets.jsonl", secret_rows)
    _write_jsonl(output_dir / "js-grep.jsonl", grep_rows)
    _write_jsonl(output_dir / "token-forge-findings.jsonl",
                 [asdict(item) for item in forge_findings])
    _write_jsonl(output_dir / "token-forge-plans.jsonl",
                 [asdict(item) for item in forge_plans])
    (output_dir / "js-endpoints.txt").write_text(
        "\n".join(sorted(endpoint_set)) + ("\n" if endpoint_set else ""), encoding="utf-8"
    )
    if scope is not None:
        endpoint_set = set(_safe_scope_filter(endpoint_set, scope))
    workflow_rows = _workflow_hypotheses(list(safe_urls) + sorted(endpoint_set))
    workflow_plans = build_workflow_plans(
        target, list(safe_urls) + sorted(endpoint_set), scope=scope,
    )
    _write_jsonl(output_dir / "workflow-hypotheses.jsonl", workflow_rows)
    _write_jsonl(output_dir / "workflow-plans.jsonl", [asdict(plan) for plan in workflow_plans])
    return {
        "js_files": len(js_files),
        "endpoints": len(endpoint_set),
        "secret_files": len(secret_rows),
        "grep_hits": len(grep_rows),
        "token_forge_findings": len(forge_findings),
        "token_forge_plans": len(forge_plans),
        "workflow_hypotheses": len(workflow_rows),
        "workflow_plans": len(workflow_plans),
        "tools": [asdict(result) for result in tool_results],
    }


def _run_crawler(name: str, urls_file: Path, destination: Path, *, timeout: int) -> ToolResult:
    executable = shutil.which(name)
    if not executable:
        return ToolResult(name, False)
    if name == "katana":
        argv = [executable, "-list", str(urls_file), "-d", "3", "-silent", "-jc", "-rl", "5"]
        stdout, stderr, code = _run_local_command(argv, timeout=timeout)
    else:
        argv = [executable, "-d", "3", "-insecure"]
        input_text = urls_file.read_text(encoding="utf-8", errors="replace")
        stdout, stderr, code = _run_local_command(argv, timeout=timeout, input_text=input_text)
    destination.write_text(stdout, encoding="utf-8")
    return ToolResult(name, True, True, str(destination), stderr[-500:] if code else "")


def run_pipeline(
    target: str,
    scope_file: str,
    output_dir: Path,
    *,
    urls_file: Optional[Path] = None,
    js_dir: Optional[Path] = None,
    ct_only: bool = False,
    js_only: bool = False,
    collect_crawlers: bool = False,
    confirm_active: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Run CT and/or local JS intelligence under the supplied scope."""
    scope = require_authorized_target(target, scope_file, active=False)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary: Dict[str, Any] = {"target": target, "started_at": _utc_now(), "tools": []}

    records: List[CertificateRecord] = []
    if not js_only:
        records = collect_certificate_records(target, scope)
        _write_jsonl(output_dir / "ct-records.jsonl", [asdict(record) for record in records])
        (output_dir / "ct-subdomains.txt").write_text(
            "\n".join(record.name for record in records) + ("\n" if records else ""), encoding="utf-8"
        )
    summary["ct_records"] = len(records)

    if not ct_only:
        source_urls: List[str] = []
        if urls_file and urls_file.is_file():
            source_urls.extend(urls_file.read_text(encoding="utf-8", errors="replace").splitlines())
        crawler_input = output_dir / "crawler-input.txt"
        safe_urls = _safe_scope_filter(source_urls, scope)
        crawler_input.write_text("\n".join(safe_urls) + ("\n" if safe_urls else ""), encoding="utf-8")
        if collect_crawlers:
            require_authorized_target(target, scope_file, active=True, confirm_active=confirm_active)
            for name in ("katana", "hakrawler"):
                result = _run_crawler(name, crawler_input, output_dir / f"{name}.txt", timeout=timeout)
                summary["tools"].append(asdict(result))
                if result.executed and Path(result.output_file).is_file():
                    safe_urls.extend(Path(result.output_file).read_text(encoding="utf-8", errors="replace").splitlines())
        safe_urls = _safe_scope_filter(safe_urls, scope)
        js_root = js_dir or output_dir / "js"
        summary["javascript"] = analyze_javascript(
            target, safe_urls, js_root, output_dir, scope=scope,
            run_tools=True, timeout=timeout,
        )
    summary["finished_at"] = _utc_now()
    (output_dir / "manifest.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf JS and CT intelligence")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--urls-file", default="")
    parser.add_argument("--js-dir", default="")
    parser.add_argument("--ct-only", action="store_true")
    parser.add_argument("--js-only", action="store_true",
                        help="skip CT requests and analyze only local JS inputs")
    parser.add_argument("--collect-crawlers", action="store_true",
                        help="run katana/hakrawler; requires --confirm-active")
    parser.add_argument("--confirm-active", action="store_true")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 300:
        parser.error("--timeout must be between 1 and 300 seconds")
    try:
        summary = run_pipeline(
            args.target, args.scope_file, Path(args.output_dir),
            urls_file=Path(args.urls_file) if args.urls_file else None,
            js_dir=Path(args.js_dir) if args.js_dir else None,
            ct_only=args.ct_only,
            js_only=args.js_only,
            collect_crawlers=args.collect_crawlers,
            confirm_active=args.confirm_active,
            timeout=args.timeout,
        )
    except (AuthorizationError, PermissionError, ValueError) as exc:
        print(f"[!] JS/CT intelligence denied: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if not args.quiet:
        print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
