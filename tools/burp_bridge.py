#!/usr/bin/env python3
"""BugWolf Burp Suite driver v1.24.1+.

Talks to a running Burp Suite Professional / Community instance via either:
  - Burp's REST API (Burp 2023.12+ exposes /burp suite api/v1)
  - The Burp Extension-driven HTTP listener (legacy)

Capabilities exposed:
  - Send a single HTTP request through Burp's Repeater
  - Send a request through Burp's Intruder with a fuzz payload
  - Fetch the most recent Scanner issues (active scan results)
  - Fetch the sitemap for a target
  - Register a BugWolf finding in Burp's issue tracker
  - Add a request to Burp's site map (for crawling / scope)

The driver is a thin client; it does NOT make BugWolf's decisions — the
mission_runner calls it to dispatch a request through Burp's toolchain
when the operator has Burp running and wants BugWolf's findings to
share Burp's session.

Configuration:
  BUGWOLF_BURP_URL = http://127.0.0.1:1337   (Burp REST API base)
  BUGWOLF_BURP_KEY = <api key>                 (printed at Burp launch)

If neither is set, every method returns {"status": "skipped", "reason":
"burp-not-configured"}.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-burp-driver/v1"

DEFAULT_URL = "http://127.0.0.1:1337"


def is_configured() -> bool:
    """True if the operator has set BUGWOLF_BURP_URL."""
    return bool(os.environ.get("BUGWOLF_BURP_URL") or
                os.environ.get("BURP_REST_URL"))


def _base_url() -> Optional[str]:
    return (os.environ.get("BUGWOLF_BURP_URL") or
            os.environ.get("BURP_REST_URL") or
            (DEFAULT_URL if is_configured() else None))


def _api_key() -> Optional[str]:
    return (os.environ.get("BUGWOLF_BURP_KEY") or
            os.environ.get("BURP_REST_API_KEY"))


def _request(path: str, method: str = "GET", body: Optional[Dict] = None,
             *, timeout: float = 30.0) -> Dict[str, Any]:
    """Send a request to Burp's REST API. Returns parsed JSON or error dict."""
    base = _base_url()
    if not base:
        return {"status": "skipped", "reason": "burp-not-configured"}
    url = f"{base.rstrip('/')}{path}"
    headers = {"Accept": "application/json"}
    key = _api_key()
    if key:
        headers["X-API-KEY"] = key
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": "ok", "body": json.loads(resp.read())}
    except urllib.error.HTTPError as exc:
        return {"status": "error", "code": exc.code,
                "body": exc.read().decode("utf-8", "replace")[:500]}
    except urllib.error.URLError as exc:
        return {"status": "error", "reason": f"connection: {exc.reason}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_to_repeater(target: str, *, http_request: str) -> Dict[str, Any]:
    """Send a raw HTTP request to Burp's Repeater for a target."""
    return _request(
        f"/burp suite api/v1/repeater/{urllib_quote(target)}/send",
        method="POST",
        body={"request": http_request},
    )


def send_to_intruder(target: str, *, http_request: str,
                     payload_set: List[Dict[str, str]]) -> Dict[str, Any]:
    """Send a request to Burp's Intruder with a fuzz payload."""
    return _request(
        f"/burp suite api/v1/intruder/{urllib_quote(target)}/send",
        method="POST",
        body={"request": http_request, "payloads": payload_set},
    )


def fetch_scanner_issues(target: Optional[str] = None) -> Dict[str, Any]:
    """Fetch the most recent Scanner issues. Optionally filtered by target."""
    path = "/burp suite api/v1/scanner/issues"
    if target:
        path += f"?target={urllib_quote(target)}"
    return _request(path, method="GET")


def fetch_sitemap(target: str) -> Dict[str, Any]:
    """Fetch Burp's sitemap for the given target."""
    return _request(
        f"/burp suite api/v1/target/{urllib_quote(target)}/sitemap",
        method="GET",
    )


def register_issue(target: str, *, issue_type: str, severity: str,
                   confidence: str, url: str, name: str,
                   detail: str = "",
                   remediation: str = "") -> Dict[str, Any]:
    """Add a BugWolf finding to Burp's site map as an issue."""
    return _request(
        f"/burp suite api/v1/target/{urllib_quote(target)}/issue",
        method="POST",
        body={
            "type": issue_type,
            "severity": severity,
            "confidence": confidence,
            "url": url,
            "name": name,
            "detail": detail,
            "remediation": remediation,
            "source": "bugwolf",
            "added_at": datetime.now(timezone.utc).isoformat(),
        },
    )


def start_active_scan(target: str, *, urls: List[str]) -> Dict[str, Any]:
    """Trigger Burp's active scanner on a list of URLs."""
    return _request(
        f"/burp suite api/v1/scanner/active/{urllib_quote(target)}",
        method="POST",
        body={"urls": urls},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def urllib_quote(value: str) -> str:
    import urllib.parse
    return urllib.parse.quote(value, safe="")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf Burp Suite driver")
    sub = p.add_subparsers(dest="cmd", required=True)

    g_rep = sub.add_parser("repeater", help="Send to Repeater")
    g_rep.add_argument("--target", required=True)
    g_rep.add_argument("--request-file", required=True,
                       help="File with the raw HTTP request")

    g_int = sub.add_parser("intruder", help="Send to Intruder")
    g_int.add_argument("--target", required=True)
    g_int.add_argument("--request-file", required=True)
    g_int.add_argument("--payloads-file", required=True,
                       help="JSONL file with one payload per line")

    g_scan = sub.add_parser("scan", help="Trigger active scan")
    g_scan.add_argument("--target", required=True)
    g_scan.add_argument("--urls-file", required=True,
                        help="File with one URL per line")

    g_iss = sub.add_parser("issue", help="Fetch scanner issues")
    g_iss.add_argument("--target", help="Optional target filter")

    g_sm = sub.add_parser("sitemap", help="Fetch site map")
    g_sm.add_argument("--target", required=True)

    args = p.parse_args()

    if not is_configured():
        print("[!] BUGWOLF_BURP_URL not set; running in skipped mode",
              file=sys.stderr)

    if args.cmd == "repeater":
        http_req = Path(args.request_file).read_text()
        print(json.dumps(send_to_repeater(args.target, http_request=http_req),
                         indent=2))
    elif args.cmd == "intruder":
        http_req = Path(args.request_file).read_text()
        payloads = [
            json.loads(l) for l in
            Path(args.payloads_file).read_text().splitlines() if l.strip()
        ]
        print(json.dumps(send_to_intruder(
            args.target, http_request=http_req, payload_set=payloads,
        ), indent=2))
    elif args.cmd == "scan":
        urls = [l.strip() for l in Path(args.urls_file).read_text().splitlines()
                if l.strip()]
        print(json.dumps(start_active_scan(args.target, urls=urls), indent=2))
    elif args.cmd == "issue":
        print(json.dumps(fetch_scanner_issues(args.target), indent=2))
    elif args.cmd == "sitemap":
        print(json.dumps(fetch_sitemap(args.target), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
