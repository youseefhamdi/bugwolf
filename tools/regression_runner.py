#!/usr/bin/env python3
"""BugWolf regression runner v1.24.1+ — re-verify past findings on a target.

Given a JSONL findings file, replay each finding's reproduction request
against the current target state and report whether the bug is still
present, fixed, or inaccessible. This is the missing piece that lets
BugWolf detect regressions AND new 0-days that share a root cause with
previously-reported bugs.

Schema (one JSONL line per finding verification):
  {
    "schema": "bugwolf-regression/v1",
    "finding_id": "f-123",
    "target": "acme.com",
    "previous_status": "confirmed",
    "current_status": "fixed|present|inconclusive|unreachable",
    "delta": "...",
    "timestamp": "...",
    "evidence_ref": "..."
  }
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-regression/v1"


@dataclass
class RegressionResult:
    finding_id: str
    target: str
    previous_status: str
    current_status: str = "inconclusive"
    delta: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_ref: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "finding_id": self.finding_id,
            "target": self.target,
            "previous_status": self.previous_status,
            "current_status": self.current_status,
            "delta": self.delta,
            "timestamp": self.timestamp,
            "evidence_ref": self.evidence_ref,
        }


def replay_finding(finding: Dict[str, Any], *, scope_check: bool = True
                    ) -> RegressionResult:
    """Replay a single finding's reproduction and classify the result.

    Three response categories:
      - "fixed"     - the reproduction now returns a non-vulnerable response
      - "present"   - the reproduction still returns a vulnerable response
      - "inconclusive" - we cannot tell (different response, no oracle)
      - "unreachable" - the target refused the request (scope, offline, etc.)
    """
    result = RegressionResult(
        finding_id=str(finding.get("id", "")),
        target=str(finding.get("target", "")),
        previous_status=str(finding.get("status", "unknown")),
    )
    if scope_check:
        try:
            from tools.runtime.scope import check_url, ScopeViolation
            url = finding.get("url", "")
            if url:
                check_url(url)
        except ScopeViolation as exc:
            result.current_status = "unreachable"
            result.delta = f"scope: {exc}"
            return result
        except Exception:  # noqa: BLE001
            pass

    # Lazy import replay
    try:
        from tools.runtime.replay.engine import replay_request
    except Exception as exc:  # noqa: BLE001
        result.current_status = "inconclusive"
        result.delta = f"replay-import: {exc}"
        return result

    method = str(finding.get("method", "GET")).upper()
    url = str(finding.get("url", ""))
    if not url:
        result.current_status = "inconclusive"
        result.delta = "no-url"
        return result
    headers = dict(finding.get("headers", {}))
    body = finding.get("body")
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    else:
        body = body or b""
    try:
        response = replay_request(method=method, url=url,
                                  headers=headers, body=body,
                                  timeout=10.0)
    except Exception as exc:  # noqa: BLE001
        result.current_status = "unreachable"
        result.delta = f"replay: {exc}"
        return result
    status = getattr(response, "status", 0)
    body_bytes = getattr(response, "body", b"")
    try:
        body_text = body_bytes.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        body_text = str(body_bytes[:200])
    # Naive oracle: if the finding's recorded vulnerable_status is now a
    # 4xx/403/200-ok (with the "fixed" sentinel) it's gone; if it's still
    # the original vulnerable status, it's present.
    vuln_status = finding.get("vulnerable_status", 200)
    if status == vuln_status:
        result.current_status = "present"
        result.delta = f"still returns {status}"
    elif status in (401, 403, 404):
        result.current_status = "fixed"
        result.delta = f"now {status} (was {vuln_status})"
    else:
        result.current_status = "inconclusive"
        result.delta = f"now {status} (was {vuln_status})"
    result.evidence_ref = f"replay-status={status} body-preview={body_text[:80]!r}"
    return result


def run_batch(findings: List[Dict[str, Any]], *,
              scope_check: bool = True) -> List[RegressionResult]:
    """Replay a list of findings and return their RegressionResults."""
    return [replay_finding(f, scope_check=scope_check) for f in findings]


def write_results(results: List[RegressionResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r.to_dict()) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf regression runner")
    p.add_argument("--findings-file", required=True,
                   help="JSONL file with past findings")
    p.add_argument("--output", required=True, help="Output JSONL path")
    p.add_argument("--no-scope-check", action="store_true",
                   help="Skip scope gate (operator trusts the input)")
    args = p.parse_args()

    findings = [json.loads(l) for l in
                Path(args.findings_file).read_text().splitlines() if l.strip()]
    results = run_batch(findings, scope_check=not args.no_scope_check)
    write_results(results, Path(args.output))
    present = sum(1 for r in results if r.current_status == "present")
    fixed = sum(1 for r in results if r.current_status == "fixed")
    inc = sum(1 for r in results if r.current_status == "inconclusive")
    unr = sum(1 for r in results if r.current_status == "unreachable")
    print(f"[+] regression: {len(results)} findings")
    print(f"    present: {present}")
    print(f"    fixed:   {fixed}")
    print(f"    inconclusive: {inc}")
    print(f"    unreachable: {unr}")
    print(f"[+] -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
