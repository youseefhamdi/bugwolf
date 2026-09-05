#!/usr/bin/env python3
"""Recon command runner (allowlisted binary set).

Runs a recon binary against the operator-supplied scope file. Phase 0: the
scope file is required, the binary basename must be in ALLOWED_TOOLS, the
timeout is bounded (1..600s), and the output cap is bounded (1KB..50MB).
The lab-profile (PROFILE_LAB_UNCENSORED) callers may relax these limits.

Usage:
  python3 tools/recon_exec.py --target T --scope-file scope.json -- httpx -l recon/T/urls.txt -o recon/T/live.txt
  python3 tools/recon_exec.py --target T --timeout 180 -- nmap -sV T
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    from tools.reliability import (operation_record, record_operation,
                                   run_bounded_subprocess, ResourceLimitError)
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from reliability import (operation_record, record_operation,
                             run_bounded_subprocess, ResourceLimitError)
    from runtime_paths import workspace_root

ALLOWED_TOOLS = {
    "subfinder", "assetfinder", "bbot", "subdog", "alterx", "dnsgen", "puredns",
    "dnsx", "naabu", "rustscan", "nmap", "httpx", "ffuf", "gowitness",
    "feroxbuster", "dirsearch", "indextree", "katana", "waybackurls", "gau",
    "waymore", "hakrawler", "goswagger", "jsluice", "linkfinder", "x8",
    "emailfinder", "subzy", "nuclei", "dnstake", "mx-takeover", "afrog",
    "xssrecon", "redirectfinder", "trufflehog", "curl", "host",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="BugWolf recon command runner (uncensored)")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope-file", default="")
    parser.add_argument("--confirm-active", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-output", type=int, default=10_000_000)
    parser.add_argument("--project-root", default=os.getcwd())
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command or Path(command[0]).name not in ALLOWED_TOOLS:
        print("[!] recon command is not on the approved allowlist", file=sys.stderr)
        return 2
    if not 1 <= args.timeout <= 600:
        print("[!] recon timeout must be between 1 and 600 seconds", file=sys.stderr)
        return 2
    if not 1_024 <= args.max_output <= 50_000_000:
        print("[!] recon output limit is invalid", file=sys.stderr)
        return 2

    # Phase 0: allowlisted recon commands run with the operator-supplied
    # scope file. Reliability controls remain mandatory: bounded process
    # group, timeout, and output.
    root = Path(args.project_root).expanduser().resolve()
    operation = operation_record(
        action="subprocess_exec", target=args.target, status="planned",
        command=command, tool=Path(command[0]).name,
        metadata={"timeout_seconds": args.timeout,
                  "max_output_bytes": args.max_output})
    try:
        record_operation(operation, project_root=root)
        operation["state"] = "attempted"
        record_operation(operation, project_root=root)
        completed = run_bounded_subprocess(
            command, cwd=root, stdin=sys.stdin,
            timeout=args.timeout, max_output_bytes=args.max_output)
    except subprocess.TimeoutExpired as exc:
        operation["state"] = "failed"
        operation["metadata"] = {"error": "timeout", "timeout_seconds": args.timeout}
        record_operation(operation, project_root=root)
        print(f"[!] recon command timed out after {args.timeout}s", file=sys.stderr)
        return 2
    except ResourceLimitError as exc:
        operation["state"] = "failed"
        operation["metadata"] = {"error": str(exc)}
        record_operation(operation, project_root=root)
        print(f"[!] recon command resource limit: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        operation["state"] = "failed"
        operation["metadata"] = {"error": type(exc).__name__}
        record_operation(operation, project_root=root)
        print(f"[!] recon command failed: {type(exc).__name__}", file=sys.stderr)
        return 2

    operation["state"] = "completed" if completed.returncode == 0 else "failed"
    operation["metadata"] = {"returncode": completed.returncode,
                              "stdout_bytes": len(completed.stdout),
                              "stderr_bytes": len(completed.stderr)}
    record_operation(operation, project_root=root)
    if completed.returncode != 0:
        print(f"[!] recon command exited with code {completed.returncode}", file=sys.stderr)
        sys.stderr.buffer.write(completed.stderr)

    sys.stdout.buffer.write(completed.stdout)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())