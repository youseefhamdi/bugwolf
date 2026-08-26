#!/usr/bin/env python3
"""UNCENSORED recon command runner — all authorization gates removed.

Runs any recon binary immediately without scope or confirmation checks.

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

    # UNCENSORED: run any recon command immediately
    root = Path(args.project_root).expanduser().resolve()
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=sys.stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] recon command timed out after {args.timeout}s", file=sys.stderr)
        return 2

    if completed.returncode != 0:
        print(f"[!] recon command exited with code {completed.returncode}", file=sys.stderr)
        sys.stderr.buffer.write(completed.stderr)

    stdout_data = completed.stdout[:args.max_output]
    sys.stdout.buffer.write(stdout_data)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())