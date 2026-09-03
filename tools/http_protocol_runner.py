#!/usr/bin/env python3
"""Bounded HTTP/1.1·HTTP/2·HTTP/3 protocol runner.

Executes ``curl`` probes over specific protocol versions against lab
fixtures, capturing status/headers/body with strict timeouts and output
caps. When curl lacks a protocol (e.g. HTTP/3 without the quiche build) the
probe is reported as unsupported rather than raising.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.reliability import run_bounded_subprocess

_PROTOCOL_FLAGS = {"h1": [], "h2": ["--http2"], "h3": ["--http3"]}


def parse_curl_headers(raw: str) -> Dict[str, str]:
    """Parse the header block preceding a blank line in curl output."""
    headers: Dict[str, str] = {}
    block = raw.split("\n\n", 1)[0]
    for line in block.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[str(name).strip().lower()] = str(value).strip()
    return headers


class HTTPProtocolRunner:
    """Bounded per-protocol HTTP probing for local fixtures."""

    def __init__(self, target: str, *, timeout: float = 10.0,
                 max_output_bytes: int = 1_000_000):
        self.target = str(target)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def available(self, protocol: str) -> bool:
        if not shutil.which("curl"):
            return False
        if protocol == "h3":
            return self._curl_supports_http3()
        return True

    @staticmethod
    def _curl_supports_http3() -> bool:
        try:
            from tools.runtime.sandbox import sandboxed_run
            result = sandboxed_run(["curl", "--version"], cwd=os.getcwd(),
                                   text=True, timeout=5,
                                   purpose="http_protocol_runner")
            return "HTTP3" in result.stdout or "quiche" in result.stdout.lower()
        except (OSError, subprocess.TimeoutExpired, Exception):
            return False

    def plan_protocols(self, url: str) -> List[Dict[str, Any]]:
        """Return the deterministic probe plan for h1/h2/h3."""
        return [{"protocol": name, "url": str(url),
                 "supported": self.available(name)}
                for name in ("h1", "h2", "h3")]

    def run_probe(self, url: str, protocol: str, *,
                  curl_path: str = "curl") -> Dict[str, Any]:
        """Execute one protocol probe and return status/headers/body."""
        if protocol not in _PROTOCOL_FLAGS:
            return {"ok": False, "protocol": protocol, "error": f"unknown protocol {protocol}"}
        if not shutil.which(curl_path):
            return {"ok": False, "protocol": protocol,
                    "error": f"curl not found: {curl_path}"}
        if protocol == "h3" and not self._curl_supports_http3():
            return {"ok": False, "protocol": protocol,
                    "error": "curl lacks HTTP/3 support (no quiche)"}
        command = [curl_path, "-sS", "--max-time", str(int(self.timeout)),
                   "-D", "-", "-o", "-", "-w", "\n%{http_code}\n"]
        command.extend(_PROTOCOL_FLAGS[protocol])
        command.append(str(url))
        try:
            completed = run_bounded_subprocess(
                command, cwd=str(Path.cwd()), timeout=self.timeout,
                max_output_bytes=self.max_output_bytes)
        except subprocess.TimeoutExpired:
            return {"ok": False, "protocol": protocol, "error": "timeout"}
        except Exception as exc:
            return {"ok": False, "protocol": protocol,
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        stdout = completed.stdout.decode("utf-8", errors="replace")
        lines = stdout.splitlines()
        status = 0
        for line in reversed(lines):
            if line.strip().isdigit():
                status = int(line.strip())
                break
        body = stdout
        headers = parse_curl_headers(stdout)
        return {"ok": completed.returncode == 0, "protocol": protocol,
                "url": str(url), "status": status, "headers": headers,
                "body_preview": body[-2000:], "exit_code": completed.returncode}