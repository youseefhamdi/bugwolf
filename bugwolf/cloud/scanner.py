"""Prowler + ScoutSuite cloud scanner wrapper.

Provides a single ``CloudScanner`` class with ``run_aws``,
``run_azure``, and ``run_gcp`` methods.  Each method is stub-safe:
if ``prowler`` / ``scoutsuite`` is not on PATH, the method logs (via
``logging``) and returns an empty dict rather than raising.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-cloud-scanner/v1"

LOG = logging.getLogger("bugwolf.cloud.scanner")


@dataclass(frozen=True)
class CloudScanResult:
    runner: str
    provider: str
    command: List[str]
    exit_code: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    available: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "provider": self.provider,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "available": self.available,
            "findings_count": len(self.findings),
            "findings": self.findings,
        }


@dataclass(frozen=True)
class CloudScanUnavailable:
    runner: str
    provider: str
    reason: str
    command: List[str] = field(default_factory=list)
    available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "provider": self.provider,
            "available": False,
            "reason": self.reason,
            "command": list(self.command),
        }


class CloudScanner:
    """Stub-safe wrapper around Prowler / ScoutSuite."""

    PROWLER = "prowler"
    SCOUTSUITE = "scout"

    def __init__(
        self,
        *,
        runner: str = "prowler",
        timeout_seconds: int = 3600,
    ) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        return shutil.which(self.runner) is not None

    def run_aws(
        self,
        profile: Optional[str] = None,
        *,
        checks: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not self.is_available():
            LOG.warning("cloud scanner unavailable: %s not on PATH", self.runner)
            return {}

        cmd: List[str] = [self.runner, "aws"]
        if profile:
            cmd += ["--profile", profile]
        if checks:
            cmd += ["--checks", ",".join(checks)]
        if output_dir:
            cmd += ["--output-directory", output_dir]
        if extra_args:
            cmd += list(extra_args)

        return self._exec(cmd, provider="aws").to_dict()

    def run_azure(
        self,
        subscription: Optional[str] = None,
        *,
        checks: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not self.is_available():
            LOG.warning("cloud scanner unavailable: %s not on PATH", self.runner)
            return {}

        cmd: List[str] = [self.runner, "azure"]
        if subscription:
            cmd += ["--subscription", subscription]
        if checks:
            cmd += ["--checks", ",".join(checks)]
        if extra_args:
            cmd += list(extra_args)

        return self._exec(cmd, provider="azure").to_dict()

    def run_gcp(
        self,
        project: Optional[str] = None,
        *,
        checks: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not self.is_available():
            LOG.warning("cloud scanner unavailable: %s not on PATH", self.runner)
            return {}

        cmd: List[str] = [self.runner, "gcp"]
        if project:
            cmd += ["--project-id", project]
        if checks:
            cmd += ["--checks", ",".join(checks)]
        if extra_args:
            cmd += list(extra_args)

        return self._exec(cmd, provider="gcp").to_dict()

    def _exec(self, cmd: List[str], *, provider: str) -> CloudScanResult:
        start = time.time()
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.time() - start) * 1000)
            LOG.warning(
                "cloud scanner %s timed out after %ss",
                self.runner,
                self.timeout_seconds,
            )
            return CloudScanResult(
                runner=self.runner,
                provider=provider,
                command=cmd,
                exit_code=124,
                findings=[],
                duration_ms=duration_ms,
            )

        duration_ms = int((time.time() - start) * 1000)
        findings = self._parse_output(completed.stdout)
        return CloudScanResult(
            runner=self.runner,
            provider=provider,
            command=cmd,
            exit_code=completed.returncode,
            findings=findings,
            duration_ms=duration_ms,
        )

    @staticmethod
    def _parse_output(stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not stdout:
            return findings
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            findings.append(
                {
                    "check": obj.get("CheckID") or obj.get("check_id") or obj.get("control"),
                    "severity": obj.get("Severity") or obj.get("severity"),
                    "status": obj.get("Status") or obj.get("status"),
                    "resource": obj.get("Resource") or obj.get("resource"),
                    "description": (obj.get("Description") or obj.get("description") or "")[:256],
                }
            )
        return findings


__all__ = ["CloudScanner", "CloudScanResult", "CloudScanUnavailable", "SCHEMA"]