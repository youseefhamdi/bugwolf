"""APK decompilation wrapper.

Wraps ``apktool`` and ``unzip`` to extract and decompile Android APKs
into a working tree of ``smali`` and resources.  Stub-safe: when the
wrapped CLI tool is missing, returns :class:`APKExtractorUnavailable`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SCHEMA = "bugwolf-mobile-apk-extractor/v1"


@dataclass(frozen=True)
class APKExtractorUnavailable:
    runner: str = ""
    reason: str = "no apktool / unzip on PATH"
    available: bool = False
    command: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": False,
            "reason": self.reason,
            "command": list(self.command),
        }


@dataclass(frozen=True)
class APKExtractResult:
    runner: str
    output_dir: str
    command: List[str]
    exit_code: int
    duration_ms: int
    files_extracted: int = 0
    available: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "available": True,
            "output_dir": self.output_dir,
            "command": list(self.command),
            "exit_code": self.exit_code,
            "files_extracted": self.files_extracted,
            "duration_ms": self.duration_ms,
        }


class APKExtractor:
    """Stub-safe APK extractor."""

    APKTOOL = "apktool"
    UNZIP = "unzip"

    def __init__(self, prefer_apktool: bool = True) -> None:
        self.prefer_apktool = prefer_apktool

    def is_available(self) -> bool:
        return shutil.which(self.APKTOOL) is not None or shutil.which(self.UNZIP) is not None

    def extract(
        self,
        apk_path: str,
        output_dir: str,
        *,
        timeout_seconds: int = 300,
    ):
        if not shutil.which(self.APKTOOL) and not shutil.which(self.UNZIP):
            return APKExtractorUnavailable(
                reason="no apktool / unzip on PATH",
            )

        if shutil.which(self.APKTOOL) and self.prefer_apktool:
            runner = self.APKTOOL
            cmd: List[str] = [
                self.APKTOOL, "d", apk_path, "-o", output_dir, "-f",
            ]
        else:
            runner = self.UNZIP
            cmd = [self.UNZIP, "-o", apk_path, "-d", output_dir]

        start = time.time()
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start) * 1000)
            return APKExtractorUnavailable(
                runner=runner,
                reason=f"extractor timed out after {timeout_seconds}s",
                command=cmd,
            )

        duration_ms = int((time.time() - start) * 1000)
        files_extracted = 0
        try:
            import os
            for _root, _dirs, files in os.walk(output_dir):
                files_extracted += len(files)
        except OSError:
            pass

        return APKExtractResult(
            runner=runner,
            output_dir=output_dir,
            command=cmd,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
            files_extracted=files_extracted,
        )


__all__ = ["APKExtractor", "APKExtractResult", "APKExtractorUnavailable", "SCHEMA"]