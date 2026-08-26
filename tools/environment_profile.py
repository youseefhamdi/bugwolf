#!/usr/bin/env python3
"""BugWolf execution-environment preflight.

The profile tells the orchestrator whether the operator says it is running on
a local workstation, VPS, or container/VM and, only after explicit local
confirmation, records basic OS/resource information. It never performs network
reconnaissance, reads environment variables, contacts metadata services, or
walks user files.

Usage:
  python3 tools/environment_profile.py --location unknown --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

ROOT = workspace_root()
PROFILE_PATH = ROOT / "state" / "environment.json"

LOCATION_CHOICES = ("local", "vps", "container_vm", "unknown")
SAFE_TOOL_PROBE_LIST = (
    "python3", "bash", "curl", "git", "jq", "nmap", "httpx", "nuclei",
    "ffuf", "foundryup", "forge", "solc", "adb", "apktool", "docker",
)


class EnvironmentProfileError(PermissionError):
    """Raised when the requested preflight action is not permitted."""


@dataclass
class EnvironmentProfile:
    location: str
    profile_id: str = ""
    created_at: float = 0.0
    os_scan_performed: bool = False
    base: str = ""
    os_name: str = ""
    os_release: str = ""
    architecture: str = ""
    python_version: str = ""
    virtualization: str = "unknown"
    hostname_hash: str = ""
    cpu_count: Optional[int] = None
    memory_bytes: Optional[int] = None
    disk_free_bytes: Optional[int] = None
    available_tools: List[str] = field(default_factory=list)
    safety_notes: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.location not in LOCATION_CHOICES:
            raise ValueError(f"unsupported environment location: {self.location}")
        if not self.created_at:
            self.created_at = time.time()
        if not self.base:
            self.base = {
                "local": "local-process",
                "vps": "vps-process",
                "container_vm": "isolated-process",
                "unknown": "unclassified-process",
            }[self.location]
        if not self.profile_id:
            canonical = json.dumps({
                "location": self.location,
                "base": self.base,
                "os_scan_performed": self.os_scan_performed,
                "os_name": self.os_name,
                "os_release": self.os_release,
                "architecture": self.architecture,
                "virtualization": self.virtualization,
            }, sort_keys=True)
            self.profile_id = hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _memory_bytes() -> Optional[int]:
    """Read aggregate memory from procfs only; return None elsewhere."""
    meminfo = Path("/proc/meminfo")
    if not meminfo.is_file():
        return None
    try:
        for line in meminfo.read_text(errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _virtualization() -> str:
    """Detect common local container markers without contacting the network."""
    if Path("/.dockerenv").exists():
        return "container"
    cgroup = Path("/proc/1/cgroup")
    if cgroup.is_file():
        try:
            text = cgroup.read_text(errors="replace").lower()
            for marker, value in (("docker", "container"),
                                  ("containerd", "container"),
                                  ("kubepods", "container"),
                                  ("lxc", "container")):
                if marker in text:
                    return value
        except OSError:
            pass
    return "unknown"


def _tool_inventory() -> List[str]:
    return [tool for tool in SAFE_TOOL_PROBE_LIST if shutil.which(tool)]


def collect_environment(location: str, *, scan_os: bool = False,
                        confirm_os_scan: bool = False) -> EnvironmentProfile:
    """Build a profile; OS/resource details require explicit confirmation."""
    if location not in LOCATION_CHOICES:
        raise EnvironmentProfileError(
            f"location must be one of: {', '.join(LOCATION_CHOICES)}")
    if scan_os and not confirm_os_scan:
        raise EnvironmentProfileError(
            "OS/resource inventory requires --confirm-os-scan")

    profile = EnvironmentProfile(location=location)
    profile.safety_notes = [
        "No network requests or port scans are performed by this preflight.",
        "Environment variables, credentials, process arguments, and user files are not read.",
        "Location is operator-provided; it is not inferred as proof of hosting or authorization.",
    ]
    if not scan_os:
        return profile

    profile.os_scan_performed = True
    profile.os_name = platform.system()
    profile.os_release = platform.release()
    profile.architecture = platform.machine()
    profile.python_version = platform.python_version()
    profile.virtualization = _virtualization()
    hostname = platform.node()
    profile.hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16] if hostname else ""
    profile.cpu_count = os.cpu_count()
    profile.memory_bytes = _memory_bytes()
    try:
        profile.disk_free_bytes = shutil.disk_usage(ROOT).free
    except OSError:
        profile.disk_free_bytes = None
    profile.available_tools = _tool_inventory()
    return profile


def save_profile(profile: EnvironmentProfile, path: Path = PROFILE_PATH) -> Path:
    """Persist only the non-secret profile snapshot atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True))
    os.replace(temporary, path)
    return path


def load_profile(path: Path = PROFILE_PATH) -> Optional[EnvironmentProfile]:
    if not path.is_file():
        return None
    try:
        return EnvironmentProfile(**json.loads(path.read_text()))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise EnvironmentProfileError(f"invalid environment profile: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="BugWolf environment preflight")
    parser.add_argument("--location", required=True, choices=LOCATION_CHOICES,
                        help="Operator-declared execution base")
    parser.add_argument("--scan-os", action="store_true",
                        help="Collect passive local OS/resource details")
    parser.add_argument("--confirm-os-scan", action="store_true",
                        help="Confirm the passive local OS/resource inventory")
    parser.add_argument("--output", help="Profile output path")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    try:
        profile = collect_environment(
            args.location,
            scan_os=args.scan_os,
            confirm_os_scan=args.confirm_os_scan,
        )
        path = save_profile(profile, Path(args.output) if args.output else PROFILE_PATH)
    except EnvironmentProfileError as exc:
        print(f"[!] Environment preflight denied: {exc}")
        raise SystemExit(2)

    output = profile.to_dict()
    output["profile_path"] = str(path)
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"[*] Execution base: {profile.base}")
        print(f"[*] Location declaration: {profile.location}")
        print(f"[*] OS/resource scan: {'performed' if profile.os_scan_performed else 'not requested'}")
        print(f"[*] Profile: {profile.profile_id}")
        print(f"[*] Saved: {path}")


if __name__ == "__main__":
    main()
