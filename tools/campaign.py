#!/usr/bin/env python3
"""BugWolf Campaign State Engine — self-driven APT-level research persistence.

A campaign is a persistent, self-driven research operation against one target.
It discovers all assets, exhausts each asset A→Z before moving to the next,
and resumes exactly where it left off across session boundaries.

State is stored under ``state/campaigns/<target>/`` and is designed to be
the plugin's single source of truth. The harness (Claude Code / Freebuff)
reads and writes this state through research units — it never improvises
outside the campaign's declared scope and budget.

Architecture:
  campaign.json              — top-level campaign state
  assets/<asset_id>.json     — per-asset surface map, threat model, coverage
  threads/<thread_id>.json   — per-thread state (hypothesis → escalation → exploit)
  findings/                  — confirmed findings with evidence
  evidence/                  — redacted, hash-linked evidence store
  resume.json                — exact resume point for session continuity
  audit.jsonl                — append-only, hash-linked audit trail
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.evidence import redact
    from tools.runtime_paths import workspace_root
    from tools.safety import safe_target_name
except ImportError:
    from evidence import redact
    from runtime_paths import workspace_root
    from safety import safe_target_name

try:
    import fcntl
except ImportError:
    fcntl = None

ROOT = workspace_root()
CAMPAIGN_ROOT = ROOT / "state" / "campaigns"

SCHEMA = "bugwolf-campaign-v2"


# ---------------------------------------------------------------------------
# Enums & data classes
# ---------------------------------------------------------------------------

class AssetType(str, Enum):
    WEB_API = "web_api"
    WEB_APP = "web_app"
    MOBILE_API = "mobile_api"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    OAUTH_IDP = "oauth_idp"
    ADMIN_PANEL = "admin_panel"
    INTERNAL_TOOL = "internal_tool"
    CI_CD = "ci_cd"
    DATABASE = "database"
    STORAGE_BUCKET = "storage_bucket"
    DNS_SERVER = "dns_server"
    EMAIL_SERVER = "email_server"
    CDN = "cdn"
    SMART_CONTRACT = "smart_contract"
    BINARY_SERVICE = "binary_service"
    CONTAINER_REGISTRY = "container_registry"
    IOT_ENDPOINT = "iot_endpoint"
    SOURCE_REPO = "source_repo"
    UNKNOWN = "unknown"


class AssetStatus(str, Enum):
    QUEUED = "queued"               # discovered but not yet started
    RECON = "recon"                 # surface mapping in progress
    THREAT_MODELING = "threat_modeling"  # building threat model
    DEEP_RESEARCH = "deep_research"  # threads actively researching
    CHAINING = "chaining"           # cross-thread chain attacks
    EXHAUSTED = "exhausted"         # all threats resolved
    PAUSED = "paused"               # operator paused


class ThreadState(str, Enum):
    HYPOTHESIS = "hypothesis"       # initial idea, not yet probed
    PROBING = "probing"             # sending test payloads
    SIGNAL_FOUND = "signal_found"   # confirmed vulnerability behavior
    ESCALATING = "escalating"       # increasing impact
    EXPLOITING = "exploiting"       # building working exploit
    VALIDATING = "validating"       # confirming exploit works
    EVIDENCE_PKG = "evidence_pkg"   # packaging evidence
    COMPLETE = "complete"           # done — vuln confirmed with exploit
    REFUTED = "refuted"             # definitively not vulnerable
    BLOCKED = "blocked"             # needs operator input
    DOCUMENTED_LIMITED = "documented_limited"  # found but impact limited


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AssetRecord:
    """One discovered asset within a campaign."""
    asset_id: str
    hostname: str
    type: AssetType | str
    priority: Priority | str = Priority.MEDIUM
    status: AssetStatus | str = AssetStatus.QUEUED
    ports: List[int] = field(default_factory=list)
    detected_tech: List[str] = field(default_factory=list)
    source: str = ""             # how it was discovered
    endpoints_discovered: int = 0
    threats_identified: int = 0
    threats_resolved: int = 0
    findings: int = 0
    zero_days: int = 0
    started_at: str = ""
    completed_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.type, AssetType):
            self.type = AssetType(self.type)
        if not isinstance(self.priority, Priority):
            self.priority = Priority(self.priority)
        if not isinstance(self.status, AssetStatus):
            self.status = AssetStatus(self.status)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["type"] = self.type.value
        data["priority"] = self.priority.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssetRecord":
        # Accept data as-is, filter to known fields
        known = {
            "asset_id", "hostname", "type", "priority", "status",
            "ports", "detected_tech", "source", "endpoints_discovered",
            "threats_identified", "threats_resolved", "findings",
            "zero_days", "started_at", "completed_at",
        }
        raw = {k: v for k, v in data.items() if k in known}
        return cls(**raw)


@dataclass
class ThreatHypothesis:
    """One threat hypothesis for an asset — becomes a research thread."""
    threat_id: str
    type: str                    # sql_injection, idor, xss, ssrf, auth_bypass, etc.
    confidence: str = "medium"   # high, medium, low
    rationale: str = ""
    target_endpoints: List[str] = field(default_factory=list)
    research_plan: str = ""
    status: str = "pending"      # pending, researching, confirmed, refuted
    finding_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageTracker:
    """Per-asset coverage across endpoint and bug-class dimensions."""
    endpoints_total: int = 0
    endpoints_tested_injection: int = 0
    endpoints_tested_authz: int = 0
    endpoints_tested_business_logic: int = 0
    endpoints_tested_all: int = 0
    bug_classes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threats_total: int = 0
    threats_resolved: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CoverageTracker":
        return cls(**data)

    @property
    def is_exhausted(self) -> bool:
        if self.endpoints_total == 0:
            return False
        return (self.threats_total > 0 and
                self.threats_resolved >= self.threats_total)


@dataclass
class ThreadRecord:
    """One persistent research thread — self-driven, never stops until resolved."""
    thread_id: str
    asset_id: str
    threat_id: str
    objective: str                         # what this thread is trying to prove
    bug_class: str = ""
    state: ThreadState | str = ThreadState.HYPOTHESIS
    endpoint: str = ""
    method: str = "GET"

    # What we know so far
    confirmed_behavior: str = ""           # what vulnerability behavior is confirmed
    current_blocker: str = ""              # what's blocking escalation
    last_successful_action: str = ""       # last thing that worked
    suggested_approaches: List[str] = field(default_factory=list)

    # History
    observations: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    finding_id: str = ""

    # Control
    iterations: int = 0
    max_iterations: int = 50
    priority: Priority | str = Priority.MEDIUM
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not isinstance(self.state, ThreadState):
            self.state = ThreadState(self.state)
        if not isinstance(self.priority, Priority):
            self.priority = Priority(self.priority)

    @property
    def is_terminal(self) -> bool:
        return self.state in {
            ThreadState.COMPLETE, ThreadState.REFUTED,
            ThreadState.BLOCKED, ThreadState.DOCUMENTED_LIMITED,
        }

    def record_observation(self, step: int, action: str, observation: str,
                           conclusion: str) -> None:
        self.observations.append({
            "step": step,
            "action": action,
            "observation": observation,
            "conclusion": conclusion,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        self.iterations = len(self.observations)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["priority"] = self.priority.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreadRecord":
        known = {
            "thread_id", "asset_id", "threat_id", "objective",
            "bug_class", "state", "endpoint", "method",
            "confirmed_behavior", "current_blocker",
            "last_successful_action", "suggested_approaches",
            "observations", "evidence_ids", "finding_id",
            "iterations", "max_iterations", "priority",
            "created_at", "updated_at",
        }
        raw = {k: v for k, v in data.items() if k in known}
        return cls(**raw)


@dataclass
class ResumePoint:
    """Exact resume point for session continuity."""
    current_asset_id: str = ""
    current_asset_status: str = ""
    active_threads: List[str] = field(default_factory=list)
    completed_threads: List[str] = field(default_factory=list)
    next_action: str = ""
    pending_decisions: List[Dict[str, Any]] = field(default_factory=list)
    operator_alerts: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: str = ""

    def __post_init__(self) -> None:
        if not self.last_updated:
            self.last_updated = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignState:
    """Top-level campaign state for one target."""
    target: str
    schema: str = SCHEMA

    # Campaign lifecycle
    status: str = "initializing"           # initializing, discovering, researching,
                                           # chaining, exhausted, paused
    phase: str = ""                        # current phase description
    created_at: str = ""
    updated_at: str = ""

    # Assets
    assets_discovered: int = 0
    assets_exhausted: int = 0

    # Findings
    total_findings: int = 0
    zero_day_candidates: int = 0

    # Budget
    max_concurrent_threads: int = 8
    budget_hours: int = 72
    started_at: str = ""

    # Resume
    resume: Optional[ResumePoint] = None

    # Integrity
    manifest_hash: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.resume:
            data["resume"] = self.resume.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CampaignState":
        known = {
            "target", "schema", "status", "phase", "created_at",
            "updated_at", "assets_discovered", "assets_exhausted",
            "total_findings", "zero_day_candidates",
            "max_concurrent_threads", "budget_hours", "started_at",
            "resume", "manifest_hash",
        }
        raw = {k: v for k, v in data.items() if k in known}
        if raw.get("resume") and isinstance(raw["resume"], dict):
            raw["resume"] = ResumePoint(**raw["resume"])
        else:
            raw["resume"] = None
        return cls(**raw)


# ---------------------------------------------------------------------------
# Atomic persistence helpers
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _jsonl_append(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record["_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, default=str).encode()
    ).hexdigest()
    with open(path, "a", encoding="utf-8") as f:
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _jsonl_read(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            record.pop("_sha256", None)
            records.append(record)
        except json.JSONDecodeError:
            continue
    return records


def _manifest_digest(data: Dict[str, Any]) -> str:
    unsigned = dict(data)
    unsigned.pop("manifest_hash", None)
    unsigned.pop("_sha256", None)
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Campaign Manager
# ---------------------------------------------------------------------------

class CampaignManager:
    """Manage one target's persistent campaign state."""

    def __init__(self, target: str) -> None:
        self.target = safe_target_name(target).replace(":", "_")[:200]
        self.root = CAMPAIGN_ROOT / self.target
        self.root.mkdir(parents=True, exist_ok=True)
        self.campaign_path = self.root / "campaign.json"
        self.resume_path = self.root / "resume.json"
        self.assets_dir = self.root / "assets"
        self.threads_dir = self.root / "threads"
        self.findings_dir = self.root / "findings"
        self.evidence_dir = self.root / "evidence"
        self.audit_path = self.root / "audit.jsonl"

        for d in [self.assets_dir, self.threads_dir, self.findings_dir,
                  self.evidence_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # -- Campaign lifecycle ------------------------------------------------

    def initialize(self, *, budget_hours: int = 72,
                   max_concurrent_threads: int = 8) -> CampaignState:
        """Create or load a campaign for this target."""
        if self.campaign_path.exists():
            return self.load()

        state = CampaignState(
            target=self.target,
            status="initializing",
            phase="Campaign initialized — awaiting asset discovery",
            budget_hours=budget_hours,
            max_concurrent_threads=max_concurrent_threads,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self.save(state)
        self._audit("campaign_initialized", {"budget_hours": budget_hours})
        return state

    def load(self) -> CampaignState:
        if not self.campaign_path.exists():
            raise FileNotFoundError(
                f"No campaign for {self.target}. Call initialize() first.")
        data = json.loads(self.campaign_path.read_text(encoding="utf-8"))
        return CampaignState.from_dict(data)

    def save(self, state: CampaignState) -> None:
        state.updated_at = datetime.now(timezone.utc).isoformat()
        data = state.to_dict()
        data["manifest_hash"] = _manifest_digest(data)
        _atomic_write(self.campaign_path, json.dumps(data, indent=2))
        # Update resume point
        self._update_resume(state)

    def _update_resume(self, state: CampaignState) -> None:
        """Write the resume point so sessions can continue."""
        current_asset = self._current_asset(state)
        active_threads = self._active_thread_ids(state)

        resume = ResumePoint(
            current_asset_id=current_asset.asset_id if current_asset else "",
            current_asset_status=current_asset.status.value if current_asset else "",
            active_threads=active_threads,
            completed_threads=self._completed_thread_ids(state),
            next_action=self._build_next_action(state, current_asset, active_threads),
            pending_decisions=self._pending_decisions(state),
            operator_alerts=self._operator_alerts(state),
            last_updated=datetime.now(timezone.utc).isoformat(),
        )
        state.resume = resume
        _atomic_write(self.resume_path, json.dumps(resume.to_dict(), indent=2))

    def get_resume(self) -> Optional[ResumePoint]:
        if not self.resume_path.exists():
            return None
        data = json.loads(self.resume_path.read_text(encoding="utf-8"))
        return ResumePoint(**data)

    # -- Asset management --------------------------------------------------

    def add_asset(self, hostname: str, asset_type: AssetType | str, *,
                  priority: Priority | str = Priority.MEDIUM,
                  ports: Optional[List[int]] = None,
                  detected_tech: Optional[List[str]] = None,
                  source: str = "") -> AssetRecord:
        asset_id = hashlib.sha256(
            f"{hostname}:{asset_type}".encode()
        ).hexdigest()[:16]

        existing = self.get_asset(asset_id)
        if existing:
            return existing

        asset = AssetRecord(
            asset_id=asset_id,
            hostname=hostname,
            type=asset_type,
            priority=priority,
            ports=ports or [],
            detected_tech=detected_tech or [],
            source=source,
        )
        _atomic_write(
            self.assets_dir / f"{asset_id}.json",
            json.dumps(asset.to_dict(), indent=2),
        )

        state = self.load()
        state.assets_discovered = len(list(self.assets_dir.glob("*.json")))
        self.save(state)
        self._audit("asset_discovered", {"asset_id": asset_id, "hostname": hostname})
        return asset

    def get_asset(self, asset_id: str) -> Optional[AssetRecord]:
        path = self.assets_dir / f"{asset_id}.json"
        if not path.exists():
            return None
        return AssetRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def update_asset(self, asset: AssetRecord) -> None:
        _atomic_write(
            self.assets_dir / f"{asset.asset_id}.json",
            json.dumps(asset.to_dict(), indent=2),
        )
        state = self.load()
        self.save(state)

    def list_assets(self, *, status: Optional[AssetStatus | str] = None,
                    priority: Optional[Priority | str] = None) -> List[AssetRecord]:
        assets = []
        for path in sorted(self.assets_dir.glob("*.json")):
            # Skip non-asset files (threats, coverage, etc.)
            if path.name.endswith(("_threats.json", "_coverage.json")):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or "asset_id" not in data:
                    continue
                asset = AssetRecord.from_dict(data)
                if status and asset.status != AssetStatus(status):
                    continue
                if priority and asset.priority != Priority(priority):
                    continue
                assets.append(asset)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
        return sorted(assets, key=lambda a: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                a.priority.value if hasattr(a.priority, 'value')
                else str(a.priority), 2),
            a.hostname,
        ))

    def _current_asset(self, state: CampaignState) -> Optional[AssetRecord]:
        """Find the active asset (first non-exhausted in priority order)."""
        for asset in self.list_assets():
            if asset.status not in {AssetStatus.EXHAUSTED, AssetStatus.PAUSED}:
                return asset
        return None

    # -- Thread management -------------------------------------------------

    def spawn_thread(self, asset: AssetRecord, threat: ThreatHypothesis) -> ThreadRecord:
        thread_id = hashlib.sha256(
            f"{asset.asset_id}:{threat.threat_id}:{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

        thread = ThreadRecord(
            thread_id=thread_id,
            asset_id=asset.asset_id,
            threat_id=threat.threat_id,
            objective=f"Research {threat.type} on {asset.hostname}: {threat.rationale[:200]}",
            bug_class=threat.type,
            endpoint=threat.target_endpoints[0] if threat.target_endpoints else "",
            state=ThreadState.HYPOTHESIS,
            suggested_approaches=self._default_approaches(threat.type),
            priority=asset.priority,
        )
        self.save_thread(thread)
        self._audit("thread_spawned", {
            "thread_id": thread_id, "asset_id": asset.asset_id,
            "bug_class": threat.type,
        })
        return thread

    def save_thread(self, thread: ThreadRecord) -> None:
        _atomic_write(
            self.threads_dir / f"{thread.thread_id}.json",
            json.dumps(thread.to_dict(), indent=2),
        )

    def get_thread(self, thread_id: str) -> Optional[ThreadRecord]:
        path = self.threads_dir / f"{thread_id}.json"
        if not path.exists():
            return None
        return ThreadRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list_threads(self, *, asset_id: str = "",
                     state: Optional[ThreadState | str] = None) -> List[ThreadRecord]:
        threads = []
        for path in sorted(self.threads_dir.glob("*.json")):
            try:
                t = ThreadRecord.from_dict(
                    json.loads(path.read_text(encoding="utf-8")))
                if asset_id and t.asset_id != asset_id:
                    continue
                if state and t.state != ThreadState(state):
                    continue
                threads.append(t)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
        return threads

    def _active_thread_ids(self, state: CampaignState) -> List[str]:
        return [t.thread_id for t in self.list_threads()
                if not t.is_terminal]

    def _completed_thread_ids(self, state: CampaignState) -> List[str]:
        return [t.thread_id for t in self.list_threads()
                if t.state == ThreadState.COMPLETE]

    # -- Threat model ------------------------------------------------------

    def save_threats(self, asset_id: str,
                     threats: List[ThreatHypothesis]) -> None:
        _atomic_write(
            self.assets_dir / f"{asset_id}_threats.json",
            json.dumps([t.to_dict() for t in threats], indent=2),
        )

    def load_threats(self, asset_id: str) -> List[ThreatHypothesis]:
        path = self.assets_dir / f"{asset_id}_threats.json"
        if not path.exists():
            return []
        return [ThreatHypothesis(**item)
                for item in json.loads(path.read_text(encoding="utf-8"))]

    # -- Coverage tracking -------------------------------------------------

    def save_coverage(self, asset_id: str,
                      coverage: CoverageTracker) -> None:
        _atomic_write(
            self.assets_dir / f"{asset_id}_coverage.json",
            json.dumps(coverage.to_dict(), indent=2),
        )

    def load_coverage(self, asset_id: str) -> CoverageTracker:
        path = self.assets_dir / f"{asset_id}_coverage.json"
        if not path.exists():
            return CoverageTracker()
        return CoverageTracker.from_dict(
            json.loads(path.read_text(encoding="utf-8")))

    # -- Resume helpers ----------------------------------------------------

    def _build_next_action(self, state: CampaignState,
                           current: Optional[AssetRecord],
                           active_threads: List[str]) -> str:
        if not current:
            if state.assets_discovered == 0:
                return ("Begin asset discovery: enumerate all subdomains, "
                        "IP ranges, cloud assets, and services for the target.")
            if state.assets_exhausted >= state.assets_discovered:
                return ("All assets exhausted. Begin cross-asset chain "
                        "analysis to connect findings across assets.")
            return "No active asset. Run asset discovery to find remaining assets."

        if current.status == AssetStatus.QUEUED:
            return (f"Begin deep reconnaissance on {current.hostname}. "
                    f"Map every endpoint, parameter, and auth boundary.")
        if active_threads:
            t = self.get_thread(active_threads[0])
            if t:
                return (f"Continue thread {t.thread_id}: {t.objective[:200]}. "
                        f"Current state: {t.state.value}. "
                        f"Last success: {t.last_successful_action[:200] or 'none yet'}.")
        return f"Review {current.hostname} state and continue from last checkpoint."

    def _pending_decisions(self, state: CampaignState) -> List[Dict[str, Any]]:
        decisions = []
        for t in self.list_threads(state=ThreadState.BLOCKED):
            decisions.append({
                "thread_id": t.thread_id,
                "blocker": t.current_blocker,
                "question": f"Thread {t.thread_id} ({t.bug_class}) is blocked. "
                           f"How should we proceed?",
            })
        return decisions

    def _operator_alerts(self, state: CampaignState) -> List[Dict[str, Any]]:
        alerts = []
        for t in self.list_threads(state=ThreadState.COMPLETE):
            if t.finding_id:
                alerts.append({
                    "thread_id": t.thread_id,
                    "finding_id": t.finding_id,
                    "severity": "needs review",
                    "message": f"Thread {t.thread_id} completed with a finding. "
                              f"Review and disclose.",
                })
        return alerts

    @staticmethod
    def _default_approaches(bug_class: str) -> List[str]:
        """Return suggested initial approaches for a bug class."""
        approaches = {
            "sql_injection": [
                "Send single-quote probe, observe for SQL errors",
                "Time-based blind: SLEEP(5) vs baseline timing",
                "Boolean-based blind: AND 1=1 vs AND 1=2",
                "Error-based: trigger type mismatch errors",
                "Union SELECT: test column count with ORDER BY",
            ],
            "idor": [
                "Create resource as Account A, access as Account B",
                "Enumerate sequential IDs (user/order IDs)",
                "Test UUID-guessing (if IDs are non-sequential)",
                "Check for composite key IDOR (org_id + resource_id)",
            ],
            "xss": [
                "Test reflected input in HTML context",
                "Test reflected input in attribute context",
                "Test reflected input in JavaScript context",
                "Bypass HTML entity encoding with event handlers",
            ],
            "ssrf": [
                "Test URL parameter reaching server-side fetch",
                "Probe internal IPs (127.0.0.1, 10.0.0.0/8, 169.254.169.254)",
                "Test protocol switching (file://, gopher://)",
                "Test DNS rebinding for same-origin bypass",
            ],
            "auth_bypass": [
                "Test endpoint without authentication header",
                "Test with malformed/expired JWT",
                "Test role confusion (user token accessing admin endpoint)",
                "Test HTTP method override for auth checks",
            ],
            "command_injection": [
                "Inject command separators (;, |, &&, ||)",
                "Inject subshell execution ($(), ``)",
                "Test blind injection with sleep/timing",
                "Test out-of-band exfiltration (curl/nslookup callback)",
            ],
            "path_traversal": [
                "Test ../ sequences for file read",
                "Test absolute paths (/etc/passwd)",
                "Test URL-encoded traversal (%2e%2e%2f)",
                "Test null-byte termination for extension bypass",
            ],
            "deserialization": [
                "Identify serialization format (Java, PHP, Python pickle)",
                "Test type confusion payloads",
                "Test gadget chain for RCE",
                "Test for YAML/JSON deserialization quirks",
            ],
        }
        return approaches.get(bug_class, [
            "Research the bug class and identify standard detection methods",
            "Map all input vectors that could trigger this vulnerability class",
            "Craft minimal test payloads and observe response differences",
            "Escalate from detection to exploitation systematically",
        ])

    # -- Audit trail -------------------------------------------------------

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        _jsonl_append(self.audit_path, {
            "event": event,
            "ts": datetime.now(timezone.utc).isoformat(),
            "data": redact(data),
        })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="BugWolf Campaign State Engine")
    parser.add_argument("--target", required=True,
                        help="Target hostname or project identifier")
    parser.add_argument("--init", action="store_true",
                        help="Initialize a new campaign")
    parser.add_argument("--status", action="store_true",
                        help="Show campaign status and resume point")
    parser.add_argument("--add-asset", help="Add an asset (format: hostname:type:priority)")
    parser.add_argument("--list-assets", action="store_true",
                        help="List all discovered assets")
    parser.add_argument("--list-threads", action="store_true",
                        help="List active research threads")
    parser.add_argument("--budget-hours", type=int, default=72,
                        help="Campaign time budget")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output")
    args = parser.parse_args()

    try:
        mgr = CampaignManager(args.target)

        if args.init:
            state = mgr.initialize(budget_hours=args.budget_hours)
            resume = mgr.get_resume()
            if args.json:
                print(json.dumps({
                    "campaign": state.to_dict(),
                    "resume": resume.to_dict() if resume else None,
                }, indent=2, default=str))
            else:
                print(f"[+] Campaign initialized for {args.target}")
                print(f"    Status: {state.status}")
                print(f"    Budget: {state.budget_hours}h")
                if resume:
                    print(f"    Resume: {resume.next_action[:120]}...")
            return 0

        if args.status:
            state = mgr.load()
            resume = mgr.get_resume()
            if args.json:
                print(json.dumps({
                    "campaign": state.to_dict(),
                    "resume": resume.to_dict() if resume else None,
                    "assets": [a.to_dict() for a in mgr.list_assets()],
                    "active_threads": len([t for t in mgr.list_threads()
                                           if not t.is_terminal]),
                }, indent=2, default=str))
            else:
                print(f"[*] Campaign: {args.target}")
                print(f"    Status: {state.status}")
                print(f"    Assets: {state.assets_discovered} discovered, "
                      f"{state.assets_exhausted} exhausted")
                print(f"    Findings: {state.total_findings} total, "
                      f"{state.zero_day_candidates} zero-day candidates")
                if resume:
                    print(f"    Next: {resume.next_action[:150]}...")
                    for alert in resume.operator_alerts:
                        print(f"    [ALERT] {alert['message'][:120]}")
            return 0

        if args.add_asset:
            parts = args.add_asset.split(":")
            hostname = parts[0]
            atype = AssetType(parts[1]) if len(parts) > 1 else AssetType.UNKNOWN
            priority = Priority(parts[2]) if len(parts) > 2 else Priority.MEDIUM
            asset = mgr.add_asset(hostname, atype, priority=priority)
            print(f"[+] Asset added: {asset.hostname} [{asset.type.value}]")
            return 0

        if args.list_assets:
            assets = mgr.list_assets()
            if args.json:
                print(json.dumps([a.to_dict() for a in assets], indent=2))
            else:
                for a in assets:
                    icon = {"queued": "⏳", "recon": "🔍", "threat_modeling": "🗺",
                            "deep_research": "⚔️", "chaining": "⛓️",
                            "exhausted": "✅", "paused": "⏸️"}
                    print(f"  {icon.get(a.status.value, '❓')} [{a.priority.value:8s}] "
                          f"{a.hostname:40s} [{a.type.value}] "
                          f"({a.findings} findings, {a.zero_days} ZD)")
            return 0

        if args.list_threads:
            threads = mgr.list_threads()
            if args.json:
                print(json.dumps([t.to_dict() for t in threads], indent=2, default=str))
            else:
                for t in threads:
                    icon = {
                        "hypothesis": "💡", "probing": "🔬",
                        "signal_found": "📡", "escalating": "📈",
                        "exploiting": "💣", "validating": "✅",
                        "complete": "🏁", "refuted": "❌",
                        "blocked": "🚫", "documented_limited": "📋",
                    }
                    print(f"  {icon.get(t.state.value, '❓')} [{t.state.value:20s}] "
                          f"{t.bug_class:25s} {t.endpoint[:50]}")
                    print(f"       {t.objective[:100]}")
            return 0

        parser.print_help()
        return 1

    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())