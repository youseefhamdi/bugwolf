#!/usr/bin/env python3
"""
BugWolf Agent Communication Bus — Cross-agent signal passing.

Enables autonomous chain building by letting agents broadcast structured
signals to each other. Signals are persisted as JSONL and replayed when
the receiving agent starts its hunt.

Usage:
  from tools.agent_bus import AgentBus, Signal
  bus = AgentBus("target.com")
  bus.send(Signal(signal_type="discovery", from_agent="web-api-agent",
                   to_agents=["access-control-agent"], ...))
  signals = bus.receive("access-control-agent")
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field, asdict

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.evidence import redact
from tools.safety import safe_target_name

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

from tools.runtime_paths import target_slug, workspace_root

ROOT = workspace_root()
SIGNALS_ROOT = ROOT / "state" / "signals"

from tools.post_finding_trigger import trigger_after_signal, record_trigger_failure


@dataclass
class Signal:
    signal_type: str  # discovery, handoff, chain, alert, request, promotion
    from_agent: str
    to_agents: List[str]  # ["*"] means all agents
    priority: str  # critical, high, medium, low
    finding_ref: Optional[str] = None  # finding_id or lead_id
    signal_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    signal_id: str = ""

    def __post_init__(self):
        if self.priority not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"invalid signal priority: {self.priority}")
        if not self.signal_type or not self.from_agent or not self.to_agents:
            raise ValueError("signals require type, sender, and recipients")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.signal_id:
            import hashlib
            raw = f"{self.from_agent}:{self.signal_type}:{self.timestamp}"
            self.signal_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_context(self) -> str:
        """Render as a context block for the receiving agent."""
        safe_data = redact(self.signal_data)
        return f"""
[CROSS-AGENT SIGNAL | {self.priority.upper()} | {self.signal_type}]
From: {self.from_agent}
To: {', '.join(self.to_agents)}
Finding: {self.finding_ref or 'N/A'}
Signal ID: {self.signal_id}
Data: {json.dumps(safe_data, indent=2)[:10000]}
"""


class AgentBus:
    """Persistent message bus for agent-to-agent communication."""

    def __init__(self, target: str):
        self.target = target
        self._dir = SIGNALS_ROOT / target_slug(target)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._inbox = self._dir / "inbox.jsonl"
        self._processed = self._dir / "processed.jsonl"
        self._deliveries = self._dir / "deliveries"
        self._deliveries.mkdir(parents=True, exist_ok=True)

    def _delivery_file(self, agent_name: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_"
                       for ch in agent_name)
        return self._deliveries / f"{safe}.jsonl"

    def _read_signals(self) -> List[Dict[str, Any]]:
        """Read inbox and archive once, de-duplicated by signal ID."""
        signals: Dict[str, Dict[str, Any]] = {}
        for path in (self._inbox, self._processed):
            if not path.exists():
                continue
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    signal_id = data.get("signal_id")
                    if signal_id:
                        signals[signal_id] = data
                except (json.JSONDecodeError, TypeError):
                    continue
        return list(signals.values())

    def _delivered_ids(self, agent_name: str) -> Set[str]:
        path = self._delivery_file(agent_name)
        if not path.exists():
            return set()
        ids = set()
        for line in path.read_text().splitlines():
            if line.strip():
                try:
                    value = json.loads(line)
                    if value.get("signal_id"):
                        ids.add(value["signal_id"])
                except json.JSONDecodeError:
                    continue
        return ids

    def send(self, signal: Signal):
        """Persist a signal and run one mandatory target-local hard trigger.

        The trigger runs once at ingress, not once per recipient, so broadcast
        signals produce one auditable receipt rather than N duplicate receipts.
        Delivery remains independently de-duplicated per receiving agent.
        """
        payload = asdict(signal)
        payload["signal_data"] = redact(payload.get("signal_data", {}))
        line = json.dumps(payload)
        if len(line.encode("utf-8")) > 256_000:
            raise ValueError("signal exceeds the 256 KiB size limit")
        with open(self._inbox, "a") as f:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        try:
            trigger_after_signal(self.target, payload, project_root=ROOT)
        except Exception as exc:
            # The signal is durable; if the coordinator itself cannot start,
            # retain a blocked repair receipt rather than losing the handoff.
            record_trigger_failure(
                self.target,
                {"finding_id": signal.signal_id},
                f"{type(exc).__name__}: {str(exc)[:300]}",
                project_root=ROOT,
                event_kind="signal",
            )

    def receive(self, agent_name: str, mark_processed: bool = True) -> List[Signal]:
        """Get unread signals for one agent without consuming broadcasts globally."""
        path = self._delivery_file(agent_name)
        delivered: Set[str] = set()
        signals = []
        with open(path, "a+") as marker:
            if fcntl:
                fcntl.flock(marker.fileno(), fcntl.LOCK_EX)
            marker.seek(0)
            for line in marker.read().splitlines():
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                    if value.get("signal_id"):
                        delivered.add(value["signal_id"])
                except json.JSONDecodeError:
                    continue

            for data in self._read_signals():
                to_agents = data.get("to_agents", [])
                signal_id = data.get("signal_id", "")
                if (("*" in to_agents or agent_name in to_agents) and
                        signal_id not in delivered):
                    signals.append(Signal(**data))

            if mark_processed and signals:
                marker.seek(0, os.SEEK_END)
                for signal in signals:
                    marker.write(json.dumps({"signal_id": signal.signal_id}) + "\n")
                marker.flush()
                os.fsync(marker.fileno())
                # Keep a durable archive without consuming broadcasts globally.
                with open(self._processed, "a+") as archive:
                    if fcntl:
                        fcntl.flock(archive.fileno(), fcntl.LOCK_EX)
                    archive.seek(0)
                    archived = {
                        json.loads(line).get("signal_id")
                        for line in archive.read().splitlines() if line.strip()
                    }
                    archive.seek(0, os.SEEK_END)
                    for signal in signals:
                        if signal.signal_id not in archived:
                            archive.write(json.dumps(asdict(signal)) + "\n")
                            archived.add(signal.signal_id)
                    archive.flush()
                    os.fsync(archive.fileno())
                    if fcntl:
                        fcntl.flock(archive.fileno(), fcntl.LOCK_UN)
            if fcntl:
                fcntl.flock(marker.fileno(), fcntl.LOCK_UN)
        return signals

    def receive_all(self, agent_name: str) -> List[Signal]:
        """Get all addressed signals, de-duplicated across inbox/archive."""
        return [Signal(**data) for data in self._read_signals()
                if "*" in data.get("to_agents", [])
                or agent_name in data.get("to_agents", [])]

    def find_chains(self) -> List[Dict]:
        """Analyze signals for potential exploit chains.

        Looks for CHAIN-type signals and DISCOVERY pairs that combine
        into higher severity.
        """
        chains = []
        all_signals = []

        for path in [self._inbox, self._processed]:
            if path.exists():
                for line in path.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        all_signals.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        # Extract explicit CHAIN signals
        for s in all_signals:
            if s.get("signal_type") == "chain":
                chains.append({
                    "type": "explicit_chain",
                    "chain_type": s.get("signal_data", {}).get("chain_type"),
                    "combined_severity": s.get("signal_data", {}).get("combined_severity"),
                    "bug_a": s.get("signal_data", {}).get("bug_a"),
                    "bug_b": s.get("signal_data", {}).get("bug_b"),
                    "signal_id": s.get("signal_id"),
                })

        # Look for implicit chains (discovery + discovery from different agents
        # targeting the same endpoint)
        discoveries = [s for s in all_signals if s.get("signal_type") == "discovery"]
        for i, d1 in enumerate(discoveries):
            for d2 in discoveries[i+1:]:
                if d1.get("from_agent") == d2.get("from_agent"):
                    continue
                d1_endpoint = d1.get("signal_data", {}).get("endpoint", "")
                d2_endpoint = d2.get("signal_data", {}).get("endpoint", "")
                # Same endpoint root = potential chain
                if d1_endpoint and d2_endpoint:
                    root1 = d1_endpoint.rstrip("0123456789").rstrip("/")
                    root2 = d2_endpoint.rstrip("0123456789").rstrip("/")
                    if root1 == root2 and root1:
                        chains.append({
                            "type": "implicit_chain",
                            "agent_a": d1.get("from_agent"),
                            "agent_b": d2.get("from_agent"),
                            "endpoint_root": root1,
                            "pattern_a": d1.get("signal_data", {}).get("pattern"),
                            "pattern_b": d2.get("signal_data", {}).get("pattern"),
                        })

        return chains

    def get_pending_for(self, agent_name: str) -> List[Signal]:
        """Get only unread signals for an agent."""
        return self.receive(agent_name, mark_processed=False)

    def clear_processed(self):
        """Clear archived signals and per-agent delivery markers."""
        if self._processed.exists():
            self._processed.unlink()
        for marker in self._deliveries.glob("*.jsonl"):
            marker.unlink()

    def stats(self) -> Dict:
        """Return signal statistics for this target."""
        inbox_count = 0
        processed_count = 0
        if self._inbox.exists():
            inbox_count = len(self._inbox.read_text().splitlines())
        if self._processed.exists():
            processed_count = len(self._processed.read_text().splitlines())

        chains = self.find_chains()

        return {
            "target": self.target,
            "pending": inbox_count,
            "processed": processed_count,
            "chains_detected": len(chains),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf Agent Bus")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--send", help="JSON signal to send")
    parser.add_argument("--receive", help="Agent name to receive signals for")
    parser.add_argument("--chains", action="store_true", help="Show detected chains")
    parser.add_argument("--stats", action="store_true", help="Show bus stats")
    args = parser.parse_args()

    bus = AgentBus(args.target)

    if args.send:
        data = json.loads(args.send)
        signal = Signal(**data)
        bus.send(signal)
        print(f"[+] Signal sent: {signal.signal_id} ({signal.signal_type})")

    elif args.receive:
        signals = bus.receive(args.receive)
        if not signals:
            print(f"[*] No signals for {args.receive}")
        for s in signals:
            print(f"  [{s.priority.upper()}] {s.signal_type} from {s.from_agent}")
            if s.signal_data:
                print(f"    {json.dumps(s.signal_data, indent=4)[:200]}")

    elif args.chains:
        chains = bus.find_chains()
        if not chains:
            print("[*] No chains detected")
        for c in chains:
            print(f"  [{c['type']}] {c.get('endpoint_root', c.get('bug_a', '?'))}")

    elif args.stats:
        stats = bus.stats()
        for k, v in stats.items():
            print(f"  {k}: {v}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
