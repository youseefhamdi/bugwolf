#!/usr/bin/env python3
"""BugWolf Event-Driven Signal Bus — the framework's "nervous system".

Where ``agent_bus`` routes *agent-addressed* signals (``from_agent`` /
``to_agents``), the signal bus is the *event-driven* layer: tools publish
typed events (``RECON_COMPLETE``, ``FINDING_DISCOVERED``, ``WAF_BLOCKED``,
``STAGE_ADVANCED``, ``SMUGGLING_CANDIDATE``, ``AUTH_CANDIDATE``) and other
tools subscribe to react — without direct function calls.

Design (deterministic, uncensored, workflow-aware):

  * Every published event is persisted as a JSONL line under
    ``state/signals/events/<target>.jsonl`` — the same durable location family
    as ``agent_bus`` — so a later-started tool can ``replay`` events it missed.
  * In-process listeners are invoked in registration order at ``publish``
    time.  A listener failure is recorded on the event (``listener_errors``)
    and never raises: the bus must not become an execution gate.
  * ``WAF_BLOCKED`` carries the defense name and the bug class that was
    blocked; the ``bypass`` research checkpoint and ``parser_differential``
    subscribe to it to (re)generate WAF-bypass payload families.
  * Events are advisory, not gates: nothing in the bus blocks a tool.

Usage:
  from tools.core.signal_bus import SignalBus, Event, RECON_COMPLETE
  bus = SignalBus("target.com")
  bus.subscribe(RECON_COMPLETE, my_handler)
  bus.publish(RECON_COMPLETE, source="asset_discovery", payload={...})

CLI:
  python3 tools/core/signal_bus.py --target acme --publish '{"event_type":"WAF_BLOCKED",...}'
  python3 tools/core/signal_bus.py --target acme --replay
  python3 tools/core/signal_bus.py --target acme --stats --json
"""

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from tools.runtime_paths import target_slug, workspace_root

# ---------------------------------------------------------------------------
# Typed events
# ---------------------------------------------------------------------------

RECON_COMPLETE = "RECON_COMPLETE"
FINDING_DISCOVERED = "FINDING_DISCOVERED"
WAF_BLOCKED = "WAF_BLOCKED"
STAGE_ADVANCED = "STAGE_ADVANCED"
SMUGGLING_CANDIDATE = "SMUGGLING_CANDIDATE"
AUTH_CANDIDATE = "AUTH_CANDIDATE"
DISCOVERY_COMPLETE = "DISCOVERY_COMPLETE"
RESEARCH_REFRESHED = "RESEARCH_REFRESHED"
CLOUD_CANDIDATE = "CLOUD_CANDIDATE"
MOBILE_CANDIDATE = "MOBILE_CANDIDATE"
ASSET_DELTA = "ASSET_DELTA"
LLM_CANDIDATE = "LLM_CANDIDATE"
LAB_PLANNED = "LAB_PLANNED"
CHAIN_PROPOSAL = "CHAIN_PROPOSAL"
EVAL_COMPLETE = "EVAL_COMPLETE"
GRAPHQL_CANDIDATE = "GRAPHQL_CANDIDATE"

EVENT_TYPES = (
    RECON_COMPLETE, FINDING_DISCOVERED, WAF_BLOCKED, STAGE_ADVANCED,
    SMUGGLING_CANDIDATE, AUTH_CANDIDATE, DISCOVERY_COMPLETE,
    RESEARCH_REFRESHED, CLOUD_CANDIDATE, MOBILE_CANDIDATE, ASSET_DELTA,
    LLM_CANDIDATE, LAB_PLANNED, CHAIN_PROPOSAL, EVAL_COMPLETE,
    GRAPHQL_CANDIDATE,
)

# Which tools are the canonical subscribers for each event (documentation /
# wiring aid for the campaign orchestrator).
CANONICAL_LISTENERS: Dict[str, List[str]] = {
    RECON_COMPLETE: ["campaign_orchestrator", "chain_orchestrator"],
    FINDING_DISCOVERED: ["chain_orchestrator", "post_finding_trigger",
                         "retest_scheduler"],
    WAF_BLOCKED: ["parser_differential", "research_loop.bypass"],
    STAGE_ADVANCED: ["campaign_orchestrator"],
    SMUGGLING_CANDIDATE: ["chain_orchestrator", "triage"],
    AUTH_CANDIDATE: ["triage", "chain_orchestrator"],
    GRAPHQL_CANDIDATE: ["chain_orchestrator", "triage"],
    CLOUD_CANDIDATE: ["chain_orchestrator", "triage"],
    MOBILE_CANDIDATE: ["chain_orchestrator", "triage"],
    ASSET_DELTA: ["campaign_orchestrator", "asset_intel"],
    LLM_CANDIDATE: ["triage", "chain_orchestrator"],
    LAB_PLANNED: ["campaign_orchestrator", "verification_lab"],
    CHAIN_PROPOSAL: ["chain_orchestrator", "triage"],
    EVAL_COMPLETE: ["campaign_orchestrator", "stage_controller"],
    DISCOVERY_COMPLETE: ["campaign_orchestrator"],
    RESEARCH_REFRESHED: ["stage_controller", "campaign_orchestrator"],
}


@dataclass
class Event:
    event_type: str
    target: str
    source: str  # tool or component that published the event
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    event_id: str = ""
    listener_errors: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.event_type not in EVENT_TYPES:
            raise ValueError(
                f"unknown event type '{self.event_type}'. Valid: "
                + ", ".join(EVENT_TYPES))
        if not self.target or not self.source:
            raise ValueError("events require a target and a source")
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.event_id:
            raw = f"{self.target}:{self.event_type}:{self.source}:{self.timestamp}"
            self.event_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# The bus
# ---------------------------------------------------------------------------

Listener = Callable[[Event], None]


class SignalBus:
    """Persistent, typed, publish/subscribe event bus for one target."""

    def __init__(self, target: str, *, project_root: Optional[str] = None):
        self.target = target
        root = workspace_root(project_root)
        self._events_dir = root / "state" / "signals" / "events"
        self._events_dir.mkdir(parents=True, exist_ok=True)
        self._log = self._events_dir / f"{target_slug(target)}.jsonl"
        self._listeners: Dict[str, List[Listener]] = {}

    # -- subscription -------------------------------------------------------

    def subscribe(self, event_type: str, listener: Listener) -> None:
        """Register a listener for one event type (no-op for unknown types)."""
        if event_type not in EVENT_TYPES:
            return
        self._listeners.setdefault(event_type, []).append(listener)

    def unsubscribe(self, event_type: str, listener: Listener) -> None:
        if event_type in self._listeners and listener in self._listeners[event_type]:
            self._listeners[event_type].remove(listener)

    def listeners(self) -> Dict[str, int]:
        return {event_type: len(fns) for event_type, fns in self._listeners.items()}

    # -- publish ------------------------------------------------------------

    def publish(self, event_type: str, source: str,
                payload: Optional[Dict[str, Any]] = None,
                *, persist: bool = True) -> Event:
        """Create, persist (optional), and dispatch an event to listeners.

        Listener failures are captured on the event and never raise — the bus
        is advisory, not a workflow gate.  When the event was persisted and a
        listener failed, the updated event (with ``listener_errors``) is
        appended so the failure remains observable in the durable log instead
        of living only in the in-memory return value.
        """
        event = Event(event_type=event_type, target=self.target, source=source,
                      payload=payload or {})
        if persist:
            self._append(event)
        for listener in self._listeners.get(event_type, []):
            try:
                listener(event)
            except Exception as exc:  # listener is advisory; never gate
                event.listener_errors.append(
                    f"{getattr(listener, '__name__', type(listener).__name__)}: "
                    f"{type(exc).__name__}: {exc}")
        if event.listener_errors and persist:
            # Durable failure record: same event id, appended after dispatch.
            self._append(event)
        return event

    def _append(self, event: Event) -> None:
        line = json.dumps(event.to_dict(), sort_keys=True)
        with open(self._log, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    # -- replay -------------------------------------------------------------

    def replay(self, *, dispatch: bool = True) -> List[Event]:
        """Read every persisted event for the target (oldest first).

        When ``dispatch`` is true the events are re-dispatched to currently
        registered listeners, letting a tool that started late react to
        events it missed.
        """
        events: List[Event] = []
        if not self._log.is_file():
            return events
        for line in self._log.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                event = Event(**data)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            events.append(event)
            if dispatch:
                for listener in self._listeners.get(event.event_type, []):
                    try:
                        listener(event)
                    except Exception as exc:
                        event.listener_errors.append(
                            f"{getattr(listener, '__name__', type(listener).__name__)}: "
                            f"{type(exc).__name__}: {exc}")
        return events

    # -- queries ------------------------------------------------------------

    def events(self, event_type: Optional[str] = None) -> List[Event]:
        out = [event for event in self.replay(dispatch=False)
               if event_type is None or event.event_type == event_type]
        return out

    def stats(self) -> Dict[str, Any]:
        all_events = self.events()
        counts: Dict[str, int] = {}
        for event in all_events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        return {
            "target": self.target,
            "log": str(self._log),
            "total_events": len(all_events),
            "by_type": counts,
            "listeners": self.listeners(),
        }


def publish_or_warn(target: str, event_type: str, source: str,
                    payload: Optional[Dict[str, Any]] = None, *,
                    project_root: Optional[str] = None,
                    base_dir: Optional[str] = None) -> Optional[Event]:
    """Publish an event, warning on environmental failure, raising on bugs.

    The bus is advisory: an unwritable event log (``OSError``) must never
    gate a tool, so it is reported to stderr and execution continues. But a
    *programming* error — publishing an event type the bus does not register
    (``ValueError``) or a malformed payload (``TypeError``) — must surface
    loudly: silently swallowing it hides the exact bug class that left
    ``GRAPHQL_CANDIDATE`` unpublished for a full release cycle.

    Returns the persisted ``Event`` on success, ``None`` when the log could
    not be written (environmental, advisory).
    """
    try:
        bus = SignalBus(target, project_root=project_root or base_dir)
        return bus.publish(event_type, source, payload)
    except OSError as exc:
        print(f"[!] signal publish skipped: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return None


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf Event-Driven Signal Bus")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--publish", help="JSON event to publish "
                        "(event_type, source, payload)")
    parser.add_argument("--replay", action="store_true",
                        help="Replay persisted events to registered listeners")
    parser.add_argument("--events", metavar="TYPE", nargs="?", const="",
                        help="List persisted events (optionally filtered by type)")
    parser.add_argument("--stats", action="store_true", help="Show bus stats")
    parser.add_argument("--json", action="store_true", help="Emit strict JSON")
    args = parser.parse_args()

    bus = SignalBus(args.target)

    if args.publish:
        try:
            data = json.loads(args.publish)
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False, "error": f"invalid JSON: {exc}"}))
            return 2
        event = bus.publish(data["event_type"], data.get("source", "cli"),
                            data.get("payload"))
        out = event.to_dict()
        print(json.dumps(out, indent=2) if args.json else
              f"[+] {event.event_type} {event.event_id} ({event.source})")
        return 0

    if args.replay:
        replayed = bus.replay(dispatch=False)
        if args.json:
            print(json.dumps({"target": args.target,
                              "replayed": [e.to_dict() for e in replayed]},
                             indent=2))
        else:
            print(f"[*] Replayed {len(replayed)} events for {args.target}")
        return 0

    if args.events is not None:
        events = bus.events(args.events or None)
        if args.json:
            print(json.dumps({"target": args.target,
                              "events": [e.to_dict() for e in events]}, indent=2))
        else:
            for e in events:
                print(f"  [{e.event_type}] {e.event_id} {e.source} {e.timestamp}")
            print(f"  ({len(events)} events)")
        return 0

    if args.stats:
        stats = bus.stats()
        print(json.dumps(stats, indent=2) if args.json else
              "\n".join(f"  {k}: {v}" for k, v in stats.items()))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
