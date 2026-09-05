#!/usr/bin/env python3
"""BugWolf DNS-OAST listener v1.24.1+.

Extends the existing HTTP OAST (tools/runtime/oast.py) with a DNS listener
for callbacks that arrive over DNS (blind SSRF, blind command injection,
log4j-style JNDI lookups, etc.).

The listener binds a UDP socket on 127.0.0.1:53 (or BUGWOLF_DNS_PORT) and
records every DNS query. The mission_runner registers a per-lead canary
subdomain of the form ``oast-<lead_id>.bugwolf.local`` (or the
operator-declared zone) and the listener attributes each query to the
right lead.

For real engagements, the operator should expose the DNS port publicly
(BUGWOLF_DNS_PUBLIC_IP) and configure the authoritative NS record for
their zone to point at the public IP. This module handles the in-process
listener + JSONL logging + per-lead attribution; the public exposure is
operator's responsibility.

Configuration:
  BUGWOLF_DNS_PORT     (default: 5354 — avoids conflict with system resolver)
  BUGWOLF_DNS_ZONE     (default: bugwolf.local)
  BUGWOLF_DNS_PUBLIC_IP (operator sets for real engagement exposure)

Schema (one JSONL line per query):
  {
    "schema": "bugwolf-dns-oast/v1",
    "qname": "oast-<lead>.bugwolf.local",
    "qtype": "A",
    "src": "10.0.0.5:54321",
    "lead_id": "ld-abc",
    "timestamp": "..."
  }
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "bugwolf-dns-oast/v1"

DEFAULT_PORT = 5354
DEFAULT_ZONE = "bugwolf.local"


# ---------------------------------------------------------------------------
# Minimal DNS protocol parser (RFC 1035)
# ---------------------------------------------------------------------------

def _parse_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a DNS name (sequence of length-prefixed labels). Returns
    (name, new_offset).  Supports compression (RFC 1035 §4.1.4)."""
    labels: List[str] = []
    jumped = False
    orig_offset = offset
    max_iter = 32  # prevent infinite loops on malformed input
    for _ in range(max_iter):
        if offset >= len(data):
            break
        ln = data[offset]
        if ln == 0:
            offset += 1
            break
        if (ln & 0xC0) == 0xC0:
            # Pointer — 14 bits, big-endian.
            if offset + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        if offset + ln > len(data):
            break
        labels.append(data[offset:offset + ln].decode("utf-8", "replace"))
        offset += ln
    name = ".".join(labels)
    return name, (orig_offset if jumped else offset)


def _build_a_response(query: bytes, *, qname_offset: int,
                      qname: str, answer_ip: str) -> bytes:
    """Build a minimal DNS A response: same ID, answer with one A record.

    This is a tiny bespoke encoder — not a full RFC 1035 implementation,
    but it answers A queries with a single record pointing at ``answer_ip``.
    """
    txn_id = query[:2]
    # Header: ID + flags (0x8180 = standard query response, no error) +
    # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    header = txn_id + struct.pack(">HHHHHH", 0x8180, 1, 1, 0, 0)
    # Question section: copy from the query (we just need the QNAME+QTYPE+QCLASS).
    q_end = qname_offset
    # Find the end of the question by skipping labels + 4 bytes (type+class).
    i = qname_offset
    while i < len(query):
        ln = query[i]
        if ln == 0:
            i += 5  # null + type(2) + class(2)
            break
        if (ln & 0xC0) == 0xC0:
            i += 2 + 4
            break
        i += ln + 1
    question = query[qname_offset:i]
    # Answer: name (pointer to question), type A, class IN, TTL 60, rdlength 4, rdata
    answer = (
        b"\xc0\x0c"  # pointer to offset 12 (start of QNAME)
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + bytes(int(p) for p in answer_ip.split("."))
    )
    return header + question + answer


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

@dataclass
class DnsQuery:
    qname: str
    qtype: int
    src: str
    lead_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "qname": self.qname,
            "qtype": self.qtype,
            "src": self.src,
            "lead_id": self.lead_id,
            "timestamp": self.timestamp,
        }


class DnsOastListener:
    """In-process DNS OAST listener with per-lead attribution."""

    def __init__(self, *, port: int = DEFAULT_PORT, zone: str = DEFAULT_ZONE,
                 answer_ip: str = "127.0.0.1",
                 log_path: Optional[Path] = None):
        self.port = port
        self.zone = zone
        self.answer_ip = answer_ip
        self.log_path = log_path or Path("state") / "dns-oast.jsonl"
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._registry: Dict[str, str] = {}  # qname prefix -> lead_id

    def register(self, lead_id: str) -> str:
        """Register a per-lead canary prefix. Returns the canary qname."""
        digest = hashlib.sha256(lead_id.encode()).hexdigest()[:12]
        qname = f"oast-{digest}.{self.zone}"
        self._registry[qname.split(".")[0]] = lead_id
        return qname

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind(("127.0.0.1", self.port))
        except OSError as exc:
            raise RuntimeError(
                f"DNS OAST could not bind 127.0.0.1:{self.port} ({exc}). "
                f"Set BUGWOLF_DNS_PORT to a free port."
            ) from exc
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                       name="bugwolf-dns-oast")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:  # noqa: BLE001
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._thread = None
        self._sock = None

    def _serve(self) -> None:
        if self._sock is None:
            return
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:  # noqa: BLE001
                break
            try:
                self._handle(data, addr)
            except Exception:  # noqa: BLE001
                # Listener errors are data, never fatal.
                continue

    def _handle(self, data: bytes, addr: Tuple[str, int]) -> None:
        if len(data) < 12:
            return
        try:
            qname, _ = _parse_name(data, 12)
        except Exception:  # noqa: BLE001
            return
        qtype = struct.unpack(">H", data[len(qname) + 13:len(qname) + 15])[0] \
            if len(data) >= len(qname) + 15 else 0
        # Find the lead_id for this qname
        lead_id = ""
        prefix = qname.split(".")[0] if qname else ""
        if prefix in self._registry:
            lead_id = self._registry[prefix]
        record = DnsQuery(
            qname=qname, qtype=qtype,
            src=f"{addr[0]}:{addr[1]}",
            lead_id=lead_id,
        )
        # Persist + respond
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict()) + "\n")
        if self._sock is None:
            return
        try:
            # Only answer A queries.  Other qtypes are logged but not
            # responded to (an attacker probe to ANY is itself evidence).
            if qtype == 1 and lead_id:
                resp = _build_a_response(data, qname_offset=12,
                                         qname=qname, answer_ip=self.answer_ip)
                self._sock.sendto(resp, addr)
        except OSError:  # noqa: BLE001
            pass

    def __enter__(self) -> "DnsOastListener":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Convenience: synchronous poll for a canary hit
# ---------------------------------------------------------------------------

def wait_for_callback(log_path: Path, *, canary: str,
                      timeout: float = 30.0) -> Optional[Dict[str, Any]]:
    """Tail the listener log and return the first record matching ``canary``."""
    deadline = time.monotonic() + timeout
    seen_bytes = 0
    while time.monotonic() < deadline:
        if log_path.exists():
            with log_path.open("r", encoding="utf-8") as fh:
                fh.seek(seen_bytes)
                for line in fh:
                    seen_bytes += len(line)
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if canary in record.get("qname", ""):
                        return record
        time.sleep(0.5)
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="BugWolf DNS-OAST listener")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("BUGWOLF_DNS_PORT", DEFAULT_PORT)))
    p.add_argument("--zone", default=os.environ.get("BUGWOLF_DNS_ZONE", DEFAULT_ZONE))
    p.add_argument("--answer-ip", default="127.0.0.1")
    p.add_argument("--log", default="state/dns-oast.jsonl")
    p.add_argument("--duration", type=float, default=0.0,
                   help="If > 0, run for N seconds and exit (for tests)")
    args = p.parse_args()

    listener = DnsOastListener(
        port=args.port, zone=args.zone,
        answer_ip=args.answer_ip, log_path=Path(args.log),
    )
    print(f"[+] DNS OAST listening on 127.0.0.1:{args.port} "
          f"(zone={args.zone}, answer_ip={args.answer_ip})")
    print(f"[+] log: {args.log}")
    print(f"[+] press Ctrl-C to stop")
    try:
        with listener:
            if args.duration > 0:
                time.sleep(args.duration)
            else:
                while True:
                    time.sleep(1.0)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
