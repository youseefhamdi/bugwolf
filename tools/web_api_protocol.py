#!/usr/bin/env python3
"""Web/API protocol trace normalization and local HAR export."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from tools.reliability import atomic_write_json


@dataclass
class ProtocolTrace:
    target: str
    protocol: str = "http"
    entries: List[Dict[str, Any]] = field(default_factory=list)
    delta: Dict[str, Any] = field(default_factory=dict)
    schema: str = "bugwolf/web-api-protocol/v1"

    @classmethod
    def from_observations(cls, target: str, observations: Iterable[Dict[str, Any]]) -> "ProtocolTrace":
        entries: List[Dict[str, Any]] = []
        for item in observations:
            request = {
                "method": str(item.get("method") or "GET").upper(),
                "url": str(item.get("url") or item.get("endpoint") or ""),
                "headers": dict(item.get("request_headers") or item.get("headers") or {}),
                "body": item.get("request_body"),
            }
            response = {
                "status": int(item.get("status") or 0),
                "headers": dict(item.get("response_headers") or {}),
                "body": str(item.get("body") or ""),
                "elapsed_ms": float(item.get("elapsed_ms") or 0.0),
                "redirects": list(item.get("redirects") or item.get("redirect_chain") or []),
            }
            entries.append({
                "id": hashlib.sha256(
                    f"{request['method']}|{request['url']}|{len(entries)}".encode()
                ).hexdigest()[:16],
                "request": request,
                "response": response,
                "metadata": dict(item.get("metadata") or {}),
            })
        delta: Dict[str, Any] = {}
        if len(entries) >= 2:
            first = entries[0]["response"]
            second = entries[1]["response"]
            delta = {
                "status_changed": first["status"] != second["status"],
                "body_changed": first["body"] != second["body"],
                "headers_changed": first["headers"] != second["headers"],
                "timing_delta_ms": round(second["elapsed_ms"] - first["elapsed_ms"], 3),
                "redirects_changed": first["redirects"] != second["redirects"],
            }
        return cls(target=str(target), entries=entries, delta=delta)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "target": self.target,
            "protocol": self.protocol,
            "entries": self.entries,
            "delta": self.delta,
        }

    def to_har(self) -> Dict[str, Any]:
        """Convert normalized traces to HAR 1.2 without dropping metadata."""
        har_entries = []
        for entry in self.entries:
            request = entry["request"]
            response = entry["response"]
            har_entries.append({
                "startedDateTime": entry.get("metadata", {}).get("started_at", ""),
                "time": response["elapsed_ms"],
                "request": {
                    "method": request["method"],
                    "url": request["url"],
                    "httpVersion": self.protocol.upper() + "/1.1" if self.protocol == "http" else self.protocol.upper(),
                    "headers": [{"name": k, "value": str(v)} for k, v in request["headers"].items()],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": len(str(request.get("body") or "").encode()),
                    "postData": ({"mimeType": "application/json", "text": str(request["body"])}
                                 if request.get("body") is not None else None),
                },
                "response": {
                    "status": response["status"],
                    "statusText": "",
                    "httpVersion": self.protocol.upper() + "/1.1" if self.protocol == "http" else self.protocol.upper(),
                    "headers": [{"name": k, "value": str(v)} for k, v in response["headers"].items()],
                    "content": {"size": len(response["body"].encode()), "mimeType": "", "text": response["body"]},
                    "redirectURL": response["redirects"][-1] if response["redirects"] else "",
                    "headersSize": -1,
                    "bodySize": len(response["body"].encode()),
                },
                "cache": {},
                "timings": {"send": 0, "wait": response["elapsed_ms"], "receive": 0},
                "comment": f"BugWolf entry {entry['id']}",
            })
        return {"log": {"version": "1.2", "creator": {"name": "BugWolf", "version": "1"}, "entries": har_entries}}


class WebApiProtocolExporter:
    def export(self, trace: ProtocolTrace, directory: str | Path) -> Dict[str, Path]:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        json_path = root / "protocol-trace.json"
        har_path = root / "protocol-trace.har"
        atomic_write_json(json_path, trace.to_dict())
        atomic_write_json(har_path, trace.to_har())
        return {"json": json_path, "har": har_path}
