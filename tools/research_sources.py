#!/usr/bin/env python3
"""Phase 6 — Provenance-bound research intelligence.

Records every internet research retrieval with full provenance (query,
provider, retrieval time, URL, title, content hash, reliability class,
applicability) so the research loop's ``latest_ready`` claims are auditable.

Two hard rules are enforced as *data* rules, never execution gates:

  * retrieved content is **untrusted data** — instructions are stripped and
    stored separately from intent;
  * stale or unreliable sources are surfaced, never silently reused.

Artifacts persist under ``state/research-sources/<target>/``.

Usage:
  python3 tools/research_sources.py --target T --record --query Q \\
      --provider serper --url U --title T --content C --json
  python3 tools/research_sources.py --target T --status --json
  python3 tools/research_sources.py --target T --strip --content C --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tools.runtime_paths import target_slug, workspace_root
except ImportError:  # direct script execution
    from runtime_paths import target_slug, workspace_root

SCHEMA = "bugwolf/research-sources/v1"
RELIABILITY_ORDER = {
    "normative": 0, "vendor_advisory": 1, "academic": 2,
    "disclosed_report": 3, "writeup": 4, "unverified": 5,
}
INSTRUCTION_MARKERS = (
    "ignore previous instructions", "ignore all previous", "you are now",
    "act as", "system prompt", "do not reveal", "forget everything",
    "override", "disregard",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dir(project_root: Optional[str] = None, target: str = "") -> Path:
    root = workspace_root(project_root)
    if target:
        return root / "state" / "research-sources" / target_slug(target)
    return root / "state" / "research-sources"


def _sha256(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def strip_instructions(content: str) -> Dict[str, Any]:
    """Detect and strip instruction-like content from retrieved material.

    Returns the sanitized content plus an inventory of what was removed so
    the operator can audit the provenance of the decision.
    """
    text = str(content or "")
    low = text.lower()
    stripped = text
    removed: List[str] = []
    for marker in INSTRUCTION_MARKERS:
        if marker in low:
            removed.append(marker)
    # Remove bracketed instruction blocks (common in prompt-injection seeds).
    stripped = re.sub(r"\[(?:instructions?|system|ignore)[^\]]*\]", "",
                      stripped, flags=re.I)
    return {
        "content_sha256": _sha256(text),
        "sanitized": stripped,
        "removed_markers": removed,
        "instruction_count": len(removed),
    }


@dataclass
class ResearchSource:
    source_id: str
    query: str
    provider: str
    url: str
    title: str
    reliability: str
    content_sha256: str
    retrieved_at: str = ""
    applicability: str = ""
    sanitized: bool = False

    def __post_init__(self):
        if not self.retrieved_at:
            self.retrieved_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SourceRegistry:
    """Append-only registry of provenance-bound research retrievals."""

    def __init__(self, target: str = "", project_root: Optional[str] = None):
        self.target = target_slug(target)
        self.root = _dir(project_root, self.target)
        self._sources: Dict[str, ResearchSource] = {}
        self._load()

    def _path(self) -> Path:
        return self.root / "sources.jsonl"

    def _load(self) -> None:
        if not self._path().is_file():
            return
        for line in self._path().read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                src = ResearchSource(**{k: v for k, v in rec.items()
                                        if k in ResearchSource.__dataclass_fields__})
                self._sources[src.source_id] = src
            except (TypeError, json.JSONDecodeError, KeyError):
                continue

    def record(self, *, query: str, provider: str, url: str, title: str,
               content: Any = None, reliability: str = "unverified",
               applicability: str = "", sanitize: bool = True
               ) -> ResearchSource:
        """Record one retrieval; content is hashed and optionally sanitized."""
        reliability = reliability if reliability in RELIABILITY_ORDER \
            else "unverified"
        digest = _sha256(content if content is not None else f"{url}:{title}")
        sanitized = False
        if sanitize and content is not None:
            sanitized = strip_instructions(content)["instruction_count"] > 0
        src = ResearchSource(
            source_id=digest[:16],
            query=str(query or ""), provider=str(provider or ""),
            url=str(url or ""), title=str(title or ""),
            reliability=reliability, content_sha256=digest,
            applicability=str(applicability or ""), sanitized=sanitized)
        if src.source_id in self._sources:
            return self._sources[src.source_id]  # content duplicate
        self._sources[src.source_id] = src
        self.root.mkdir(parents=True, exist_ok=True)
        with self._path().open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(src.to_dict(), sort_keys=True) + "\n")
        return src

    def sources(self) -> List[ResearchSource]:
        return sorted(self._sources.values(),
                      key=lambda s: (RELIABILITY_ORDER.get(s.reliability, 9),
                                     s.retrieved_at))

    def report(self) -> Dict[str, Any]:
        by_reliability: Dict[str, int] = {}
        sanitized = 0
        for src in self._sources.values():
            by_reliability[src.reliability] = \
                by_reliability.get(src.reliability, 0) + 1
            if src.sanitized:
                sanitized += 1
        return {
            "schema": SCHEMA,
            "target": self.target,
            "sources": len(self._sources),
            "by_reliability": by_reliability,
            "sanitized_retrievals": sanitized,
            "latest_retrieved_at": max(
                (s.retrieved_at for s in self._sources.values()), default=""),
        }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf provenance-bound research intelligence")
    parser.add_argument("--target", default="")
    parser.add_argument("--project-root", help="workspace root override")
    parser.add_argument("--json", action="store_true")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--record", action="store_true",
                         help="record one retrieval")
    actions.add_argument("--status", action="store_true",
                         help="source registry summary")
    actions.add_argument("--strip", action="store_true",
                         help="strip instructions from --content")
    parser.add_argument("--query", default="")
    parser.add_argument("--provider", default="serper")
    parser.add_argument("--url", default="")
    parser.add_argument("--title", default="")
    parser.add_argument("--content", default="")
    parser.add_argument("--reliability", default="unverified",
                        choices=sorted(RELIABILITY_ORDER))
    parser.add_argument("--applicability", default="")
    parser.add_argument("--no-sanitize", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.record:
            registry = SourceRegistry(args.target, args.project_root)
            src = registry.record(
                query=args.query, provider=args.provider, url=args.url,
                title=args.title, content=args.content,
                reliability=args.reliability, applicability=args.applicability,
                sanitize=not args.no_sanitize)
            result = {"schema": SCHEMA, "recorded": src.to_dict()}
        elif args.strip:
            result = {"schema": SCHEMA, **strip_instructions(args.content)}
        else:
            registry = SourceRegistry(args.target, args.project_root)
            result = registry.report()
        status = 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "error": str(exc)}
        status = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True)[:2000])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
