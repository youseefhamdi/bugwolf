#!/usr/bin/env python3
"""Understanding Layer CLI (master plan §8.1 — /bugwolf-understand's engine).

Fetches the U1 business pages through the replay engine (scope gate +
governor inherited), optionally loads a mission's crawl/session artifacts,
runs U1→U9 strict-sequential, and prints the coverage gate + Hunting Brief.

Usage:
  python3 -m tools.runtime.understanding --target https://t.example \
      [--paths /pricing,/tos] [--mission-id <id>] [--refresh] [--json]

Deterministic tier: no model calls.  All network I/O rides the Phase 1
engine — out-of-scope targets are refused by the scope gate, not by hope.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.runtime.understanding.pipeline import (
    PipelineResult, UnderstandingPipeline,
)


def _fetch_pages(target: str, paths: list, *, rate: float = 10.0,
                 budget: int = 200) -> tuple[dict, Optional[dict]]:
    """Fetch pages (+ conventional schema locations) via the replay engine.

    Returns (pages, openapi).  A dead page is a missing fact, not a crash.
    """
    from tools.runtime.replay.engine import replay_raw
    from tools.runtime.replay.governor import Governor
    from tools.runtime.understanding.antibot import is_antibot_page, \
        ANTIBOT_FACT
    from urllib.parse import urlparse

    host = urlparse(target if "://" in target else f"https://{target}").netloc \
        or str(target)
    pages: dict = {}
    openapi: Optional[dict] = None
    antibot: list = []
    governor = Governor(rate_rps=rate, budget=budget)
    for path in list(paths) + ["/openapi.json", "/swagger.json"]:
        if path in pages:
            continue
        raw = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: BugWolf-Understand/1\r\n"
               "Accept: text/html,application/json\r\n"
               "Connection: close\r\n\r\n").encode("latin-1")
        try:
            report = replay_raw(raw, host=target, governor=governor)
        except Exception:  # noqa: BLE001 - missing page != failed model
            continue
        if report.status == 200 and report.body_preview:
            # v1.29 Phase F: a bot-wall challenge page passes 200-with-
            # content and would silently poison U1's business-lens
            # inference with challenge boilerplate.  Detected pages are
            # EXCLUDED from pages and recorded as facts instead.
            if is_antibot_page(report.body_preview):
                antibot.append(dict(ANTIBOT_FACT, path=path))
                continue
            pages[path] = report.body_preview[:20000]
            if openapi is None and path.endswith(".json"):
                try:
                    doc = json.loads(report.body_preview)
                    if isinstance(doc, dict) and (
                            "openapi" in doc or "swagger" in doc):
                        openapi = doc
                except ValueError:
                    pass
    return pages, openapi, antibot


def _load_mission(mission_id: str, project_root):
    """Load a mission's crawl + session artifacts (facts, when they exist)."""
    crawl = session_store = None
    if not mission_id:
        return crawl, session_store
    from tools.runtime.session_context import SessionContextStore
    store = SessionContextStore(mission_id, project_root=project_root).load()
    if store.sessions:
        session_store = store
    crawl_dir = (Path(project_root) if project_root else Path.cwd()) / \
        "state" / "orchestrator" / mission_id / "crawl"
    matrix_path = crawl_dir / "access_matrix.json"
    if matrix_path.is_file():
        try:
            payload = json.loads(matrix_path.read_text(encoding="utf-8"))

            class _Page:
                pass

            pages = {}
            pages_path = crawl_dir / "pages.jsonl"
            if pages_path.is_file():
                for line in pages_path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    page = _Page()
                    page.path = rec.get("path", "")
                    page.status_by_label = rec.get("status_by_label", {})
                    page.title = rec.get("title", "")
                    page.links = rec.get("links", [])
                    page.forms = rec.get("forms", [])
                    pages[page.path] = page

            class _Crawl:
                pass

            crawl = _Crawl()
            crawl.pages = pages
            crawl.labels = list(payload.get("labels") or [])
            crawl.differential_paths = lambda: list(
                payload.get("differential_paths") or [])
            crawl.to_dict = lambda: payload
        except (OSError, ValueError):
            pass
    return crawl, session_store


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf Understanding Layer (U1-U9) — the Hunting Brief")
    parser.add_argument("--target", required=True)
    parser.add_argument("--paths", default="/,/pricing,/signup,/tos",
                        help="comma-separated U1 business pages to fetch")
    parser.add_argument("--mission-id", default="",
                        help="consume this mission's crawl + session artifacts")
    parser.add_argument("--refresh", action="store_true",
                        help="force recompute of all stages")
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    pages, openapi, antibot = _fetch_pages(
        args.target, [p if p.startswith("/") else "/" + p
                      for p in args.paths.split(",") if p.strip()])
    crawl, session_store = _load_mission(args.mission_id, args.project_root)

    pipeline = UnderstandingPipeline(args.target,
                                     project_root=args.project_root)
    try:
        result = pipeline.run(pages=pages, crawl=crawl,
                              session_store=session_store, openapi=openapi,
                              refresh=args.refresh)
    except RuntimeError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 2

    if args.json:
        out = result.to_dict()
        out["fetched_pages"] = sorted(pages)
        brief = Path(result.brief_path)
        if brief.is_file():
            out["hunting_brief"] = brief.read_text(encoding="utf-8")
        print(json.dumps(out, indent=2))
    else:
        print(f"stages run:    {', '.join(result.stages_run) or '-'}")
        print(f"stages cached: {', '.join(result.stages_cached) or '-'}")
        print(f"hunts:         {', '.join(result.coverage_hunts) or '-'}")
        print(f"parked:        "
              f"{', '.join(p['bug_class'] for p in result.coverage_parked) or '-'}")
        print(f"ledger:        {result.ledger_size} assumptions")
        print(f"model hash:    {result.model_hash[:16]}…")
        print(f"brief:         {result.brief_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
