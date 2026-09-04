#!/usr/bin/env python3
"""Authenticated per-credential crawl (master plan Phase 2.3).

The doctrine this mechanizes: differential access becomes DATA, not
guesswork.  The same URL space is crawled once per bound identity (anon,
A, B, C) and every observation is recorded with WHO saw it:

    * Page     (visited by: <labels that reached it>, per-label status)
    * Trigger  (forms/buttons/links, visible to: <labels>)
    * form schemas (action, method, field names/types)

Outputs (``state/orchestrator/<mission>/crawl/``):

    * ``access_matrix.json`` — path x label status grid + differential
      paths (the authz hunt's base map; the U4 artifact's backbone);
    * ``pages.jsonl`` — one record per page per label (facts only).

The crawler rides the Phase 1 replay engine for transport (scope gate +
governor inherited — no separate network path), parses HTML with the
stdlib ``html.parser`` (zero dependencies), and feeds every response into
the Phase 2.2 ``SessionContextStore`` so roles/object IDs/endpoints
accumulate as a side effect of crawling.

Anomaly RULES are not applied here beyond flagging differential paths —
verdicts belong to the F0.5 gate and the authz lanes.  This module
produces the map; it does not shoot.

Deterministic tier: no model calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from tools.runtime_paths import runtime_path
from tools.runtime.replay.engine import replay_raw
from tools.runtime.replay.backend_socket import BackendRefused
from tools.runtime.replay.governor import DEFAULTS as GOV_DEFAULTS, Governor

SCHEMA = "bugwolf-authed-crawl/v1"

DEFAULT_MAX_PAGES = 40
DEFAULT_MAX_LINKS_PER_PAGE = 25
_USER_AGENT = "BugWolf-AuthCrawl/1"


class _HtmlFacts(HTMLParser):
    """Stdlib HTML harvest: title, links, forms (+field schemas)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrd = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "a":
            href = attrd.get("href", "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)
        elif tag == "form":
            self._form = {"action": attrd.get("action", ""),
                          "method": (attrd.get("method") or "GET").upper(),
                          "fields": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["fields"].append(
                {"name": attrd.get("name", ""),
                 "type": attrd.get("type", tag)})

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


@dataclass
class CrawlPage:
    """One URL's observation, per identity."""

    path: str
    status_by_label: Dict[str, int] = field(default_factory=dict)
    title: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    content_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "status_by_label": dict(self.status_by_label),
                "title": self.title, "links": list(self.links),
                "forms": [dict(f) for f in self.forms],
                "content_type": self.content_type}


@dataclass
class CrawlReport:
    """The crawl's facts: pages, access matrix, differentials."""

    base_url: str
    pages: Dict[str, CrawlPage] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    requests: int = 0
    transport_errors: int = 0

    @property
    def access_matrix(self) -> Dict[str, Dict[str, int]]:
        return {path: dict(page.status_by_label)
                for path, page in sorted(self.pages.items())}

    def differential_paths(self) -> List[str]:
        """Paths where identities see DIFFERENT statuses (the authz hunt's
        candidate list — a fact, not a verdict)."""
        out = []
        for path, page in self.pages.items():
            statuses = set(page.status_by_label.values()) - {0}
            if len(statuses) > 1:
                out.append(path)
        return sorted(out)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "base_url": self.base_url,
            "labels": list(self.labels),
            "requests": self.requests,
            "transport_errors": self.transport_errors,
            "access_matrix": self.access_matrix,          # @property
            "differential_paths": self.differential_paths(),
            "pages": {path: page.to_dict()
                      for path, page in sorted(self.pages.items())},
        }


def _normalize_path(base_url: str, link: str) -> str:
    """Same-host absolute-or-relative link -> path (+query), else ''."""
    absolute = urljoin(base_url.rstrip("/") + "/", link.strip())
    parsed = urlparse(absolute)
    if not parsed.scheme and not parsed.netloc:
        return ""
    base = urlparse(base_url)
    if (parsed.scheme, parsed.hostname) not in \
            {(base.scheme, base.hostname), ("http", base.hostname),
             ("https", base.hostname)}:
        return ""
    path = parsed.path or "/"
    return path + (f"?{parsed.query}" if parsed.query else "")


class AuthedCrawler:
    """Crawl one URL space once per bound identity; record who saw what."""

    def __init__(self, base_url: str, mission_id: str, *,
                 matrix=None, session_store=None,
                 max_pages: int = DEFAULT_MAX_PAGES,
                 max_links_per_page: int = DEFAULT_MAX_LINKS_PER_PAGE,
                 project_root=None,
                 governor: Optional[Governor] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.mission_id = mission_id
        self.matrix = matrix
        self.session_store = session_store
        self.max_pages = max(1, max_pages)
        self.max_links_per_page = max(1, max_links_per_page)
        self.project_root = project_root
        # A differential crawl sends labels×pages in quick succession —
        # the hunt default (5 rps burst) would refuse its own tail.  10 rps
        # stays polite while the circuit breaker + global budget keep the
        # anti-self-DoS guarantees (both remain governor-enforced).
        self.governor = governor or Governor(
            rate_rps=max(10.0, GOV_DEFAULTS["rate_limit_start_rps"]),
            budget=GOV_DEFAULTS["global_request_budget"])

    # -- identity labels ------------------------------------------------------

    def _labels(self) -> List[str]:
        labels = ["anon"]
        if self.matrix is not None:
            labels += [l for l in self.matrix.bound_labels if l not in labels]
        return labels

    def _auth_headers(self, label: str) -> Dict[str, str]:
        if label == "anon" or self.matrix is None:
            return {}
        return self.matrix.auth_headers(label)

    # -- transport (through the replay engine: scope + governor inherited) ----

    def _fetch(self, path: str, label: str) -> Tuple[int, str, Dict[str, str]]:
        method = "GET"
        headers = {"Host-Override": "crawler", "User-Agent": _USER_AGENT,
                   "Accept": "text/html,application/json"}
        headers.update(self._auth_headers(label))
        target = self.base_url + path
        lines = [f"{method} {path} HTTP/1.1"]
        host_header = urlparse(self.base_url).netloc
        if host_header:
            lines.append(f"Host: {host_header}")
        for name, value in headers.items():
            if value:
                lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        try:
            report = replay_raw(raw, host=self.base_url,
                                governor=self.governor)
        except BackendRefused:
            # Governor refusal (budget/circuit/rate) is a transport fact,
            # not a crash — the crawl degrades to status 0 for this page.
            return 0, "", {}
        return (report.status or 0, report.body_preview,
                report.headers)

    # -- the crawl ---------------------------------------------------------------

    def crawl(self, seeds: List[str]) -> CrawlReport:
        labels = self._labels()
        report = CrawlReport(base_url=self.base_url, labels=labels)
        frontier: List[str] = []
        seen: set = set()

        def _push(path: str) -> None:
            path = path.split("#", 1)[0]
            if not path or path in seen:
                return
            if len(seen) >= self.max_pages:
                return
            seen.add(path)
            frontier.append(path)

        for seed in seeds or ["/"]:
            _push(seed if seed.startswith("/") else "/" + seed)

        while frontier and len(report.pages) < self.max_pages:
            path = frontier.pop(0)
            page = self._crawl_one(path, labels, report)
            report.pages[path] = page
            if len(report.pages) >= self.max_pages:
                break
            if "html" not in page.content_type.lower():
                continue
            added = 0
            for link in page.links:
                if added >= self.max_links_per_page:
                    break
                normalized = _normalize_path(self.base_url, link)
                if normalized and normalized not in seen:
                    _push(normalized)
                    added += 1
        return report

    def _crawl_one(self, path: str, labels: List[str],
                   report: CrawlReport) -> CrawlPage:
        page = CrawlPage(path=path)
        html = ""
        for label in labels:
            report.requests += 1
            status, body, headers = self._fetch(path, label)
            if status == 0:
                report.transport_errors += 1
            page.status_by_label[label] = status
            if self.session_store is not None and label != "anon":
                self.session_store.observe_response(
                    label, path.split("?", 1)[0], method="GET",
                    status=status, body=body[:20000])
            if status == 200 and not page.forms:
                ctype = headers.get("content-type", "")
                if "html" in ctype.lower() or body.lstrip()[:1] == "<":
                    html, page.content_type = body, ctype
        if html:
            facts = _HtmlFacts()
            try:
                facts.feed(html)
            except Exception:  # noqa: BLE001 - malformed HTML is still a page
                pass
            page.title = facts.title[:200]
            page.links = facts.links[:50]
            page.forms = facts.forms[:10]
        return page

    # -- artifacts -----------------------------------------------------------------

    def persist(self, report: CrawlReport) -> Dict[str, str]:
        """Write the access matrix + page records; returns artifact paths."""
        out_dir = runtime_path("state", "orchestrator", self.mission_id,
                               "crawl", root=self.project_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        matrix_path = out_dir / "access_matrix.json"
        matrix_path.write_text(json.dumps({
            "schema": SCHEMA,
            "base_url": self.base_url,
            "labels": report.labels,
            "access_matrix": report.access_matrix,
            "differential_paths": report.differential_paths(),
        }, indent=2), encoding="utf-8")
        pages_path = out_dir / "pages.jsonl"
        with pages_path.open("w", encoding="utf-8") as fh:
            for page in report.pages.values():
                fh.write(json.dumps(page.to_dict()) + "\n")
        return {"access_matrix": str(matrix_path), "pages": str(pages_path)}
