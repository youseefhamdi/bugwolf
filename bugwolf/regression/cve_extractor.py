"""Phase 3.4 — CVE extractor for NVD JSON + GitHub Security Advisory markdown.

The :class:`CVEExtractor` parses two wire formats into a frozen
:class:`CVEEntry` dataclass:

  * ``parse_nvd_json`` — the NVD CVE 2.0 REST API response (the same
    shape returned by ``https://services.nvd.nist.gov/rest/json/cves/2.0``).
  * ``parse_ghsa_advisory`` — a GitHub Security Advisory (markdown).
    Real GHSA advisories are rendered as markdown on github.com.

The :meth:`CVEExtractor.match_to_tech_stack` method gives a 0..1
confidence score based on keyword overlap between the CVE description
and a tech-stack keyword list.

STUB-SAFE: any malformed input returns ``[]`` rather than raising.

SCHEMA = "bugwolf-regression-v1"

## Source: derived from internal bug bounty tooling (no public source).
## License: AGPL-3.0-or-later (matches root LICENSE).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


SCHEMA = "bugwolf-regression-v1"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CVEEntry:
    """A single CVE entry.

    Fields are chosen so the entry can round-trip through :func:`dataclasses.asdict`
    and be embedded in a markdown report without further transformation.
    """

    cve_id: str
    description: str
    cvss_score: float
    published_date: str
    affected_products: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# NVD JSON parsing
# ---------------------------------------------------------------------------


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _extract_cvss(metrics: Dict[str, Any]) -> float:
    """Best-effort CVSS score extraction from NVD ``metrics`` block.

    Priority: ``cvssMetricV31[0].cvssData.baseScore`` → ``cvssMetricV30``
    → ``cvssMetricV2``.  Returns ``0.0`` when nothing usable is found.
    """
    if not isinstance(metrics, dict):
        return 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        entries = metrics.get(key) or []
        if entries and isinstance(entries, list):
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    entries = metrics.get("cvssMetricV2") or []
    if entries and isinstance(entries, list):
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    return 0.0


def _extract_affected_products(configurations: Any) -> Tuple[str, ...]:
    """Extract CPE strings from an NVD ``configurations`` array.

    STUB-SAFE: never raises on malformed input.
    """
    out: List[str] = []
    if not isinstance(configurations, list):
        return tuple(out)
    for node in configurations:
        if not isinstance(node, dict):
            continue
        for inner in node.get("nodes", []) or []:
            if not isinstance(inner, dict):
                continue
            for match in inner.get("cpeMatch", []) or []:
                if not isinstance(match, dict):
                    continue
                crit = match.get("criteria")
                if isinstance(crit, str) and crit:
                    out.append(crit)
    # de-dup while preserving order
    seen: set = set()
    deduped: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            deduped.append(x)
    return tuple(deduped)


def _extract_references(refs: Any) -> Tuple[str, ...]:
    """Extract ``url`` fields from an NVD ``references`` array."""
    out: List[str] = []
    if not isinstance(refs, list):
        return tuple(out)
    for ref in refs:
        if isinstance(ref, dict):
            url = ref.get("url")
            if isinstance(url, str) and url:
                out.append(url)
    return tuple(out)


def _extract_description(descriptions: Any) -> str:
    """Pull the first English description out of NVD ``descriptions``."""
    if not isinstance(descriptions, list):
        return ""
    for entry in descriptions:
        if isinstance(entry, dict):
            lang = entry.get("lang", "")
            value = entry.get("value", "")
            if lang.startswith("en") and value:
                return str(value)
    # fallback: first value
    for entry in descriptions:
        if isinstance(entry, dict):
            value = entry.get("value", "")
            if value:
                return str(value)
    return ""


def _parse_nvd_entry(entry: Dict[str, Any]) -> CVEEntry | None:
    """Convert a single NVD ``cve`` dict to a :class:`CVEEntry`.

    Returns ``None`` on any structural problem (caller will filter).
    """
    if not isinstance(entry, dict):
        return None
    cve_id = entry.get("id") or ""
    if not isinstance(cve_id, str) or not _CVE_ID_RE.match(cve_id):
        return None
    return CVEEntry(
        cve_id=cve_id,
        description=_extract_description(entry.get("descriptions", [])),
        cvss_score=_extract_cvss(entry.get("metrics", {})),
        published_date=str(entry.get("published", "") or ""),
        affected_products=_extract_affected_products(entry.get("configurations", [])),
        references=_extract_references(entry.get("references", [])),
    )


# ---------------------------------------------------------------------------
# GHSA markdown parsing
# ---------------------------------------------------------------------------


# Example lines we expect:
#   # CVE-2024-12345
#   **GHSA-xxxx-xxxx-xxxx** — Title...
#   ## Description
#   Some prose paragraph...
#   ## Severity
#   - CVSS: 7.5
#   - Published: 2024-01-02
#   ## Affected products
#   - pkg:generic/nginx@1.0.0
_GHSA_TITLE_RE = re.compile(
    r"^\s*#\s*(CVE-\d{4}-\d{4,7})\b[^\n]*", re.IGNORECASE | re.MULTILINE
)
_GHSA_ALT_TITLE_RE = re.compile(
    r"^\s*#\s*GHSA-([a-z0-9]{4})-([a-z0-9]{4})-([a-z0-9]{4})\b",
    re.IGNORECASE | re.MULTILINE,
)
_GHSA_CVSS_RE = re.compile(
    r"(?im)^\s*[-*]?\s*(?:CVSS(?:\s*Score)?|Severity)\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)"
)
_GHSA_PUBLISHED_RE = re.compile(
    r"(?im)^\s*[-*]?\s*Published(?:\s*Date)?\s*[:=]\s*(\d{4}-\d{2}-\d{2}(?:[T\s][^\n]+)?)"
)
_GHSA_AFFECTED_LINE_RE = re.compile(
    r"(?im)^\s*[-*]\s*((?:pkg|product|cpe):\S+)"
)
_GHSA_DESC_HEADING_RE = re.compile(
    r"(?im)^\s*#+\s*(?:Description|Summary)\s*$\n(.*?)(?:\n\s*#|\Z)"
)
_GHSA_REF_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((https?://[^\s)]+)\)"
)


def _parse_ghsa(markdown: str) -> CVEEntry | None:
    """Parse a single GHSA-style advisory into a :class:`CVEEntry`.

    Returns ``None`` if no CVE / GHSA id can be located.
    """
    if not isinstance(markdown, str) or not markdown.strip():
        return None

    cve_id = ""
    m = _GHSA_TITLE_RE.search(markdown)
    if m:
        cve_id = m.group(1).upper()
    else:
        m2 = _GHSA_ALT_TITLE_RE.search(markdown)
        if m2:
            # GHSA id only — synthesise a placeholder CVE id so the
            # entry still rides through downstream code.  Real systems
            # would join against an id-mapping table.
            cve_id = "GHSA-" + "-".join(m2.groups()).upper()
        else:
            return None

    # Description — first non-heading paragraph after the title
    description = ""
    md = _GHSA_DESC_HEADING_RE.search(markdown)
    if md:
        description = md.group(1).strip()
    if not description:
        # fall back to first non-empty line after the title heading
        lines = [ln.strip() for ln in markdown.splitlines() if ln.strip()]
        for ln in lines[1:]:
            if not ln.startswith("#") and not ln.startswith("|") and len(ln) > 20:
                description = ln
                break

    # CVSS
    cvss_match = _GHSA_CVSS_RE.search(markdown)
    cvss_score = float(cvss_match.group(1)) if cvss_match else 0.0

    # Published date
    pub_match = _GHSA_PUBLISHED_RE.search(markdown)
    published_date = pub_match.group(1).strip() if pub_match else ""

    # Affected products
    affected = tuple(sorted({m.group(1) for m in _GHSA_AFFECTED_LINE_RE.finditer(markdown)}))

    # References — every markdown link whose URL is http(s)
    refs: List[str] = []
    seen: set = set()
    for m in _GHSA_REF_LINK_RE.finditer(markdown):
        url = m.group(2)
        if url not in seen:
            seen.add(url)
            refs.append(url)
    references = tuple(refs)

    return CVEEntry(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        published_date=published_date,
        affected_products=affected,
        references=references,
    )


# ---------------------------------------------------------------------------
# Tech-stack matching
# ---------------------------------------------------------------------------


def _tokenise(s: str) -> set:
    """Lower-cased alphanumeric tokens — used for confidence scoring."""
    if not s:
        return set()
    return {t for t in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{2,}", s.lower()) if t}


class CVEExtractor:
    """Parse NVD JSON + GHSA markdown advisories into :class:`CVEEntry`.

    Pure-stdlib parser.  No third-party deps.

    >>> extractor = CVEExtractor()
    >>> entries = extractor.parse_nvd_json(json_text)
    """

    def parse_nvd_json(self, json_text: str) -> List[CVEEntry]:
        """Parse an NVD REST API response and return a list of CVEs.

        STUB-SAFE: returns ``[]`` on JSON / structural errors.
        """
        try:
            data = json.loads(json_text)
        except Exception:
            return []
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(vulns, list):
            return []
        out: List[CVEEntry] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve = v.get("cve")
            entry = _parse_nvd_entry(cve) if isinstance(cve, dict) else None
            if entry is not None:
                out.append(entry)
        return out

    def parse_ghsa_advisory(self, markdown_text: str) -> List[CVEEntry]:
        """Parse a single GHSA-style advisory into a list of CVEs.

        The list is normally length 0 or 1; multi-CVE blocks are split
        on consecutive ``# CVE-…`` / ``# GHSA-…`` headings.

        STUB-SAFE: returns ``[]`` on any structural problem.
        """
        if not isinstance(markdown_text, str) or not markdown_text.strip():
            return []

        # Split on top-level headings that announce a new advisory
        chunks: List[str] = []
        buf: List[str] = []
        for line in markdown_text.splitlines():
            if re.match(r"^\s*#\s*(CVE-\d{4}-\d{4,7}|GHSA-[A-Za-z0-9-]+)\b", line):
                if buf:
                    chunks.append("\n".join(buf))
                    buf = []
            buf.append(line)
        if buf:
            chunks.append("\n".join(buf))

        out: List[CVEEntry] = []
        for chunk in chunks:
            entry = _parse_ghsa(chunk)
            if entry is not None:
                out.append(entry)
        return out

    def match_to_tech_stack(self, cve: CVEEntry, tech_keywords: List[str]) -> float:
        """Return a 0..1 confidence that a CVE applies to a tech stack.

        Algorithm:
          * combine CVE description + affected_products into a token bag;
          * count how many tech keywords appear in that bag (substring
            match — robust to ``nginx`` vs ``nginx-http`` etc.);
          * confidence = ``matched_keywords / total_keywords``.

        Returns 0.0 when no keywords are provided or the CVE has no text.
        """
        if not tech_keywords:
            return 0.0
        if not isinstance(cve, CVEEntry):
            return 0.0

        haystack = " ".join(
            [cve.description or "", " ".join(cve.affected_products or ())]
        ).lower()

        if not haystack.strip():
            return 0.0

        hits = 0
        for kw in tech_keywords:
            if not isinstance(kw, str) or not kw:
                continue
            if kw.lower() in haystack:
                hits += 1
        # cap to 1.0 — defensive against duplicate tokens
        ratio = hits / max(1, len([k for k in tech_keywords if k]))
        return max(0.0, min(1.0, ratio))


__all__ = [
    "CVEEntry",
    "CVEExtractor",
    "_parse_ghsa",
    "_parse_nvd_entry",
    "_extract_cvss",
    "_tokenise",
]
