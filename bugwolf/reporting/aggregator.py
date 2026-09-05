# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-aggregator-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-aggregator-v1"

import hashlib
import json
import os
from collections import Counter
from typing import Any, Iterable, List, Optional

from .types import Finding, Severity, finding_from_dict


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _coerce(item: Any) -> Finding:
    if isinstance(item, Finding):
        return item
    if isinstance(item, dict):
        return finding_from_dict(item)
    raise TypeError(f"Cannot coerce {type(item).__name__} to Finding")


def _dedupe_key(f: Finding):
    target = (f.target or "N/A").strip().lower()
    evidence = (f.evidence or "")[:100].strip().lower()
    return (target, evidence)


def aggregate(*sources: Iterable[Any]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for source in sources:
        if source is None:
            continue
        for item in source:
            try:
                f = _coerce(item)
            except (TypeError, ValueError):
                continue
            key = _dedupe_key(f)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    out.sort(
        key=lambda f: (
            -(float(f.cvss_score) if f.cvss_score is not None else 0.0),
            -_SEVERITY_RANK.get(
                f.severity if isinstance(f.severity, Severity) else Severity.from_any(f.severity),
                0,
            ),
        )
    )
    return out


def aggregate_from_files(*paths: str) -> List[Finding]:
    findings: List[Finding] = []
    for path in paths:
        if not path:
            continue
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        items = []
        if isinstance(data, dict):
            items = data.get("findings") or data.get("results") or []
        elif isinstance(data, list):
            items = data
        for item in items or []:
            try:
                findings.append(_coerce(item))
            except (TypeError, ValueError):
                continue
    return aggregate(findings)


def stats(findings: List[Any]) -> dict:
    by_sev = Counter({s.value: 0 for s in Severity})
    by_class = Counter()
    by_target = Counter()
    conf_sum = 0.0
    cvss_sum = 0.0
    cvss_n = 0
    norm = []
    for f in findings or []:
        try:
            norm.append(_coerce(f))
        except (TypeError, ValueError):
            continue
    for f in norm:
        sev = f.severity if isinstance(f.severity, Severity) else Severity.from_any(f.severity)
        by_sev[sev.value] += 1
        cls = getattr(f, "finding_class", "") or "uncategorized"
        by_class[cls] += 1
        by_target[f.target or "N/A"] += 1
        conf_sum += float(f.confidence or 0.0)
        if f.cvss_score is not None:
            try:
                cvss_sum += float(f.cvss_score)
                cvss_n += 1
            except (TypeError, ValueError):
                pass
    total = len(norm)
    avg_conf = (conf_sum / total) if total else 0.0
    avg_cvss = (cvss_sum / cvss_n) if cvss_n else 0.0
    return {
        "total": total,
        "by_severity": dict(by_sev),
        "by_class": dict(by_class),
        "by_target": dict(by_target),
        "avg_confidence": round(avg_conf, 4),
        "avg_cvss": round(avg_cvss, 3),
    }


def dedupe_hash(target: str, evidence: str) -> str:
    h = hashlib.sha256()
    h.update((target or "N/A").encode("utf-8"))
    h.update(b"\x00")
    h.update((evidence or "")[:100].encode("utf-8"))
    return h.hexdigest()
