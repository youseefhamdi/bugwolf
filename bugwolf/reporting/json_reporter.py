# bugwolf/reporting — unified report generators
# SCHEMA: bugwolf-reporting-json-v1
# ## Source: original work for Phase 5.2
# ## License: BugWolf internal
# ## Capability tier: C0 (read-only — generates reports from findings)

from __future__ import annotations

SCHEMA = "bugwolf-reporting-json-v1"

import json
import os
from collections import Counter
from typing import Optional

from .types import (
    Severity,
    finding_to_dict,
    finding_from_dict,
)

JSON_SCHEMA_VERSION = "bugwolf-report-v1"


def _severity_name(value) -> str:
    if isinstance(value, Severity):
        return value.value
    if value is None:
        return "info"
    return str(value).lower()


def _normalize(findings):
    out = []
    for f in findings or []:
        if f is None:
            continue
        if isinstance(f, dict):
            try:
                out.append(finding_from_dict(f))
            except Exception:
                continue
        else:
            out.append(f)
    return out


def _stats(findings):
    by_sev = Counter({s.value: 0 for s in Severity})
    by_class = Counter()
    by_target = Counter()
    conf_sum = 0.0
    cvss_sum = 0.0
    cvss_n = 0
    for f in findings:
        sev = _severity_name(getattr(f, "severity", "info"))
        by_sev[sev] += 1
        cls = getattr(f, "finding_class", "") or "uncategorized"
        by_class[cls] += 1
        tgt = getattr(f, "target", "N/A") or "N/A"
        by_target[tgt] += 1
        conf_sum += float(getattr(f, "confidence", 0.0) or 0.0)
        cvss = getattr(f, "cvss_score", None)
        if cvss is not None:
            try:
                cvss_sum += float(cvss)
                cvss_n += 1
            except (TypeError, ValueError):
                pass
    total = len(findings)
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


def render(findings, *, metadata=None):
    normalized = _normalize(findings)
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "metadata": metadata or {},
        "stats": _stats(normalized),
        "findings": [finding_to_dict(f) for f in normalized],
    }
    return json.dumps(payload, indent=2, sort_keys=False, default=str)


def write(findings, path, *, metadata=None):
    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        data = render(findings, metadata=metadata)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(data)
        return True
    except Exception:
        return False
