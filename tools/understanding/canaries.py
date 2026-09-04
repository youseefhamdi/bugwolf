#!/usr/bin/env python3
"""Injection canaries (INTEGRATION_PLAN Phase D, v1.27).

Doctrine (stated in the plan, enforced here): **target content is data
with provenance, never instruction.**  The U-layer fetches untrusted
target pages into the model store; a malicious target can embed
instruction-forgery ("ignore previous instructions..."), fake system
prompts, or exfiltration lures in its pages.  The deterministic engines
structurally read that content as strings to extract from — this module
DETECTS the attempt and records it as a fact, so:

  * the attempt itself becomes hunting evidence (a target that
    injection-baits its pages is telling on itself);
  * affected stage assumptions lose a bounded slice of confidence;
  * the Hunting Brief can surface the attempt to the operator.

Threat-model source: ECC the-security-guide (Feb-2026 Claude Code CVEs,
lethal-trifecta framing) — verified against bugwolf's actual intake
(``_fetch_pages`` -> ``pages`` -> U1/U2/U6 extraction).

Deterministic, stdlib-only, fail-open: detection is pure string pattern
work over content bugwolf already holds.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

SCHEMA = "bugwolf-canaries/v1"

# Confidence reduction applied to affected-stage assumptions when an
# injection attempt is detected in their intake content.  BOUNDED: one
# detection never zeroes a stage's work.
ASSUMPTION_CONFIDENCE_PENALTY = 0.2

# Detectors: (pattern_kind, compiled regex).  Ordered by specificity;
# each match is reported once per page per kind.
_DETECTORS = (
    ("instruction-forgery", re.compile(
        r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+"
        r"(instructions|prompts?|rules?)", re.IGNORECASE)),
    ("instruction-forgery", re.compile(
        r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+"
        r"(instructions|prompts?|rules?)", re.IGNORECASE)),
    ("fake-system-prompt", re.compile(
        r"(system\s*prompt|system\s*message)\s*[:：]", re.IGNORECASE)),
    ("fake-system-prompt", re.compile(
        r"\[\s*system\s*\]|<\|system\|>|###\s*system\s*:", re.IGNORECASE)),
    ("agent-targeting", re.compile(
        r"\b(ai|llm|agent|assistant|claude|gpt|chatgpt|copilot)\b\s*"
        r"(,|:)?\s*(you\s+are|please\s+note|important)[:：]", re.IGNORECASE)),
    ("exfil-lure", re.compile(
        r"(send|post|forward|exfiltrate|upload)\s+.{0,60}"
        r"(findings?|results?|data|credentials?|tokens?|api\s*keys?)\s+"
        r"(to|at)\s+(https?://|ftp://)", re.IGNORECASE)),
    ("exfil-lure", re.compile(
        r"(https?://[^\s\"'<>]{4,120})\s*[-—–]?\s*"
        r"(send|post).{0,30}(here|now|immediately|secretly)",
        re.IGNORECASE)),
    ("hidden-instruction", re.compile(
        r"<span[^>]*style\s*=\s*[\"'][^\"']*(display\s*:\s*none|"
        r"visibility\s*:\s*hidden|font-size\s*:\s*0)", re.IGNORECASE)),
    ("hidden-instruction", re.compile(
        r"<!--[^>]{10,400}?-->\s*(ignore|disregard|send|post)",
        re.IGNORECASE | re.DOTALL)),
)


def scan_pages(pages: Dict[str, str]) -> List[Dict[str, Any]]:
    """Scan fetched page bodies for injection attempts.

    ``pages`` maps path -> body text (the U-layer's own intake shape).
    Returns one fact per (path, kind) match:

        {"schema": ..., "path": "/pricing", "kind": "instruction-forgery",
         "excerpt": "...<=120 chars...", "attempt": True}
    """
    facts: List[Dict[str, Any]] = []
    for path in sorted(pages or {}):
        body = pages.get(path) or ""
        if not isinstance(body, str) or not body:
            continue
        seen: set = set()
        for kind, pattern in _DETECTORS:
            if kind in seen:
                continue
            match = pattern.search(body)
            if match:
                seen.add(kind)
                start = max(0, match.start() - 40)
                excerpt = " ".join(body[start:match.end() + 80].split())
                facts.append({
                    "schema": SCHEMA,
                    "path": path,
                    "kind": kind,
                    "excerpt": excerpt[:120],
                    "attempt": True,
                })
    return facts


def scan_stage_data(stage: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan a stage's persisted data for intake-sourced attempts.

    The pipeline calls this AFTER each content-consuming stage (U1/U2/U6)
    over the stage's own evidence fields, so the fact lands in the model
    store beside the stage that ingested the poisoned page.
    """
    pages: Dict[str, str] = {}
    if not isinstance(data, dict):
        return []
    for key, value in data.items():
        if isinstance(value, str) and len(value) > 40:
            pages[key] = value
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    for sub, subv in item.items():
                        if isinstance(subv, str) and len(subv) > 40:
                            pages[f"{key}[{i}].{sub}"] = subv
                elif isinstance(item, str) and len(item) > 40:
                    pages[f"{key}[{i}]"] = item
    facts = scan_pages(pages)
    for fact in facts:
        fact["stage"] = stage
    return facts


def apply_confidence_penalty(assumptions: List[Dict[str, Any]],
                             attempts: int) -> int:
    """Reduce open-assumption confidence by the bounded penalty.

    Mutates in place (the pipeline's assumption list); returns the number
    of assumptions adjusted.  Confidence floors at 0.05 (the chain
    predictor's own floor): one detection nudges, it never zeroes.
    """
    if attempts <= 0:
        return 0
    adjusted = 0
    for assumption in assumptions or []:
        if not isinstance(assumption, dict):
            continue
        if assumption.get("status") not in (None, "", "open"):
            continue
        try:
            confidence = float(assumption.get("confidence", 0.4))
        except (TypeError, ValueError):
            continue
        new = max(0.05, round(confidence - ASSUMPTION_CONFIDENCE_PENALTY, 3))
        if new != confidence:
            assumption["confidence"] = new
            assumption["canary_adjusted"] = True
            adjusted += 1
    return adjusted
