"""Prompt-injection scanner with an initial corpus of known attack patterns."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from bugwolf.scanners import Scanner
from bugwolf.scanners.live_finding import LiveFinding


SCHEMA = "bugwolf-scanner-v1"


INJECTION_PATTERNS = (
    {"id": "ignore-previous",
     "label": "Ignore previous instructions",
     "regex": r"ignore (?:all )?previous (?:instructions|prompts)",
     "severity": "critical"},
    {"id": "system-impersonation",
     "label": "System role impersonation",
     "regex": r"(?:^|\n)\s*(?:system|sys)\s*:\s*",
     "severity": "high"},
    {"id": "prompt-leak",
     "label": "Prompt extraction",
     "regex": r"(?:reveal|print|show|repeat)\s+(?:your\s+)?(?:system\s+)?prompt",
     "severity": "high"},
    {"id": "jailbreak-dan",
     "label": "DAN-style jailbreak",
     "regex": r"\byou\s+are\s+now\s+(?:DAN|do\s+anything\s+now)\b",
     "severity": "high"},
    {"id": "instruction-override",
     "label": "Instruction override via delimiter",
     "regex": r"###\s*instruction\s*###|<\s*/?inst\s*>|\[\s*INST\s*\]",
     "severity": "medium"},
    {"id": "base64-payload",
     "label": "Obfuscated base64 payload",
     "regex": r"(?:decode|base64)[^\n]{0,30}(?:[A-Za-z0-9+/]{40,}={0,2})",
     "severity": "high"},
    {"id": "tool-hijack",
     "label": "Tool-call hijack attempt",
     "regex": r"(?:call|invoke)\s+(?:tool|function)\s+[\"']?(?:exec|shell|fs|delete)",
     "severity": "critical"},
    {"id": "policy-override",
     "label": "Policy override keyword",
     "regex": r"override\s+(?:safety|guardrails?|policy|filters?)",
     "severity": "critical"},
)


COMPILED = [(p, re.compile(p["regex"], re.IGNORECASE | re.MULTILINE)) for p in INJECTION_PATTERNS]


def _pid(pat_id: str) -> str:
    return "prompt-inj-" + hashlib.sha256(pat_id.encode()).hexdigest()[:10]


class PromptInjectionScanner(Scanner):
    name = "prompt_injection"
    description = "Detects prompt injection / jailbreak patterns in model inputs"
    bug_class = "prompt_injection"
    default_severity = "high"

    def matches(self, target: Dict[str, Any]) -> bool:
        return "prompt" in target or "input" in target

    def scan(self, target: Dict[str, Any], transport) -> List[LiveFinding]:
        findings: List[LiveFinding] = []
        prompt = str(target.get("prompt") or target.get("input") or "")
        endpoint = target.get("url", target.get("endpoint", ""))
        method = target.get("method", "POST")
        if not prompt:
            return findings
        try:
            resp = transport(method, endpoint,
                             headers={"Content-Type": "application/json"},
                             body=prompt)
        except Exception:
            resp = None
        rbody = (resp.get("body") or "") if isinstance(resp, dict) else ""
        full_blob = prompt + "\n" + rbody
        for meta, regex in COMPILED:
            m = regex.search(full_blob)
            if m:
                findings.append(LiveFinding(
                    scanner=self.name,
                    bug_class=self.bug_class,
                    severity=meta["severity"],
                    endpoint=endpoint,
                    method=method,
                    evidence=f"{meta['label']} (pattern {meta['id']} matched {m.group(0)[:60]!r})",
                    reproducer=f"{method} {endpoint}  body={prompt[:80]!r}",
                    remediation="Strip / escape known injection delimiters; isolate system prompt from user-controlled text; add an injection classifier in front of the model.",
                    payload_id=_pid(meta["id"]),
                    extra={"pattern_id": meta["id"], "match": m.group(0)[:120]},
                ))
        return findings


__all__ = ["PromptInjectionScanner", "INJECTION_PATTERNS"]
