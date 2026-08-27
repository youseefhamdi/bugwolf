#!/usr/bin/env python3
"""Claude Code entrypoint for supplied-asset, four-domain research."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.lab_runtime_adapters import diagnostics
from tools.research_model import Surface
from tools.zero_day import ZeroDayResearchEngine

DOMAINS = {
    "web": Surface.WEB_API,
    "web_api": Surface.WEB_API,
    "web3": Surface.SMART_CONTRACT,
    "mobile": Surface.MOBILE_BINARY,
    "ai": Surface.LLM_AGENTIC,
    "cloud": Surface.CLOUD_CICD,
}


def analyze_file(target: str, domain: str, path: str) -> Dict[str, Any]:
    if domain not in DOMAINS:
        raise ValueError(f"unsupported domain: {domain}")
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"asset not found: {path}")
    engine = ZeroDayResearchEngine(target)
    surface = DOMAINS[domain]
    if surface == Surface.MOBILE_BINARY:
        candidates = engine.analyze_binary(source.read_bytes(), str(source))
    else:
        candidates = engine.analyze_text(surface, source.read_text(encoding="utf-8", errors="replace"), str(source))
    registered = engine.register(candidates)
    ranked = engine.prioritize(registered)
    return {
        "schema": "bugwolf/claude-workflow/v1",
        "target": target,
        "domain": surface.value,
        "asset": str(source),
        "candidates": [candidate.to_dict() for candidate in ranked],
        "runtime_diagnostics": diagnostics(),
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--domain", choices=sorted(DOMAINS), required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        result = analyze_file(args.target, args.domain, args.path)
    except (OSError, ValueError) as exc:
        result = {"schema": "bugwolf/claude-workflow/v1", "ok": False, "error": str(exc)}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
