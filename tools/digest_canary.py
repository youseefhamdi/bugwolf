#!/usr/bin/env python3
"""Model/data digest verification and canary leakage checks.

Provides deterministic digests for model adapters and datasets, plus a
canary-secret generator and output leakage detector for lab fixtures.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, Iterable, List, Optional


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def model_digest(model_name: str, version: str, *, adapter: str = "",
                 config: Optional[Dict[str, Any]] = None) -> str:
    """Stable digest of a model identity + adapter + configuration."""
    payload = json.dumps({
        "model_name": str(model_name), "version": str(version),
        "adapter": str(adapter), "config": config or {},
    }, sort_keys=True)
    return "model:" + _sha256(payload)[:24]


def dataset_digest(name: str, items: Iterable[str], *, version: str = "") -> str:
    """Stable digest of a dataset's content and provenance."""
    content_hash = _sha256("\n".join(sorted(set(items))))
    return f"dataset:{str(name)}:{version or 'unversioned'}:{content_hash[:16]}"


def canary_secret(label: str) -> str:
    """Generate a unique labeled canary secret for leakage tests."""
    return f"BW-CANARY-{str(label)[:24]}-{uuid.uuid4().hex[:12]}"


def check_output_leakage(output: str, canaries: Iterable[str]) -> Dict[str, Any]:
    """Return whether any canary secret appears in the output."""
    text = str(output or "")
    leaked = [c for c in set(canaries) if c and c in text]
    return {"leaked": bool(leaked), "leaked_canaries": sorted(leaked),
            "output_length": len(text)}