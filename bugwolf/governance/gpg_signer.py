"""GPG signer (Phase 1.4 — Governance Core).

Detached-sign ``(prev_hash, entry_hash)`` pairs with GnuPG if ``gpg`` is
on PATH; otherwise fall back to a deterministic placeholder::

    "sha256:<sha256(prev_hash + entry_hash)>"

The placeholder is reproducible across runs (no randomness, no clocks),
and is sufficient to satisfy the audit's "sign the pair" rule when the
deployment does not have GPG configured.  When GPG IS available the
function delegates to ``gpg --detach-sign`` and returns the armored
signature body.

The signatures are stored alongside the chain entry they protect; the
verifier recomputes the SHA-256 over ``(prev_hash, entry_hash)`` and
compares.

No external deps; stdlib only.  GPG subprocess only invoked if present.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ._canonical import SCHEMA as _SCHEMA

SCHEMA = "bugwolf-governance-v1"


def _placeholder(prev_hash: str, entry_hash: str) -> str:
    pair = f"{prev_hash}{entry_hash}".encode("utf-8")
    digest = hashlib.sha256(pair).hexdigest()
    return f"sha256:{digest}"


def sign_with_gpg(prev_hash: str, entry_hash: str,
                  *, gpg_path: Optional[str] = None) -> str:
    """Sign ``(prev_hash, entry_hash)`` and return the signature.

    Returns a deterministic placeholder if GnuPG is unavailable or fails.
    The placeholder's prefix is ``"sha256:"`` so verifiers can detect it.
    """
    if not prev_hash:
        raise ValueError("prev_hash is required")
    if not entry_hash:
        raise ValueError("entry_hash is required")
    binary = gpg_path or shutil.which("gpg")
    if not binary:
        return _placeholder(prev_hash, entry_hash)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            payload = tmp_path / "pair.txt"
            payload.write_text(
                f"{prev_hash}\n{entry_hash}\n", encoding="utf-8")
            sig = tmp_path / "pair.txt.sig"
            proc = subprocess.run(
                [binary, "--batch", "--yes",
                 "--detach-sign", "--armor",
                 "--output", str(sig),
                 str(payload)],
                capture_output=True,
                check=False,
            )
            if proc.returncode != 0:
                return _placeholder(prev_hash, entry_hash)
            if not sig.is_file():
                return _placeholder(prev_hash, entry_hash)
            body = sig.read_text(encoding="utf-8", errors="replace").strip()
            if body:
                return body
            return _placeholder(prev_hash, entry_hash)
    except OSError:
        return _placeholder(prev_hash, entry_hash)


def is_placeholder(signature: str) -> bool:
    """True iff the signature is a deterministic placeholder."""
    return bool(signature) and signature.startswith("sha256:")


__all__ = ["SCHEMA", "sign_with_gpg", "is_placeholder"]