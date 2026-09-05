#!/usr/bin/env python3
"""Release signing and install verification (master plan Phase 6).

Opsec contract:

  * The only thing an operator should ever trust is a hash they verified
    against a signature made with the release key -- never a network fetch
    at session time (the removed "home-beacon" checked raw.githubusercontent
    on every session start, which was both an unsigned trust channel and an
    opsec tripwire).
  * ``build_manifest`` enumerates a built tree/bundle into SHA-256SUMS.
  * ``sign_manifest`` produces a minisign-style detached signature over the
    manifest using the ``MINISIGN_KEY`` secret (Ed25519 via
    ``cryptography``).  No key => the manifest is still produced; the
    signature is honestly reported as absent rather than fabricated.
  * ``verify_manifest`` re-hashes every file and fails closed on any
    mismatch, missing file, or unlisted extra file.
  * ``verify_tree`` is the installed-tree gate for ``harness_guard``: it
    compares the tree against the manifest that shipped with it.

Design rule: every function is pure filesystem + hashing.  Verification
NEVER performs network I/O -- the operator brings the manifest, the
signature, and the public key to the machine that verifies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOG = logging.getLogger(__name__)

try:
    from tools.core.medium_safety import safe_json_loads as _safe_json_loads
except Exception:  # pragma: no cover - tools.* not always importable
    def _safe_json_loads(text, *, default=None, context=""):  # type: ignore[no-redef]
        try:
            import json as _json
            return _json.loads(text)
        except Exception:
            return default

SCHEMA = "bugwolf-release-signing/v1"

# Files that never enter a manifest (local state, caches, build droppings).
SKIP_DIRS = {"__pycache__", ".git", ".bugwolf", "state", "node_modules",
             ".pytest_cache", "dist", "exploits"}
SKIP_SUFFIXES = (".pyc", ".pyo", ".log")

# Where the verify tree looks for the shipped manifest (relative to root).
MANIFEST_NAME = "SHA256SUMS"
SIGNATURE_NAME = "SHA256SUMS.minisig"
PUBLIC_KEY_NAME = "bugwolf_release.pub"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _is_skipped(relative: Path) -> bool:
    if any(part in SKIP_DIRS for part in relative.parts):
        return True
    return relative.suffix.lower() in SKIP_SUFFIXES


def build_manifest(root: str | Path, *,
                   extra_files: Iterable[str | Path] = ()) -> Dict[str, Any]:
    """Enumerate ``root`` into a SHA-256 manifest (deterministic order).

    ``extra_files`` are appended as (name, sha256) pairs for artifacts that
    live outside the tree (release bundles in ``dist/``).
    """
    root_path = Path(root).resolve()
    entries: List[Dict[str, str]] = []
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root_path)
        if _is_skipped(relative):
            continue
        entries.append({
            "path": str(relative),
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        })
    for extra in extra_files:
        extra_path = Path(extra)
        entries.append({
            "path": extra_path.name,
            "sha256": _sha256_file(extra_path),
            "size": extra_path.stat().st_size,
        })
    return {
        "schema": SCHEMA,
        "algorithm": "sha256",
        "created_at": _now(),
        "root": str(root_path),
        "file_count": len(entries),
        "files": entries,
    }


def manifest_bytes(manifest: Dict[str, Any]) -> bytes:
    """The exact bytes that get signed (stable JSON, sorted keys)."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def write_manifest(manifest: Dict[str, Any], out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / MANIFEST_NAME
    path.write_bytes(manifest_bytes(manifest))
    return path


def _ed25519_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)  # noqa: F401
        return True
    except Exception as exc:
        LOG.debug("release_signing.ed25519_unavailable: %s", exc)
        return False


def generate_keypair(out_dir: str | Path) -> Dict[str, str]:
    """Generate the release signing keypair (Ed25519). One-time, offline."""
    if not _ed25519_available():
        raise RuntimeError(
            "the 'cryptography' package is required to generate a release "
            "keypair (pip install cryptography)")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    secret = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    secret_path = out / "bugwolf_release.key"
    public_path = out / PUBLIC_KEY_NAME
    secret_path.write_bytes(secret)
    public_path.write_bytes(public)
    return {"secret_key": str(secret_path), "public_key": str(public_path)}


def sign_bytes(data: bytes, secret_key: str | Path) -> Dict[str, Any]:
    """Sign arbitrary bytes with the release secret key (Ed25519)."""
    if not _ed25519_available():
        return {
            "schema": SCHEMA, "signed": False,
            "reason": "the 'cryptography' package is not installed",
        }
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    key_bytes = Path(secret_key).read_bytes()
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        return {"schema": SCHEMA, "signed": False,
                "reason": "secret key is not an Ed25519 key"}
    signature = key.sign(data)
    return {
        "schema": SCHEMA,
        "signed": True,
        "algorithm": "ed25519",
        "signed_at": _now(),
        # Standard minisign-style armor so `minisign -V`-style tooling can
        # recognize the artifact shape.
        "signature": (
            "untrusted comment: bugwolf release signature\n"
            + signature.hex() + "\n"),
    }


def sign_manifest(manifest: Dict[str, Any], secret_key: str | Path) -> Dict[str, Any]:
    """Sign the manifest bytes with the release secret key (Ed25519)."""
    return sign_bytes(manifest_bytes(manifest), secret_key)


def write_signature(signature: Dict[str, Any], out_dir: str | Path) -> Optional[Path]:
    if not signature.get("signed"):
        return None
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / SIGNATURE_NAME
    path.write_text(signature["signature"], encoding="utf-8")
    return path


def verify_manifest(root: str | Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Re-hash the tree against the manifest. Fail closed on any drift.

    Fails on: mismatched hash, missing file, and unlisted files (an extra
    file is exactly how a backdoor rides in with a clean manifest).
    """
    root_path = Path(root).resolve()
    errors: List[str] = []
    listed: Dict[str, Dict[str, str]] = {}
    for entry in manifest.get("files", []):
        listed[entry["path"]] = entry

    for entry in listed.values():
        path = root_path / entry["path"]
        if not path.is_file():
            errors.append(f"missing: {entry['path']}")
            continue
        actual = _sha256_file(path)
        if actual != entry["sha256"]:
            errors.append(f"hash mismatch: {entry['path']}")

    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        relative = Path(path.relative_to(root_path))
        if _is_skipped(relative):
            continue
        if str(relative) in listed:
            continue
        # The verification artifacts themselves ride along with the tree.
        if relative.name in (MANIFEST_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME):
            continue
        errors.append(f"unlisted file: {relative}")

    return {
        "schema": SCHEMA,
        "root": str(root_path),
        "verified": not errors,
        "file_count": len(listed),
        "errors": errors,
        "checked_at": _now(),
        "network": "not performed",
    }


def verify_bytes(data: bytes, signature_text: str,
                 public_key: str | Path) -> Dict[str, Any]:
    """Verify a detached signature over arbitrary bytes."""
    if not _ed25519_available():
        return {"schema": SCHEMA, "verified": False,
                "reason": "the 'cryptography' package is not installed"}
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = serialization.load_pem_public_key(
            Path(public_key).read_bytes())
    except Exception as exc:
        return {"schema": SCHEMA, "verified": False,
                "reason": f"unreadable public key: {exc}"}
    lines = signature_text.strip().splitlines()
    if len(lines) < 2:
        return {"schema": SCHEMA, "verified": False,
                "reason": "signature file has no signature line"}
    try:
        signature = bytes.fromhex(lines[-1].strip())
    except ValueError:
        return {"schema": SCHEMA, "verified": False,
                "reason": "signature line is not hex"}
    try:
        Ed25519PublicKey.from_public_bytes(pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)).verify(signature, data)
        return {"schema": SCHEMA, "verified": True, "reason": "",
                "algorithm": "ed25519"}
    except Exception as exc:
        LOG.info("release_signing.verify_ed25519_failed: %s", exc)
        return {"schema": SCHEMA, "verified": False,
                "reason": "signature does not match data",
                "algorithm": "ed25519"}


def verify_signature(manifest: Dict[str, Any], signature_text: str,
                     public_key: str | Path) -> Dict[str, Any]:
    """Verify the detached signature over the manifest bytes."""
    return verify_bytes(manifest_bytes(manifest), signature_text, public_key)


def verify_tree(root: str | Path) -> Dict[str, Any]:
    """Verify an INSTALLED tree against its shipped manifest.

    Used by harness_guard: the manifest (and, when present, the signature)
    ship with the tree, so verification is a local, offline operation.
    Missing manifest => fail closed with the honest reason.
    """
    root_path = Path(root).resolve()
    manifest_path = root_path / MANIFEST_NAME
    if not manifest_path.is_file():
        return {
            "schema": SCHEMA, "root": str(root_path), "verified": False,
            "errors": [f"no shipped manifest ({MANIFEST_NAME}) in tree; "
                       "cannot verify install integrity"],
            "checked_at": _now(), "network": "not performed",
        }
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema": SCHEMA, "root": str(root_path), "verified": False,
            "errors": [f"unreadable manifest: {exc}"],
            "checked_at": _now(), "network": "not performed",
        }
    result = verify_manifest(root_path, manifest)

    signature_path = root_path / SIGNATURE_NAME
    public_key_path = root_path / PUBLIC_KEY_NAME
    if signature_path.is_file() and public_key_path.is_file():
        result["signature"] = verify_signature(
            manifest, signature_path.read_text(encoding="utf-8"),
            public_key_path)
        if not result["signature"].get("verified"):
            result["verified"] = False
            result["errors"].append(
                "release signature invalid: "
                + result["signature"].get("reason", "unknown"))
    else:
        result["signature"] = {
            "schema": SCHEMA, "verified": False,
            "reason": "no signature shipped with this tree "
                      "(unsigned release)",
        }
    return result


# ---------------------------------------------------------------------------
# Opt-in update check (the home-beacon replacement; master plan Phase 6)
# ---------------------------------------------------------------------------

def check_update(current_version: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Compare the local version against the latest GitHub RELEASE.

    Rules that make this opsec-safe (vs the removed session-start beacon):

      * **Opt-in only** — exposed exclusively through
        ``/bugwolf-doctor --check-update``; nothing calls this at session
        start, and no silent background fetch exists.
      * **Releases API, not a branch file** — reads tagged release
        metadata over TLS; the answer is only trusted together with the
        release's SHA256SUMS + minisign signature (see ``verify_tree``).
      * **Fail silent, never fail the session** — every error becomes a
        fact in the returned dict; no exception ever propagates.

    Requires ``urllib`` (stdlib).  Returns a fact dict, never raises.
    """
    url = "https://api.github.com/repos/youseefhamdi/bugwolf/releases/latest"
    fact: Dict[str, Any] = {
        "schema": SCHEMA, "check": "update", "opt_in": True,
        "current_version": current_version, "network": "attempted",
        "checked_at": _now(),
    }
    try:
        import urllib.request
        import urllib.error
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "bugwolf-opsec-check",
        })
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        latest = str(payload.get("tag_name", "")).lstrip("v")
        fact["latest_version"] = latest
        fact["update_available"] = bool(
            latest and latest != current_version
            and _version_tuple(latest) > _version_tuple(current_version))
        fact["release_url"] = payload.get("html_url", "")
        fact["network"] = "performed"
    except Exception as exc:  # noqa: BLE001 - fail silent by contract
        fact["network"] = "failed"
        fact["error"] = f"{type(exc).__name__}: {exc}"
        LOG.warning("release_signing.update_check_failed: %s", exc)
    return fact


def _version_tuple(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for chunk in str(version).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="BugWolf release signing / install verification (Phase 6)")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--build-manifest", metavar="ROOT",
                         help="hash a tree into SHA256SUMS JSON")
    actions.add_argument("--sign", nargs=2, metavar=("MANIFEST", "KEY"),
                         help="sign a manifest with the release secret key")
    actions.add_argument("--sign-file", nargs=2, metavar=("FILE", "KEY"),
                         help="sign an arbitrary release file (e.g. SHA256SUMS.txt)")
    actions.add_argument("--verify-file", nargs=3,
                         metavar=("FILE", "SIG", "PUBKEY"),
                         help="verify a signed release file (offline)")
    actions.add_argument("--verify-tree", metavar="ROOT",
                         help="verify an installed tree against its manifest")
    actions.add_argument("--check-update", action="store_true",
                         help="OPT-IN: check the latest GitHub release")
    parser.add_argument("--out", help="output directory for manifest/signature")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.build_manifest:
        manifest = build_manifest(args.build_manifest)
        if args.out:
            write_manifest(manifest, args.out)
        result: Dict[str, Any] = manifest
        status = 0
    elif args.sign:
        manifest = _safe_json_loads(
            Path(args.sign[0]).read_text(encoding="utf-8"),
            default={},
            context="release_signing.sign_manifest")
        result = sign_manifest(manifest, args.sign[1])
        if args.out and result.get("signed"):
            write_signature(result, args.out)
        status = 0 if result.get("signed") else 2
    elif args.sign_file:
        target = Path(args.sign_file[0])
        result = sign_bytes(target.read_bytes(), args.sign_file[1])
        if result.get("signed"):
            out = (Path(args.out) if args.out else target.parent)
            out.mkdir(parents=True, exist_ok=True)
            (out / (target.name + ".minisig")).write_text(
                result["signature"], encoding="utf-8")
        status = 0 if result.get("signed") else 2
    elif args.verify_file:
        target, sig, pub = args.verify_file
        result = verify_bytes(Path(target).read_bytes(),
                              Path(sig).read_text(encoding="utf-8"), pub)
        status = 0 if result.get("verified") else 2
    elif args.verify_tree:
        result = verify_tree(args.verify_tree)
        status = 0 if result["verified"] else 2
    else:
        version = (Path(__file__).resolve().parent.parent / "VERSION")
        current = version.read_text().strip() if version.is_file() else "0.0.0"
        result = check_update(current)
        status = 0

    if args.json:
        _signed_blob = result if isinstance(result, dict) else {"result": result}
        if "signature" in _signed_blob and isinstance(_signed_blob.get("signature"), str):
            display = dict(_signed_blob)
            sig = display["signature"]
            display["signature"] = sig[:6] + "…[REDACTED len=" + str(len(sig)) + "]"
        else:
            display = _signed_blob
        print(json.dumps(display, indent=2, sort_keys=True))
        LOG.debug("release_signing.json: keys=%s",
                  sorted(result.keys()))
    else:
        if "verified" in result:
            print("VERIFIED" if result["verified"] else "FAILED")
            LOG.info("release_signing.verified=%s errors=%d",
                     result["verified"], len(result.get("errors", [])))
            for error in result.get("errors", []):
                print(f"  ERROR: {error}")
                LOG.warning("release_signing.error: %s", error)
        elif result.get("signed") is not None:
            print("SIGNED" if result.get("signed") else "NOT SIGNED",
                  result.get("reason", ""))
            LOG.info("release_signing.signed=%s reason=%s",
                     result.get("signed"), result.get("reason", ""))
        elif "files" in result:
            print(f"manifest: {result['file_count']} files")
            LOG.info("release_signing.manifest files=%d",
                     result['file_count'])
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
            LOG.debug("release_signing.result: keys=%s",
                      sorted(result.keys()))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
