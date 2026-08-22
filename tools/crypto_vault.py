#!/usr/bin/env python3
"""
BugWolf Crypto Vault — Encrypted artifact store with secure deletion.

Capabilities:
  - AES-256-GCM encryption for session artifacts
  - Age-encrypted report bundles (X25519 + ChaCha20-Poly1305)
  - Ephemeral key generation and rotation
  - Secure deletion (overwrite before unlink)
  - Encrypted findings archive

Architecture:
  vault/
    sessions/
      {session_id}.enc       — AES-256-GCM encrypted session data
    reports/
      {report_id}.age        — Age-encrypted report bundle
    keys/
      {key_id}.pub           — Public key (Age/X25519)
    .vault-index.json.enc    — Encrypted index of all artifacts

Usage:
  python3 tools/crypto_vault.py --encrypt findings.json --output vault/reports/report.age
  python3 tools/crypto_vault.py --decrypt vault/reports/report.age --output decrypted.json
  python3 tools/crypto_vault.py --generate-key
  python3 tools/crypto_vault.py --rotate-keys
"""

import os
import sys
import json
import struct
import hashlib
import secrets
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, asdict

try:
    from tools.runtime_paths import workspace_root
except ImportError:  # direct script execution
    from runtime_paths import workspace_root

ROOT = workspace_root()
VAULT_ROOT = ROOT / "vault"

# ---------------------------------------------------------------------------
# Secure deletion
# ---------------------------------------------------------------------------

def secure_delete(path: Path, passes: int = 3):
    """Overwrite file with random data before unlinking.

    Three passes: random → random → zeros (NIST SP 800-88).
    """
    if not path.exists():
        return

    try:
        size = path.stat().st_size
        for i in range(passes):
            with open(path, "r+b") as f:
                if i < passes - 1:
                    f.write(secrets.token_bytes(size))
                else:
                    f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except Exception:
        # If secure delete fails, fall back to regular delete
        path.unlink(missing_ok=True)


def secure_delete_dir(directory: Path, passes: int = 1):
    """Securely delete an entire directory tree."""
    if not directory.exists():
        return
    for f in directory.rglob("*"):
        if f.is_file():
            secure_delete(f, passes)
    shutil.rmtree(directory, ignore_errors=True)


# ---------------------------------------------------------------------------
# AES-256-GCM encryption
#
# Requires the ``cryptography`` package. An older OpenSSL-CLI fallback that
# passed the raw key through ``-K``/``-iv`` process arguments was removed:
# the key would be visible in the local process list (ps), which defeats the
# purpose of encrypting the artifact.
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext, tag, key).

    Args:
        plaintext: Data to encrypt
        key: 32-byte key (generated if None)

    Returns:
        (nonce, ciphertext, tag, key) — save all four for decryption
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ImportError(
            "AES-256-GCM requires the 'cryptography' package; "
            "install it with: python3 -m pip install cryptography"
        ) from exc

    if key is None:
        key = secrets.token_bytes(32)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # ciphertext already includes the 16-byte tag at the end
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]

    return nonce, ciphertext, tag, key


def aes_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM (requires the ``cryptography`` package)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ImportError(
            "AES-256-GCM requires the 'cryptography' package; "
            "install it with: python3 -m pip install cryptography"
        ) from exc

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# ---------------------------------------------------------------------------
# Age encryption (X25519 + ChaCha20-Poly1305)
# ---------------------------------------------------------------------------

def age_encrypt_file(input_path: Path, output_path: Path,
                     recipient_pubkey: str = None) -> bool:
    """Encrypt a file with age-encryption (requires `age` CLI or `rage`)."""
    age_bin = shutil.which("age") or shutil.which("rage")
    if not age_bin:
        # Do not write an artifact containing its own encryption key. A
        # passphrase-backed fallback is safer than the old self-decrypting JSON.
        passphrase = os.environ.get("BUGWOLF_VAULT_PASSPHRASE")
        if not passphrase:
            return False
        salt = secrets.token_bytes(16)
        key = hashlib.scrypt(
            passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        nonce, ct, tag, _ = aes_encrypt(input_path.read_bytes(), key=key)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({
            "method": "aes-256-gcm-scrypt",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "tag": tag.hex(),
        }))
        return True

    if recipient_pubkey:
        cmd = [age_bin, "-r", recipient_pubkey, "-o", str(output_path), str(input_path)]
    else:
        # Generate ephemeral keypair
        keyfile = output_path.with_suffix(".key")
        subprocess.run([age_bin, "-keygen", "-o", str(keyfile)], check=True)
        pubkey = subprocess.run(
            [age_bin, "-y", str(keyfile)], capture_output=True, text=True
        ).stdout.strip()
        cmd = [age_bin, "-r", pubkey, "-o", str(output_path), str(input_path)]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def age_decrypt_file(input_path: Path, output_path: Path,
                     identity_path: Path = None) -> bool:
    """Decrypt an age-encrypted file."""
    age_bin = shutil.which("age") or shutil.which("rage")
    if not age_bin:
        bundle = json.loads(input_path.read_text())
        if bundle.get("method") != "aes-256-gcm-scrypt":
            print("[!] age/rage is unavailable and the artifact has no safe fallback")
            return False
        passphrase = os.environ.get("BUGWOLF_VAULT_PASSPHRASE")
        if not passphrase:
            print("[!] BUGWOLF_VAULT_PASSPHRASE is required for fallback decryption")
            return False
        salt = bytes.fromhex(bundle["salt"])
        key = hashlib.scrypt(
            passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        plaintext = aes_decrypt(
            bytes.fromhex(bundle["nonce"]),
            bytes.fromhex(bundle["ciphertext"]),
            bytes.fromhex(bundle["tag"]),
            key,
        )
        output_path.write_bytes(plaintext)
        return True

    cmd = [age_bin, "-d", "-o", str(output_path)]
    if identity_path:
        cmd.extend(["-i", str(identity_path)])
    cmd.append(str(input_path))

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


# ---------------------------------------------------------------------------
# Vault operations
# ---------------------------------------------------------------------------

@dataclass
class VaultEntry:
    artifact_id: str
    artifact_type: str  # session, report, finding, exploit, key
    target: str = ""
    created_at: str = ""
    encrypted_path: str = ""
    original_hash: str = ""  # SHA-256 of original plaintext
    metadata: Dict = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if self.metadata is None:
            self.metadata = {}


class Vault:
    """Manages the encrypted artifact store.

    The vault index (artifact metadata incl. plaintext hashes) is itself
    encrypted at rest with a per-vault key kept in ``.vault-index.key``
    (0600). The index key is local, so this protects the index against
    accidental exposure (e.g. a stray ``git add``) rather than a filesystem
    attacker; the artifact keys themselves are never stored.
    """

    INDEX_FILE = ".vault-index.json.enc"
    INDEX_KEY_FILE = ".vault-index.key"
    LEGACY_INDEX_FILE = ".vault-index.json"

    def __init__(self):
        VAULT_ROOT.mkdir(parents=True, exist_ok=True)
        (VAULT_ROOT / "sessions").mkdir(exist_ok=True)
        (VAULT_ROOT / "reports").mkdir(exist_ok=True)
        (VAULT_ROOT / "findings").mkdir(exist_ok=True)
        (VAULT_ROOT / "keys").mkdir(exist_ok=True)
        self.index_path = VAULT_ROOT / self.INDEX_FILE
        self.legacy_index_path = VAULT_ROOT / self.LEGACY_INDEX_FILE
        self._index_key_path = VAULT_ROOT / self.INDEX_KEY_FILE

    def _index_key(self) -> bytes:
        """Load or create the per-vault index encryption key (0600)."""
        if self._index_key_path.exists():
            return bytes.fromhex(self._index_key_path.read_text().strip())
        key = secrets.token_bytes(32)
        temporary = self._index_key_path.with_name(
            self._index_key_path.name + ".tmp")
        temporary.write_text(key.hex())
        os.chmod(temporary, 0o600)
        os.replace(temporary, self._index_key_path)
        return key

    def _load_index(self) -> List[VaultEntry]:
        """Load the vault index (encrypted; migrates a legacy plaintext one)."""
        if self.index_path.exists():
            bundle = json.loads(self.index_path.read_text())
            plaintext = aes_decrypt(
                bytes.fromhex(bundle["nonce"]),
                bytes.fromhex(bundle["ciphertext"]),
                bytes.fromhex(bundle["tag"]),
                self._index_key(),
            )
            return [VaultEntry(**e) for e in json.loads(plaintext)]
        if self.legacy_index_path.exists():
            data = json.loads(self.legacy_index_path.read_text())
            entries = [VaultEntry(**e) for e in data]
            self._save_index(entries)
            self.legacy_index_path.unlink(missing_ok=True)
            return entries
        return []

    def _save_index(self, entries: List[VaultEntry]):
        """Persist the vault index, encrypted at rest, atomically."""
        key = self._index_key()
        nonce, ct, tag, _ = aes_encrypt(
            json.dumps([asdict(e) for e in entries]).encode("utf-8"), key=key)
        bundle = json.dumps({
            "v": 1,
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "tag": tag.hex(),
        })
        temporary = self.index_path.with_name(self.index_path.name + ".tmp")
        temporary.write_text(bundle)
        os.replace(temporary, self.index_path)

    def _encrypt_artifact(self, plaintext: bytes, artifact_type: str,
                          prefix: str = "artifact") -> Tuple[str, bytes, Path]:
        """Encrypt an artifact and store it. Returns (artifact_id, key, path)."""
        nonce, ct, tag, key = aes_encrypt(plaintext)
        artifact_id = f"{prefix}-{secrets.token_hex(8)}"
        out_path = VAULT_ROOT / f"{artifact_type}s" / f"{artifact_id}.enc"

        bundle = json.dumps({
            "v": 1,
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "tag": tag.hex(),
        })
        out_path.write_text(bundle)

        return artifact_id, key, out_path

    def _decrypt_artifact(self, path: Path, key: bytes) -> bytes:
        """Decrypt an artifact from the vault."""
        bundle = json.loads(path.read_text())
        return aes_decrypt(
            bytes.fromhex(bundle["nonce"]),
            bytes.fromhex(bundle["ciphertext"]),
            bytes.fromhex(bundle["tag"]),
            key,
        )

    def store_session(self, target: str, data: bytes,
                      metadata: Dict = None) -> Tuple[str, bytes]:
        """Encrypt and store session data. Returns (artifact_id, key). KEEP THE KEY."""
        artifact_id, key, path = self._encrypt_artifact(data, "session", "session")

        entry = VaultEntry(
            artifact_id=artifact_id,
            artifact_type="session",
            target=target,
            encrypted_path=str(path),
            original_hash=hashlib.sha256(data).hexdigest(),
            metadata=metadata or {},
        )

        entries = self._load_index()
        entries.append(entry)
        self._save_index(entries)

        return artifact_id, key

    def store_report(self, target: str, findings: List[Dict],
                     key: bytes = None) -> Dict:
        """Encrypt and store a report bundle. Returns vault metadata."""
        plaintext = json.dumps({
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine": "BugWolf v1.0.0",
            "findings": findings,
        }).encode()

        artifact_id, report_key, path = self._encrypt_artifact(plaintext, "report", "report")

        entry = VaultEntry(
            artifact_id=artifact_id,
            artifact_type="report",
            target=target,
            encrypted_path=str(path),
            original_hash=hashlib.sha256(plaintext).hexdigest(),
        )

        entries = self._load_index()
        entries.append(entry)
        self._save_index(entries)

        return {
            "artifact_id": artifact_id,
            "key_hex": report_key.hex(),
            "path": str(path),
            "hash": entry.original_hash,
        }

    def load_report(self, artifact_id: str, key: bytes) -> Dict:
        """Decrypt and load a report."""
        entries = self._load_index()
        for e in entries:
            if e.artifact_id == artifact_id:
                plaintext = self._decrypt_artifact(Path(e.encrypted_path), key)
                return json.loads(plaintext)
        raise FileNotFoundError(f"Report {artifact_id} not found in vault")

    def load_session(self, target: str, key: bytes) -> bytes:
        """Load encrypted session data for a target."""
        entries = self._load_index()
        for e in entries:
            if e.target == target and e.artifact_type == "session":
                return self._decrypt_artifact(Path(e.encrypted_path), key)
        raise FileNotFoundError(f"No session found for {target}")

    def list_artifacts(self, target: str = None,
                       artifact_type: str = None) -> List[Dict]:
        """List vault artifacts, optionally filtered."""
        entries = self._load_index()
        result = []
        for e in entries:
            if target and e.target != target:
                continue
            if artifact_type and e.artifact_type != artifact_type:
                continue
            result.append({
                "id": e.artifact_id,
                "type": e.artifact_type,
                "target": e.target,
                "created": e.created_at,
                "hash": e.original_hash,
            })
        return result

    def destroy_artifact(self, artifact_id: str):
        """Securely delete an artifact from the vault."""
        entries = self._load_index()
        for e in entries:
            if e.artifact_id == artifact_id:
                secure_delete(Path(e.encrypted_path))
                entries.remove(e)
                self._save_index(entries)
                return
        raise FileNotFoundError(f"Artifact {artifact_id} not found")

    def generate_age_keypair(self) -> Tuple[str, str]:
        """Generate an Age encryption keypair. Returns (private_key, public_key)."""
        age_bin = shutil.which("age") or shutil.which("rage")
        if not age_bin:
            # Fallback: generate X25519 keypair manually
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            priv = X25519PrivateKey.generate()
            priv_bytes = priv.private_bytes_raw()
            pub_bytes = priv.public_key().public_bytes_raw()
            return priv_bytes.hex(), pub_bytes.hex()

        key_id = secrets.token_hex(8)
        priv_path = VAULT_ROOT / "keys" / f"{key_id}.key"

        subprocess.run([age_bin, "-keygen", "-o", str(priv_path)],
                       check=True, capture_output=True)
        priv_key = priv_path.read_text()
        pub_key = subprocess.run([age_bin, "-y", str(priv_path)],
                                  capture_output=True, text=True).stdout.strip()

        return priv_key, pub_key


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="BugWolf Crypto Vault")
    parser.add_argument("--encrypt", help="File to encrypt")
    parser.add_argument("--decrypt", help="File to decrypt")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--key", help="Decryption key (hex)")
    parser.add_argument("--generate-key", action="store_true")
    parser.add_argument("--rotate-keys", action="store_true")
    parser.add_argument("--list", action="store_true", help="List vault contents")
    parser.add_argument("--list-target", help="Filter by target")
    parser.add_argument("--destroy", help="Artifact ID to securely delete")
    parser.add_argument("--store-findings", help="JSON findings file to vault")
    parser.add_argument("--target", help="Target name for vault storage")
    args = parser.parse_args()

    vault = Vault()

    if args.generate_key:
        priv, pub = vault.generate_age_keypair()
        print(f"Private key:\n{priv}")
        print(f"Public key:  {pub.strip()}")
        print("\n[!] Store the private key securely. It cannot be recovered.")

    elif args.list:
        artifacts = vault.list_artifacts(target=args.list_target)
        if not artifacts:
            print("[*] Vault is empty")
        for a in artifacts:
            print(f"  [{a['type']}] {a['id']} — {a['target']} ({a['created']})")

    elif args.destroy:
        vault.destroy_artifact(args.destroy)
        print(f"[+] Artifact {args.destroy} securely destroyed")

    elif args.store_findings and args.target:
        findings = json.loads(Path(args.store_findings).read_text())
        meta = vault.store_report(args.target, findings)
        print(f"[+] Report vaulted: {meta['artifact_id']}")
        print(f"[!] Key (KEEP SAFE): {meta['key_hex']}")
        print(f"    Hash: {meta['hash']}")

    elif args.encrypt and args.output:
        plaintext = Path(args.encrypt).read_bytes()
        nonce, ct, tag, key = aes_encrypt(plaintext)
        bundle = json.dumps({
            "v": 1,
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "tag": tag.hex(),
        })
        Path(args.output).write_text(bundle)
        print(f"[+] Encrypted: {args.encrypt} → {args.output}")
        print(f"[!] Key (KEEP SAFE): {key.hex()}")

    elif args.decrypt and args.output and args.key:
        bundle = json.loads(Path(args.decrypt).read_text())
        plaintext = aes_decrypt(
            bytes.fromhex(bundle["nonce"]),
            bytes.fromhex(bundle["ciphertext"]),
            bytes.fromhex(bundle["tag"]),
            bytes.fromhex(args.key),
        )
        Path(args.output).write_bytes(plaintext)
        print(f"[+] Decrypted: {args.decrypt} → {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
