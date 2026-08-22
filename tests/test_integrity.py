#!/usr/bin/env python3
import json
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.crypto_vault import (
    Vault, aes_decrypt, aes_encrypt, age_decrypt_file, age_encrypt_file,
)
from tools.ledger import LedgerVerifier
from tools.state import (
    _state_dir, add_finding, load_state, log_journal, mark_dead_end,
    mark_tested, rotate_state,
)


class TestJournalIntegrity(unittest.TestCase):
    def setUp(self):
        self.target = "ledger-test-" + uuid.uuid4().hex[:10]
        self.state_dir = _state_dir(self.target)
        shutil.rmtree(self.state_dir, ignore_errors=True)

    def tearDown(self):
        shutil.rmtree(self.state_dir, ignore_errors=True)
        shutil.rmtree(Path("state/ledger") / self.target, ignore_errors=True)

    def test_hash_linked_journal_verifies(self):
        log_journal(self.target, "one", {"value": 1})
        log_journal(self.target, "two", {"value": 2})
        integrity = LedgerVerifier(self.target).check_integrity()
        self.assertTrue(integrity.is_valid)
        self.assertTrue(integrity.hash_chain_intact)
        self.assertEqual(integrity.total_entries, 2)

    def test_tampering_breaks_journal_verification(self):
        log_journal(self.target, "one", {"value": 1})
        journal = self.state_dir / "journal.jsonl"
        entry = json.loads(journal.read_text())
        entry["data"]["value"] = 999
        journal.write_text(json.dumps(entry) + "\n")
        integrity = LedgerVerifier(self.target).check_integrity()
        self.assertFalse(integrity.is_valid)
        self.assertFalse(integrity.hash_chain_intact)

    def test_rotation_preserves_hash_chain_anchor(self):
        for value in range(4):
            log_journal(self.target, f"event-{value}", {"value": value})
        rotate_state(self.target, max_journal_lines=2)
        integrity = LedgerVerifier(self.target).check_integrity()
        self.assertTrue(integrity.is_valid)
        self.assertEqual(integrity.total_entries, 2)

    def test_state_counters_follow_persisted_records(self):
        mark_tested(self.target, "https://example.com/a")
        mark_tested(self.target, "https://example.com/b")
        mark_dead_end(self.target, "https://example.com/c", reason="404")
        add_finding(self.target, {
            "title": "test", "endpoint": "https://example.com/a",
            "bug_class": "test", "method": "GET",
        })
        state = load_state(self.target)
        self.assertEqual(state.endpoints_tested, 2)
        self.assertEqual(state.dead_ends, 1)
        self.assertEqual(state.findings_count, 1)


class TestVaultCrypto(unittest.TestCase):
    def test_aes_requires_cryptography_with_clear_error(self):
        real_import = __import__

        def blocked(name, *args, **kwargs):
            if name.split(".")[0] == "cryptography":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=blocked):
            with self.assertRaises(ImportError) as ctx:
                aes_encrypt(b"data")
        self.assertIn("cryptography", str(ctx.exception))

    def test_vault_index_is_encrypted_and_key_is_restricted(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("tools.crypto_vault.VAULT_ROOT", Path(tmp)):
            vault = Vault()
            artifact_id, key = vault.store_session(
                "example.com", b"session data", metadata={"source": "test"})
            encrypted = Path(tmp) / ".vault-index.json.enc"
            legacy = Path(tmp) / ".vault-index.json"
            key_path = Path(tmp) / ".vault-index.key"
            self.assertTrue(encrypted.exists())
            self.assertFalse(legacy.exists())
            self.assertTrue(key_path.exists())
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            # Plaintext content must not appear in the index file itself.
            self.assertNotIn(b"session data", encrypted.read_bytes())
            self.assertEqual(len(vault.list_artifacts("example.com")), 1)
            self.assertEqual(vault.load_session("example.com", key), b"session data")

    def test_legacy_plaintext_index_is_migrated(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch("tools.crypto_vault.VAULT_ROOT", Path(tmp)):
            Path(tmp).mkdir(parents=True, exist_ok=True)
            legacy = Path(tmp) / ".vault-index.json"
            legacy.write_text(json.dumps([{
                "artifact_id": "session-abc",
                "artifact_type": "session",
                "target": "example.com",
                "created_at": "2026-01-01T00:00:00+00:00",
                "encrypted_path": "vault/sessions/session-abc.enc",
                "original_hash": "x",
                "metadata": {},
            }]))
            vault = Vault()
            self.assertEqual(len(vault.list_artifacts("example.com")), 1)
            self.assertFalse(legacy.exists())
            self.assertTrue((Path(tmp) / ".vault-index.json.enc").exists())

    def test_aes_roundtrip(self):
        nonce, ct, tag, key = aes_encrypt(b"secret payload", key=b"k" * 32)
        self.assertEqual(aes_decrypt(nonce, ct, tag, key), b"secret payload")


class TestVaultFallback(unittest.TestCase):
    def test_fallback_does_not_store_the_raw_key(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.dict(os.environ, {"BUGWOLF_VAULT_PASSPHRASE": "test-pass"}), \
             mock.patch("tools.crypto_vault.shutil.which", return_value=None):
            root = Path(tmp)
            source = root / "source.txt"
            encrypted = root / "artifact.json"
            decrypted = root / "decrypted.txt"
            source.write_text("sensitive artifact")

            self.assertTrue(age_encrypt_file(source, encrypted))
            bundle = json.loads(encrypted.read_text())
            self.assertNotIn("key", bundle)
            self.assertTrue(age_decrypt_file(encrypted, decrypted))
            self.assertEqual(decrypted.read_text(), source.read_text())


if __name__ == "__main__":
    unittest.main()
