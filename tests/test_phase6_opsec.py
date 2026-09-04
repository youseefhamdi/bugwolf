#!/usr/bin/env python3
"""Phase 6 opsec hardening tests (master plan Part VII).

Locks the opsec contract:

  * home-beacon stays dead — no session-time network fetch of version /
    instruction files anywhere in the skill surfaces (SKILL.md, commands,
    hooks, bridge, README, harness instruction files);
  * the update check is opt-in only (exposed through /bugwolf-doctor and
    the release_signing CLI, never session start);
  * release signing: SHA-256 manifest → Ed25519 detached signature →
    fail-closed tree verification (mismatch / missing / unlisted file);
  * harness_guard --verify-install verifies a shipped tree offline;
  * recon tooling pins installs (no @latest, no curl|sh from main);
  * OAST transparency doc exists and covers the three trust modes.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.release_signing import (  # noqa: E402
    SCHEMA,
    build_manifest,
    generate_keypair,
    manifest_bytes,
    sign_manifest,
    verify_manifest,
    verify_signature,
    verify_tree,
    check_update,
    _version_tuple,
)

RECON_TOOLING = (ROOT / "references" / "recon-tooling.md").read_text(encoding="utf-8")
SKILL = (ROOT / "SKILL.md").read_text(encoding="utf-8")


class TestBeaconDead(unittest.TestCase):
    """The session-start update beacon must never come back."""

    def test_skill_md_has_no_session_time_fetch(self):
        self.assertNotIn("raw.githubusercontent.com/youseefhamdi", SKILL)
        self.assertNotIn("AUTO-UPDATE SYSTEM", SKILL)
        self.assertNotIn("UPDATE AVAILABLE", SKILL)
        self.assertNotIn("check this every session start", SKILL)

    def test_skill_md_declares_the_opt_in_policy(self):
        self.assertIn("OPT-IN ONLY", SKILL)
        self.assertIn("release_signing.py --check-update", SKILL)
        self.assertIn("NEVER fetch VERSION", SKILL)

    def test_no_beacon_in_any_session_surface(self):
        surfaces = [
            ROOT / "SKILL.md", ROOT / "README.md",
            ROOT / "commands" / "bugwolf-doctor.md",
            ROOT / "hooks" / "hooks.json",
            ROOT / "hooks" / "bugwolf_stop_hook.py",
            ROOT / "hooks" / "bugwolf_pretool_scope_hook.py",
            ROOT / "hooks" / "bugwolf_hooks.py",
            ROOT / "bridge" / "bugwolf-mcp.py",
        ]
        for path in surfaces:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for pattern in ("raw.githubusercontent.com/youseefhamdi",
                            "AUTO-UPDATE", "UPDATE AVAILABLE"):
                self.assertNotIn(pattern, text, f"{path.name}: beacon residue")

    def test_instruction_files_clean(self):
        for name in ("BUGWOLF.md", "AGENTS.md"):
            path = ROOT / name
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("raw.githubusercontent.com/youseefhamdi", text)

    def test_doctor_sells_check_update_as_opt_in_only(self):
        doctor = (ROOT / "commands" / "bugwolf-doctor.md").read_text(
            encoding="utf-8")
        norm = " ".join(doctor.split())
        self.assertIn("ONLY when the operator explicitly asks", norm)
        self.assertIn("Never run unprompted", norm)

    def test_check_update_fails_silent_offline(self):
        """Network down => fact dict degrades; the check never raises."""
        from unittest import mock
        with mock.patch("urllib.request.urlopen",
                        side_effect=OSError("no network in test")):
            fact = check_update("0.0.0", timeout=0.1)
        self.assertEqual(fact["schema"], SCHEMA)
        self.assertTrue(fact["opt_in"])
        self.assertEqual(fact["network"], "failed")
        self.assertIn("error", fact)

    def test_version_tuple_ordering(self):
        self.assertGreater(_version_tuple("1.10.0"), _version_tuple("1.9.2"))
        self.assertGreater(_version_tuple("2.0.0"), _version_tuple("1.99.99"))
        self.assertEqual(_version_tuple("1.16.0"), _version_tuple("1.16.0"))


class TestReleaseSigning(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.tree = self.work / "tree"
        (self.tree / "tools").mkdir(parents=True)
        (self.tree / "SKILL.md").write_text("skill bytes\n")
        (self.tree / "tools" / "engine.py").write_text("print('engine')\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_manifest_is_deterministic_and_complete(self):
        first = build_manifest(self.tree)
        second = build_manifest(self.tree)
        # The created_at timestamp differs between runs by design; the
        # FILE inventory must be byte-identical (that is what gets signed).
        self.assertEqual(json.dumps(first["files"], sort_keys=True),
                         json.dumps(second["files"], sort_keys=True))
        paths = {entry["path"] for entry in first["files"]}
        self.assertEqual(paths, {"SKILL.md", "tools/engine.py"})

    def test_sign_verify_round_trip(self):
        try:
            keys = generate_keypair(self.work / "keys")
        except RuntimeError as exc:
            if "cryptography" in str(exc):
                self.skipTest("cryptography not installed")
            raise
        manifest = build_manifest(self.tree)
        signature = sign_manifest(manifest, keys["secret_key"])
        self.assertTrue(signature["signed"])
        self.assertIn("untrusted comment:", signature["signature"])
        result = verify_signature(manifest, signature["signature"],
                                  keys["public_key"])
        self.assertTrue(result["verified"], result)

    def test_verify_fails_on_tamper(self):
        manifest = build_manifest(self.tree)
        (self.tree / "tools" / "engine.py").write_text("print('evil')\n")
        result = verify_manifest(self.tree, manifest)
        self.assertFalse(result["verified"])
        self.assertTrue(any("hash mismatch" in e for e in result["errors"]))

    def test_verify_fails_on_missing_and_unlisted(self):
        manifest = build_manifest(self.tree)
        (self.tree / "tools" / "engine.py").unlink()
        (self.tree / "backdoor.py").write_text("evil\n")
        result = verify_manifest(self.tree, manifest)
        self.assertFalse(result["verified"])
        self.assertTrue(any("missing:" in e for e in result["errors"]))
        self.assertTrue(any("unlisted file" in e for e in result["errors"]))

    def test_verify_tree_fails_closed_without_manifest(self):
        result = verify_tree(self.tree)
        self.assertFalse(result["verified"])
        self.assertIn("no shipped manifest", result["errors"][0])

    def test_verify_tree_passes_with_shipped_manifest(self):
        manifest = build_manifest(self.tree)
        (self.tree / "SHA256SUMS").write_bytes(manifest_bytes(manifest))
        result = verify_tree(self.tree)
        self.assertTrue(result["verified"], result["errors"])

    def test_sign_without_cryptography_is_honest(self):
        try:
            import cryptography  # noqa: F401
            self.skipTest("cryptography installed; absence path N/A")
        except ImportError:
            pass
        result = sign_manifest(build_manifest(self.tree), "nokey.pem")
        self.assertFalse(result["signed"])
        self.assertIn("cryptography", result["reason"])


class TestHarnessGuardVerifyInstall(unittest.TestCase):
    def test_verify_install_contract(self):
        """harness_guard must expose the tree gate and route it to
        release_signing (offline, fail-closed)."""
        text = (ROOT / "tools" / "harness_guard.py").read_text(
            encoding="utf-8")
        self.assertIn("--verify-install", text)
        self.assertIn("from tools.release_signing import verify_tree", text)
        self.assertIn("verify_install", text)

    def test_cli_wiring(self):
        proc = subprocess.run(
            [sys.executable, "tools/harness_guard.py", "--verify-install",
             "--json", "--skill-root", str(tempfile.mkdtemp())],
            capture_output=True, text=True, cwd=str(ROOT), check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": tempfile.mkdtemp()})
        self.assertEqual(proc.returncode, 2)  # fail-closed, no manifest
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["verified"])
        self.assertIn("no shipped manifest", payload["errors"][0])


class TestToolPinning(unittest.TestCase):
    def test_supply_chain_policy_present(self):
        self.assertIn("Supply-chain policy", RECON_TOOLING)
        self.assertIn("Tagged releases, never `@latest`", RECON_TOOLING)
        self.assertIn("No pipe-to-shell", RECON_TOOLING)

    def test_no_latest_pins_left_in_catalog(self):
        pins = re.findall(r"`go install \S+@latest`", RECON_TOOLING)
        self.assertEqual(pins, [], f"unpinned @latest installs: {pins}")

    def test_no_floating_pip_installs(self):
        floating = re.findall(r"`pip install [a-z0-9_-]+`", RECON_TOOLING)
        self.assertEqual(floating, [],
                         f"floating pip installs (pin ==version): {floating}")

    def test_no_curl_pipe_shell(self):
        # Install cells fetch a URL and pipe it to a shell; the POLICY LINE
        # naming the ban (~line 20) shows the pattern WITHOUT a URL, so it
        # must not match. The trufflehog pipe-to-shell cell was removed.
        pipes = re.findall(r"`curl[^`]*https?://[^`]*\|\s*(?:ba)?sh`",
                           RECON_TOOLING)
        self.assertEqual(pipes, [], f"pipe-to-shell installs: {pipes}")

    def test_pinned_clone_pattern_used_for_source_builds(self):
        self.assertIn("git clone --branch <tag> --depth 1",
                      RECON_TOOLING)


class TestOASTTransparency(unittest.TestCase):
    def setUp(self):
        self.doc = (ROOT / "docs" / "OAST_TRANSPARENCY.md").read_text(
            encoding="utf-8")

    def test_doc_exists_and_covers_the_trust_model(self):
        for marker in ("What OAST is for", "default mode",
                       "public-tunnel path", "self-hosted option",
                       "serveo.net", "BUGWOLF_OAST_TUNNEL_HOST",
                       "BUGWOLF_OAST_PUBLIC_URL"):
            self.assertIn(marker, self.doc)

    def test_data_crossing_documented(self):
        self.assertIn("What crosses the relay", self.doc)
        self.assertIn("canary hostname", self.doc)
        self.assertIn("callback metadata", self.doc)
        self.assertIn("relay operator", self.doc)

    def test_env_contract_matches_code(self):
        from tools.runtime import oast_tunnel
        self.assertIn(oast_tunnel.DEFAULT_TUNNEL_HOST, self.doc)


if __name__ == "__main__":
    unittest.main()
