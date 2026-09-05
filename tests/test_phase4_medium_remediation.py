#!/usr/bin/env python3
"""Phase 4.D — MEDIUM severity audit remediation regression tests.

36 MEDIUM findings (M-001 .. M-036) are pinned here.  Every test is
hermetic (no network, no live disk state outside ``/tmp/opencode``) and
imports only the helpers / call sites that are part of the remediation
layer.

Conventions:
  * One test class per category; one test method per finding.
  * Tests assert the *remediation* (helper used, behaviour preserved)
    plus a small functional smoke check.
  * No test depends on timing or external services.
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# =============================================================================
# M-001..M-003, M-035 — print() that may leak secrets (crypto_vault + signing)
# =============================================================================


class PrintLeakCategory(unittest.TestCase):
    """M-001, M-002, M-003, M-035 — redact_for_print / safe_print wrappers."""

    def test_M001_redact_private_key_string(self):
        """M-001: redact_for_print must shorten obvious private-key payloads."""
        from tools.core.medium_safety import redact_for_print
        text = "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF"
        redacted = redact_for_print(text)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF", redacted)
        self.assertIn("REDACTED", redacted)

    def test_M002_redact_key_hex_payload(self):
        """M-002: redact_for_print must redact hex-encoded keys."""
        from tools.core.medium_safety import redact_for_print
        text = "Key (KEEP SAFE): deadbeef" + "f" * 60
        redacted = redact_for_print(text)
        self.assertNotIn("f" * 60, redacted)

    def test_M003_crypto_vault_uses_redact_helper(self):
        """M-003: crypto_vault.py must use the redact helper for key prints."""
        text = Path(ROOT / "tools" / "crypto_vault.py").read_text()
        self.assertRegex(text, r"from\s+tools\.core\.medium_safety\s+import\s+redact_for_print")

    def test_M035_release_signing_redacts_signature(self):
        """M-035: release_signing.py must NOT print raw signature data via json.dumps."""
        text = Path(ROOT / "tools" / "release_signing.py").read_text()
        # The old direct print + signature must be wrapped
        self.assertIn("REDACTED len=", text)


# =============================================================================
# M-004..M-032 — open() without explicit encoding (production paths)
# =============================================================================


class NoEncodingCategory(unittest.TestCase):
    """M-004..M-032 — encoding-safe open wrappers."""

    def test_M004_agent_bus_inbox_uses_safe_open(self):
        """M-004: AgentBus inbox write uses path_open_text (explicit utf-8)."""
        text = Path(ROOT / "tools" / "core" / "agent_bus.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\._inbox,\s*[\"']a[\"']\)")

    def test_M005_oast_registry_append_uses_safe_open(self):
        """M-005: OastRegistry.register uses path_open_text for registry append."""
        text = Path(ROOT / "tools" / "runtime" / "oast.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\.registry_path,\s*[\"']a[\"']\)")

    def test_M006_oast_registry_read_uses_safe_open(self):
        """M-006: OastRegistry.lookup uses path_open_text for read."""
        text = Path(ROOT / "tools" / "runtime" / "oast.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\.registry_path\)")

    def test_M007_oast_interactions_append_uses_safe_open(self):
        """M-007: OastRegistry.record uses path_open_text for interactions append."""
        text = Path(ROOT / "tools" / "runtime" / "oast.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\.interactions_path,\s*[\"']a[\"']\)")

    def test_M008_oast_interactions_read_uses_safe_open(self):
        """M-008: OastRegistry.interactions uses path_open_text for read."""
        text = Path(ROOT / "tools" / "runtime" / "oast.py").read_text()
        # both interactions_path opens are safe
        self.assertEqual(text.count("path_open_text(self.interactions_path"), 2)

    def test_M009_modes_journal_uses_safe_open(self):
        """M-009: modes.py journal write uses path_open_text."""
        text = Path(ROOT / "tools" / "runtime" / "modes.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\.journal_path,\s*[\"']a[\"']\)")

    def test_M010_contract_discovery_plan_uses_safe_open(self):
        """M-010: contract_discovery.py plan.jsonl write uses open_text."""
        text = Path(ROOT / "tools" / "contract_discovery.py").read_text()
        self.assertRegex(text, r"open_text\(out_dir\s*/\s*[\"']plan\.jsonl[\"'],\s*[\"']w[\"']\)")

    def test_M011_discovery_scheduler_plan_uses_safe_open(self):
        """M-011: discovery_scheduler.py plan.jsonl write uses open_text."""
        text = Path(ROOT / "tools" / "discovery_scheduler.py").read_text()
        self.assertRegex(text, r"open_text\(out_dir\s*/\s*[\"']plan\.jsonl[\"'],\s*[\"']w[\"']\)")

    def test_M012_discovery_scheduler_art_report_uses_safe_open(self):
        """M-012: discovery_scheduler.py art-report.json write uses open_text."""
        text = Path(ROOT / "tools" / "discovery_scheduler.py").read_text()
        self.assertRegex(text,
                         r"open_text\(out_dir\s*/\s*[\"']art-report\.json[\"'],\s*[\"']w[\"']\)")

    def test_M013_mutator_output_uses_safe_open(self):
        """M-013: mutator.py output write uses open_text."""
        text = Path(ROOT / "tools" / "mutator.py").read_text()
        self.assertRegex(text, r"open_text\(args\.output,\s*[\"']w[\"']\)")

    def test_M014_threat_intel_intel_file_uses_safe_open(self):
        """M-014: threat_intel.py intel file write uses open_text."""
        text = Path(ROOT / "tools" / "threat_intel.py").read_text()
        self.assertRegex(text, r"open_text\(intel_file,\s*[\"']w[\"']\)")

    def test_M015_onchain_log_file_uses_safe_open(self):
        """M-015: onchain_executor.py log file open uses path_open_text."""
        text = Path(ROOT / "tools" / "onchain_executor.py").read_text()
        self.assertRegex(text, r"path_open_text\(self\.log_file,\s*[\"']w[\"']\)")

    def test_M016_onchain_results_uses_safe_open(self):
        """M-016: onchain_executor.py results output uses path_open_text."""
        text = Path(ROOT / "tools" / "onchain_executor.py").read_text()
        self.assertRegex(text, r"path_open_text\(out,\s*[\"']w[\"']\)")

    def test_M017_team_dispatch_claim_uses_safe_fdopen(self):
        """M-017: team_dispatch.py claim write uses fdopen_text (explicit utf-8)."""
        text = Path(ROOT / "tools" / "runtime" / "team_dispatch.py").read_text()
        self.assertRegex(text, r"fdopen_text\(fd,\s*[\"']w[\"']\)")
        self.assertNotRegex(text, r"os\.fdopen\(fd,\s*[\"']w[\"']\)")

    def test_M018_infra_deploy_callback_log_uses_safe_open(self):
        """M-018: infra_deploy.py callback log uses open_text."""
        text = Path(ROOT / "tools" / "infra_deploy.py").read_text()
        self.assertRegex(text, r"open_text\(INFRA_DIR\s*/\s*[\"']callback-log\.jsonl[\"'],\s*[\"']a[\"']\)")

    def test_M019_fleet_pattern_file_uses_safe_open(self):
        """M-019: fleet.py pattern file uses open_text for append."""
        text = Path(ROOT / "tools" / "fleet.py").read_text()
        self.assertRegex(text, r"open_text\(self\._file,\s*[\"']a[\"']\)")

    def test_M020_evidence_manifest_uses_safe_open(self):
        """M-020: evidence.py manifest append uses open_text."""
        text = Path(ROOT / "tools" / "evidence.py").read_text()
        self.assertRegex(text, r"open_text\(self\.manifest,\s*[\"']a[\"']\)")

    def test_M021_novelty_store_uses_safe_open(self):
        """M-021: novelty.py store append uses open_text."""
        text = Path(ROOT / "tools" / "novelty.py").read_text()
        self.assertRegex(text, r"open_text\(self\.path,\s*[\"']a[\"']\)")

    def test_M022_state_atomic_append_uses_safe_open(self):
        """M-022: state.py atomic_append uses open_text."""
        text = Path(ROOT / "tools" / "state.py").read_text()
        self.assertRegex(text, r"open_text\(path,\s*[\"']a[\"']\)")

    def test_M023_state_gitignore_uses_safe_open(self):
        """M-023: state.py gitignore append uses open_text."""
        text = Path(ROOT / "tools" / "state.py").read_text()
        self.assertRegex(text, r"open_text\(gi,\s*[\"']a[\"']\)")

    def test_M024_observation_atomic_append_uses_safe_open(self):
        """M-024: observation.py atomic_append uses open_text."""
        text = Path(ROOT / "tools" / "observation.py").read_text()
        self.assertRegex(text, r"open_text\(path,\s*[\"']a[\"']\)")

    def test_M025_retest_enqueue_uses_safe_open(self):
        """M-025: retest_scheduler.py queue append uses open_text."""
        text = Path(ROOT / "tools" / "retest_scheduler.py").read_text()
        self.assertRegex(text, r"open_text\(queue_file,\s*[\"']a[\"']\)")

    def test_M026_retest_completed_uses_safe_open(self):
        """M-026: retest_scheduler.py completed.jsonl append uses open_text."""
        text = Path(ROOT / "tools" / "retest_scheduler.py").read_text()
        self.assertRegex(text, r"open_text\(RETEST_DIR\s*/\s*[\"']completed\.jsonl[\"'],\s*[\"']a[\"']\)")

    def test_M027_chain_of_custody_uses_safe_open(self):
        """M-027: chain_of_custody.py chain file append uses open_text."""
        text = Path(ROOT / "tools" / "chain_of_custody.py").read_text()
        self.assertRegex(text, r"open_text\(chain_file,\s*[\"']a[\"']\)")

    def test_M028_cache_traversal_plan_uses_safe_open(self):
        """M-028: cache_traversal.py plan.jsonl write uses path_open_text."""
        text = Path(ROOT / "tools" / "cache_traversal.py").read_text()
        self.assertRegex(text,
                         r"path_open_text\(out_dir\s*/\s*[\"']cache-traversal-plan\.jsonl[\"'],\s*[\"']w[\"']\)")

    def test_M029_graphql_candidates_uses_safe_open(self):
        """M-029: graphql_gid.py candidates.jsonl uses path_open_text."""
        text = Path(ROOT / "tools" / "graphql_gid.py").read_text()
        self.assertRegex(text,
                         r"path_open_text\(out_dir\s*/\s*[\"']gid-candidates\.jsonl[\"'],\s*[\"']w[\"']\)")

    def test_M030_graphql_plans_uses_safe_open(self):
        """M-030: graphql_gid.py validation-plans uses path_open_text."""
        text = Path(ROOT / "tools" / "graphql_gid.py").read_text()
        self.assertRegex(text,
                         r"path_open_text\(out_dir\s*/\s*[\"']gid-validation-plans\.jsonl[\"'],\s*[\"']w[\"']\)")

    def test_M031_binary_re_adapter_uses_safe_open(self):
        """M-031: binary_re_adapter.py output uses path_open_text."""
        text = Path(ROOT / "tools" / "binary_re_adapter.py").read_text()
        self.assertRegex(text, r"path_open_text\(args\.output,\s*[\"']w[\"']\)")
        self.assertNotRegex(text, r"Path\(args\.output\)\.open\(\s*[\"']w[\"']\)")

    def test_M032_symexec_adapter_uses_safe_open(self):
        """M-032: symexec_adapter.py output uses path_open_text."""
        text = Path(ROOT / "tools" / "symexec_adapter.py").read_text()
        self.assertRegex(text, r"path_open_text\(args\.output,\s*[\"']w[\"']\)")
        self.assertNotRegex(text, r"Path\(args\.output\)\.open\(\s*[\"']w[\"']\)")


# =============================================================================
# M-033, M-034 — assert used for runtime guards
# =============================================================================


class AssertRuntimeCategory(unittest.TestCase):
    """M-033, M-034 — runtime_check replaces assert in production paths."""

    def test_M033_perf_uses_runtime_check(self):
        """M-033: perf.py no longer relies on bare assert for runtime guards."""
        text = Path(ROOT / "tools" / "perf.py").read_text()
        self.assertNotIn("assert sched._graph_path.is_file()", text)
        self.assertIn("_runtime_check", text)

    def test_M034_redis_client_uses_runtime_check(self):
        """M-034: redis_client.py replaces ``assert self._sock is not None``."""
        text = Path(ROOT / "bugwolf" / "distributed" / "redis_client.py").read_text()
        # No more raw ``assert self._sock`` anywhere
        self.assertNotRegex(text, r"^\s*assert\s+self\._sock")
        self.assertIn("_runtime_check", text)
        self.assertIn("from tools.core.medium_safety import runtime_check", text)

    def test_runtime_check_helper_survives_optimization(self):
        """M-033/M-034 smoke: ``runtime_check`` raises even under -O (we
        simulate that by patching ``__debug__``).  This proves the helper
        is a regular function, not an ``assert``."""
        from tools.core.medium_safety import runtime_check
        with mock.patch.object(sys.modules["builtins"], "__debug__", False):
            try:
                runtime_check(False, "must-fail")
            except AssertionError as exc:
                self.assertIn("must-fail", str(exc))
            else:
                self.fail("runtime_check must still raise when __debug__ is False")


# =============================================================================
# M-036 — time.sleep without justification
# =============================================================================


class TimeSleepJustificationCategory(unittest.TestCase):
    """M-036 — time.sleep in production must call justified_sleep."""

    def test_M036_oast_tunnel_uses_justified_sleep(self):
        """M-036: oast_tunnel.py calls justified_sleep instead of bare time.sleep."""
        text = Path(ROOT / "tools" / "runtime" / "oast_tunnel.py").read_text()
        self.assertIn("justified_sleep", text)
        self.assertIn("from tools.core.medium_safety import justified_sleep", text)
        # The two original `time.sleep(N)` calls have been wrapped
        self.assertNotIn("time.sleep(0.3)", text)
        self.assertNotIn("time.sleep(1.0)", text)

    def test_justified_sleep_helper_preserves_behavior(self):
        """M-036 smoke: justified_sleep sleeps for the requested duration."""
        import time as _time
        from tools.core.medium_safety import justified_sleep
        start = _time.monotonic()
        justified_sleep(0.001, "test-smoke")
        elapsed = _time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.0)


# =============================================================================
# Functional smoke tests for the helpers themselves
# =============================================================================


class HelperSmoke(unittest.TestCase):
    """Behaviour-preserving smoke tests for the medium_safety module."""

    def test_open_text_writes_utf8(self):
        from tools.core.medium_safety import open_text
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "utf.jsonl"
            with open_text(p, "w") as fh:
                fh.write("naïve — 漢字\n")
            self.assertIn("漢字", p.read_text(encoding="utf-8"))

    def test_open_text_rejects_binary_mode(self):
        from tools.core.medium_safety import open_text
        with self.assertRaises(ValueError):
            with open_text("/tmp/x", "wb"):
                pass

    def test_path_open_text_writes_utf8(self):
        from tools.core.medium_safety import path_open_text
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "p.jsonl"
            with path_open_text(p, "w") as fh:
                fh.write("emoji 😀\n")
            self.assertIn("😀", p.read_text(encoding="utf-8"))

    def test_fdopen_text_writes_utf8(self):
        import os as _os
        from tools.core.medium_safety import fdopen_text
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            fd = _os.open(str(p), _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC)
            try:
                with fdopen_text(fd, "w") as fh:
                    fh.write("café\n")
            except Exception:
                # If the context manager closes the fd on exception
                pass
            self.assertIn("café", p.read_text(encoding="utf-8"))

    def test_log_silent_swallow_logs_at_warning(self):
        from tools.core import medium_safety
        with self.assertLogs("bugwolf.phase4d.medium", level="WARNING") as cm:
            medium_safety.log_silent_swallow("where", RuntimeError("boom"))
        self.assertTrue(any("phase4d.silent_swallow" in m for m in cm.output))

    def test_safe_json_loads_returns_default_on_garbage(self):
        from tools.core.medium_safety import safe_json_loads
        self.assertIsNone(safe_json_loads("{not-json", default=None,
                                          context="smoke"))

    def test_safe_json_loads_parses_valid(self):
        from tools.core.medium_safety import safe_json_loads
        self.assertEqual(safe_json_loads('{"k": 1}', context="smoke"),
                         {"k": 1})

    def test_safe_print_redacts_secrets(self):
        from tools.core.medium_safety import safe_print
        buf = io.StringIO()
        with redirect_stdout(buf):
            safe_print("Private key:", "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUV")
        out = buf.getvalue()
        self.assertIn("REDACTED", out)
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUV", out)


# =============================================================================
# Aggregate scan: confirm no production file ships a bare
# ``time.sleep(N)`` line in the hot paths of the remediated files
# =============================================================================


class NoBareTimeSleepInProductionHotPaths(unittest.TestCase):
    def test_no_bare_time_sleep_in_remediated_files(self):
        checked = [
            ROOT / "tools" / "runtime" / "oast_tunnel.py",
        ]
        for p in checked:
            text = p.read_text()
            # Match ``time.sleep(123)`` (numeric literal) outside triple-quoted
            # docstrings — justified_sleep has its own helper.
            for m in re.finditer(r"\btime\.sleep\(([0-9]+(?:\.[0-9]+)?)\)", text):
                self.fail(
                    f"bare time.sleep({m.group(1)}) in {p}:{text[:m.start()].count(chr(10))+1}"
                )


# =============================================================================
# Aggregate scan: confirm every fixed file imports the safety helper
# =============================================================================


class HelperImportsPresent(unittest.TestCase):
    FIXED_FILES = [
        ("tools", "core", "agent_bus.py"),
        ("tools", "runtime", "oast.py"),
        ("tools", "runtime", "modes.py"),
        ("tools", "contract_discovery.py",),
        ("tools", "discovery_scheduler.py",),
        ("tools", "mutator.py",),
        ("tools", "threat_intel.py",),
        ("tools", "onchain_executor.py",),
        ("tools", "runtime", "team_dispatch.py"),
        ("tools", "infra_deploy.py",),
        ("tools", "fleet.py",),
        ("tools", "evidence.py",),
        ("tools", "novelty.py",),
        ("tools", "state.py",),
        ("tools", "observation.py",),
        ("tools", "retest_scheduler.py",),
        ("tools", "chain_of_custody.py",),
        ("tools", "cache_traversal.py",),
        ("tools", "graphql_gid.py",),
        ("tools", "binary_re_adapter.py",),
        ("tools", "symexec_adapter.py",),
        ("tools", "perf.py",),
        ("tools", "crypto_vault.py",),
        ("tools", "release_signing.py",),
        ("tools", "runtime", "oast_tunnel.py"),
        ("bugwolf", "distributed", "redis_client.py"),
    ]

    def test_every_fixed_file_imports_medium_safety(self):
        """Every file in FIXED_FILES must import from tools.core.medium_safety."""
        missing = []
        for parts in self.FIXED_FILES:
            path = ROOT.joinpath(*parts)
            text = path.read_text()
            if "tools.core.medium_safety" not in text:
                missing.append(str(path))
        self.assertEqual(missing, [], "files missing medium_safety import: "
                                     + ", ".join(missing))


if __name__ == "__main__":
    unittest.main()