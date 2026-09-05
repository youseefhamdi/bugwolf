# Phase 4.D — MEDIUM Audit Remediation

This document tracks the 36 MEDIUM-severity findings (M-001 through M-036)
discovered during the Phase 4.D audit sweep, the remediation applied to each,
and the regression tests that pin the fix.

## Remediated helper module

All remediations go through a single, additive helper module:

`tools/core/medium_safety.py`

It exports the following wrapping helpers (stdlib-only):

| Helper | Purpose |
| --- | --- |
| `open_text(path, mode, *, encoding="utf-8", errors="replace")` | Encoding-safe text ``open()`` |
| `open_bytes(path, mode)` | Symmetric binary opener |
| `path_open_text(path, mode, ...)` | Encoding-safe ``Path.open()`` wrapper for text modes |
| `path_open_bytes(path, mode)` | Symmetric binary ``Path.open()`` wrapper |
| `fdopen_text(fd, mode, *, encoding="utf-8", ...)` | Encoding-safe ``os.fdopen()`` wrapper |
| `log_silent_swallow(where, exc, *, level=logging.WARNING)` | Structured log emission for swallowed exceptions |
| `runtime_check(condition, message)` | ``assert``-replacement that survives ``python -O`` |
| `safe_json_loads(text, *, default=None, context)` | ``json.loads`` with fail-closed fallback |
| `redact_for_print(value)` | Truncate payloads that look like secrets before they hit ``print()`` |
| `safe_print(*values, ...)` | ``print()`` wrapper that runs values through ``redact_for_print`` |
| `justified_sleep(seconds, reason)` | ``time.sleep`` with required justification string |
| `audit_log_marker(action, *, audit_log=True)` | Audit-trail flag helper |

Every fix is additive — original call sites are wrapped, not removed, so the
behaviour is preserved for every existing test.

## Findings

| ID | Category | File:line | Description | Remediation | Test |
| --- | --- | --- | --- | --- | --- |
| M-001 | print-leak | `tools/crypto_vault.py:495` | `print(f"Private key:\n{priv}")` leaks the AGE secret to stdout. | Wrap with `redact_for_print` via the `_redact_for_print` alias. | `tests/test_phase4_medium_remediation.py:PrintLeakCategory.test_M001_redact_private_key_string` |
| M-002 | print-leak | `tools/crypto_vault.py:514` | `print(f"[!] Key (KEEP SAFE): {meta['key_hex']}")` leaks the AES key. | Wrap with `_redact_for_print`. | `tests/test_phase4_medium_remediation.py:PrintLeakCategory.test_M002_redact_key_hex_payload` |
| M-003 | print-leak | `tools/crypto_vault.py:528` | `print(f"[!] Key (KEEP SAFE): {key.hex()}")` leaks the AES key. | Wrap with `_redact_for_print`. | `tests/test_phase4_medium_remediation.py:PrintLeakCategory.test_M003_crypto_vault_uses_redact_helper` |
| M-004 | no-encoding | `tools/core/agent_bus.py:147` | `open(self._inbox, "a")` no encoding. | Replace with `path_open_text(self._inbox, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M004_agent_bus_inbox_uses_safe_open` |
| M-005 | no-encoding | `tools/runtime/oast.py:82` | `self.registry_path.open("a")` no encoding. | Replace with `path_open_text(self.registry_path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M005_oast_registry_append_uses_safe_open` |
| M-006 | no-encoding | `tools/runtime/oast.py:91` | `self.registry_path.open()` no encoding. | Replace with `path_open_text(self.registry_path)`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M006_oast_registry_read_uses_safe_open` |
| M-007 | no-encoding | `tools/runtime/oast.py:107` | `self.interactions_path.open("a")` no encoding. | Replace with `path_open_text(self.interactions_path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M007_oast_interactions_append_uses_safe_open` |
| M-008 | no-encoding | `tools/runtime/oast.py:122` | `self.interactions_path.open()` no encoding. | Replace with `path_open_text(self.interactions_path)`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M008_oast_interactions_read_uses_safe_open` |
| M-009 | no-encoding | `tools/runtime/modes.py:126` | `self.journal_path.open("a")` no encoding. | Replace with `path_open_text(self.journal_path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M009_modes_journal_uses_safe_open` |
| M-010 | no-encoding | `tools/contract_discovery.py:560` | `open(out_dir / "plan.jsonl", "w")` no encoding. | Replace with `open_text(out_dir / "plan.jsonl", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M010_contract_discovery_plan_uses_safe_open` |
| M-011 | no-encoding | `tools/discovery_scheduler.py:365` | `open(out_dir / "plan.jsonl", "w")` no encoding. | Replace with `open_text(out_dir / "plan.jsonl", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M011_discovery_scheduler_plan_uses_safe_open` |
| M-012 | no-encoding | `tools/discovery_scheduler.py:375` | `open(out_dir / "art-report.json", "w")` no encoding. | Replace with `open_text(out_dir / "art-report.json", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M012_discovery_scheduler_art_report_uses_safe_open` |
| M-013 | no-encoding | `tools/mutator.py:472` | `open(args.output, "w")` no encoding. | Replace with `open_text(args.output, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M013_mutator_output_uses_safe_open` |
| M-014 | no-encoding | `tools/threat_intel.py:489` | `open(intel_file, "w")` no encoding. | Replace with `open_text(intel_file, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M014_threat_intel_intel_file_uses_safe_open` |
| M-015 | no-encoding | `tools/onchain_executor.py:124` | `self.log_file.open("w")` no encoding. | Replace with `path_open_text(self.log_file, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M015_onchain_log_file_uses_safe_open` |
| M-016 | no-encoding | `tools/onchain_executor.py:335` | `out.open("w")` no encoding. | Replace with `path_open_text(out, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M016_onchain_results_uses_safe_open` |
| M-017 | no-encoding (fdopen) | `tools/runtime/team_dispatch.py:288` | `os.fdopen(fd, "w")` no encoding on claim-token write. | Replace with `fdopen_text(fd, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M017_team_dispatch_claim_uses_safe_fdopen` |
| M-018 | no-encoding | `tools/infra_deploy.py:117` | `open(INFRA_DIR / "callback-log.jsonl", "a")` no encoding. | Replace with `open_text(INFRA_DIR / "callback-log.jsonl", "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M018_infra_deploy_callback_log_uses_safe_open` |
| M-019 | no-encoding | `tools/fleet.py:132` | `open(self._file, "a")` no encoding. | Replace with `open_text(self._file, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M019_fleet_pattern_file_uses_safe_open` |
| M-020 | no-encoding | `tools/evidence.py:177` | `open(self.manifest, "a")` no encoding. | Replace with `open_text(self.manifest, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M020_evidence_manifest_uses_safe_open` |
| M-021 | no-encoding | `tools/novelty.py:116` | `open(self.path, "a")` no encoding. | Replace with `open_text(self.path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M021_novelty_store_uses_safe_open` |
| M-022 | no-encoding | `tools/state.py:160` | `open(path, "a")` no encoding. | Replace with `open_text(path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M022_state_atomic_append_uses_safe_open` |
| M-023 | no-encoding | `tools/state.py:179` | `open(gi, "a")` no encoding. | Replace with `open_text(gi, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M023_state_gitignore_uses_safe_open` |
| M-024 | no-encoding | `tools/observation.py:794` | `open(path, "a")` no encoding. | Replace with `open_text(path, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M024_observation_atomic_append_uses_safe_open` |
| M-025 | no-encoding | `tools/retest_scheduler.py:354` | `open(queue_file, "a")` no encoding. | Replace with `open_text(queue_file, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M025_retest_enqueue_uses_safe_open` |
| M-026 | no-encoding | `tools/retest_scheduler.py:431` | `open(RETEST_DIR / "completed.jsonl", "a")` no encoding. | Replace with `open_text(RETEST_DIR / "completed.jsonl", "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M026_retest_completed_uses_safe_open` |
| M-027 | no-encoding | `tools/chain_of_custody.py:242` | `open(chain_file, "a")` no encoding. | Replace with `open_text(chain_file, "a")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M027_chain_of_custody_uses_safe_open` |
| M-028 | no-encoding | `tools/cache_traversal.py:446` | `(out_dir / "cache-traversal-plan.jsonl").open("w")` no encoding. | Replace with `path_open_text(out_dir / "cache-traversal-plan.jsonl", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M028_cache_traversal_plan_uses_safe_open` |
| M-029 | no-encoding | `tools/graphql_gid.py:419` | `(out_dir / "gid-candidates.jsonl").open("w")` no encoding. | Replace with `path_open_text(out_dir / "gid-candidates.jsonl", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M029_graphql_candidates_uses_safe_open` |
| M-030 | no-encoding | `tools/graphql_gid.py:422` | `(out_dir / "gid-validation-plans.jsonl").open("w")` no encoding. | Replace with `path_open_text(out_dir / "gid-validation-plans.jsonl", "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M030_graphql_plans_uses_safe_open` |
| M-031 | no-encoding | `tools/binary_re_adapter.py:392` | `Path(args.output).open("w")` no encoding. | Replace with `path_open_text(args.output, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M031_binary_re_adapter_uses_safe_open` |
| M-032 | no-encoding | `tools/symexec_adapter.py:316` | `Path(args.output).open("w")` no encoding. | Replace with `path_open_text(args.output, "w")`. | `tests/test_phase4_medium_remediation.py:NoEncodingCategory.test_M032_symexec_adapter_uses_safe_open` |
| M-033 | assert-runtime | `tools/perf.py:148` | `assert sched._graph_path.is_file()` is stripped under `python -O`. | Replace with `runtime_check` (helper). | `tests/test_phase4_medium_remediation.py:AssertRuntimeCategory.test_M033_perf_uses_runtime_check` |
| M-034 | assert-runtime | `bugwolf/distributed/redis_client.py:111,115,125,156,193` | Five `assert self._sock is not None` runtime guards stripped under `-O`. | Replace all five with `_runtime_check`. | `tests/test_phase4_medium_remediation.py:AssertRuntimeCategory.test_M034_redis_client_uses_runtime_check` |
| M-035 | print-leak | `tools/release_signing.py:455` | `print(json.dumps(result, indent=2))` prints raw Ed25519 signature. | Render a redacted copy when `signature` is in the dict and print that instead. | `tests/test_phase4_medium_remediation.py:PrintLeakCategory.test_M035_release_signing_redacts_signature` |
| M-036 | sleep-no-comment | `tools/runtime/oast_tunnel.py:103,215` | Two `time.sleep(N)` calls in production paths with no justification comment. | Wrap with `justified_sleep(N, reason)` (helper logs the reason at DEBUG). | `tests/test_phase4_medium_remediation.py:TimeSleepJustificationCategory.test_M036_oast_tunnel_uses_justified_sleep` |

## Helper smoke tests (extras, beyond the 36 finding tests)

`HelperSmoke` exercises the new helpers directly so any regression in the
wrapper itself is caught before it can silently re-introduce the original
pattern:

  * `open_text` writes UTF-8 and rejects binary modes.
  * `path_open_text` writes UTF-8.
  * `fdopen_text` writes UTF-8.
  * `log_silent_swallow` emits at WARNING level.
  * `safe_json_loads` returns the default on garbage and parses valid input.
  * `safe_print` redacts obvious secrets before they hit stdout.

## Aggregate guards

  * `NoBareTimeSleepInProductionHotPaths` scans every remediated file and
    fails if any bare `time.sleep(<numeric>)` re-appears.
  * `HelperImportsPresent` walks a fixed list of every patched file and
    fails if any of them loses the `tools.core.medium_safety` import —
    this prevents "I removed the helper import but forgot to revert the
    call site" drift.

## Verification

The full Phase 0 + Phase 1 + Phase 1.5 + Phase 2 + Phase 3 + Phase 4 test
suite plus the new Phase 4.D file passes (see the
`PHASE_4_D_MEDIUM_REMEDIATION.md` deliverable in the Phase 4.D PR):

```
================== 3 failed, 812 passed, 1 skipped in ~21s ==================
```

The 3 failures are pre-existing, environment-specific tests in
`tests/test_phase4_distributed.py::TestIPCBridge` — they expect
`bugwolf-rs/target/debug/{healthcheck,bench}` to be absent, but the
binaries happen to be already built on this machine (Phase 4 build was
run before the remediation started).  They are unrelated to the MEDIUM
remediation and were failing before any of the M-001..M-036 edits.

Without those three environment-specific failures, the baseline
(764 passing + 1 skipped before Phase 4.D) plus the 48 new tests
(36 finding-pinned + 12 helper / aggregate guards) gives 812 passing
total — i.e. every Phase 4.D test passes and no previously-passing
test regresses.