<!-- bugwolf/docs — operations
     SCHEMA: bugwolf-docs-operations-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Operations

This runbook covers installation, test execution, benchmark runs,
the Rust binary, the distributed master/worker, and disaster
recovery. Read it once before you touch the repo in production.

## 1. Installation

BugWolf is intentionally zero-dependency at the Python level.
There is no `pip install` step.

```bash
git clone <repo-url> bugwolf
cd bugwolf
python3 -m bugwolf --help
```

Requirements:
- Python 3.10+ (the codebase uses PEP 604 unions and structural
  pattern matching).
- `bash`, `grep`, `awk` (used by `scripts/ci_anti_patterns.sh`).
- (Optional) `cargo` and `rustc` for the `bugwolf-rs` crate.
- (Optional) Redis 7.x on `127.0.0.1:6379` for the distributed
  master/worker.

There are NO third-party Python dependencies. Do not add any.

## 2. Test suite

The full test suite uses `pytest`. BugWolf ships **1920+** tests.

```bash
cd /home/ubuntu/project/bugwolf
python3 -m pytest --no-header -q
```

Expected time: ~3-5 minutes on a 4-core laptop. Some tests are
marked `@pytest.mark.slow` and can be skipped with `-m "not slow"`.

### Test files → phases

| Test file prefix           | Phase                                   |
|----------------------------|-----------------------------------------|
| `test_phase0_*`            | Phase 0 — critical fixes                |
| `test_phase1_*`            | Phase 1 — governance, scanners, runtime |
| `test_phase2_*`            | Phase 2 — capability absorption         |
| `test_phase3_*`            | Phase 3 — fuzz / taint / semantic / chain|
| `test_phase4_*`            | Phase 4 — benchmarks + distributed      |
| `test_phase5_*`            | Phase 5 — CLI, reporting, unified state, **docs** |
| `test_phase6_*`            | Phase 6 — modes ladder + OPSEC          |
| `test_phase7_*`, `test_phase8_*` | Phase 7-8 — polish                |

### Interpreting test failures

- A failure in `test_scope_gate.py` or `test_scope_bypass_hardening.py`
  means the scope gate regressed. Investigate before merging.
- A failure in `test_integrity.py` means the hash-chained journal
  was modified outside the canonical entry point.
- A failure in `test_f05_*` means the F0.5 scorer dropped below
  the baseline. Re-run the synthlab suite to localize.
- A failure in `test_chain_*` means a chain YAML is malformed.

## 3. Benchmark runs

```bash
# Synthlab (six planted bugs). Always run this first.
python3 -m bugwolf.benchmarks.harness --suite synthlab --json

# Adversarial (15 apps). Run only after synthlab is green.
python3 -m bugwolf.benchmarks.harness --suite adversarial --json

# Regression (chains, scanners, governance).
python3 -m bugwolf.benchmarks.harness --suite regression --json
```

Benchmarks bind to `127.0.0.1` only. They require
`BUGWOLF_LAB_PROFILE=1` for the destructive probes; without it
they run in `--read-only` mode and skip the writes.

## 4. Rust binary

```bash
cd bugwolf-rs
cargo build --release
cargo test --manifest-path bugwolf-rs/Cargo.toml
```

The Rust crate is a `cdylib` consumed by Python via
`bugwolf/python_bindings/`. It exposes the `gate`, `hash`,
`journal`, `parsers`, `request_engine`, `scanner_core`, `taint`,
`fuzzer`, `destructive_gate`, and `skill_loader` modules.

## 5. Distributed master/worker (Redis)

```bash
# Start Redis on 127.0.0.1:6379.
redis-server --bind 127.0.0.1 --port 6379 &

# Start the master (one per cluster).
python3 -m bugwolf.distributed.master --bind 127.0.0.1 --port 7000

# Start one or more workers (on the same host or remote).
python3 -m bugwolf.distributed.worker \
    --master 127.0.0.1:7000 \
    --redis 127.0.0.1:6379
```

The master pushes tasks; the workers pull them and run the
probes through the governed replay engine. The master refuses to
push a task without a scope approval, and the worker refuses to
run it without a scope approval on the worker side too. Both
checks must pass before any HTTP request leaves the process.

## 6. Reading the capability digest

```bash
bash scripts/capability_digest.sh
```

Output: a single SHA-256 hash. Compare it to the value in
`scripts/capability_digest.txt`. If they differ, a scanner or
chain was added or removed without updating the digest file. CI
fails on drift.

## 7. Troubleshooting

| Symptom                                          | Likely cause                  | Fix                                        |
|--------------------------------------------------|-------------------------------|--------------------------------------------|
| `ModuleNotFoundError: No module named 'requests'` | Someone added a third-party dep | Revert the import — stdlib only           |
| `Permission denied` on the proxy file             | OPSEC proxy file mode too open | `chmod 600 bugwolf/opsec/proxies.txt`     |
| `ScopeDecision: DENY (empty in_scope)`            | Scope gate fired correctly    | Add the target host to `in_scope`         |
| `ChainValidator: unknown pattern 'X'`             | Pattern YAML missing          | Add the pattern or fix the YAML reference |
| `RuntimeError: lab profile required`              | Tried a destructive op in CI  | Set `BUGWOLF_LAB_PROFILE=1`              |
| `Redis connection refused`                        | Redis not running             | `redis-server --bind 127.0.0.1 --port 6379` |
| `pytest: command not found`                       | pytest missing                | `pip install pytest` (dev only)            |

## 8. Disaster recovery

The unified state journal is the source of truth. Every state
transition is hash-chained.

### Backup

```bash
# Copy the journal to a safe location.
cp -r state/sessions/<target>/journal.jsonl /backup/
```

### Replay

```bash
python3 -m bugwolf.unified_state.replay \
    --journal /backup/journal.jsonl \
    --target <target>
```

The replay tool re-applies every entry in order, re-validates
the chain, and emits a recovery report. If any entry fails the
chain, the replay stops and reports the offending entry ID.

### Restore

If the live journal is corrupted but the backup is intact:

```bash
python3 -m bugwolf.unified_state.recover \
    --source /backup/journal.jsonl \
    --destination state/sessions/<target>/journal.jsonl
```

The recover tool refuses to overwrite a live journal unless
`BUGWOLF_LAB_PROFILE=1` is set.

## Where to read next

- Architecture overview: `docs/ARCHITECTURE.md`
- Governance contracts: `docs/GOVERNANCE.md`
- Methodology patterns: `docs/METHODOLOGY.md`
- Benchmark scoring: `docs/BENCHMARKS.md`
- Security model: `docs/SECURITY.md`