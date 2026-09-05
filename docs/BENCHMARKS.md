<!-- bugwolf/docs — benchmarks
     SCHEMA: bugwolf-docs-benchmarks-v1
     ## Source: original work for Phase 5.4 + 5.5
     ## License: BugWolf internal
     ## Capability tier: C0 (documentation) -->

# BugWolf Benchmarks

The benchmark layer is how BugWolf measures itself: synthlab (six
planted bugs in a stub app), adversarial (15 vulnerable mini apps),
regression (three suites), and scoring (F0.5, chain validity,
line/branch coverage). This file documents each component, the
end-to-end run command, and how to add a new vulnerability class.

All benchmark modules live in `bugwolf/benchmarks/` and are
invoked via `python3 -m bugwolf.benchmarks.harness`.

## 1. `synthlab/` — six planted bugs

`synthlab/` ships a self-contained stub app with six intentionally
vulnerable endpoints. The harness probes each one and checks
whether the scanner flags it as a true positive.

| ID | Class      | Endpoint                     | Expected finding           |
|----|------------|------------------------------|----------------------------|
| B1 | SQLi       | `/search?q=`                 | SQL injection (UNION-based)|
| B2 | XSS        | `/echo?name=`                | Reflected XSS              |
| B3 | IDOR       | `/users/<id>`                | IDOR (no authz check)      |
| B4 | SSRF       | `/fetch?url=`                | SSRF (private IP allow)    |
| B5 | JWT        | `/admin`                     | JWT alg=none forgery       |
| B6 | Arg-inject | `/ping?host=`                | OS command injection       |

The synthlab app binds only to `127.0.0.1` on a random port; no
public listener is ever started. The harness picks the port,
spins the app, runs the probes, and tears it down.

## 2. `adversarial/` — 15 vulnerable apps

`adversarial/` ships 15 mini apps, each demonstrating a different
bug class. They are heavier than synthlab (full mini-app per
class) and exercise the scanner chains end-to-end.

| # | App                                | Class                                  |
|---|------------------------------------|----------------------------------------|
| 1 | `sqli_app.py`                      | SQL injection (multi-DB)               |
| 2 | `xss_app.py`                       | XSS (DOM, stored, reflected)           |
| 3 | `ssrf_app.py`                      | SSRF (DNS rebinding, IPv6)             |
| 4 | `idor_app.py`                      | IDOR (object + function-level)         |
| 5 | `jwt_app.py`                       | JWT (alg confusion, key confusion)     |
| 6 | `race_app.py`                      | Race condition (TOCTOU, double-spend)  |
| 7 | `deserialize_app.py`               | Insecure deserialization (Python, Java)|
| 8 | `business_logic_app.py`            | Business logic (FIN matrix)            |
| 9 | `smart_contract.sol`               | Reentrancy + oracle manipulation       |
|10 | `cicd_workflow.yaml`               | GitHub Actions expression injection    |
|11 | `llm_app.py`                       | Prompt injection + RAG poisoning      |
|12 | `mobile_app.MANIFEST.txt` (+.apk)  | Deep link + MASVS/MASWE               |
|13 | `cloud_terraform.tf`               | AWS misconfig (S3, IAM, SG)            |
|14 | `graphql_app.py`                   | GraphQL batching + introspection      |
|15 | `grpc_app.proto`                   | gRPC reflection + authz bypass        |

Like synthlab, every adversarial app binds to `127.0.0.1` only.

## 3. `regression/` — three suites

`regression/` ships three test suites that run on every CI
commit:

- `test_all_chains.py` — loads every chain YAML and confirms it
  builds without error, references known patterns, and passes
  the chain validator.
- `test_all_scanners.py` — instantiates every scanner and runs a
  smoke test (does it parse a sample target?).
- `test_governance.py` — runs every governance gate (scope,
  question, CVSS, OPSEC, capability digest, evidence, contracts,
  safety, execution semantics).

## 4. `scoring/` — F0.5, chain validity, coverage

`scoring/` produces three numbers for each benchmark run:

- **F0.5** (`f05_scorer.py`) — the F-score with β=0.5, weighting
  precision more than recall. This is the primary metric.
- **Chain validity** (`chain_scorer.py`) — the fraction of chains
  that pass the chain validator. A chain that fails is reported
  with the failing step ID.
- **Line/branch coverage** (`coverage_scorer.py`) — the line and
  branch coverage of the scanner code paths exercised by the
  benchmark run.

## 5. Running the suite end-to-end

```bash
# 1. Synthlab (six planted bugs).
python3 -m bugwolf.benchmarks.harness --suite synthlab --json

# 2. Adversarial (15 apps).
python3 -m bugwolf.benchmarks.harness --suite adversarial --json

# 3. Regression (three suites).
python3 -m bugwolf.benchmarks.harness --suite regression --json

# 4. Combined scoring.
python3 -m bugwolf.benchmarks.harness \
    --suite synthlab,adversarial,regression \
    --score --json
```

**Safety guarantees.**
- The harness binds every app to `127.0.0.1` only. No public
  listener is ever started.
- The harness refuses to run unless `BUGWOLF_LAB_PROFILE=1` is
  set in the environment (otherwise it runs in `--read-only`
  mode and skips the destructive probes).
- The harness records every probe as an evidence block in the
  unified state journal; tampering breaks the chain and the
  scoring refuses the report.

## 6. How to add a new vulnerability class to the benchmark suite

1. **Synthlab.** Add a new endpoint to the synthlab stub app
   (`bugwolf/benchmarks/synthlab/`). Add a new row to the table
   in this file (id, class, endpoint, expected finding). Add a
   unit test in `tests/test_benchmark.py` that asserts the new
   endpoint is flagged.
2. **Adversarial.** Add a new mini app under
   `bugwolf/benchmarks/adversarial/`. Follow the existing
   pattern: a self-contained module with a `main()` that binds
   to `127.0.0.1`. Add a row to the adversarial table above.
3. **Regression.** If the new class introduces a new chain or
   scanner, add a test under `bugwolf/benchmarks/regression/`.
4. **Scoring.** If the new class needs a custom scorer, add a
   module to `bugwolf/benchmarks/scoring/` and a row to the
   `SCORERS` dict in `bugwolf/benchmarks/harness.py`.
5. Run the full suite and confirm the new metric lands at or
   above the baseline.

## Where to read next

- Architecture overview: `docs/ARCHITECTURE.md`
- Governance contracts: `docs/GOVERNANCE.md`
- Methodology patterns: `docs/METHODOLOGY.md`
- Operator runbook: `docs/OPERATIONS.md`