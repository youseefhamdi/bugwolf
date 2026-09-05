# bugwolf-rs — Rust core (Phase 4.A scaffold)

## Design

`bugwolf-rs/` is the Rust core of BugWolf. It is a **stdlib-only** crate:
no `Cargo.toml` dependencies, no `serde`, no `tokio`, no `reqwest`, no `pyo3`,
no `regex`. Everything is built on the Rust standard library
(`std::collections`, `std::net`, `std::io`, `std::fs`, `std::process`,
`std::sync`, `std::thread`, `std::time`, `std::cell`).

This is a deliberate constraint: the scanner core must be auditable line-by-line,
have a reproducible supply chain, and produce no transitive-dependency surprise
when shipped to a pentest operator's laptop or a CI runner.

## Modules

| Module                  | Purpose                                                       |
| ----------------------- | ------------------------------------------------------------- |
| `request_engine`        | Minimal synchronous HTTP/1.1 client (no TLS).                |
| `parsers`               | Pure parsers: HTTP response, query string, Set-Cookie, JWT.   |
| `scanner_core`          | Scanner trait, `ScanEngine` orchestrator, sample scanners.    |
| `gate`                  | Fail-closed scope gate with RFC1918 detection.                |
| `journal`               | Append-only SHA-256 hash-chained journal.                     |
| `hash`                  | SHA-256, HMAC-SHA256, constant-time equality.                 |
| `fuzzer`                | Coverage-guided fuzzer scaffold (STUB-SAFE).                 |
| `taint`                 | Taint tracking data structures (bitset, sinks).               |
| `destructive_gate`      | Opt-in registry of destructive primitives.                    |
| `skill_loader`          | SKILL.md frontmatter parser.                                  |

## Binaries

- `bench` — 10000 SHA-256 operations, prints elapsed ms.
- `healthcheck` — TCP `PING` to 127.0.0.1:6379, prints `OK` or `unavailable`.

## Build & test

```bash
cargo build --manifest-path bugwolf-rs/Cargo.toml
cargo test  --manifest-path bugwolf-rs/Cargo.toml
```

## Tests

All tests are module-local `#[cfg(test)] mod tests` blocks. No cross-file
imports, no fixtures, no `tests/` directory.

Capability tier: **C2** (active scanner) and **C3** (exploit) are **opt-in only**.