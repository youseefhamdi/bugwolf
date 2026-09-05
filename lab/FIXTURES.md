# BugWolf Lab Fixtures

Each fixture is a self-contained, intentionally-vulnerable target that
local BugWolf tools (Slither, Foundry, Echidna, Medusa, Mythril, Halmos)
can analyze. None of these are deployment targets — they are local
test fixtures only.

## Available fixtures

| Fixture | Path | Purpose |
|---|---|---|
| Vulnerable Vault (Solidity) | `web3/` | Reentrancy, oracle manipulation, access-control, rounding |

## Isolation requirements

- **No deployment.** All fixtures are flagged `lab-only` in `manifest.json`.
- **No network.** `engagement_boundary.network = "none"`.
- **Deterministic fuzzing.** `foundry.toml` pins seed + run count so local
  reproduction is bit-identical across runs.
- **Operator gates.** Tools that need external binaries (Slither, Foundry)
  gracefully report `available=False` when the binary is missing; the
  in-process executor in `tools/web3_fixture_runner.py` continues.

## Usage

```bash
# 1. Run Slither (if installed)
slither lab/web3/src/Vault.sol

# 2. Run Foundry invariants (if installed)
cd lab/web3 && forge test

# 3. Run via BugWolf fixture runner
python3 tools/web3_fixture_runner.py --target vault \
    --source lab/web3/src/Vault.sol --tools slither,foundry
```

## Adding a new fixture

1. Create `lab/<domain>/<fixture-name>/` with `src/`, `test/`, `manifest.json`.
2. Set `isolation_flags` and `declared_intentional_findings` in the manifest.
3. Pin fuzz seed + run count in `foundry.toml` (or equivalent).
4. Add a one-line entry to this README.
