"""BugWolf Phase 2.2 — Web3 Smart Contract Suite.

Additive package providing pattern registries, runner wrappers, a minimal
EVM disassembler, and audit methodology for EVM/Solana smart contracts.

All runners in this package are stub-safe: when the wrapped external tool
(slither, mythril, manticore, foundry) is not on PATH, they return a
``RunnerUnavailable`` dataclass with ``exit_code=127`` rather than raising.
"""

from __future__ import annotations

SCHEMA = "bugwolf-web3-v1"

__all__ = ["SCHEMA"]