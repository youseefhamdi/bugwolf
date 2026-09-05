"""Solana smart contract (Anchor / native Rust) bug patterns.

Pattern registry for Solana programs drawing on the Anchor framework's
detector taxonomy, OtterSec's audits, and the Neodyme / Trail-of-Bits
write-ups. Each pattern is a frozen dataclass for hashing across the
bugwolf event bus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


SCHEMA = "bugwolf-web3-solana-patterns/v1"


@dataclass(frozen=True)
class SolanaPattern:
    """A single Solana program bug pattern."""

    id: str
    name: str
    severity: str
    category: str
    description: str
    detection_signature: str
    remediation: str
    cwe: Optional[str] = None

    def matches_source(self, source: str) -> bool:
        try:
            return bool(re.search(self.detection_signature, source, re.IGNORECASE))
        except re.error:
            return False


PATTERNS: List[SolanaPattern] = [
    # ---- account confusion (1-8) ----
    SolanaPattern(
        id="SOL-ACC-001",
        severity="critical",
        category="account-confusion",
        name="Missing account ownership check",
        description=(
            "AccountInfo is read without checking `account.owner == "
            "expected_program`."
        ),
        detection_signature=r"AccountInfo\s*<",
        remediation="Use Anchor's `Account<'info, T>` wrapper or call `assert_owned_by`.",
    ),
    SolanaPattern(
        id="SOL-ACC-002",
        severity="critical",
        category="account-confusion",
        name="Missing signer check",
        description="Instruction handler uses AccountInfo without `is_signer`.",
        detection_signature=r"pub\s+user:\s*AccountInfo",
        remediation="Use `Signer<'info>` type; add `#[account(signer)]` constraint.",
    ),
    SolanaPattern(
        id="SOL-ACC-003",
        severity="high",
        category="account-confusion",
        name="Discriminator mismatch",
        description=(
            "Account not deserialized with the expected 8-byte "
            "discriminator."
        ),
        detection_signature=r"try_from_slice\b",
        remediation="Use `Account::try_deserialize` which verifies the discriminator.",
    ),
    SolanaPattern(
        id="SOL-ACC-004",
        severity="critical",
        category="account-confusion",
        name="PDA substitution",
        description=(
            "PDA seeds include only user-supplied data; attacker can "
            "re-derive a different PDA."
        ),
        detection_signature=r"Pubkey::find_program_address\s*\(",
        remediation="Seeds must include static prefix + signer key + bump; store bump on initialization.",
    ),
    SolanaPattern(
        id="SOL-ACC-005",
        severity="high",
        category="account-confusion",
        name="Init-if-needed ambiguity",
        description=(
            "Instruction uses `init_if_needed` on an account the caller "
            "controls — front-running reset."
        ),
        detection_signature=r"init_if_needed",
        remediation="Split initialize and use instructions; never share.",
    ),
    SolanaPattern(
        id="SOL-ACC-006",
        severity="high",
        category="account-confusion",
        name="Type cosplay",
        description=(
            "Account deserialized as type A can be re-submitted as type B "
            "due to identical layout."
        ),
        detection_signature=r"#[account]\s*$",
        remediation="Use explicit discriminator + account size; rely on Anchor type-check.",
    ),
    SolanaPattern(
        id="SOL-ACC-007",
        severity="medium",
        category="account-confusion",
        name="Duplicated mutable accounts",
        description=(
            "Two mutable AccountInfo<'info> parameters both referencing the "
            "same key."
        ),
        detection_signature=r"\[account\(mut\)\]",
        remediation="Add a runtime constraint `a.key() != b.key()` or use constraint macros.",
    ),
    SolanaPattern(
        id="SOL-ACC-008",
        severity="high",
        category="account-confusion",
        name="Sysvar confusion",
        description=(
            "Sysvar passed as raw AccountInfo can be substituted by attacker."
        ),
        detection_signature=r"sysvar:\s*AccountInfo",
        remediation="Use `Sysvar<'info, T>` typed wrapper.",
    ),

    # ---- arithmetic / math (9-12) ----
    SolanaPattern(
        id="SOL-ARITH-009",
        severity="critical",
        category="arithmetic",
        name="u64 / u128 overflow",
        description="Raw +, -, * on integers without checked_*.",
        detection_signature=r"\b\w+\s*\+\s*\w+",
        remediation="Use `checked_add`, `checked_sub`, `checked_mul` or `saturating_*`.",
    ),
    SolanaPattern(
        id="SOL-ARITH-010",
        severity="high",
        category="arithmetic",
        name="Cast truncation",
        description="Casting a larger int to smaller — truncation attacks.",
        detection_signature=r"as\s+u64\b",
        remediation="Bounds-check before cast; use `try_into()` returning Option.",
    ),
    SolanaPattern(
        id="SOL-ARITH-011",
        severity="high",
        category="arithmetic",
        name="Division by zero (unchecked)",
        description="Division without zero check.",
        detection_signature=r"\w+\s*/\s*\w+\s*;",
        remediation="Check denominator > 0 before division; use `checked_div`.",
    ),
    SolanaPattern(
        id="SOL-ARITH-012",
        severity="medium",
        category="arithmetic",
        name="Lamport underflow on refund",
        description="Refund lamports calculation can underflow.",
        detection_signature=r"lamports\(\)\s*-\s*",
        remediation="Use `checked_sub`; ensure sufficient balance before subtracting.",
    ),

    # ---- CPI & instruction replay (13-19) ----
    SolanaPattern(
        id="SOL-CPI-013",
        severity="critical",
        category="cpi",
        name="Unverified program ID in CPI",
        description=(
            "CPI target program not checked — calling wrong program."
        ),
        detection_signature=r"invoke\b",
        remediation="Compare `program_id` against a known Pubkey before invoke.",
    ),
    SolanaPattern(
        id="SOL-CPI-014",
        severity="high",
        category="cpi",
        name="Arbitrary CPI",
        description=(
            "User-supplied program passed to invoke_signed — privilege "
            "escalation."
        ),
        detection_signature=r"invoke_signed\b",
        remediation="Whitelist allowed programs in your IDL.",
    ),
    SolanaPattern(
        id="SOL-CPI-015",
        severity="critical",
        category="cpi",
        name="Privilege escalation via CPI",
        description=(
            "Program signs for PDA without ensuring the CPI target is "
            "trusted."
        ),
        detection_signature=r"invoke_signed\s*\([^,]*,\s*\[[\s\S]*?\]",
        remediation="Restrict CPI targets; never sign for arbitrary programs.",
    ),
    SolanaPattern(
        id="SOL-CPI-016",
        severity="high",
        category="cpi",
        name="Return-data confusion",
        description=(
            "Program reads `return_data` without verifying source program."
        ),
        detection_signature=r"SolanaReturnData",
        remediation="Verify `sol_get_return_data` source program ID.",
    ),
    SolanaPattern(
        id="SOL-CPI-017",
        severity="medium",
        category="cpi",
        name="Stale instruction sysvar",
        description=(
            "Reads instructions sysvar without checking last instruction "
            "identity."
        ),
        detection_signature=r"SysvarInstruction",
        remediation="Verify the last instruction's program_id matches expected.",
    ),
    SolanaPattern(
        id="SOL-CPI-018",
        severity="high",
        category="cpi",
        name="Missing has_one constraint",
        description=(
            "Token account's mint or authority not bound via has_one — "
            "attacker can pass their own account."
        ),
        detection_signature=r"token::mint\s*=",
        remediation="Add `has_one = mint` constraint.",
    ),
    SolanaPattern(
        id="SOL-CPI-019",
        severity="high",
        category="cpi",
        name="Unbounded realloc",
        description=(
            "Account realloc with user-supplied size — DoS or fake account "
            "swap."
        ),
        detection_signature=r"realloc\s*\(",
        remediation="Cap realloc growth; use Anchor's `realloc::zero = false`.",
    ),

    # ---- PDA & seeds (20-22) ----
    SolanaPattern(
        id="SOL-PDA-020",
        severity="critical",
        category="pda",
        name="Seed collision",
        description=(
            "PDA seeds don't include user key — two users derive the same "
            "address."
        ),
        detection_signature=r"seeds\s*=\s*\[\s*b\"[^\"]+\"\s*\]",
        remediation="Seeds must include user-supplied key (e.g. user.key().as_ref()).",
    ),
    SolanaPattern(
        id="SOL-PDA-021",
        severity="high",
        category="pda",
        name="Hardcoded bump not stored",
        description=(
            "PDA bump is recomputed each call instead of stored — slow + "
            "may collide."
        ),
        detection_signature=r"Pubkey::create_program_address",
        remediation="Store bump on initialization; use `bump = ctx.bumps.vault`.",
    ),
    SolanaPattern(
        id="SOL-PDA-022",
        severity="high",
        category="pda",
        name="Rent-exempt not enforced",
        description=(
            "New account not made rent-exempt — owner can be elided after "
            "garbage collection."
        ),
        detection_signature=r"Rent::from_account\b",
        remediation="Anchor's `init` automatically enforces rent-exempt; verify in custom code.",
    ),

    # ---- logic & randomness (23-30) ----
    SolanaPattern(
        id="SOL-LOG-023",
        severity="critical",
        category="logic",
        name="Instruction replay (no nonce)",
        description=(
            "Instruction handler accepts same payload twice — replay "
            "attack."
        ),
        detection_signature=r"pub\s+state:\s*Account",
        remediation="Store a processed-tx hash / nonce on the state account.",
    ),
    SolanaPattern(
        id="SOL-LOG-024",
        severity="high",
        category="logic",
        name="Missing signer on privileged action",
        description=(
            "Privileged instruction path lacks Signer type."
        ),
        detection_signature=r"pub\s+authority:\s*AccountInfo",
        remediation="Use `Signer<'info>` for authority.",
    ),
    SolanaPattern(
        id="SOL-LOG-025",
        severity="medium",
        category="logic",
        name="Clock as randomness",
        description=(
            "Uses Clock or slot as randomness — validator can manipulate."
        ),
        detection_signature=r"Clock::get\(\)",
        remediation="Use Switchboard VRF or commit-reveal.",
    ),
    SolanaPattern(
        id="SOL-LOG-026",
        severity="high",
        category="logic",
        name="Owner from data field (mutable)",
        description=(
            "Owner pubkey read from account data without checking signer."
        ),
        detection_signature=r"data\.owner",
        remediation="Trust only `account_info.key` plus is_signer.",
    ),
    SolanaPattern(
        id="SOL-LOG-027",
        severity="high",
        category="logic",
        name="Freeze authority not renounced",
        description=(
            "Token mint retains freeze authority — owner can freeze user "
            "balances."
        ),
        detection_signature=r"freeze_authority",
        remediation="Set freeze_authority to None after deployment.",
    ),
    SolanaPattern(
        id="SOL-LOG-028",
        severity="high",
        category="logic",
        name="Mint authority not renounced",
        description="Mint authority retained — owner can inflate supply.",
        detection_signature=r"mint_authority",
        remediation="Set mint_authority to None after fixed supply minted.",
    ),
    SolanaPattern(
        id="SOL-LOG-029",
        severity="medium",
        category="logic",
        name="Token-2022 extension oversight",
        description=(
            "Code assumes SPL Token but program uses Token-2022 with "
            "transfer hooks."
        ),
        detection_signature=r"anchor_spl::token",
        remediation="Test against Token-2022 if support claimed.",
    ),
    SolanaPattern(
        id="SOL-LOG-030",
        severity="critical",
        category="logic",
        name="Close account sends lamports to attacker",
        description=(
            "Closing an account with attacker-supplied destination."
        ),
        detection_signature=r"close_account\b",
        remediation="Hard-code destination; or use Anchor's `close = ` constraint.",
    ),
]


def by_category(category: str) -> List[SolanaPattern]:
    return [p for p in PATTERNS if p.category == category]


def by_severity(severity: str) -> List[SolanaPattern]:
    return [p for p in PATTERNS if p.severity == severity]


def find_by_id(pid: str) -> Optional[SolanaPattern]:
    for p in PATTERNS:
        if p.id == pid:
            return p
    return None