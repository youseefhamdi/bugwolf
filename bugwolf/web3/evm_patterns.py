"""EVM (Ethereum Virtual Machine) rug-pull / smart contract bug patterns.

This module publishes a registry of 50+ patterns drawn from public
post-mortems, the Damn Vulnerable DeFi / Ethernaut challenge lineage,
and Trail-of-Bits' Slither detector taxonomy. Each pattern is a frozen
dataclass so it can be hashed and shipped across the bugwolf event bus.

The signatures here are *detection signatures* — either a regex over
Solidity source or an EVM bytecode opcode sequence. They are not
exploits; they are the heuristic an auditor (human or automated)
should look for when triaging a target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


SCHEMA = "bugwolf-web3-evm-patterns/v1"


SEVERITIES = ("critical", "high", "medium", "low", "informational")


@dataclass(frozen=True)
class Pattern:
    """A single EVM/Solidity bug pattern."""

    id: str
    name: str
    severity: str
    category: str
    description: str
    detection_signature: str
    remediation: str
    cwe: Optional[str] = None

    def matches_source(self, source: str) -> bool:
        """Return True iff the regex signature matches the given source."""
        try:
            return bool(re.search(self.detection_signature, source, re.IGNORECASE))
        except re.error:
            return False


PATTERNS: List[Pattern] = [
    # ---- rug-pull family (1-12) ----
    Pattern(
        id="EVM-RUG-001",
        severity="critical",
        category="rug-pull",
        name="Hidden mint authority",
        description=(
            "Owner-only mint function with no timelock or zero-address check, "
            "allowing unbounded supply inflation."
        ),
        detection_signature=r"function\s+mint\s*\([^)]*\)\s*(?:public|external)[^{]*onlyOwner",
        remediation="Add a hard supply cap and zero-address sanity check; route mint through a timelock.",
        cwe="CWE-732",
    ),
    Pattern(
        id="EVM-RUG-002",
        severity="critical",
        category="rug-pull",
        name="Pausable transfer trap",
        description="Transfer function gated by a pausable modifier that owner can flip to lock user funds.",
        detection_signature=r"function\s+transfer\s*\([^)]*\)[^{]*whenNotPaused",
        remediation="Avoid pausing transfers entirely; if required, use a per-user allowlist instead of a global kill-switch.",
    ),
    Pattern(
        id="EVM-RUG-003",
        severity="high",
        category="rug-pull",
        name="Owner blacklist on ERC20",
        description=(
            "Owner can blacklist arbitrary addresses from transferring — a "
            "honeypot primitive."
        ),
        detection_signature=r"mapping\s*\([^)]*\)\s*(?:public|private)?\s*blacklist",
        remediation="Remove owner-mediated blacklists; rely on slashing/burn for compliance flows.",
    ),
    Pattern(
        id="EVM-RUG-004",
        severity="high",
        category="rug-pull",
        name="Unbounded fee increase",
        description="Owner can raise the transfer fee up to 100% via setFee().",
        detection_signature=r"function\s+setFee\s*\(\s*uint\d*\s+_fee\s*\)",
        remediation="Cap fee at a low immutable bound (e.g. 5%) and emit an event with timelock.",
    ),
    Pattern(
        id="EVM-RUG-005",
        severity="critical",
        category="rug-pull",
        name="Upgradeable + selfdestruct",
        description="Proxy pattern combined with a selfdestruct fallback that can brick user funds.",
        detection_signature=r"selfdestruct\s*\(\s*address\s*\(\s*\d+\s*\)\s*\)",
        remediation="Remove selfdestruct entirely; UUPS proxies do not need it.",
    ),
    Pattern(
        id="EVM-RUG-006",
        severity="high",
        category="rug-pull",
        name="Withdraw-trap fallback",
        description=(
            "Fallback function reverts unless a hidden admin flag is set, "
            "trapping ETH sent to the contract."
        ),
        detection_signature=r"fallback\s*\(\s*\)\s*(?:external|payable)[^{]*\{[^}]*require\s*\(\s*!locked",
        remediation="Fallback should only enforce interface correctness, never an admin flag.",
    ),
    Pattern(
        id="EVM-RUG-007",
        severity="high",
        category="rug-pull",
        name="Hidden ownership transfer",
        description="RenounceOwnership() that actually transfers ownership to a backdoor address.",
        detection_signature=r"function\s+renounceOwnership\s*\(\s*\)\s*public\s*\{[^}]*_transferOwnership",
        remediation="RenounceOwnership must set owner to address(0) and emit the canonical event.",
    ),
    Pattern(
        id="EVM-RUG-008",
        severity="high",
        category="rug-pull",
        name="LP token withdrawal",
        description="Contract removes liquidity from a Uniswap pair without timelock.",
        detection_signature=r"function\s+removeLiquidity\s*\([^)]*\)[^{]*onlyOwner",
        remediation="Lock LP tokens via a multisig with mandatory 48h delay.",
    ),
    Pattern(
        id="EVM-RUG-009",
        severity="medium",
        category="rug-pull",
        name="Token tax redirection",
        description="Tax/fee redirector that can be flipped to send 100% of fees to attacker.",
        detection_signature=r"function\s+setTaxRecipient\s*\(",
        remediation="Tax recipient should be immutable or set once at deploy.",
    ),
    Pattern(
        id="EVM-RUG-010",
        severity="critical",
        category="rug-pull",
        name="Whitelist-only sell window",
        description=(
            "Sell is gated by a whitelist that owner controls, allowing "
            "selective trapping."
        ),
        detection_signature=r"function\s+(?:sell|transferFrom)\s*\([^)]*\)[^{]*require\s*\(\s*whitelist",
        remediation="Never gate sell on a mutable whitelist; allowlist at deploy time only.",
    ),
    Pattern(
        id="EVM-RUG-011",
        severity="high",
        category="rug-pull",
        name="Max-tx-percentage honeypot",
        description="Max tx % set to 0 in constructor with a hidden toggle to unlock and dump.",
        detection_signature=r"(?:maxTx|maxTxAmount)\s*=\s*0\s*;",
        remediation="Honest max-tx limits are derived from supply (e.g. 0.5%); never zero.",
    ),
    Pattern(
        id="EVM-RUG-012",
        severity="medium",
        category="rug-pull",
        name="Honeypot name decoder",
        description=(
            "Token name/symbol encoded to bypass scanner regexes."
        ),
        detection_signature=r"unicode\\u00",
        remediation="Plain ASCII identifiers; reject obfuscated strings in CI.",
    ),

    # ---- reentrancy family (13-22) ----
    Pattern(
        id="EVM-REE-013",
        severity="critical",
        category="reentrancy",
        name="Classic single-function reentrancy",
        description="External call to untrusted address before state update.",
        detection_signature=r"\.call\s*\([^)]*\)[^{]*;\s*(?!.*\n\s*\w+\s*=)",
        remediation="Checks-Effects-Interactions; update state before the external call.",
        cwe="CWE-841",
    ),
    Pattern(
        id="EVM-REE-014",
        severity="critical",
        category="reentrancy",
        name="Cross-function reentrancy",
        description=(
            "External call in function A allows reentering function B that "
            "shares state."
        ),
        detection_signature=r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)[^{]*\{[^}]*\.call\s*\(",
        remediation="Apply nonReentrant to all state-touching functions sharing storage.",
    ),
    Pattern(
        id="EVM-REE-015",
        severity="high",
        category="reentrancy",
        name="Read-only reentrancy via view",
        description=(
            "View function returns stale data because state is read mid-"
            "callback."
        ),
        detection_signature=r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)\s+view\s+returns",
        remediation="Use transient storage / EIP-1153 to coordinate.",
    ),
    Pattern(
        id="EVM-REE-016",
        severity="high",
        category="reentrancy",
        name="ERC777 hook reentrancy",
        description="TokensReceived callback re-enters the sender before balance update.",
        detection_signature=r"tokensReceived\s*\([^)]*\)\s*(?:external|public)",
        remediation="Apply nonReentrant to all balance-reading and balance-modifying paths.",
    ),
    Pattern(
        id="EVM-REE-017",
        severity="high",
        category="reentrancy",
        name="ETH-handler reentrancy",
        description="Receive/Fallback re-enters withdraw() before balances decrement.",
        detection_signature=r"receive\s*\(\s*\)\s*external\s+payable\s*\{[^}]*withdraw",
        remediation="Mark withdraw() nonReentrant; decrement balance before sending.",
    ),
    Pattern(
        id="EVM-REE-018",
        severity="medium",
        category="reentrancy",
        name="Multi-call reentrancy",
        description=(
            "Aggregate call allows interleaving external calls across "
            "sub-accounts."
        ),
        detection_signature=r"function\s+multicall\s*\([^)]*\)\s*(?:public|external)",
        remediation="Wrap multicall body in a single nonReentrant lock.",
    ),
    Pattern(
        id="EVM-REE-019",
        severity="high",
        category="reentrancy",
        name="Approval reentrancy",
        description="approve() then external call allows the spender to drain via transferFrom.",
        detection_signature=r"\.approve\s*\([^)]*\)\s*;\s*[^\n]*\.call\s*\(",
        remediation="Use forceApprove or set allowance to 0 before non-zero.",
    ),
    Pattern(
        id="EVM-REE-020",
        severity="critical",
        category="reentrancy",
        name="Proxy delegatecall reentrancy",
        description="Delegatecall into implementation that re-enters the proxy.",
        detection_signature=r"assembly\s*\{[^}]*delegatecall",
        remediation="Avoid delegatecall + external calls; use UUPS with storage gaps.",
    ),
    Pattern(
        id="EVM-REE-021",
        severity="medium",
        category="reentrancy",
        name="Transient storage missing",
        description="Reentrancy guard implemented in storage instead of EIP-1153 transient storage.",
        detection_signature=r"uint\d+\s+_status\s*;\s*function\s+nonReentrant",
        remediation="Use tstore/tload (Solidity 0.8.24+ transient).",
    ),
    Pattern(
        id="EVM-REE-022",
        severity="high",
        category="reentrancy",
        name="Cross-chain reentrancy",
        description=(
            "Cross-chain message handler re-enters L1 before finality."
        ),
        detection_signature=r"(?:IAcross|IL1OpStack|ICcip)\.send",
        remediation="Confirm finality on destination before mutating state.",
    ),

    # ---- access control family (23-32) ----
    Pattern(
        id="EVM-ACC-023",
        severity="critical",
        category="access-control",
        name="Missing onlyOwner modifier",
        description="Privileged function without any access modifier.",
        detection_signature=r"function\s+set\w+\s*\([^)]*\)\s*(?:public|external)\s*\{",
        remediation="Add onlyOwner or Role-based access control.",
        cwe="CWE-284",
    ),
    Pattern(
        id="EVM-ACC-024",
        severity="high",
        category="access-control",
        name="tx.origin authentication",
        description="Using tx.origin for auth — phishing vector.",
        detection_signature=r"require\s*\(\s*tx\.origin\s*==",
        remediation="Use msg.sender; tx.origin can be spoofed through intermediary contracts.",
    ),
    Pattern(
        id="EVM-ACC-025",
        severity="high",
        category="access-control",
        name="Constructor privilege escalation",
        description="Constructor sets owner to msg.sender but later function lets owner be reassigned without auth.",
        detection_signature=r"_transferOwnership\s*\(\s*0x",
        remediation="Renounce ownership properly; never pass arbitrary addresses to _transferOwnership.",
    ),
    Pattern(
        id="EVM-ACC-026",
        severity="medium",
        category="access-control",
        name="Unprotected initializer",
        description="__ERC1967Upgrade_initialize not gated by onlyInitializing.",
        detection_signature=r"function\s+initialize\s*\([^)]*\)\s*public",
        remediation="Use onlyInitializing modifier or initializable pattern.",
    ),
    Pattern(
        id="EVM-ACC-027",
        severity="high",
        category="access-control",
        name="Default visibility public",
        description="Function without visibility — defaults to public in legacy Solidity.",
        detection_signature=r"function\s+\w+\s*\([^)]*\)\s*(?:payable\s*)?\{",
        remediation="Always specify public/external/internal/private explicitly.",
    ),
    Pattern(
        id="EVM-ACC-028",
        severity="critical",
        category="access-control",
        name="Unprotected selfdestruct",
        description="selfdestruct callable by anyone.",
        detection_signature=r"selfdestruct\s*\(\s*\w+\s*\)",
        remediation="Restrict selfdestruct to owner; or remove it entirely (post-EIP-6780).",
    ),
    Pattern(
        id="EVM-ACC-029",
        severity="high",
        category="access-control",
        name="Owner can drain contract balance",
        description="withdraw() function owned by EOA can sweep all ETH.",
        detection_signature=r"function\s+withdraw\s*\(\s*\)\s*(?:public|external)[^{]*onlyOwner",
        remediation="Withdraw should be pro-rata to depositors, not owner-only.",
    ),
    Pattern(
        id="EVM-ACC-030",
        severity="medium",
        category="access-control",
        name="Single-owner multisig bypass",
        description="Multisig with threshold 1 on a single EOA.",
        detection_signature=r"threshold\s*=\s*1",
        remediation="Threshold must be >= 2 with distinct keyholders.",
    ),
    Pattern(
        id="EVM-ACC-031",
        severity="high",
        category="access-control",
        name="Role escalation via grantRole",
        description="grantRole callable by anyone.",
        detection_signature=r"function\s+grantRole\s*\([^)]*\)\s*(?:public|external)\s*\{",
        remediation="Default to onlyRole(DEFAULT_ADMIN_ROLE).",
    ),
    Pattern(
        id="EVM-ACC-032",
        severity="medium",
        category="access-control",
        name="Initializer re-initializable",
        description="_initialized flag in custom upgradeable contract allows re-init.",
        detection_signature=r"_initialized\s*=\s*true",
        remediation="Use OpenZeppelin Initializable; never expose a public re-init path.",
    ),

    # ---- oracle / price manipulation family (33-42) ----
    Pattern(
        id="EVM-ORC-033",
        severity="critical",
        category="oracle",
        name="Single-source spot price",
        description="Price read from a single DEX pair — sandwich / oracle manipulation.",
        detection_signature=r"function\s+getPrice\s*\([^)]*\)\s*(?:public|external)\s+(?:view|returns)[^{]*\{[^}]*IUniswapV2",
        remediation="Use Chainlink or a TWAP over multiple blocks.",
        cwe="CWE-829",
    ),
    Pattern(
        id="EVM-ORC-034",
        severity="high",
        category="oracle",
        name="Stale Chainlink price",
        description="Chainlink price read without checking updatedAt staleness.",
        detection_signature=r"latestRoundData\s*\([^)]*\)\s*\)",
        remediation="Check returned updatedAt is within an acceptable staleness window.",
    ),
    Pattern(
        id="EVM-ORC-035",
        severity="critical",
        category="oracle",
        name="LP-token oracle",
        description="Using Uniswap LP totalSupply as price — manipulable via donation.",
        detection_signature=r"totalSupply\s*\(\s*\)\s*;[^}]*reserve",
        remediation="Never derive price from LP balances; use Chainlink or a curated basket.",
    ),
    Pattern(
        id="EVM-ORC-036",
        severity="high",
        category="oracle",
        name="Time-weighted average price slip",
        description="TWAP window too narrow (< 30 minutes) — flash loan attacks feasible.",
        detection_signature=r"consult\s*\([^)]*,\s*1[0-9]{1,2}\s*\)",
        remediation="TWAP window must be >= 30 minutes for non-trivial value.",
    ),
    Pattern(
        id="EVM-ORC-037",
        severity="high",
        category="oracle",
        name="Internal price feed",
        description="Price set by owner only — operator rug.",
        detection_signature=r"function\s+setPrice\s*\(.*\)\s*(?:public|external)",
        remediation="Use decentralized oracles; never owner-only price.",
    ),
    Pattern(
        id="EVM-ORC-038",
        severity="high",
        category="oracle",
        name="Missing sequencer uptime check",
        description="L2 oracle without DataFeeds / SequencerUptimeFeed check.",
        detection_signature=r"function\s+latestRoundData\s*\([^)]*\)[^{]*\{",
        remediation="On L2, check SequencerUptimeFeed before reading price.",
    ),
    Pattern(
        id="EVM-ORC-039",
        severity="medium",
        category="oracle",
        name="Price inverted without bounds",
        description="1e36 / price is unbounded — overflow / underflow on tiny prices.",
        detection_signature=r"1e(?:36|18)\s*/\s*price",
        remediation="Use a clamped reciprocal library (Remco/Maker).",
    ),
    Pattern(
        id="EVM-ORC-040",
        severity="high",
        category="oracle",
        name="Push oracle front-runnable",
        description="Push oracle allows price submitter to front-run their own update.",
        detection_signature=r"function\s+update\s*\([^)]*\)\s*(?:public|external)",
        remediation="Use commit-reveal or Chainlink Push (EIP-6229).",
    ),
    Pattern(
        id="EVM-ORC-041",
        severity="high",
        category="oracle",
        name="Multi-asset oracle without deviation check",
        description="Curve / Balancer oracle without deviation cap.",
        detection_signature=r"Oracle\.consult\s*\([^)]*\)\s*;",
        remediation="Apply a max deviation bound (e.g. 5%) and revert on excess.",
    ),
    Pattern(
        id="EVM-ORC-042",
        severity="medium",
        category="oracle",
        name="Fallback to spot on staleness",
        description="Falls back to spot price when Chainlink is unavailable — re-introduces manipulable source.",
        detection_signature=r"if\s*\(\s*roundID\s*==\s*0\s*\)[^{]*\{[^}]*getReserves",
        remediation="Pause the protocol on staleness; never degrade to spot.",
    ),

    # ---- flash-loan & DeFi invariants (43-52) ----
    Pattern(
        id="EVM-FLA-043",
        severity="high",
        category="flash-loan",
        name="Flash-loan-mutable invariant",
        description=(
            "Liquidity invariant computed inside a function that accepts "
            "flash-loaned balances."
        ),
        detection_signature=r"function\s+\w+\s*\([^)]*\)[^{]*\{[^}]*flashLoan",
        remediation="Snapshot invariant before flash loan executes; check after.",
    ),
    Pattern(
        id="EVM-FLA-044",
        severity="high",
        category="flash-loan",
        name="Reward accrual in same block",
        description="AccrueRewards in same block as stake — flash loan can claim without locking.",
        detection_signature=r"function\s+accrue\w*[Rr]ewards?\s*\([^)]*\)[^{]*\{",
        remediation="Require stake > 0 across N blocks before rewards accrue.",
    ),
    Pattern(
        id="EVM-FLA-045",
        severity="high",
        category="flash-loan",
        name="Governance vote flash-loan",
        description="Voting power computed at vote time without snapshot — flash loan amplifies.",
        detection_signature=r"function\s+(?:castVote|vote)\s*\([^)]*\)[^{]*\{[^}]*getPriorTotal",
        remediation="Use ERC20Votes snapshot; check snapshot block is in the past.",
    ),
    Pattern(
        id="EVM-FLA-046",
        severity="critical",
        category="flash-loan",
        name="Donation attack on first-deposit",
        description="Virtual shares donation can be exploited on empty pool.",
        detection_signature=r"function\s+deposit\s*\([^)]*\)[^{]*\{[^}]*totalSupply",
        remediation="Mint dead shares on first deposit (Uniswap V2 pattern).",
    ),
    Pattern(
        id="EVM-FLA-047",
        severity="high",
        category="flash-loan",
        name="Unbounded mint via flash",
        description="Mint function reads spot price, manipulable via flash swap.",
        detection_signature=r"function\s+mint\s*\([^)]*\)[^{]*\{[^}]*getReserves",
        remediation="Use TWAP with 30+ min window for mint pricing.",
    ),
    Pattern(
        id="EVM-FLA-048",
        severity="medium",
        category="flash-loan",
        name="Fee-on-transfer not handled",
        description="transferFrom balance check fails when token deducts on transfer.",
        detection_signature=r"balAfter\s*-\s*balBefore",
        remediation="Read balanceOf before and after; compute received delta.",
    ),
    Pattern(
        id="EVM-FLA-049",
        severity="high",
        category="flash-loan",
        name="Reward distribution by balance ratio",
        description="Rewards proportional to balance; flash-stake drain.",
        detection_signature=r"reward\s*=\s*totalReward\s*\*\s*balanceOf",
        remediation="Vest rewards; require stake-duration >= T before claim.",
    ),
    Pattern(
        id="EVM-FLA-050",
        severity="medium",
        category="flash-loan",
        name="Liquidation bonus flash-bait",
        description="Liquidation bonus is fixed ratio flash-loan can capture repeatedly.",
        detection_signature=r"function\s+liquidate\s*\([^)]*\)[^{]*\{[^}]*bonus",
        remediation="Cap bonus size; require partial repay only.",
    ),
    Pattern(
        id="EVM-FLA-051",
        severity="high",
        category="flash-loan",
        name="Slippage check absent",
        description="Swap without minOut parameter — sandwich extractable.",
        detection_signature=r"amountOutMin\s*=\s*0",
        remediation="Always require minOut; default to >= 0.5% slippage tolerance.",
    ),
    Pattern(
        id="EVM-FLA-052",
        severity="critical",
        category="flash-loan",
        name="Vault share inflation",
        description="Vault share price inflated by direct token transfer (ERC4626 inflation attack).",
        detection_signature=r"function\s+(?:deposit|mint)\s*\([^)]*\)[^{]*\{[^}]*totalAssets\s*\(\s*\)",
        remediation="Implement virtual shares / dead-shares minimum (OpenZeppelin ERC4626).",
    ),

    # ---- integer / overflow (53-56) ----
    Pattern(
        id="EVM-INT-053",
        severity="high",
        category="integer",
        name="unchecked arithmetic",
        description="unchecked block can silently wrap on overflow.",
        detection_signature=r"unchecked\s*\{",
        remediation="Minimize unchecked; document any wrapped math with proofs.",
    ),
    Pattern(
        id="EVM-INT-054",
        severity="critical",
        category="integer",
        name="Solidity < 0.8 arithmetic",
        description="Compiler version < 0.8 with raw add/mul.",
        detection_signature=r"pragma\s+solidity\s*\^?0\.(?:4|5|6|7)\.",
        remediation="Upgrade to 0.8+; or use SafeMath explicitly.",
    ),
    Pattern(
        id="EVM-INT-055",
        severity="medium",
        category="integer",
        name="uint to int cast",
        description="Cast uint to int can produce negative on large values.",
        detection_signature=r"int256\(\s*\w+\s*\)",
        remediation="Bounds-check before casting; prefer uint internally.",
    ),
    Pattern(
        id="EVM-INT-056",
        severity="high",
        category="integer",
        name="Truncated division",
        description="Division rounds down, can be exploited for rounding-attack.",
        detection_signature=r"\w+\s*/\s*\w+",
        remediation="Use mulDiv with rounding-up variant when accumulating fees.",
    ),

    # ---- gas / DoS (57-58) ----
    Pattern(
        id="EVM-GAS-057",
        severity="medium",
        category="denial-of-service",
        name="Unbounded loop",
        description="Loop over an unbounded array — gas DoS.",
        detection_signature=r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length",
        remediation="Paginate; use accumulator pattern; cap loop bound.",
    ),
    Pattern(
        id="EVM-GAS-058",
        severity="high",
        category="denial-of-service",
        name="External call inside loop",
        description="Multiple external calls in a single tx — failure of one reverts all.",
        detection_signature=r"for[^{]*\{[^}]*\.call\s*\(",
        remediation="Pull-payment pattern; never loop over external calls in core flow.",
    ),

    # ---- logic / signature (59-62) ----
    Pattern(
        id="EVM-LOG-059",
        severity="high",
        category="logic",
        name="Permit replay (without nonce)",
        description="eip-712 permit without nonce or chainId.",
        detection_signature=r"function\s+permit\s*\([^)]*\)[^{]*\{",
        remediation="Use OpenZeppelin ERC20Permit; it includes nonce + chainId.",
    ),
    Pattern(
        id="EVM-LOG-060",
        severity="critical",
        category="logic",
        name="Signature malleability",
        description="ecrecover without s-value check accepts malleable sigs.",
        detection_signature=r"ecrecover\s*\(",
        remediation="Check s in lower half-order range; check v is 27 or 28.",
    ),
    Pattern(
        id="EVM-LOG-061",
        severity="high",
        category="logic",
        name="Missing deadline on permit",
        description="Permit without deadline parameter — replay forever.",
        detection_signature=r"function\s+permit\s*\([^)]*\)\s*(?:public|external)[^{]*\{",
        remediation="Always include deadline and verify block.timestamp < deadline.",
    ),
    Pattern(
        id="EVM-LOG-062",
        severity="medium",
        category="logic",
        name="Timestamp dependence",
        description="block.timestamp used as randomness source.",
        detection_signature=r"block\.timestamp\s*%",
        remediation="Use VRF (Chainlink); never derive randomness from block fields.",
    ),
]


def by_category(category: str) -> List[Pattern]:
    return [p for p in PATTERNS if p.category == category]


def by_severity(severity: str) -> List[Pattern]:
    return [p for p in PATTERNS if p.severity == severity]


def find_by_id(pid: str) -> Optional[Pattern]:
    for p in PATTERNS:
        if p.id == pid:
            return p
    return None