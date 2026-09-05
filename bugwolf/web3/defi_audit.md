# DeFi Bug Classes — Audit Methodology

This document collects the canonical bug classes that show up repeatedly
in DeFi audits and post-mortems.  The methodology is intentionally
implementation-agnostic: it works on a white-box source tree, on a
brown-box ABI, and on raw bytecode.  Examples are drawn from public
Hackmd posts and Trail-of-Bits / OtterSec / Spearbit reports — no
proprietary or paid-only material is referenced.

The structure is **bug class → recognition heuristic → exploitation
shape → remediation sketch**.  Each section ends with a one-paragraph
"audit checklist" that an auditor can paste into a Notion / Linear
template.

---

## 1. Reentrancy (single-function, cross-function, read-only)

### Recognition
- A function transfers ETH or calls an external contract *before*
  updating a balance mapping.
- The contract uses a nonReentrant modifier on withdraw() but not on
  deposit(), or vice-versa.
- An ERC-777 / ERC-1366 / ERC-3156 hook (tokensReceived /
  onTransferReceived / onFlashLoan) re-enters the caller.

### Exploitation
The attacker wraps the victim address in a contract whose `fallback`
re-enters `withdraw()`.  Each recursion decrements the user's stored
balance *only after* the external call returns.  Nested recursion
compounds to drain the contract.

### Remediation
- **Checks-Effects-Interactions** — verify preconditions, write
  effects, then call externals.
- A single `nonReentrant` mutex across every function that mutates
  shared state.
- For read-only reentrancy: use EIP-1153 transient storage
  (`tstore`/`tload`) to coordinate.

### Audit checklist
- [ ] All external calls follow CEI ordering.
- [ ] A single reentrancy guard spans the entire accounting surface.
- [ ] View functions return data that is consistent post-callback.

---

## 2. Oracle Manipulation (spot, TWAP, LP, push)

### Recognition
- `getPrice()` reads `IUniswapV2Pair.getReserves()` directly.
- `consult()` is called with a TWAP window < 30 minutes.
- The fallback when Chainlink fails is a spot price from a thin
  pair.
- LP `totalSupply` is used as a price oracle.

### Exploitation
- **Sandwich**: front-run the victim with a large swap, let the
  victim trade at the inflated price, then back-run.
- **Flash-swap**: borrow via Uniswap V2 flash-swap, dump, recover in
  the same tx.
- **Donation attack**: send tokens directly to the LP to inflate
  price.

### Remediation
- Use Chainlink with a **staleness window check** (`updatedAt` within
  N minutes).
- Use a TWAP with a 30-minute minimum window.
- Never degrade to spot on failure — **pause** the protocol.

### Audit checklist
- [ ] Chainlink feeds verified for heartbeat + deviation threshold.
- [ ] TWAP window ≥ 30 min for non-trivial value.
- [ ] L2 oracles check `SequencerUptimeFeed`.

---

## 3. Sandwich & MEV Extraction

### Recognition
- A swap function omits `amountOutMin` or sets it to 0.
- A liquidation allows an unbounded bonus.
- The vault does not commit to a private mempool (Flashbots).

### Exploitation
The searcher monitors the public mempool, sandwiches the victim's
swap, and pockets the difference.  Off-chain "just-in-time" (JIT)
liquidity attacks compound the problem.

### Remediation
- Always require a non-zero `amountOutMin`.
- Use private mempools / MEV-blocker RPC.
- Cap slippage tolerance; validate post-swap invariants.

### Audit checklist
- [ ] `amountOutMin` is parameterized and bounded below.
- [ ] User-visible slippage check happens *after* fees.

---

## 4. Governance Attack

### Recognition
- Voting power is computed at vote time from current balance.
- There is no snapshot block; ERC20Votes isn't used.
- Proposal threshold is < 1% of supply.

### Exploitation
Attacker flash-loans a large amount of governance token, votes
themselves through a hostile proposal, then returns the loan.  In
practice proposals are guarded by a timelock, so the attacker uses a
flash loan only if timelock < vote duration.

### Remediation
- Use OpenZeppelin's `ERC20Votes` with explicit snapshot blocks.
- Bound vote weight by `getPastVotes(blockNumber - 1)`.
- Set proposal threshold ≥ 2.5% of supply.

### Audit checklist
- [ ] Vote weight is bounded by past balance.
- [ ] Timelock ≥ 48 hours on every privileged action.

---

## 5. Flash Loan Exploits (vault-drain type)

### Recognition
- A vault computes share price from spot balances.
- An ERC-4626 vault has zero first-deposit (no dead shares).
- Reward distribution is `balanceOf * rate` without vesting.

### Exploitation
The attacker flash-loans enough to become the dominant share, mints
the inflated share set, redeems against the inflated pool, returns
the loan, and pockets the residual.

### Remediation
- Mint **dead shares** on first deposit (Uniswap V2 / OpenZeppelin
  ERC4626 pattern).
- Use a virtual share offset to immunize first-deposit math.
- Vest rewards across N blocks before allowing claim.

### Audit checklist
- [ ] First-deposit minimum < 1000 wei of virtual shares.
- [ ] Reward vesting period ≥ 1 day.

---

## 6. Hidden Mints & Owner Key Abuse

### Recognition
- A `mint(address, uint)` function has `onlyOwner`.
- There is no hard cap.
- `renounceOwnership` actually calls `_transferOwnership(secretAddr)`.

### Exploitation
The owner key is compromised, or the deployer team simply mints to
themselves, dumps, and abandons.  Replicating the famous Squid Game
or AnubisDAO rug pattern.

### Remediation
- No `mint` function — supply is fixed at deploy.
- If mint is required: cap it, route it through a multisig + DAO,
  and emit a `SupplyCapChanged` event.

### Audit checklist
- [ ] No owner-mintable supply.
- [ ] Ownership renounced or held by ≥ 4-of-7 multisig.

---

## 7. Honeypots

### Recognition
- `transfer()` reverts when `from` is a contract (e.g.
  `tx.origin != from`).
- `approve` only succeeds for a pre-blessed spender.
- The contract's bytecode ends with a `SELFDESTRUCT` that only the
  owner can trigger.

### Exploitation
Bots detect honeypots and drain victim traders.  The pattern is
non-malicious for the contract owner; it traps user funds.

### Remediation
- Hound the codebase for `tx.origin`, `isContract`, and `onlyOwner`
  in places where users are required to interact.
- Run the codebase through a public honeypot detector (e.g.
  honeypot.is) as a smoke test.

### Audit checklist
- [ ] No `isContract(sender)` checks on user-only flows.
- [ ] SELFDESTRUCT removed (or owner-only behind a 7-day timelock).

---

## 8. Signature Malleability & Permit Replay

### Recognition
- `ecrecover` is used without bounding `s` to the lower half-order.
- Permit accepts arbitrary `deadline` (or no deadline).
- The contract does not include `chainId` in the EIP-712 digest.

### Exploitation
An attacker re-signs a valid permit with a malleable signature,
producing a second valid signature for the same data.  They then
redeem twice or across chains.

### Remediation
- Bound `s` ∈ [1, n/2]; verify `v ∈ {27, 28}`.
- Include `chainId` and `verifyingContract` in the EIP-712 digest.
- Always enforce `block.timestamp < deadline`.

### Audit checklist
- [ ] Signature verification includes s-value bounds.
- [ ] Permit enforces deadline + chainId.

---

## 9. Upgradeability Risks (UUPS, Transparent, Diamond)

### Recognition
- The implementation contract has a `setImplementation` callable by
  owner.
- Storage layout is not gap-padded.
- `delegatecall` goes through arbitrary user-supplied selectors.

### Exploitation
A compromised upgrade key ships a malicious implementation that
re-initializes state, sets a new owner, and drains funds.

### Remediation
- Use OpenZeppelin UUPS with `onlyProxy` / `onlyAdmin` modifiers.
- Storage gap (50 unused slots) before inherited layout.
- 48-hour timelock on every upgrade.

### Audit checklist
- [ ] Initializer re-init impossible.
- [ ] Storage layout gap verified against prior implementation.

---

## 10. Cross-Chain Bridge Bugs

### Recognition
- The bridge does not verify a Merkle proof against a finalized
  block.
- Messages can be replayed on the destination chain.
- The relayer is a single address with no rotation.

### Exploitation
Replay or forge a cross-chain message to mint free tokens on the
destination, or skip verification to claim tokens that were never
burned on the source.  This is the shape of the Ronin, Wormhole,
Harmony, and Nomad exploits.

### Remediation
- Verify Merkle proof against a finalized block on the source.
- Include a unique nonce per message and reject duplicates.
- Multi-relayer quorum with slashing.

### Audit checklist
- [ ] Source block finality confirmed.
- [ ] Message nonces strictly increasing.

---

## Appendix A — Cross-cutting tool guidance

- **Static**: Slither (`--detect all`); Mythril on the bytecode for
  fallback checks.
- **Dynamic**: Foundry invariant tests; Echidna property tests; Manticore
  concolic runs on critical functions.
- **Audit lifecycle**: write the test *before* the patch; record
  rationale, what you tried, and what you skipped.  The audit log
  itself is a deliverable.

## Appendix B — Severity rubric

| Class | Critical if | High if | Medium if |
|---|---|---|---|
| Reentrancy | Drains > 1% of TVL | Drains user opt-in funds | View-only return inconsistency |
| Oracle | Loss > $100k historical | Loss > $10k | Bounded to L2 sequencer downtime |
| Governance | Quorum < 25% | Quorum < 50% | Quorum ≥ 50% |
| Honeypot | All users locked | Large subset locked | Single user trapped |

Severity ratings must be re-anchored at the engagement boundary;
do not import a rubric from a previous engagement.