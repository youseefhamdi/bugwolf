# Meme Coin Audit Methodology

Meme coins — typically low-float ERC-20 tokens with viral marketing
and a 1-2 week lifecycle — exhibit a *specific* family of bugs that
mainstream ERC-20 audits miss.  This document captures the
recognition heuristics, exploitation shapes, and remediation
guidance an auditor should apply when triaging a meme-coin target.

The patterns are drawn from public reports on Squid Game (SQUID),
AnubisDAO, Tiger King, SafeMoon forks, and the broader honeypot-is
corpus.  They are not theoretical.

---

## 1. Lifecycle Assumptions

A meme coin usually has a 1-7 day ramp window.  The assumption set:

1. The team ships once and never updates the contract.
2. The Uniswap V2 pair is the *only* price source.
3. The first 1,000 holders are 80% of supply.
4. There is no multisig — only an EOA owner.

These assumptions collapse in two ways:

- **Static exploit before launch**: the contract has a backdoor in
  bytecode that the team triggers once liquidity is established.
- **Slow rug during the ramp**: a transfer-tax toggle is flipped
  mid-flight.

### Audit implication
You must scan the deployed bytecode, not just the source.  The
team can ship one source, deploy a different bytecode.

---

## 2. Token Standard Mismatch

A "BEP-20" or "ERC-20" meme coin often ships with:

- A transfer-tax that is collected in a side-balance and re-minted
  on each transfer (fee-on-transfer).
- A max-tx-percentage that is **mutable** in storage.
- A blacklist mapping keyed by address.
- A cooldown between transfers (anti-bot).
- A reflection mechanism (RFI) that mints to holders from fees.

### Recognition
- `function _transfer(...)` contains a `if (from != pair && to != pair)`
  branch — the swap path is tax-free.
- `setMaxTx(uint)` is `external` and `onlyOwner`.
- `setBlacklist(address,bool)` exists.

### Exploitation
- The team flips `setMaxTx(0)` to lock non-EOA traders out, while
  allowing their own bot to drain.
- The blacklist is silently populated with addresses that bought
  early.
- The fee-on-transfer mechanism dusts wallets and is later redirected
  via `setTaxRecipient`.

### Remediation
- `maxTx` and `tax` must be **immutable** or set once at deploy.
- `blacklist` must be removed entirely.
- Tax recipient must be the LP pair (locked).

---

## 3. Honeypot Variants Specific to Meme Coins

### 3.1 Anti-bot, but also anti-everyone
A cooldown that resets on each transfer combined with a `block.timestamp`
requirement.  The team waits until after the cooldown to dump.

### 3.2 Whitelisted sell window
`transfer()` reverts unless `msg.sender == owner || block.timestamp >
launch + 30 days`.  Early buyers cannot exit; owner can.

### 3.3 Liquidity add-only
The token can be sold back to the pair only after a manual
`enableTrading()` call.  Owner calls this only after accumulating a
large position.

### 3.4 Hidden upgrade
The contract is a UUPS proxy.  Source looks fine; bytecode has a
backdoor selector.

### Audit checklist
- [ ] `transfer()` works for non-owner addresses immediately after
  launch.
- [ ] No `enableTrading` / `setBlacklist` / `setMaxTx` mutator.
- [ ] Source and deployed bytecode match (compare the constructor
  args + runtime code).

---

## 4. Deployer Risk

The deployer EOA controls:

1. Initial mint (full supply).
2. LP token custody.
3. Source-of-truth for the contract source on the website.

### Audit checklist
- [ ] Supply is fixed at deploy; `mint` is `internal` or absent.
- [ ] LP tokens are time-locked (e.g. Unicrypt / Team.Finance) for
  ≥ 6 months.
- [ ] Source on the website is verified on the explorer with
  matching bytecode.

---

## 5. Owner Key Compromise

Even a well-written meme coin fails if the owner key is compromised.
The owner key usually:

- Sits on a single laptop.
- Has no hardware wallet.
- Has signed into a phishing site.

### Mitigation guidance (cumulative)
- Multisig with ≥ 4 signers from different geographies.
- Hardware wallet + dedicated laptop.
- Critical functions disabled (`setFee`, `setMaxTx` removed) and
  declared immutable.

---

## 6. Pricing & Sandwich

A meme coin's liquidity is usually < $50k.  At this size:

- A single swap > 1% of pool moves price > 5%.
- Sandwich bots extract 30-50 bps per victim tx.

### Recognition
- `swapExactTokensForETHSupportingFeeOnTransferTokens` is called
  without `amountOutMin`.

### Remediation
- Encourage users to use a private RPC (Flashbots Protect, MEV
  Blocker).
- For automated market-making, integrate CowSwap or 1inch Fusion.

### Audit implication
The token contract itself can do little here — but the project
should publish slippage guidance and the audit should note it.

---

## 7. Launch-pad Specific Risks

Meme coins launched on Pinksale, Unicrypt, or similar launch-pads
inherit the launch-pad's contracts but may add their own wrappers.
Common wrappers:

- Refundable liquidity lock that can be re-claimed by owner.
- Vesting schedule that can be bypassed.
- Anti-snipe that can be toggled off mid-IDO.

### Audit checklist
- [ ] Liquidity lock is non-revocable.
- [ ] Vesting schedule is enforced by the lock contract, not by
  the team token.
- [ ] No upgrade hook in the wrapper.

---

## 8. Honeypot Detector Cross-checks

A defense-in-depth measure: run the token through honeypot.is,
TokenSniffer, and GoPlus.  If they flag it, escalate to a manual
review regardless of source clarity.

### Audit workflow
1. Confirm bytecode hash matches the published source.
2. Run Slither + Mythril on the bytecode.
3. Run a Foundry invariant that attempts `transfer` from a contract
   to the pair and from the pair to a contract.
4. Run honeypot.is / TokenSniffer.
5. Inspect storage layout — any state variable prefixed `owner`,
  `paused`, `fee`, `maxTx`, `blacklist` deserves a deeper look.

---

## 9. Reporting Tone

Meme coin projects are usually run by 1-2 founders with no formal
process.  Reports should:

- Lead with severity and impact in plain language.
- Provide a copy-pasteable Foundry PoC.
- End with a checklist of "before you ship" items.

Avoid lecturing; the team often doesn't have a security background
and will tune out jargon-heavy language.

---

## 10. Closing Thoughts

Meme coin security is dominated by **operational** risk rather than
**code** risk.  The bug class that hurts users the most is the one
that flips an owner-only parameter mid-flight.  A 50-line audit that
flags every `setXxx` function is more valuable than a 500-line audit
that flags a missing `unchecked` block.

References (public):
- Trail-of-Bits Slither detector taxonomy
- TokenSniffer methodology blog
- Slowmist Rug-pull post-mortems
- DeFiHackReports / rekt.news